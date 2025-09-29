use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{StreamExt, stream};
use gha_cache_server::storage::{BlobStore, BlobUploadPayload, fs::FsStore};
use tempfile::TempDir;

fn payload_from_bytes(chunks: Vec<&'static [u8]>) -> BlobUploadPayload {
    stream::iter(
        chunks
            .into_iter()
            .map(|chunk| Ok(Bytes::from_static(chunk))),
    )
    .boxed()
}

#[cfg(target_os = "linux")]
fn read_rss_kb() -> Result<usize> {
    let contents = std::fs::read_to_string("/proc/self/smaps_rollup")
        .context("failed to read smaps_rollup")?;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("Rss:") {
            let value = value.trim().trim_end_matches(" kB");
            let rss: usize = value
                .split_whitespace()
                .next()
                .context("unexpected Rss format")?
                .parse()
                .context("failed to parse Rss value")?;
            return Ok(rss);
        }
    }
    anyhow::bail!("Rss entry not found in smaps_rollup");
}

#[tokio::test]
async fn multipart_upload_writes_file() -> Result<()> {
    let temp = TempDir::new()?;
    let store = FsStore::new(PathBuf::from(temp.path()), None, None, None).await?;
    let key = "artifacts/demo/cache.tgz";

    let upload_id = store.create_multipart(key).await?;

    let part_one = payload_from_bytes(vec![b"hello ", b"world"]);
    let part_two = payload_from_bytes(vec![b" from fs store"]);

    let etag_one = store.upload_part(key, &upload_id, 1, part_one).await?;
    let etag_two = store.upload_part(key, &upload_id, 2, part_two).await?;

    store
        .complete_multipart(
            key,
            &upload_id,
            vec![(1, etag_one.clone()), (2, etag_two.clone())],
        )
        .await?;

    let final_path = temp.path().join(key);
    let contents = tokio::fs::read(&final_path).await?;
    assert_eq!(contents, b"hello world from fs store");

    let root = PathBuf::from(temp.path());
    let uploads_root = if let Some(parent) = root.parent() {
        let mut dir_name = OsString::from(".gha-cache-uploads");
        if let Some(name) = root.file_name() {
            dir_name.push("-");
            dir_name.push(name);
        }
        parent.join(dir_name)
    } else {
        root.join(".gha-cache-uploads")
    };
    let uploads_dir = uploads_root.join(&upload_id);
    assert!(
        !uploads_dir.exists(),
        "temporary upload directory should be cleaned up"
    );

    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn dropping_download_stream_releases_page_cache() -> Result<()> {
    use std::time::Duration;

    use tokio::time::sleep;

    let temp = TempDir::new()?;
    let store = FsStore::new(PathBuf::from(temp.path()), None, None, None).await?;
    let key = "large/artifact.bin";

    let baseline_rss = read_rss_kb()?;

    let chunk_size = 1024 * 1024;
    let chunk_count = 32;
    let total_size = chunk_size * chunk_count;
    let payload = stream::iter((0..chunk_count).map(move |index| {
        let byte = (index & 0xFF) as u8;
        Ok::<Bytes, anyhow::Error>(Bytes::from(vec![byte; chunk_size]))
    }))
    .boxed();

    let upload_id = store.create_multipart(key).await?;
    let etag = store.upload_part(key, &upload_id, 1, payload).await?;
    store
        .complete_multipart(key, &upload_id, vec![(1, etag)])
        .await?;

    let mut stream = store.get(key).await?.context("expected download stream")?;

    let mut downloaded = 0usize;
    while let Some(chunk) = stream.next().await {
        downloaded += chunk?.len();
    }
    assert_eq!(downloaded, total_size);

    let rss_after_download = read_rss_kb()?;
    assert!(
        rss_after_download >= baseline_rss,
        "rss should not decrease while stream is active"
    );

    drop(stream);

    sleep(Duration::from_millis(250)).await;

    let rss_after_drop = read_rss_kb()?;
    assert!(
        rss_after_drop <= baseline_rss + 2 * 1024,
        "rss should return near baseline after dropping stream (baseline: {baseline_rss}, after drop: {rss_after_drop})"
    );

    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn respects_configured_permissions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new()?;
    let root = PathBuf::from(temp.path());
    let file_mode = 0o640;
    let dir_mode = 0o750;

    let store = FsStore::new(root.clone(), None, Some(file_mode), Some(dir_mode)).await?;
    let key = "caches/example.bin";

    let upload_id = store.create_multipart(key).await?;
    let payload = payload_from_bytes(vec![b"content"]);
    let etag = store.upload_part(key, &upload_id, 1, payload).await?;
    store
        .complete_multipart(key, &upload_id, vec![(1, etag)])
        .await?;

    let file_metadata = tokio::fs::metadata(root.join(key)).await?;
    assert_eq!(file_metadata.permissions().mode() & 0o777, file_mode);

    let dir_metadata = tokio::fs::metadata(root.join("caches")).await?;
    assert_eq!(dir_metadata.permissions().mode() & 0o777, dir_mode);

    Ok(())
}

#[tokio::test]
async fn delete_removes_file_and_empty_directories() -> Result<()> {
    let temp = TempDir::new()?;
    let store = FsStore::new(PathBuf::from(temp.path()), None, None, None).await?;
    let key = "nested/path/cache.bin";

    let upload_id = store.create_multipart(key).await?;
    let payload = payload_from_bytes(vec![b"contents"]);
    let etag = store.upload_part(key, &upload_id, 1, payload).await?;
    store
        .complete_multipart(key, &upload_id, vec![(1, etag)])
        .await?;

    let file_path = temp.path().join(key);
    assert!(file_path.exists(), "cache file should exist after upload");

    store.delete(key).await?;

    assert!(!file_path.exists(), "cache file should be removed");
    assert!(
        !temp.path().join("nested/path").exists(),
        "deep directory should be removed when empty"
    );
    assert!(
        !temp.path().join("nested").exists(),
        "top-level cache directory should be removed when empty"
    );

    Ok(())
}

#[tokio::test]
async fn delete_is_idempotent_and_preserves_non_empty_dirs() -> Result<()> {
    let temp = TempDir::new()?;
    let store = FsStore::new(PathBuf::from(temp.path()), None, None, None).await?;
    let key = "keep/nested/cache.bin";

    let upload_id = store.create_multipart(key).await?;
    let payload = payload_from_bytes(vec![b"contents"]);
    let etag = store.upload_part(key, &upload_id, 1, payload).await?;
    store
        .complete_multipart(key, &upload_id, vec![(1, etag)])
        .await?;

    let sibling = temp.path().join("keep/other.bin");
    if let Some(parent) = sibling.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&sibling, b"other").await?;

    store.delete(key).await?;

    assert!(
        !temp.path().join(key).exists(),
        "cache file should be deleted"
    );
    assert!(
        !temp.path().join("keep/nested").exists(),
        "empty nested directory should be removed"
    );
    assert!(sibling.exists(), "sibling file should be preserved");
    assert!(
        temp.path().join("keep").exists(),
        "parent directory should remain because it still contains files"
    );

    // Second deletion should be a no-op
    store.delete(key).await?;

    Ok(())
}
