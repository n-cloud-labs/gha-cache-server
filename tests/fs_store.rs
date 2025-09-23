use std::path::PathBuf;

use anyhow::Result;
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

#[tokio::test]
async fn multipart_upload_writes_file() -> Result<()> {
    let temp = TempDir::new()?;
    let store = FsStore::new(PathBuf::from(temp.path()), None, None).await?;
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

    let uploads_dir = temp.path().join(".uploads").join(&upload_id);
    assert!(
        !uploads_dir.exists(),
        "temporary upload directory should be cleaned up"
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

    let store = FsStore::new(root.clone(), Some(file_mode), Some(dir_mode)).await?;
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
    let store = FsStore::new(PathBuf::from(temp.path()), None, None).await?;
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
    let store = FsStore::new(PathBuf::from(temp.path()), None, None).await?;
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
