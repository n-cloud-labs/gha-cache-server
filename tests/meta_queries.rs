use chrono::Utc;
use gha_cache_server::config::DatabaseDriver;
use gha_cache_server::meta::{self, CacheEntry};
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;
use std::time::Duration;
use uuid::Uuid;

const TEST_VERSION: &str = "v1";

async fn setup_pool() -> AnyPool {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:?cache=shared")
        .await
        .expect("connect sqlite");
    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .expect("run migrations");
    pool
}

async fn create_entry(pool: &AnyPool, key: &str) -> CacheEntry {
    meta::create_entry(
        pool,
        DatabaseDriver::Sqlite,
        "org",
        "repo",
        key,
        TEST_VERSION,
        "_",
        key,
    )
    .await
    .expect("create entry")
}

async fn set_entry_fields(
    pool: &AnyPool,
    entry: &CacheEntry,
    last_access: i64,
    ttl: i64,
    size: i64,
) {
    sqlx::query(
        "UPDATE cache_entries SET last_access_at = ?, ttl_seconds = ?, size_bytes = ? WHERE id = ?",
    )
    .bind(last_access)
    .bind(ttl)
    .bind(size)
    .bind(entry.id.to_string())
    .execute(pool)
    .await
    .expect("update entry fields");
}

#[tokio::test]
async fn expired_entry_ids_returns_only_expired_entries() {
    let pool = setup_pool().await;
    let expired = create_entry(&pool, "expired").await;
    let fresh = create_entry(&pool, "fresh").await;
    let boundary = create_entry(&pool, "boundary").await;

    set_entry_fields(&pool, &expired, 0, 10, 1).await;
    set_entry_fields(&pool, &fresh, 90, 20, 1).await;
    set_entry_fields(&pool, &boundary, 1, 99, 1).await;

    let now = chrono::DateTime::<Utc>::from_timestamp(100, 0).expect("timestamp");
    let entries = meta::expired_entries(&pool, DatabaseDriver::Sqlite, now, None)
        .await
        .expect("fetch expired entries");

    let ids: Vec<Uuid> = entries.into_iter().map(|entry| entry.id).collect();
    assert_eq!(ids, vec![expired.id]);
}

#[tokio::test]
async fn expired_entries_respect_age_override() {
    let pool = setup_pool().await;
    let old = create_entry(&pool, "old").await;
    let newer = create_entry(&pool, "newer").await;

    set_entry_fields(&pool, &old, 0, 1_000, 1).await;
    set_entry_fields(&pool, &newer, 80, 1_000, 1).await;

    let now = chrono::DateTime::<Utc>::from_timestamp(100, 0).expect("timestamp");
    let entries = meta::expired_entries(
        &pool,
        DatabaseDriver::Sqlite,
        now,
        Some(Duration::from_secs(30)),
    )
    .await
    .expect("fetch expired entries");

    let ids: Vec<Uuid> = entries.into_iter().map(|entry| entry.id).collect();
    assert_eq!(ids, vec![old.id]);
}

#[tokio::test]
async fn total_occupancy_sums_all_entries() {
    let pool = setup_pool().await;
    let first = create_entry(&pool, "first").await;
    let second = create_entry(&pool, "second").await;

    set_entry_fields(&pool, &first, 0, 10, 128).await;
    set_entry_fields(&pool, &second, 0, 10, 256).await;

    let total = meta::total_occupancy(&pool, DatabaseDriver::Sqlite)
        .await
        .expect("sum occupancy");

    assert_eq!(total, 384);
}

#[tokio::test]
async fn list_entries_ordered_sorts_by_last_access_and_limits() {
    let pool = setup_pool().await;
    let first = create_entry(&pool, "first").await;
    let second = create_entry(&pool, "second").await;
    let third = create_entry(&pool, "third").await;

    set_entry_fields(&pool, &first, 30, 10, 1).await;
    set_entry_fields(&pool, &second, 10, 10, 1).await;
    set_entry_fields(&pool, &third, 20, 10, 1).await;

    let limited = meta::list_entries_ordered(&pool, DatabaseDriver::Sqlite, Some(2))
        .await
        .expect("list limited");
    assert_eq!(limited.len(), 2);
    assert_eq!(limited[0].id, second.id);
    assert_eq!(limited[1].id, third.id);

    let full = meta::list_entries_ordered(&pool, DatabaseDriver::Sqlite, None)
        .await
        .expect("list full");
    let order: Vec<Uuid> = full.into_iter().map(|entry| entry.id).collect();
    assert_eq!(order, vec![second.id, third.id, first.id]);
}

#[tokio::test]
async fn delete_entry_removes_row_and_cascades_uploads() {
    let pool = setup_pool().await;
    let entry = create_entry(&pool, "target").await;

    let upload_id = Uuid::new_v4().to_string();
    meta::upsert_upload(
        &pool,
        DatabaseDriver::Sqlite,
        entry.id,
        &upload_id,
        "reserved",
    )
    .await
    .expect("create upload");

    meta::delete_entry(&pool, DatabaseDriver::Sqlite, entry.id)
        .await
        .expect("delete entry");

    let remaining_entries: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM cache_entries WHERE id = ?")
            .bind(entry.id.to_string())
            .fetch_one(&pool)
            .await
            .expect("count entries");
    assert_eq!(remaining_entries, 0);

    let remaining_uploads: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM cache_uploads WHERE upload_id = ?")
            .bind(upload_id)
            .fetch_one(&pool)
            .await
            .expect("count uploads");
    assert_eq!(remaining_uploads, 0);
}

#[tokio::test]
async fn concurrent_part_updates_are_ordered() {
    let pool = setup_pool().await;
    let entry = create_entry(&pool, "concurrent").await;
    let upload_id = Uuid::new_v4().to_string();

    let upload = meta::upsert_upload(
        &pool,
        DatabaseDriver::Sqlite,
        entry.id,
        &upload_id,
        "reserved",
    )
    .await
    .expect("create upload");

    assert_eq!(upload.upload_id, upload_id);

    let first = {
        let pool = &pool;
        let upload = upload_id.clone();
        async move {
            let offset = meta::reserve_part(pool, DatabaseDriver::Sqlite, &upload, 0, Some(0), 10)
                .await
                .expect("reserve part 0");
            assert_eq!(offset, 0);
            meta::complete_part(pool, DatabaseDriver::Sqlite, &upload, 0, Some(0), "etag-0")
                .await
                .expect("complete part 0");
        }
    };
    let second = {
        let pool = &pool;
        let upload = upload_id.clone();
        async move {
            let offset = meta::reserve_part(pool, DatabaseDriver::Sqlite, &upload, 1, Some(10), 7)
                .await
                .expect("reserve part 1");
            assert_eq!(offset, 10);
            meta::complete_part(pool, DatabaseDriver::Sqlite, &upload, 1, Some(10), "etag-1")
                .await
                .expect("complete part 1");
        }
    };

    tokio::join!(first, second);

    let offset = meta::reserve_part(&pool, DatabaseDriver::Sqlite, &upload_id, 2, None, 3)
        .await
        .expect("reserve compat part");
    assert_eq!(offset, 17);
    meta::complete_part(&pool, DatabaseDriver::Sqlite, &upload_id, 2, None, "etag-2")
        .await
        .expect("complete compat part");

    let parts = meta::get_completed_parts(&pool, DatabaseDriver::Sqlite, &upload_id)
        .await
        .expect("fetch parts");
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].part_number, 1);
    assert_eq!(parts[1].part_number, 2);
    assert_eq!(parts[2].part_number, 3);
    assert_eq!(parts[0].offset, 0);
    assert_eq!(parts[1].offset, 10);
    assert_eq!(parts[2].offset, 17);
    assert_eq!(parts[2].size, 3);
}

#[tokio::test]
async fn overlapping_part_uploads_hold_state_until_last_part_finishes() {
    let pool = setup_pool().await;
    let entry = create_entry(&pool, "overlap").await;
    let upload_id = Uuid::new_v4().to_string();

    meta::upsert_upload(
        &pool,
        DatabaseDriver::Sqlite,
        entry.id,
        &upload_id,
        "reserved",
    )
    .await
    .expect("create upload");

    let moved = meta::transition_upload_state(
        &pool,
        DatabaseDriver::Sqlite,
        &upload_id,
        &["reserved"],
        "uploading",
    )
    .await
    .expect("transition to uploading");
    assert!(moved);

    let offset = meta::reserve_part(&pool, DatabaseDriver::Sqlite, &upload_id, 0, Some(0), 5)
        .await
        .expect("reserve part 0");
    assert_eq!(offset, 0);
    meta::begin_part_upload(&pool, DatabaseDriver::Sqlite, &upload_id)
        .await
        .expect("begin part 0");

    let offset = meta::reserve_part(&pool, DatabaseDriver::Sqlite, &upload_id, 1, Some(5), 7)
        .await
        .expect("reserve part 1");
    assert_eq!(offset, 5);
    meta::begin_part_upload(&pool, DatabaseDriver::Sqlite, &upload_id)
        .await
        .expect("begin part 1");

    let status = meta::get_upload_status(&pool, DatabaseDriver::Sqlite, &upload_id)
        .await
        .expect("fetch status after begins");
    assert_eq!(status.active_part_count, 2);
    assert_eq!(status.state, "uploading");

    meta::complete_part(
        &pool,
        DatabaseDriver::Sqlite,
        &upload_id,
        0,
        Some(0),
        "etag-0",
    )
    .await
    .expect("complete part 0");
    let remaining = meta::finish_part_upload(&pool, DatabaseDriver::Sqlite, &upload_id)
        .await
        .expect("finish part 0");
    assert_eq!(remaining, 1);

    let status = meta::get_upload_status(&pool, DatabaseDriver::Sqlite, &upload_id)
        .await
        .expect("fetch status after first finish");
    assert_eq!(status.active_part_count, 1);
    assert_eq!(status.state, "uploading");

    meta::complete_part(
        &pool,
        DatabaseDriver::Sqlite,
        &upload_id,
        1,
        Some(5),
        "etag-1",
    )
    .await
    .expect("complete part 1");
    let remaining = meta::finish_part_upload(&pool, DatabaseDriver::Sqlite, &upload_id)
        .await
        .expect("finish part 1");
    assert_eq!(remaining, 0);

    let status = meta::get_upload_status(&pool, DatabaseDriver::Sqlite, &upload_id)
        .await
        .expect("fetch status after all finishes");
    assert_eq!(status.active_part_count, 0);
    assert_eq!(status.state, "uploading");
}
