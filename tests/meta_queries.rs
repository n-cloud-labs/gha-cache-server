use chrono::Utc;
use gha_cache_server::meta::{self, CacheEntry};
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;
use uuid::Uuid;

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
    meta::create_entry(pool, "org", "repo", key, "scope", key)
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
    let ids = meta::expired_entry_ids(&pool, now)
        .await
        .expect("fetch expired ids");

    assert_eq!(ids, vec![expired.id]);
}

#[tokio::test]
async fn total_occupancy_sums_all_entries() {
    let pool = setup_pool().await;
    let first = create_entry(&pool, "first").await;
    let second = create_entry(&pool, "second").await;

    set_entry_fields(&pool, &first, 0, 10, 128).await;
    set_entry_fields(&pool, &second, 0, 10, 256).await;

    let total = meta::total_occupancy(&pool).await.expect("sum occupancy");

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

    let limited = meta::list_entries_ordered(&pool, Some(2))
        .await
        .expect("list limited");
    assert_eq!(limited.len(), 2);
    assert_eq!(limited[0].id, second.id);
    assert_eq!(limited[1].id, third.id);

    let full = meta::list_entries_ordered(&pool, None)
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
    meta::upsert_upload(&pool, entry.id, &upload_id, "reserved")
        .await
        .expect("create upload");

    meta::delete_entry(&pool, entry.id)
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
