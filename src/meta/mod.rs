use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub id: Uuid,
    pub org: String,
    pub repo: String,
    pub key: String,
    pub scope: String,
    pub size_bytes: i64,
    pub checksum: Option<String>,
    pub storage_key: String,
    pub created_at: DateTime<Utc>,
    pub last_access_at: DateTime<Utc>,
    pub ttl_seconds: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadRow {
    pub id: Uuid,
    pub entry_id: Option<Uuid>,
    pub upload_id: String,
    pub parts_json: serde_json::Value,
    pub state: String,
}

pub async fn create_entry(
    pool: &PgPool,
    org: &str,
    repo: &str,
    key: &str,
    scope: &str,
    storage_key: &str,
) -> Result<CacheEntry, sqlx::Error> {
    let rec = sqlx::query_as!(
        CacheEntry,
        r#"INSERT INTO cache_entries (id, org, repo, key, scope, storage_key)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, org, repo, key, scope, size_bytes, checksum, storage_key,
created_at, last_access_at, ttl_seconds"#,
        Uuid::new_v4(),
        org,
        repo,
        key,
        scope,
        storage_key
    )
    .fetch_one(pool)
    .await?;
    Ok(rec)
}

pub async fn upsert_upload(
    pool: &PgPool,
    entry_id: Uuid,
    upload_id: &str,
    state: &str,
) -> Result<UploadRow, sqlx::Error> {
    let rec = sqlx::query_as!(
        UploadRow,
        r#"INSERT INTO cache_uploads (id, entry_id, upload_id, state)
VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO NOTHING
RETURNING id, entry_id, upload_id, parts_json as "parts_json!", state"#,
        Uuid::new_v4(),
        entry_id,
        upload_id,
        state
    )
    .fetch_one(pool)
    .await?;
    Ok(rec)
}

pub async fn add_part(
    pool: &PgPool,
    upload_id: &str,
    part_number: i32,
    etag: &str,
) -> Result<(), sqlx::Error> {
    let _ = sqlx::query!(
r#"UPDATE cache_uploads
SET parts_json = COALESCE(parts_json, '[]'::jsonb) || jsonb_build_array(jsonb_build_object('partNumber', $2::integer, 'etag', $3::varchar)),
updated_at = NOW()
WHERE upload_id = $1"#,
upload_id, part_number, etag
).execute(pool).await?;
    Ok(())
}

pub async fn get_parts(pool: &PgPool, upload_id: &str) -> Result<Vec<(i32, String)>, sqlx::Error> {
    let rec = sqlx::query!(
        "SELECT parts_json FROM cache_uploads WHERE upload_id = $1",
        upload_id
    )
    .fetch_one(pool)
    .await?;
    let parts: Vec<serde_json::Value> = serde_json::from_value(rec.parts_json).unwrap_or_default();
    Ok(parts
        .into_iter()
        .filter_map(|v| {
            let n = v.get("partNumber")?.as_i64()? as i32;
            let e = v.get("etag")?.as_str()?.to_string();
            Some((n, e))
        })
        .collect())
}
