use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, Row};
use std::io;
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct UploadPart {
    #[serde(rename = "partNumber")]
    part_number: i32,
    etag: String,
}

fn parse_uuid(value: String) -> sqlx::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|err| sqlx::Error::Decode(Box::new(err)))
}

fn parse_uuid_opt(value: Option<String>) -> sqlx::Result<Option<Uuid>> {
    value.map(parse_uuid).transpose()
}

fn timestamp_to_datetime(ts: i64) -> sqlx::Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(ts, 0).ok_or_else(|| {
        sqlx::Error::Decode(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid timestamp: {ts}"),
        )))
    })
}

fn map_cache_entry(row: sqlx::any::AnyRow) -> Result<CacheEntry, sqlx::Error> {
    let id = parse_uuid(row.try_get::<String, _>("id")?)?;
    let created_at = timestamp_to_datetime(row.try_get::<i64, _>("created_at")?)?;
    let last_access_at = timestamp_to_datetime(row.try_get::<i64, _>("last_access_at")?)?;
    Ok(CacheEntry {
        id,
        org: row.try_get("org")?,
        repo: row.try_get("repo")?,
        key: row.try_get("cache_key")?,
        scope: row.try_get("scope")?,
        size_bytes: row.try_get("size_bytes")?,
        checksum: row.try_get("checksum")?,
        storage_key: row.try_get("storage_key")?,
        created_at,
        last_access_at,
        ttl_seconds: row.try_get("ttl_seconds")?,
    })
}

fn map_upload_row(row: sqlx::any::AnyRow) -> Result<UploadRow, sqlx::Error> {
    let id = parse_uuid(row.try_get::<String, _>("id")?)?;
    let entry_id = parse_uuid_opt(row.try_get("entry_id")?)?;
    let parts_raw: Option<String> = row.try_get("parts_json")?;
    let parts_value = parts_raw.as_deref().unwrap_or("[]");
    let parts_json =
        serde_json::from_str(parts_value).unwrap_or_else(|_| serde_json::Value::Array(Vec::new()));

    Ok(UploadRow {
        id,
        entry_id,
        upload_id: row.try_get("upload_id")?,
        parts_json,
        state: row.try_get("state")?,
    })
}

fn parse_parts(raw: &str) -> Result<Vec<UploadPart>, sqlx::Error> {
    serde_json::from_str(raw).map_err(|err| sqlx::Error::Decode(Box::new(err)))
}

fn format_parts(parts: &[UploadPart]) -> Result<String, sqlx::Error> {
    serde_json::to_string(parts).map_err(|err| sqlx::Error::Decode(Box::new(err)))
}

async fn fetch_parts(pool: &AnyPool, upload_id: &str) -> Result<Vec<UploadPart>, sqlx::Error> {
    let row = sqlx::query("SELECT parts_json FROM cache_uploads WHERE upload_id = ?")
        .bind(upload_id)
        .fetch_one(pool)
        .await?;
    let raw: Option<String> = row.try_get("parts_json")?;
    let serialized = raw.unwrap_or_else(|| "[]".to_string());
    parse_parts(&serialized)
}

async fn fetch_upload(pool: &AnyPool, upload_id: &str) -> Result<UploadRow, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, entry_id, upload_id, parts_json, state FROM cache_uploads WHERE upload_id = ?",
    )
    .bind(upload_id)
    .fetch_one(pool)
    .await?;
    map_upload_row(row)
}

async fn fetch_entry(pool: &AnyPool, id: Uuid) -> Result<CacheEntry, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, org, repo, cache_key, scope, size_bytes, checksum, storage_key, created_at, last_access_at, ttl_seconds FROM cache_entries WHERE id = ?",
    )
    .bind(id.to_string())
    .fetch_one(pool)
    .await?;
    map_cache_entry(row)
}

pub async fn create_entry(
    pool: &AnyPool,
    org: &str,
    repo: &str,
    key: &str,
    scope: &str,
    storage_key: &str,
) -> Result<CacheEntry, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cache_entries (id, org, repo, cache_key, scope, storage_key) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(org)
    .bind(repo)
    .bind(key)
    .bind(scope)
    .bind(storage_key)
    .execute(pool)
    .await?;

    fetch_entry(pool, id).await
}

pub async fn upsert_upload(
    pool: &AnyPool,
    entry_id: Uuid,
    upload_id: &str,
    state: &str,
) -> Result<UploadRow, sqlx::Error> {
    let id = Uuid::new_v4();
    let entry = entry_id.to_string();

    let insert = sqlx::query(
        "INSERT INTO cache_uploads (id, entry_id, upload_id, parts_json, state) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(entry.clone())
    .bind(upload_id)
    .bind("[]")
    .bind(state)
    .execute(pool)
    .await;

    if let Err(err) = insert {
        if let sqlx::Error::Database(db_err) = &err {
            if db_err.is_unique_violation() {
                let now = Utc::now().timestamp();
                sqlx::query(
                    "UPDATE cache_uploads SET entry_id = ?, state = ?, updated_at = ? WHERE upload_id = ?",
                )
                .bind(entry)
                .bind(state)
                .bind(now)
                .bind(upload_id)
                .execute(pool)
                .await?;
            } else {
                return Err(err);
            }
        } else {
            return Err(err);
        }
    }

    fetch_upload(pool, upload_id).await
}

pub async fn add_part(
    pool: &AnyPool,
    upload_id: &str,
    part_number: i32,
    etag: &str,
) -> Result<(), sqlx::Error> {
    let mut parts = fetch_parts(pool, upload_id).await?;
    parts.push(UploadPart {
        part_number,
        etag: etag.to_string(),
    });
    let serialized = format_parts(&parts)?;
    let now = Utc::now().timestamp();

    sqlx::query("UPDATE cache_uploads SET parts_json = ?, updated_at = ? WHERE upload_id = ?")
        .bind(serialized)
        .bind(now)
        .bind(upload_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_parts(pool: &AnyPool, upload_id: &str) -> Result<Vec<(i32, String)>, sqlx::Error> {
    let parts = fetch_parts(pool, upload_id).await?;
    Ok(parts.into_iter().map(|p| (p.part_number, p.etag)).collect())
}
