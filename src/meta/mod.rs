use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, Row};
use std::convert::TryFrom;
use std::io;
use std::time::Duration;
use uuid::Uuid;

use crate::config::DatabaseDriver;
use crate::db::rewrite_placeholders;

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub id: Uuid,
    pub org: String,
    pub repo: String,
    pub key: String,
    pub version: String,
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
        version: row.try_get("cache_version")?,
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

async fn fetch_parts(
    pool: &AnyPool,
    driver: DatabaseDriver,
    upload_id: &str,
) -> Result<Vec<UploadPart>, sqlx::Error> {
    let query = rewrite_placeholders(
        "SELECT parts_json FROM cache_uploads WHERE upload_id = ?",
        driver,
    );
    let row = sqlx::query(&query).bind(upload_id).fetch_one(pool).await?;
    let raw: Option<String> = row.try_get("parts_json")?;
    let serialized = raw.unwrap_or_else(|| "[]".to_string());
    parse_parts(&serialized)
}

async fn fetch_upload(
    pool: &AnyPool,
    driver: DatabaseDriver,
    upload_id: &str,
) -> Result<UploadRow, sqlx::Error> {
    let query = rewrite_placeholders(
        "SELECT id, entry_id, upload_id, parts_json, state FROM cache_uploads WHERE upload_id = ?",
        driver,
    );
    let row = sqlx::query(&query).bind(upload_id).fetch_one(pool).await?;
    map_upload_row(row)
}

async fn fetch_entry(
    pool: &AnyPool,
    driver: DatabaseDriver,
    id: Uuid,
) -> Result<CacheEntry, sqlx::Error> {
    let query = rewrite_placeholders(
        "SELECT id, org, repo, cache_key, cache_version, scope, size_bytes, checksum, storage_key, created_at, last_access_at, ttl_seconds FROM cache_entries WHERE id = ?",
        driver,
    );
    let row = sqlx::query(&query)
        .bind(id.to_string())
        .fetch_one(pool)
        .await?;
    map_cache_entry(row)
}

pub async fn touch_entry(
    pool: &AnyPool,
    driver: DatabaseDriver,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    let now = Utc::now().timestamp();
    let query = rewrite_placeholders(
        "UPDATE cache_entries SET last_access_at = ? WHERE id = ?",
        driver,
    );
    sqlx::query(&query)
        .bind(now)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn delete_entry(
    pool: &AnyPool,
    driver: DatabaseDriver,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    let query = rewrite_placeholders("DELETE FROM cache_entries WHERE id = ?", driver);
    sqlx::query(&query)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn expired_entries(
    pool: &AnyPool,
    driver: DatabaseDriver,
    now: DateTime<Utc>,
    max_entry_age: Option<Duration>,
) -> Result<Vec<CacheEntry>, sqlx::Error> {
    let ts = now.timestamp();

    let rows = if let Some(limit) = max_entry_age {
        let secs = i64::try_from(limit.as_secs()).unwrap_or(i64::MAX);
        let query = rewrite_placeholders(
            "SELECT id, org, repo, cache_key, cache_version, scope, size_bytes, checksum, storage_key, created_at, last_access_at, ttl_seconds \
FROM cache_entries WHERE last_access_at + CASE WHEN ttl_seconds > ? THEN ? ELSE ttl_seconds END < ? ORDER BY last_access_at ASC",
            driver,
        );
        sqlx::query(&query)
            .bind(secs)
            .bind(secs)
            .bind(ts)
            .fetch_all(pool)
            .await?
    } else {
        let query = rewrite_placeholders(
            "SELECT id, org, repo, cache_key, cache_version, scope, size_bytes, checksum, storage_key, created_at, last_access_at, ttl_seconds \
FROM cache_entries WHERE last_access_at + ttl_seconds < ? ORDER BY last_access_at ASC",
            driver,
        );
        sqlx::query(&query).bind(ts).fetch_all(pool).await?
    };

    rows.into_iter().map(map_cache_entry).collect()
}

#[allow(dead_code)]
pub async fn expired_entry_ids(
    pool: &AnyPool,
    driver: DatabaseDriver,
    now: DateTime<Utc>,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let entries = expired_entries(pool, driver, now, None).await?;
    Ok(entries.into_iter().map(|entry| entry.id).collect())
}

#[allow(dead_code)]
pub async fn total_occupancy(pool: &AnyPool, driver: DatabaseDriver) -> Result<i64, sqlx::Error> {
    let query = rewrite_placeholders(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM cache_entries",
        driver,
    );
    let total = sqlx::query_scalar::<_, i64>(&query).fetch_one(pool).await?;
    Ok(total)
}

#[allow(dead_code)]
pub async fn list_entries_ordered(
    pool: &AnyPool,
    driver: DatabaseDriver,
    limit: Option<i64>,
) -> Result<Vec<CacheEntry>, sqlx::Error> {
    if let Some(limit) = limit {
        let query = rewrite_placeholders(
            "SELECT id, org, repo, cache_key, cache_version, scope, size_bytes, checksum, storage_key, created_at, last_access_at, ttl_seconds FROM cache_entries ORDER BY last_access_at ASC LIMIT ?",
            driver,
        );
        let rows = sqlx::query(&query).bind(limit).fetch_all(pool).await?;

        rows.into_iter().map(map_cache_entry).collect()
    } else {
        let query = rewrite_placeholders(
            "SELECT id, org, repo, cache_key, cache_version, scope, size_bytes, checksum, storage_key, created_at, last_access_at, ttl_seconds FROM cache_entries ORDER BY last_access_at ASC",
            driver,
        );
        let rows = sqlx::query(&query).fetch_all(pool).await?;

        rows.into_iter().map(map_cache_entry).collect()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_entry(
    pool: &AnyPool,
    driver: DatabaseDriver,
    org: &str,
    repo: &str,
    key: &str,
    version: &str,
    scope: &str,
    storage_key: &str,
) -> Result<CacheEntry, sqlx::Error> {
    let id = Uuid::new_v4();
    let query = rewrite_placeholders(
        "INSERT INTO cache_entries (id, org, repo, cache_key, cache_version, scope, storage_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
        driver,
    );
    sqlx::query(&query)
        .bind(id.to_string())
        .bind(org)
        .bind(repo)
        .bind(key)
        .bind(version)
        .bind(scope)
        .bind(storage_key)
        .execute(pool)
        .await?;

    fetch_entry(pool, driver, id).await
}

pub async fn find_entry_by_key_version(
    pool: &AnyPool,
    driver: DatabaseDriver,
    key: &str,
    version: &str,
) -> Result<Option<CacheEntry>, sqlx::Error> {
    let query = rewrite_placeholders(
        "SELECT id, org, repo, cache_key, cache_version, scope, size_bytes, checksum, storage_key, created_at, last_access_at, ttl_seconds FROM cache_entries WHERE cache_key = ? AND cache_version = ? ORDER BY created_at DESC LIMIT 1",
        driver,
    );
    let maybe_row = sqlx::query(&query)
        .bind(key)
        .bind(version)
        .fetch_optional(pool)
        .await?;

    if let Some(row) = maybe_row {
        Ok(Some(map_cache_entry(row)?))
    } else {
        Ok(None)
    }
}

pub async fn upsert_upload(
    pool: &AnyPool,
    driver: DatabaseDriver,
    entry_id: Uuid,
    upload_id: &str,
    state: &str,
) -> Result<UploadRow, sqlx::Error> {
    let id = Uuid::new_v4();
    let entry = entry_id.to_string();

    let insert_query = rewrite_placeholders(
        "INSERT INTO cache_uploads (id, entry_id, upload_id, parts_json, state) VALUES (?, ?, ?, ?, ?)",
        driver,
    );
    let insert = sqlx::query(&insert_query)
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
                let update_query = rewrite_placeholders(
                    "UPDATE cache_uploads SET entry_id = ?, state = ?, updated_at = ? WHERE upload_id = ?",
                    driver,
                );
                sqlx::query(&update_query)
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

    fetch_upload(pool, driver, upload_id).await
}

pub async fn add_part(
    pool: &AnyPool,
    driver: DatabaseDriver,
    upload_id: &str,
    part_number: i32,
    etag: &str,
) -> Result<(), sqlx::Error> {
    let mut parts = fetch_parts(pool, driver, upload_id).await?;
    parts.push(UploadPart {
        part_number,
        etag: etag.to_string(),
    });
    let serialized = format_parts(&parts)?;
    let now = Utc::now().timestamp();

    let query = rewrite_placeholders(
        "UPDATE cache_uploads SET parts_json = ?, updated_at = ? WHERE upload_id = ?",
        driver,
    );
    sqlx::query(&query)
        .bind(serialized)
        .bind(now)
        .bind(upload_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_parts(
    pool: &AnyPool,
    driver: DatabaseDriver,
    upload_id: &str,
) -> Result<Vec<(i32, String)>, sqlx::Error> {
    let mut parts = fetch_parts(pool, driver, upload_id).await?;
    parts.sort_by_key(|part| part.part_number);
    Ok(parts.into_iter().map(|p| (p.part_number, p.etag)).collect())
}
