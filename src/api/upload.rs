use axum::http::StatusCode;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use futures::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{io, time::Duration};
use uuid::Uuid;

use crate::db::rewrite_placeholders;
use crate::http::AppState;
use crate::meta;
use crate::{
    error::{ApiError, Result},
    storage::{BlobStore, BlobUploadPayload},
};

const MAX_CACHE_KEY_LENGTH: usize = 512;

#[derive(Debug, Deserialize)]
pub struct ListCachesQuery {
    key: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCachesResponse {
    total_count: usize,
    artifact_caches: Vec<ArtifactCacheSummary>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactCacheSummary {
    cache_id: Uuid,
    scope: String,
    cache_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_version: Option<String>,
    creation_time: DateTime<Utc>,
    last_access_time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed_size: Option<i64>,
}

#[derive(Debug, Clone)]
struct CacheListRow {
    id: Uuid,
    scope: String,
    key: String,
    size_bytes: i64,
    storage_key: String,
    created_at: DateTime<Utc>,
    last_access_at: DateTime<Utc>,
}

fn parse_uuid(value: String) -> sqlx::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|err| sqlx::Error::Decode(Box::new(err)))
}

fn timestamp_to_datetime(ts: i64) -> sqlx::Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(ts, 0).ok_or_else(|| {
        sqlx::Error::Decode(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid timestamp: {ts}"),
        )))
    })
}

async fn build_list_response(
    entries: Vec<CacheListRow>,
    store: &dyn BlobStore,
    enable_direct: bool,
) -> Result<ListCachesResponse> {
    let mut artifact_caches = Vec::with_capacity(entries.len());
    for entry in entries {
        let archive_location = if enable_direct {
            store
                .presign_get(&entry.storage_key, Duration::from_secs(3600))
                .await
                .map_err(|e| ApiError::S3(format!("{e}")))?
                .map(|p| p.url.to_string())
        } else {
            None
        };

        artifact_caches.push(ArtifactCacheSummary {
            cache_id: entry.id,
            scope: entry.scope,
            cache_key: entry.key,
            cache_version: None,
            creation_time: entry.created_at,
            last_access_time: entry.last_access_at,
            archive_location,
            compressed_size: (entry.size_bytes > 0).then_some(entry.size_bytes),
        });
    }

    Ok(ListCachesResponse {
        total_count: artifact_caches.len(),
        artifact_caches,
    })
}

fn extract_list_key(key: Option<String>) -> Result<String> {
    let raw = key
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::BadRequest("query parameter 'key' is required".into()))?;
    if raw.len() > MAX_CACHE_KEY_LENGTH {
        return Err(ApiError::BadRequest("key exceeds maximum length".into()));
    }
    if raw.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest(
            "key contains invalid characters".into(),
        ));
    }
    Ok(raw)
}

// ====== actions/cache: GET /_apis/artifactcache/caches?key=my-key ======
pub async fn list_caches(
    State(st): State<AppState>,
    Query(query): Query<ListCachesQuery>,
) -> Result<Json<ListCachesResponse>> {
    let key = extract_list_key(query.key)?;

    let query = rewrite_placeholders(
        "SELECT id, scope, cache_key, size_bytes, storage_key, created_at, last_access_at FROM cache_entries WHERE cache_key = ? ORDER BY created_at DESC",
        st.database_driver,
    );
    let rows = sqlx::query(&query).bind(&key).fetch_all(&st.pool).await?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let id = parse_uuid(row.try_get::<String, _>("id")?)?;
        let created_at = timestamp_to_datetime(row.try_get::<i64, _>("created_at")?)?;
        let last_access_at = timestamp_to_datetime(row.try_get::<i64, _>("last_access_at")?)?;
        entries.push(CacheListRow {
            id,
            scope: row.try_get("scope")?,
            key: row.try_get("cache_key")?,
            size_bytes: row.try_get("size_bytes")?,
            storage_key: row.try_get("storage_key")?,
            created_at,
            last_access_at,
        });
    }

    let body = build_list_response(entries, st.store.as_ref(), st.enable_direct).await?;
    Ok(Json(body))
}

// ====== actions/cache: GET /_apis/artifactcache/cache?keys=k1,k2&version=sha ======
pub async fn get_cache_entry(
    State(st): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let keys = q.get("keys").cloned().unwrap_or_default();
    // let version = q.get("version").cloned().unwrap_or_default();
    // Simplified lookup: pick first matching entry (TODO: add restore-keys precedence)
    let query = rewrite_placeholders(
        "SELECT id, storage_key, created_at FROM cache_entries WHERE cache_key = ? ORDER BY created_at DESC LIMIT 1",
        st.database_driver,
    );
    let rec = sqlx::query(&query)
        .bind(keys.split(',').next().unwrap_or(""))
        .fetch_optional(&st.pool)
        .await?;

    if let Some(row) = rec {
        let id = parse_uuid(row.try_get::<String, _>("id")?)?;
        let created_at = timestamp_to_datetime(row.try_get::<i64, _>("created_at")?)?;
        // Return 200 with archiveLocation (direct presigned URL); scope kept generic
        let storage_key: String = row.try_get("storage_key")?;
        meta::touch_entry(&st.pool, st.database_driver, id).await?;
        let url = st
            .store
            .presign_get(&storage_key, std::time::Duration::from_secs(3600))
            .await
            .map_err(|e| ApiError::S3(format!("{e}")))?
            .map(|p| p.url.to_string())
            .unwrap_or_default();
        let body = serde_json::json!({
        "cacheKey": keys,
        "scope": "",
        "creationTime": created_at,
        "archiveLocation": url,
        });
        return Ok((StatusCode::OK, Json(body)));
    }
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!({}))))
}

// ====== actions/cache: POST /_apis/artifactcache/caches { key, version } ======
pub async fn reserve_cache(
    State(st): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let key = req.get("key").and_then(|v| v.as_str()).unwrap_or("");
    let version = req.get("version").and_then(|v| v.as_str()).unwrap_or("");

    let storage_key = format!(
        "ac/org/_/repo/_/key/{}/{}",
        general_purpose::STANDARD.encode(key),
        Uuid::new_v4()
    );
    let entry = meta::create_entry(
        &st.pool,
        st.database_driver,
        "_",
        "_",
        key,
        version,
        &storage_key,
    )
    .await?;
    let upload_id = st
        .store
        .create_multipart(&storage_key)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    let _ = meta::upsert_upload(
        &st.pool,
        st.database_driver,
        entry.id,
        &upload_id,
        "reserved",
    )
    .await?;

    Ok(Json(serde_json::json!({ "cacheId": entry.id })))
}

// ====== actions/cache: PATCH /_apis/artifactcache/caches/:id with Content-Range ======
pub async fn upload_chunk(
    State(st): State<AppState>,
    Path(id): Path<String>,
    body: axum::body::Body,
) -> Result<StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("invalid cacheId".into()))?;
    let query = rewrite_placeholders(
        "SELECT upload_id, storage_key FROM cache_uploads u JOIN cache_entries e ON e.id = u.entry_id WHERE e.id = ?",
        st.database_driver,
    );
    let rec = sqlx::query(&query)
        .bind(uuid.to_string())
        .fetch_one(&st.pool)
        .await?;
    let upload_id: String = rec.try_get("upload_id")?;
    let storage_key: String = rec.try_get("storage_key")?;

    // We don't actually need offsets here because we map each PATCH to an S3 part in order.
    let next_part = 1 + meta::get_parts(&st.pool, st.database_driver, &upload_id)
        .await?
        .len() as i32;

    let bs = body_to_blob_payload(body);
    let etag = st
        .store
        .upload_part(&storage_key, &upload_id, next_part, bs)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    meta::add_part(&st.pool, st.database_driver, &upload_id, next_part, &etag).await?;

    Ok(StatusCode::OK)
}

pub(crate) fn body_to_blob_payload(body: axum::body::Body) -> BlobUploadPayload {
    body.into_data_stream().map_err(anyhow::Error::from).boxed()
}

// ====== actions/cache: POST /_apis/artifactcache/caches/:id { size } ======
pub async fn commit_cache(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Result<StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("invalid cacheId".into()))?;
    let query = rewrite_placeholders(
        "SELECT upload_id, storage_key FROM cache_uploads u JOIN cache_entries e ON e.id = u.entry_id WHERE e.id = ?",
        st.database_driver,
    );
    let rec = sqlx::query(&query)
        .bind(uuid.to_string())
        .fetch_one(&st.pool)
        .await?;
    let upload_id: String = rec.try_get("upload_id")?;
    let storage_key: String = rec.try_get("storage_key")?;
    let parts = meta::get_parts(&st.pool, st.database_driver, &upload_id).await?;
    st.store
        .complete_multipart(&storage_key, &upload_id, parts)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;

    // Persist size if provided
    if let Some(size) = req.get("size").and_then(|v| v.as_i64()) {
        let update_query = rewrite_placeholders(
            "UPDATE cache_entries SET size_bytes = ? WHERE id = ?",
            st.database_driver,
        );
        sqlx::query(&update_query)
            .bind(size)
            .bind(uuid.to_string())
            .execute(&st.pool)
            .await?;
    }
    Ok(StatusCode::CREATED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{BlobStore, BlobUploadPayload, PresignedUrl};
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use url::Url;

    #[derive(Clone, Default)]
    struct DummyStore {
        url: Option<String>,
        calls: Arc<AtomicUsize>,
    }

    impl DummyStore {
        fn with_url(url: Option<&str>) -> Self {
            Self {
                url: url.map(|u| u.to_string()),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl BlobStore for DummyStore {
        async fn create_multipart(&self, _key: &str) -> anyhow::Result<String> {
            unimplemented!("not required for tests")
        }

        async fn upload_part(
            &self,
            _key: &str,
            _upload_id: &str,
            _part_number: i32,
            _body: BlobUploadPayload,
        ) -> anyhow::Result<String> {
            unimplemented!("not required for tests")
        }

        async fn complete_multipart(
            &self,
            _key: &str,
            _upload_id: &str,
            _parts: Vec<(i32, String)>,
        ) -> anyhow::Result<()> {
            unimplemented!("not required for tests")
        }

        async fn presign_get(
            &self,
            _key: &str,
            _ttl: Duration,
        ) -> anyhow::Result<Option<PresignedUrl>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.url.as_ref().map(|u| PresignedUrl {
                url: Url::parse(u).unwrap(),
            }))
        }

        async fn delete(&self, _key: &str) -> anyhow::Result<()> {
            unimplemented!("not required for tests")
        }
    }

    fn sample_row() -> CacheListRow {
        CacheListRow {
            id: Uuid::new_v4(),
            scope: "refs/heads/main".into(),
            key: "demo".into(),
            size_bytes: 42,
            storage_key: "storage/demo".into(),
            created_at: Utc::now(),
            last_access_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn list_caches_builds_success_response() {
        let store = DummyStore::with_url(Some("https://example.com/archive"));
        let rows = vec![sample_row()];
        let response = build_list_response(rows.clone(), &store, true)
            .await
            .expect("response");

        assert_eq!(response.total_count, 1);
        assert_eq!(store.call_count(), 1);
        let cache = response.artifact_caches.first().expect("cache entry");
        assert_eq!(cache.cache_key, rows[0].key);
        assert_eq!(
            cache.archive_location.as_deref(),
            Some("https://example.com/archive")
        );
        assert_eq!(cache.compressed_size, Some(42));
    }

    #[tokio::test]
    async fn list_caches_handles_empty_result() {
        let store = DummyStore::with_url(Some("https://example.com/archive"));
        let response = build_list_response(Vec::new(), &store, true)
            .await
            .expect("response");

        assert_eq!(response.total_count, 0);
        assert!(response.artifact_caches.is_empty());
        assert_eq!(store.call_count(), 0);
    }

    #[test]
    fn list_caches_rejects_invalid_key() {
        let err = extract_list_key(None).expect_err("missing key should error");
        assert!(matches!(err, ApiError::BadRequest(_)));

        let err = extract_list_key(Some("   ".into())).expect_err("blank key should error");
        assert!(matches!(err, ApiError::BadRequest(_)));

        let err = extract_list_key(Some("a".repeat(MAX_CACHE_KEY_LENGTH + 1)))
            .expect_err("long key should error");
        assert!(matches!(err, ApiError::BadRequest(_)));

        let err =
            extract_list_key(Some("bad\u{0007}".into())).expect_err("control chars should error");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
