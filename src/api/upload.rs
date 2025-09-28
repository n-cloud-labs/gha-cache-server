use axum::http::{HeaderMap, StatusCode};
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
const MAX_CACHE_VERSION_LENGTH: usize = 512;

#[derive(Debug, Deserialize)]
pub struct ListCachesQuery {
    key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UploadChunkQuery {
    #[serde(default)]
    pub _comp: Option<String>,
    #[serde(default, alias = "blockId", alias = "blockID")]
    pub block_id: Option<String>,
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
    version: String,
    size_bytes: i64,
    storage_key: String,
    created_at: DateTime<Utc>,
    last_access_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveCacheRequest {
    key: String,
    version: String,
}

fn validate_identifier(value: &str, label: &str, max_len: usize) -> Result<()> {
    if value.len() > max_len {
        return Err(ApiError::BadRequest(format!(
            "{label} exceeds maximum length"
        )));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest(format!(
            "{label} contains invalid characters"
        )));
    }
    Ok(())
}

pub(crate) fn normalize_key(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("key is required".into()));
    }
    validate_identifier(trimmed, "key", MAX_CACHE_KEY_LENGTH)?;
    Ok(trimmed.to_string())
}

pub(crate) fn normalize_version(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("version is required".into()));
    }
    validate_identifier(trimmed, "version", MAX_CACHE_VERSION_LENGTH)?;
    Ok(trimmed.to_string())
}

fn parse_keys_parameter(raw: Option<&String>) -> Result<Vec<String>> {
    let value =
        raw.ok_or_else(|| ApiError::BadRequest("query parameter 'keys' is required".into()))?;
    let mut keys = Vec::new();
    for fragment in value.split(',') {
        if fragment.trim().is_empty() {
            continue;
        }
        let key = normalize_key(fragment)?;
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        return Err(ApiError::BadRequest(
            "query parameter 'keys' is required".into(),
        ));
    }
    Ok(keys)
}

fn parse_version_parameter(raw: Option<&String>) -> Result<String> {
    let value =
        raw.ok_or_else(|| ApiError::BadRequest("query parameter 'version' is required".into()))?;
    normalize_version(value)
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
            cache_version: (!entry.version.is_empty()).then_some(entry.version.clone()),
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
    validate_identifier(&raw, "key", MAX_CACHE_KEY_LENGTH)?;
    Ok(raw)
}

// ====== actions/cache: GET /_apis/artifactcache/caches?key=my-key ======
pub async fn list_caches(
    State(st): State<AppState>,
    Query(query): Query<ListCachesQuery>,
) -> Result<Json<ListCachesResponse>> {
    let key = extract_list_key(query.key)?;

    let query = rewrite_placeholders(
        "SELECT id, scope, cache_key, cache_version, size_bytes, storage_key, created_at, last_access_at FROM cache_entries WHERE cache_key = ? ORDER BY created_at DESC",
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
            version: row.try_get("cache_version")?,
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
    let keys = parse_keys_parameter(q.get("keys")).map_err(|err| match &err {
        ApiError::BadRequest(message) if message == "key is required" => {
            ApiError::BadRequest("query parameter 'keys' is required".into())
        }
        _ => err,
    })?;
    let version = parse_version_parameter(q.get("version"))?;

    let query = rewrite_placeholders(
        "SELECT id, cache_key, scope, storage_key, created_at FROM cache_entries WHERE cache_key = ? AND cache_version = ? ORDER BY created_at DESC LIMIT 1",
        st.database_driver,
    );

    for key in keys {
        let rec = sqlx::query(&query)
            .bind(&key)
            .bind(&version)
            .fetch_optional(&st.pool)
            .await?;

        if let Some(row) = rec {
            let id = parse_uuid(row.try_get::<String, _>("id")?)?;
            let created_at = timestamp_to_datetime(row.try_get::<i64, _>("created_at")?)?;
            let storage_key: String = row.try_get("storage_key")?;
            let scope: String = row.try_get("scope")?;
            meta::touch_entry(&st.pool, st.database_driver, id).await?;
            let url = st
                .store
                .presign_get(&storage_key, std::time::Duration::from_secs(3600))
                .await
                .map_err(|e| ApiError::S3(format!("{e}")))?
                .map(|p| p.url.to_string())
                .unwrap_or_default();
            let body = serde_json::json!({
                "cacheKey": key,
                "scope": scope,
                "creationTime": created_at,
                "archiveLocation": url,
            });
            return Ok((StatusCode::OK, Json(body)));
        }
    }

    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!({}))))
}

// ====== actions/cache: POST /_apis/artifactcache/caches { key, version } ======
pub async fn reserve_cache(
    State(st): State<AppState>,
    Json(req): Json<ReserveCacheRequest>,
) -> Result<Json<serde_json::Value>> {
    let key = normalize_key(&req.key)?;
    let version = normalize_version(&req.version)?;

    let storage_key = format!(
        "ac/org/_/repo/_/key/{}/{}",
        general_purpose::STANDARD.encode(&key),
        Uuid::new_v4()
    );
    let entry = meta::create_entry(
        &st.pool,
        st.database_driver,
        "_",
        "_",
        &key,
        &version,
        "_",
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
    Query(query): Query<UploadChunkQuery>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Result<StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("invalid cacheId".into()))?;
    let sql = rewrite_placeholders(
        "SELECT upload_id, storage_key FROM cache_uploads u JOIN cache_entries e ON e.id = u.entry_id WHERE e.id = ?",
        st.database_driver,
    );
    let rec = sqlx::query(&sql)
        .bind(uuid.to_string())
        .fetch_one(&st.pool)
        .await?;
    let upload_id: String = rec.try_get("upload_id")?;
    let storage_key: String = rec.try_get("storage_key")?;

    let status = meta::get_upload_status(&st.pool, st.database_driver, &upload_id).await?;
    if status.pending_finalize {
        return Err(ApiError::BadRequest("upload is finalizing".into()));
    }

    let block_id = query
        .block_id
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("missing blockId query parameter".into()))?;
    let chunk_index = chunk_index_from_block_id(block_id)?;
    let part_index = i32::try_from(chunk_index)
        .map_err(|_| ApiError::BadRequest("invalid chunk index".into()))?;
    let part_number = part_index + 1;
    let (offset, size, _) = parse_content_range(&headers)?;
    if size <= 0 {
        return Err(ApiError::BadRequest("chunk size must be positive".into()));
    }

    let ready = meta::transition_upload_state(
        &st.pool,
        st.database_driver,
        &upload_id,
        &["reserved", "ready"],
        "uploading",
    )
    .await?;
    if !ready {
        return Err(ApiError::BadRequest(
            "upload is not ready to accept more parts".into(),
        ));
    }

    if let Err(err) = meta::reserve_part(
        &st.pool,
        st.database_driver,
        &upload_id,
        part_index,
        Some(offset),
        size,
    )
    .await
    {
        let _ = meta::transition_upload_state(
            &st.pool,
            st.database_driver,
            &upload_id,
            &["uploading"],
            "ready",
        )
        .await;
        return Err(err.into());
    }

    if let Err(err) = meta::begin_part_upload(&st.pool, st.database_driver, &upload_id).await {
        let _ = meta::transition_upload_state(
            &st.pool,
            st.database_driver,
            &upload_id,
            &["uploading"],
            "ready",
        )
        .await;
        return Err(err.into());
    }

    let bs = body_to_blob_payload(body);
    let etag = match st
        .store
        .upload_part(&storage_key, &upload_id, part_number, bs)
        .await
    {
        Ok(etag) => etag,
        Err(err) => {
            let finish = meta::finish_part_upload(&st.pool, st.database_driver, &upload_id).await;
            let _ = meta::transition_upload_state(
                &st.pool,
                st.database_driver,
                &upload_id,
                &["uploading"],
                "ready",
            )
            .await;
            return match finish {
                Ok(()) => Err(ApiError::S3(format!("{err}"))),
                Err(db_err) => Err(db_err.into()),
            };
        }
    };
    if let Err(err) = meta::complete_part(
        &st.pool,
        st.database_driver,
        &upload_id,
        part_index,
        Some(offset),
        &etag,
    )
    .await
    {
        let finish = meta::finish_part_upload(&st.pool, st.database_driver, &upload_id).await;
        let _ = meta::transition_upload_state(
            &st.pool,
            st.database_driver,
            &upload_id,
            &["uploading"],
            "ready",
        )
        .await;
        return match finish {
            Ok(()) => Err(err.into()),
            Err(db_err) => Err(db_err.into()),
        };
    }

    let ready = meta::transition_upload_state(
        &st.pool,
        st.database_driver,
        &upload_id,
        &["uploading"],
        "ready",
    )
    .await?;
    if !ready {
        let finish = meta::finish_part_upload(&st.pool, st.database_driver, &upload_id).await;
        return match finish {
            Ok(()) => Err(ApiError::Internal(
                "failed to finalize upload part because state changed".into(),
            )),
            Err(db_err) => Err(db_err.into()),
        };
    }

    meta::finish_part_upload(&st.pool, st.database_driver, &upload_id).await?;

    Ok(StatusCode::OK)
}

fn parse_content_range(headers: &HeaderMap) -> Result<(i64, i64, Option<i64>)> {
    let value = headers
        .get(axum::http::header::CONTENT_RANGE)
        .ok_or_else(|| ApiError::BadRequest("missing Content-Range header".into()))?;
    let value = value
        .to_str()
        .map_err(|_| ApiError::BadRequest("invalid Content-Range header".into()))?;
    let value = value
        .strip_prefix("bytes ")
        .ok_or_else(|| ApiError::BadRequest("invalid Content-Range header".into()))?;
    let mut parts = value.split('/');
    let range = parts
        .next()
        .ok_or_else(|| ApiError::BadRequest("invalid Content-Range header".into()))?;
    let total = parts.next();
    if parts.next().is_some() {
        return Err(ApiError::BadRequest("invalid Content-Range header".into()));
    }

    let mut bounds = range.split('-');
    let start = bounds
        .next()
        .ok_or_else(|| ApiError::BadRequest("invalid Content-Range header".into()))?
        .parse::<i64>()
        .map_err(|_| ApiError::BadRequest("invalid Content-Range header".into()))?;
    let end = bounds
        .next()
        .ok_or_else(|| ApiError::BadRequest("invalid Content-Range header".into()))?
        .parse::<i64>()
        .map_err(|_| ApiError::BadRequest("invalid Content-Range header".into()))?;
    if bounds.next().is_some() || start < 0 || end < start {
        return Err(ApiError::BadRequest("invalid Content-Range header".into()));
    }

    let length = end - start + 1;
    if length <= 0 {
        return Err(ApiError::BadRequest("invalid Content-Range header".into()));
    }

    let total = match total {
        Some("*") | None => None,
        Some(raw_total) => Some(
            raw_total
                .parse::<i64>()
                .map_err(|_| ApiError::BadRequest("invalid Content-Range header".into()))?,
        ),
    };

    Ok((start, length, total))
}

pub(crate) fn chunk_index_from_block_id(block_id: &str) -> Result<u32> {
    let decoded = general_purpose::STANDARD
        .decode(block_id)
        .map_err(|_| ApiError::BadRequest("invalid block id".into()))?;

    match decoded.len() {
        64 => {
            if decoded.len() < 20 {
                return Err(ApiError::BadRequest("invalid block id".into()));
            }
            let bytes: [u8; 4] = decoded[16..20]
                .try_into()
                .map_err(|_| ApiError::BadRequest("invalid block id".into()))?;
            Ok(u32::from_be_bytes(bytes))
        }
        48 => {
            let decoded_str = std::str::from_utf8(&decoded)
                .map_err(|_| ApiError::BadRequest("invalid block id".into()))?;
            let index_str = decoded_str
                .get(36..)
                .ok_or_else(|| ApiError::BadRequest("invalid block id".into()))?;
            index_str
                .parse::<u32>()
                .map_err(|_| ApiError::BadRequest("invalid block id".into()))
        }
        _ => Err(ApiError::BadRequest("invalid block id".into())),
    }
}

pub(crate) fn body_to_blob_payload(body: axum::body::Body) -> BlobUploadPayload {
    body.into_data_stream().map_err(anyhow::Error::from).boxed()
}

pub(crate) fn ensure_all_parts_uploaded(
    parts: &[meta::UploadPartRecord],
    expected_size: Option<i64>,
) -> Result<()> {
    if parts.is_empty() {
        return Err(ApiError::BadRequest(
            "multipart upload must include at least one part".into(),
        ));
    }
    let mut expected_offset = 0i64;
    for (index, part) in parts.iter().enumerate() {
        let expected_index = index as i32;
        let expected_part_number = expected_index + 1;
        if part.part_index != expected_index {
            return Err(ApiError::BadRequest(format!(
                "missing part {expected_part_number} before finalization"
            )));
        }
        if part.offset != expected_offset {
            return Err(ApiError::BadRequest(format!(
                "unexpected offset for part {}",
                part.part_number
            )));
        }
        if part.size <= 0 {
            return Err(ApiError::BadRequest(format!(
                "invalid size recorded for part {}",
                part.part_number
            )));
        }
        expected_offset = expected_offset
            .checked_add(part.size)
            .ok_or_else(|| ApiError::BadRequest("upload size overflow".into()))?;
    }
    if let Some(total) = expected_size
        && total != expected_offset
    {
        return Err(ApiError::BadRequest(
            "uploaded parts do not match expected size".into(),
        ));
    }
    Ok(())
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
    let notifier = meta::register_finalize_waiter(&upload_id);
    if let Err(err) =
        meta::set_pending_finalize(&st.pool, st.database_driver, &upload_id, true).await
    {
        meta::clear_finalize_waiter(&upload_id);
        return Err(err.into());
    }

    if let Err(err) =
        meta::wait_for_no_active_parts(&st.pool, st.database_driver, &upload_id, notifier.clone())
            .await
    {
        let _ = meta::set_pending_finalize(&st.pool, st.database_driver, &upload_id, false).await;
        meta::clear_finalize_waiter(&upload_id);
        return Err(err.into());
    }

    let reserved = meta::transition_upload_state(
        &st.pool,
        st.database_driver,
        &upload_id,
        &["reserved", "ready"],
        "finalizing",
    )
    .await?;
    if !reserved {
        let _ = meta::set_pending_finalize(&st.pool, st.database_driver, &upload_id, false).await;
        meta::clear_finalize_waiter(&upload_id);
        return Err(ApiError::BadRequest(
            "upload is still receiving parts".into(),
        ));
    }

    let expected_size = req.get("size").and_then(|v| v.as_i64());
    let parts = meta::get_completed_parts(&st.pool, st.database_driver, &upload_id).await?;
    if let Err(err) = ensure_all_parts_uploaded(&parts, expected_size) {
        let _ = meta::transition_upload_state(
            &st.pool,
            st.database_driver,
            &upload_id,
            &["finalizing"],
            "ready",
        )
        .await;
        let _ = meta::set_pending_finalize(&st.pool, st.database_driver, &upload_id, false).await;
        meta::clear_finalize_waiter(&upload_id);
        return Err(err);
    }

    let complete_result = st
        .store
        .complete_multipart(
            &storage_key,
            &upload_id,
            parts
                .iter()
                .map(|part| (part.part_number, part.etag.clone()))
                .collect(),
        )
        .await;
    match complete_result {
        Ok(()) => {
            let finalized = meta::transition_upload_state(
                &st.pool,
                st.database_driver,
                &upload_id,
                &["finalizing"],
                "completed",
            )
            .await?;
            if !finalized {
                let _ = meta::set_pending_finalize(&st.pool, st.database_driver, &upload_id, false)
                    .await;
                meta::clear_finalize_waiter(&upload_id);
                return Err(ApiError::Internal(
                    "failed to record completed upload state".into(),
                ));
            }
        }
        Err(err) => {
            let _ = meta::transition_upload_state(
                &st.pool,
                st.database_driver,
                &upload_id,
                &["finalizing"],
                "ready",
            )
            .await;
            let _ =
                meta::set_pending_finalize(&st.pool, st.database_driver, &upload_id, false).await;
            meta::clear_finalize_waiter(&upload_id);
            return Err(ApiError::S3(format!("{err}")));
        }
    }

    let _ = meta::set_pending_finalize(&st.pool, st.database_driver, &upload_id, false).await;
    meta::clear_finalize_waiter(&upload_id);

    // Persist size if provided
    if let Some(size) = expected_size {
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
    use crate::storage::{BlobDownloadStream, BlobStore, BlobUploadPayload, PresignedUrl};
    use crate::{api::proxy::ProxyHttpClient, config::DatabaseDriver, http::AppState};
    use async_trait::async_trait;
    use axum::{
        Json,
        extract::{Path, State},
    };
    use serde_json::json;
    use sqlx::any::AnyPoolOptions;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::time::sleep;
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

    #[derive(Clone, Default)]
    struct FinalizeStore {
        finalized: Arc<AtomicUsize>,
    }

    impl FinalizeStore {
        fn finalized_count(&self) -> usize {
            self.finalized.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl BlobStore for FinalizeStore {
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
            self.finalized.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn presign_get(
            &self,
            _key: &str,
            _ttl: Duration,
        ) -> anyhow::Result<Option<PresignedUrl>> {
            Ok(None)
        }

        async fn get(&self, _key: &str) -> anyhow::Result<Option<BlobDownloadStream>> {
            Ok(None)
        }

        async fn delete(&self, _key: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct DummyProxyClient;

    #[async_trait]
    impl ProxyHttpClient for DummyProxyClient {
        async fn execute(
            &self,
            _request: axum::http::Request<axum::body::Body>,
        ) -> std::result::Result<axum::response::Response, axum::BoxError> {
            panic!("proxy client should not be used in tests");
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

        async fn get(&self, _key: &str) -> anyhow::Result<Option<BlobDownloadStream>> {
            Ok(None)
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
            version: "v1".into(),
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
        assert_eq!(cache.cache_version.as_deref(), Some("v1"));
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

    #[test]
    fn parse_keys_parameter_handles_multiple_values() {
        let raw = "primary, fallback, primary ,".to_string();
        let parsed = parse_keys_parameter(Some(&raw)).expect("keys");
        assert_eq!(parsed, vec!["primary", "fallback"]);
    }

    #[test]
    fn ensure_all_parts_uploaded_accepts_contiguous_sequence() {
        let parts = vec![
            meta::UploadPartRecord {
                part_index: 0,
                part_number: 1,
                offset: 0,
                size: 10,
                etag: "etag-1".into(),
            },
            meta::UploadPartRecord {
                part_index: 1,
                part_number: 2,
                offset: 10,
                size: 5,
                etag: "etag-2".into(),
            },
        ];
        assert!(ensure_all_parts_uploaded(&parts, Some(15)).is_ok());
    }

    #[test]
    fn ensure_all_parts_uploaded_rejects_gaps() {
        let parts = vec![
            meta::UploadPartRecord {
                part_index: 0,
                part_number: 1,
                offset: 0,
                size: 10,
                etag: "etag-1".into(),
            },
            meta::UploadPartRecord {
                part_index: 2,
                part_number: 3,
                offset: 10,
                size: 5,
                etag: "etag-3".into(),
            },
        ];
        let err = ensure_all_parts_uploaded(&parts, None).expect_err("gap should be rejected");
        if let ApiError::BadRequest(message) = err {
            assert!(message.contains("missing part 2"));
        } else {
            panic!("unexpected error variant");
        }
    }

    #[tokio::test]
    async fn commit_waits_for_in_flight_parts() {
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

        let store = Arc::new(FinalizeStore::default());
        let state = AppState {
            pool: pool.clone(),
            store: store.clone() as Arc<dyn BlobStore>,
            enable_direct: false,
            proxy_client: Arc::new(DummyProxyClient) as Arc<dyn ProxyHttpClient>,
            database_driver: DatabaseDriver::Sqlite,
        };

        let entry = meta::create_entry(
            &pool,
            DatabaseDriver::Sqlite,
            "org",
            "repo",
            "key",
            "v1",
            "_",
            "storage",
        )
        .await
        .expect("create entry");
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
        let uploading = meta::transition_upload_state(
            &pool,
            DatabaseDriver::Sqlite,
            &upload_id,
            &["reserved"],
            "uploading",
        )
        .await
        .expect("transition to uploading");
        assert!(uploading);

        meta::reserve_part(&pool, DatabaseDriver::Sqlite, &upload_id, 0, Some(0), 3)
            .await
            .expect("reserve part");
        meta::begin_part_upload(&pool, DatabaseDriver::Sqlite, &upload_id)
            .await
            .expect("begin part upload");

        let commit_state = state.clone();
        let cache_id = entry.id.to_string();
        let commit_handle = tokio::spawn(async move {
            commit_cache(
                State(commit_state),
                Path(cache_id),
                Json(json!({ "size": 3 })),
            )
            .await
        });

        sleep(Duration::from_millis(100)).await;
        assert!(!commit_handle.is_finished(), "commit should wait for parts");

        meta::complete_part(
            &pool,
            DatabaseDriver::Sqlite,
            &upload_id,
            0,
            Some(0),
            "etag",
        )
        .await
        .expect("complete part");
        let back_to_reserved = meta::transition_upload_state(
            &pool,
            DatabaseDriver::Sqlite,
            &upload_id,
            &["uploading"],
            "reserved",
        )
        .await
        .expect("transition to reserved after upload");
        assert!(back_to_reserved);
        meta::finish_part_upload(&pool, DatabaseDriver::Sqlite, &upload_id)
            .await
            .expect("finish part upload");

        let status = commit_handle
            .await
            .expect("join commit task")
            .expect("commit result");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(store.finalized_count(), 1);

        let upload_status = meta::get_upload_status(&pool, DatabaseDriver::Sqlite, &upload_id)
            .await
            .expect("fetch upload status");
        assert_eq!(upload_status.active_part_count, 0);
        assert!(!upload_status.pending_finalize);
    }
}
