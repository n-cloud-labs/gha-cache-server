use axum::http::StatusCode;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use base64::{Engine as _, engine::general_purpose};
use uuid::Uuid;

use crate::http::AppState;
use crate::meta;
use crate::{
    error::{ApiError, Result},
    storage::BlobStore,
    storage::s3::S3Store,
};

// ====== actions/cache: GET /_apis/artifactcache/cache?keys=k1,k2&version=sha ======
pub async fn get_cache_entry(
    State(st): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let keys = q.get("keys").cloned().unwrap_or_default();
    // let version = q.get("version").cloned().unwrap_or_default();
    // Simplified lookup: pick first matching entry (TODO: add restore-keys precedence)
    let rec = sqlx::query!(
"SELECT id, storage_key, created_at FROM cache_entries WHERE key = $1 ORDER BY created_at DESC LIMIT 1",
keys.split(',').next().unwrap_or("")
).fetch_optional(&st.pool).await?;

    if let Some(r) = rec {
        // Return 200 with archiveLocation (direct presigned URL); scope kept generic
        let url = st
            .store
            .presign_get(&r.storage_key, std::time::Duration::from_secs(3600))
            .await
            .map_err(|e| ApiError::S3(format!("{e}")))?
            .map(|p| p.url.to_string())
            .unwrap_or_default();
        let body = serde_json::json!({
        "cacheKey": keys,
        "scope": "",
        "creationTime": r.created_at,
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
    let entry = meta::create_entry(&st.pool, "_", "_", key, version, &storage_key).await?;
    let upload_id = st
        .store
        .create_multipart(&storage_key)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    let _ = meta::upsert_upload(&st.pool, entry.id, &upload_id, "reserved").await?;

    Ok(Json(serde_json::json!({ "cacheId": entry.id })))
}

// ====== actions/cache: PATCH /_apis/artifactcache/caches/:id with Content-Range ======
pub async fn upload_chunk(
    State(st): State<AppState>,
    Path(id): Path<String>,
    body: axum::body::Body,
) -> Result<StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("invalid cacheId".into()))?;
    let rec = sqlx::query!("SELECT upload_id, storage_key FROM cache_uploads u JOIN cache_entries e ON e.id=u.entry_id WHERE e.id=$1", uuid)
        .fetch_one(&st.pool).await?;

    // We don't actually need offsets here because we map each PATCH to an S3 part in order.
    let next_part = 1 + meta::get_parts(&st.pool, &rec.upload_id).await?.len() as i32;

    let bs = S3Store::bytestream_from_reader(body)
        .await
        .map_err(|e| ApiError::Internal(format!("{e}")))?;
    let etag = st
        .store
        .upload_part(&rec.storage_key, &rec.upload_id, next_part, bs)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    meta::add_part(&st.pool, &rec.upload_id, next_part, &etag).await?;

    Ok(StatusCode::OK)
}

// ====== actions/cache: POST /_apis/artifactcache/caches/:id { size } ======
pub async fn commit_cache(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Result<StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("invalid cacheId".into()))?;
    let rec = sqlx::query!("SELECT upload_id, storage_key FROM cache_uploads u JOIN cache_entries e ON e.id=u.entry_id WHERE e.id=$1", uuid)
        .fetch_one(&st.pool).await?;
    let parts = meta::get_parts(&st.pool, &rec.upload_id).await?;
    st.store
        .complete_multipart(&rec.storage_key, &rec.upload_id, parts)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;

    // Persist size if provided
    if let Some(size) = req.get("size").and_then(|v| v.as_i64()) {
        let _ = sqlx::query!(
            "UPDATE cache_entries SET size_bytes=$2 WHERE id=$1",
            uuid,
            size
        )
        .execute(&st.pool)
        .await?;
    }
    Ok(StatusCode::CREATED)
}
