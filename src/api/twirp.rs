use axum::{Json, extract::State};
use base64::Engine;
use base64::engine::general_purpose;
use uuid::Uuid;

use super::types::*;
use crate::http::AppState;
use crate::meta;
use crate::{
    error::{ApiError, Result},
    storage::BlobStore,
};

// POST /twirp/.../CreateCacheEntry
pub async fn create_cache_entry(
    State(st): State<AppState>,
    Json(req): Json<TwirpCreateReq>,
) -> Result<Json<TwirpCreateResp>> {
    let storage_key = format!(
        "twirp/{}-{}-{}",
        general_purpose::STANDARD.encode(&req.key),
        req.version,
        Uuid::new_v4()
    );
    let entry = meta::create_entry(
        &st.pool,
        "_",
        "_",
        &req.key,
        req.version.as_str(),
        &storage_key,
    )
    .await?;
    let upload_id = st
        .store
        .create_multipart(&storage_key)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    let _ = meta::upsert_upload(&st.pool, entry.id, &upload_id, "reserved").await?;
    Ok(Json(TwirpCreateResp {
        cache_id: entry.id.to_string(),
    }))
}

// POST /twirp/.../FinalizeCacheEntryUpload
pub async fn finalize_cache_entry_upload(
    State(st): State<AppState>,
    Json(req): Json<TwirpFinalizeReq>,
) -> Result<Json<TwirpFinalizeResp>> {
    let uuid = Uuid::parse_str(&req.cache_id)
        .map_err(|_| ApiError::BadRequest("invalid cache_id".into()))?;
    let rec = sqlx::query!("SELECT upload_id, storage_key FROM cache_uploads u JOIN cache_entries e ON e.id=u.entry_id WHERE e.id=$1", uuid)
        .fetch_one(&st.pool).await?;
    let parts = crate::meta::get_parts(&st.pool, &rec.upload_id).await?;
    st.store
        .complete_multipart(&rec.storage_key, &rec.upload_id, parts)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;

    let _ = sqlx::query!(
        "UPDATE cache_entries SET size_bytes=$2 WHERE id=$1",
        uuid,
        req.size_bytes
    )
    .execute(&st.pool)
    .await?;
    Ok(Json(TwirpFinalizeResp { ok: true }))
}

// POST /twirp/.../GetCacheEntryDownloadURL
pub async fn get_cache_entry_download_url(
    State(st): State<AppState>,
    Json(req): Json<TwirpGetUrlReq>,
) -> Result<Json<TwirpGetUrlResp>> {
    let uuid = Uuid::parse_str(&req.cache_id)
        .map_err(|_| ApiError::BadRequest("invalid cache_id".into()))?;
    let rec = sqlx::query!("SELECT storage_key FROM cache_entries WHERE id=$1", uuid)
        .fetch_one(&st.pool)
        .await?;
    let pres = st
        .store
        .presign_get(&rec.storage_key, std::time::Duration::from_secs(3600))
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    let url = pres.ok_or(ApiError::NotFound)?.url.to_string();
    Ok(Json(TwirpGetUrlResp {
        archive_location: url,
    }))
}
