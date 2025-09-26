use axum::{Json, extract::State};
use base64::Engine;
use base64::engine::general_purpose;
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

use super::types::*;
use crate::api::upload::{normalize_key, normalize_version};
use crate::db::rewrite_placeholders;
use crate::error::{ApiError, Result};
use crate::http::AppState;
use crate::meta;

fn build_upload_url(id: Uuid) -> String {
    format!("/upload/{id}")
}

fn unique_keys(primary: String, restores: &[String]) -> Vec<String> {
    let mut result = Vec::with_capacity(restores.len() + 1);
    result.push(primary);
    for item in restores {
        if !result.iter().any(|existing| existing == item) {
            result.push(item.clone());
        }
    }
    result
}

// POST /twirp/.../CreateCacheEntry
pub async fn create_cache_entry(
    State(st): State<AppState>,
    Json(req): Json<TwirpCreateReq>,
) -> Result<Json<TwirpCreateResp>> {
    let key = normalize_key(&req.key)?;
    let version = normalize_version(&req.version)?;
    let storage_key = format!(
        "twirp/{}/{}-{}",
        general_purpose::STANDARD.encode(&key),
        version,
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
    Ok(Json(TwirpCreateResp {
        ok: true,
        signed_upload_url: build_upload_url(entry.id),
    }))
}

// POST /twirp/.../FinalizeCacheEntryUpload
pub async fn finalize_cache_entry_upload(
    State(st): State<AppState>,
    Json(req): Json<TwirpFinalizeReq>,
) -> Result<Json<TwirpFinalizeResp>> {
    let key = normalize_key(&req.key)?;
    let version = normalize_version(&req.version)?;
    let Some(entry) =
        meta::find_entry_by_key_version(&st.pool, st.database_driver, &key, &version).await?
    else {
        return Ok(Json(TwirpFinalizeResp {
            ok: false,
            entry_id: String::new(),
        }));
    };
    let query = rewrite_placeholders(
        "SELECT upload_id, storage_key FROM cache_uploads u JOIN cache_entries e ON e.id = u.entry_id WHERE e.id = ?",
        st.database_driver,
    );
    let rec = sqlx::query(&query)
        .bind(entry.id.to_string())
        .fetch_one(&st.pool)
        .await?;
    let upload_id: String = rec.try_get("upload_id")?;
    let storage_key: String = rec.try_get("storage_key")?;
    let parts = crate::meta::get_parts(&st.pool, st.database_driver, &upload_id).await?;
    st.store
        .complete_multipart(&storage_key, &upload_id, parts)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;

    Ok(Json(TwirpFinalizeResp {
        ok: true,
        entry_id: entry.id.to_string(),
    }))
}

// POST /twirp/.../GetCacheEntryDownloadURL
pub async fn get_cache_entry_download_url(
    State(st): State<AppState>,
    Json(req): Json<TwirpGetUrlReq>,
) -> Result<Json<TwirpGetUrlResp>> {
    let key = normalize_key(&req.key)?;
    let version = normalize_version(&req.version)?;
    let mut restore_keys = Vec::with_capacity(req.restore_keys.len());
    for candidate in req.restore_keys {
        restore_keys.push(normalize_key(&candidate)?);
    }
    let candidates = unique_keys(key, &restore_keys);

    for candidate in candidates {
        if let Some(entry) =
            meta::find_entry_by_key_version(&st.pool, st.database_driver, &candidate, &version)
                .await?
        {
            meta::touch_entry(&st.pool, st.database_driver, entry.id).await?;
            let pres = st
                .store
                .presign_get(&entry.storage_key, Duration::from_secs(3600))
                .await
                .map_err(|e| ApiError::S3(format!("{e}")))?;
            if let Some(url) = pres {
                return Ok(Json(TwirpGetUrlResp {
                    ok: true,
                    signed_download_url: url.url.to_string(),
                    matched_key: candidate,
                }));
            }
        }
    }

    Ok(Json(TwirpGetUrlResp {
        ok: false,
        signed_download_url: String::new(),
        matched_key: String::new(),
    }))
}
