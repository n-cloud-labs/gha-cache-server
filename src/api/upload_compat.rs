use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use sqlx::Row;
use std::convert::TryInto;
use uuid::Uuid;

use crate::api::upload::body_to_blob_payload;
use crate::db::rewrite_placeholders;
use crate::error::{ApiError, Result};
use crate::http::AppState;
use crate::meta;

// PUT /upload/{cache-id}
// Compatibility handler some forks rely on. Treats the whole body as a single part.
#[derive(Default, Deserialize)]
pub struct UploadQuery {
    #[serde(default)]
    comp: Option<String>,
    #[serde(default)]
    blockid: Option<String>,
}

pub async fn put_upload(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<UploadQuery>,
    body: axum::body::Body,
) -> Result<Response> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("invalid cacheId".into()))?;

    if matches!(query.comp.as_deref(), Some("blocklist")) {
        return Ok(created_response());
    }

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

    let chunk_index = match query.blockid.as_deref() {
        Some(block_id) => chunk_index_from_block_id(block_id)?,
        None => 0,
    };

    let part_no = i32::try_from(chunk_index + 1)
        .map_err(|_| ApiError::BadRequest("invalid chunk index".into()))?;
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
    let bs = body_to_blob_payload(body);
    let etag = match st
        .store
        .upload_part(&storage_key, &upload_id, part_no, bs)
        .await
    {
        Ok(etag) => etag,
        Err(err) => {
            let _ = meta::transition_upload_state(
                &st.pool,
                st.database_driver,
                &upload_id,
                &["uploading"],
                "ready",
            )
            .await;
            return Err(ApiError::S3(format!("{err}")));
        }
    };
    if let Err(err) = meta::add_part(&st.pool, st.database_driver, &upload_id, part_no, &etag).await
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

    let ready = meta::transition_upload_state(
        &st.pool,
        st.database_driver,
        &upload_id,
        &["uploading"],
        "ready",
    )
    .await?;
    if !ready {
        return Err(ApiError::Internal(
            "failed to finalize upload part because state changed".into(),
        ));
    }

    Ok(created_response())
}

fn chunk_index_from_block_id(block_id: &str) -> Result<u32> {
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

fn created_response() -> Response {
    let mut response = StatusCode::CREATED.into_response();
    let request_id = Uuid::new_v4().to_string();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-ms-request-id", value);
    }
    response
}
