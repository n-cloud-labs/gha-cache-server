use axum::extract::{Path, State};
use axum::http::StatusCode;
use sqlx::Row;
use uuid::Uuid;

use crate::api::upload::body_to_blob_payload;
use crate::db::rewrite_placeholders;
use crate::error::{ApiError, Result};
use crate::http::AppState;
use crate::meta;

// PUT /upload/{cache-id}
// Compatibility handler some forks rely on. Treats the whole body as a single part.
pub async fn put_upload(
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

    let part_no = 1 + meta::get_parts(&st.pool, st.database_driver, &upload_id)
        .await?
        .len() as i32;
    let bs = body_to_blob_payload(body);
    let etag = st
        .store
        .upload_part(&storage_key, &upload_id, part_no, bs)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    meta::add_part(&st.pool, st.database_driver, &upload_id, part_no, &etag).await?;
    Ok(StatusCode::OK)
}
