use axum::extract::{Path, State};
use axum::http::StatusCode;
use uuid::Uuid;

use crate::http::AppState;
use crate::meta;
use crate::{
    error::{ApiError, Result},
    storage::s3::S3Store,
};

// PUT /upload/{cache-id}
// Compatibility handler some forks rely on. Treats the whole body as a single part.
pub async fn put_upload(
    State(st): State<AppState>,
    Path(id): Path<String>,
    body: axum::body::Body,
) -> Result<StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("invalid cacheId".into()))?;
    let rec = sqlx::query!("SELECT upload_id, storage_key FROM cache_uploads u JOIN cache_entries e ON e.id=u.entry_id WHERE e.id=$1", uuid)
        .fetch_one(&st.pool).await?;

    let part_no = 1 + meta::get_parts(&st.pool, &rec.upload_id).await?.len() as i32;
    let bs = S3Store::bytestream_from_reader(body)
        .await
        .map_err(|e| ApiError::Internal(format!("{e}")))?;
    let etag = st
        .store
        .upload_part(&rec.storage_key, &rec.upload_id, part_no, bs)
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    meta::add_part(&st.pool, &rec.upload_id, part_no, &etag).await?;
    Ok(StatusCode::OK)
}
