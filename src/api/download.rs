use axum::{
    extract::{Path, State},
    response::Redirect,
};
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

use crate::db::rewrite_placeholders;
use crate::error::{ApiError, Result};
use crate::http::AppState;
use crate::meta;

// GET /download/{random}/{filename}
// We treat {random} as an opaque object key prefix (already known/stored in DB), and {filename} ignored for routing convenience
pub async fn download_proxy(
    State(st): State<AppState>,
    Path((random, _filename)): Path<(String, String)>,
) -> Result<Redirect> {
    if !st.enable_direct {
        return Err(ApiError::BadRequest("direct downloads disabled".into()));
    }
    let entry_id =
        Uuid::parse_str(&random).map_err(|_| ApiError::BadRequest("invalid cache id".into()))?;
    let query = rewrite_placeholders(
        "SELECT storage_key FROM cache_entries WHERE id = ?",
        st.database_driver,
    );
    let rec = sqlx::query(&query)
        .bind(entry_id.to_string())
        .fetch_optional(&st.pool)
        .await?;
    let row = rec.ok_or(ApiError::NotFound)?;
    let storage_key: String = row.try_get("storage_key")?;
    meta::touch_entry(&st.pool, st.database_driver, entry_id).await?;
    let pres = st
        .store
        .presign_get(&storage_key, Duration::from_secs(3600))
        .await
        .map_err(|e| ApiError::S3(format!("{e}")))?;
    if let Some(p) = pres {
        return Ok(Redirect::temporary(p.url.as_str()));
    }
    Err(ApiError::NotFound)
}
