use axum::{
    extract::{Path, State},
    response::Redirect,
};
use std::time::Duration;

use crate::error::{ApiError, Result};
use crate::http::AppState;

// GET /download/{random}/{filename}
// We treat {random} as an opaque object key prefix (already known/stored in DB), and {filename} ignored for routing convenience
pub async fn download_proxy(
    State(st): State<AppState>,
    Path((random, _filename)): Path<(String, String)>,
) -> Result<Redirect> {
    if !st.enable_direct {
        return Err(ApiError::BadRequest("direct downloads disabled".into()));
    }
    // Compose object key from opaque token; in real impl, map token->storage_key via DB
    let storage_key = format!("dl/{random}"); // TODO: lookup token in DB to exact storage key
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
