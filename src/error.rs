use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found")]
    NotFound,
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("s3: {0}")]
    S3(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct Problem {
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (code, msg) = match &self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            ApiError::Db(e) => (StatusCode::BAD_GATEWAY, format!("db: {}", e)),
            ApiError::S3(e) => (StatusCode::BAD_GATEWAY, format!("s3: {}", e)),
            ApiError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.clone()),
        };
        (code, Json(Problem { message: msg })).into_response()
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;
