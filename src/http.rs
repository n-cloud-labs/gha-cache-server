use axum::{
    Router,
    routing::{get, patch, post, put},
};
use sqlx::PgPool;
use std::sync::Arc;

use crate::api::{download, twirp, upload, upload_compat};
use crate::config::Config;
use crate::storage::BlobStore;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub store: Arc<dyn BlobStore>,
    pub enable_direct: bool,
}

pub fn build_router(pool: PgPool, store: Arc<dyn BlobStore>, cfg: &Config) -> Router {
    let app_state = AppState {
        pool: pool.clone(),
        store,
        enable_direct: cfg.enable_direct_downloads,
    };

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // ===== Official actions/cache style =====
        // GET lookup
        .route("/_apis/artifactcache/cache", get(upload::get_cache_entry))
        // POST reserve
        .route(
            "/_apis/artifactcache/caches",
            get(upload::list_caches).post(upload::reserve_cache),
        )
        // PATCH chunks
        .route(
            "/_apis/artifactcache/caches/:id",
            patch(upload::upload_chunk),
        )
        // POST commit
        .route(
            "/_apis/artifactcache/caches/:id",
            post(upload::commit_cache),
        )
        // ===== Extra routes you asked =====
        // 1) GET /download/{random}/{filename}
        .route("/download/:random/:filename", get(download::download_proxy))
        // 2) TWIRP endpoints
        .route(
            "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry",
            post(twirp::create_cache_entry),
        )
        .route(
            "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
            post(twirp::finalize_cache_entry_upload),
        )
        .route(
            "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
            post(twirp::get_cache_entry_download_url),
        )
        // 3) PUT /upload/{cache-id}
        .route("/upload/:cache_id", put(upload_compat::put_upload))
        .with_state(app_state)
}
