mod api;
mod config;
mod error;
mod http;
mod meta;
mod obs;
mod storage;

use axum::Router;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::limit::ConcurrencyLimitLayer;

use crate::http::build_router;
use config::Config;
use storage::{BlobStore, s3::S3Store};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    obs::init_tracing();
    let cfg = Config::from_env()?;

    // DB
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    // S3 / MinIO
    let store: Arc<dyn BlobStore> = Arc::new(
        S3Store::new(
            cfg.s3_bucket.clone(),
            cfg.aws_region.clone(),
            cfg.aws_endpoint_url.clone(),
            cfg.force_path_style,
        )
        .await?,
    );

    // Router
    let app: Router =
        build_router(pool, store, &cfg).layer(ConcurrencyLimitLayer::new(cfg.max_concurrency));

    let addr: SocketAddr = ([0, 0, 0, 0], cfg.port).into();
    tracing::info!(%addr, "listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
