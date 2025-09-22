mod api;
mod config;
mod error;
mod http;
mod meta;
mod obs;
mod storage;

use axum::Router;
use sqlx::postgres::PgPoolOptions;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;

use crate::http::build_router;
use config::{BlobStoreSelector, Config};
use storage::{BlobStore, fs::FsStore, gcs::GcsStore, s3::S3Store};

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

    // Storage backend
    let store: Arc<dyn BlobStore> = match cfg.blob_store {
        BlobStoreSelector::S3 => {
            let s3_cfg = cfg
                .s3
                .as_ref()
                .context("missing S3 configuration for selected backend")?;
            Arc::new(
                S3Store::new(
                    s3_cfg.bucket.clone(),
                    s3_cfg.region.clone(),
                    s3_cfg.endpoint_url.clone(),
                    s3_cfg.force_path_style,
                )
                .await?,
            )
        }
        BlobStoreSelector::Fs => {
            let fs_cfg = cfg
                .fs
                .as_ref()
                .context("missing filesystem configuration for selected backend")?;
            Arc::new(FsStore::new(fs_cfg.root.clone(), fs_cfg.file_mode, fs_cfg.dir_mode).await?)
        }
        BlobStoreSelector::Gcs => {
            let gcs_cfg = cfg
                .gcs
                .as_ref()
                .context("missing GCS configuration for selected backend")?;
            Arc::new(GcsStore::new(gcs_cfg.clone()).await?)
        }
    };

    // Router
    let app: Router = build_router(pool, store, &cfg);

    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), cfg.port);
    tracing::info!(%addr, "listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
