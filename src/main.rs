mod api;
mod cleanup;
mod config;
mod error;
mod http;
mod meta;
mod obs;
mod storage;

use axum::Router;
use clap::Parser;
use sqlx::{AnyPool, any::AnyPoolOptions, migrate::Migrator};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;

use crate::http::build_router;
use config::{BlobStoreSelector, Config, DatabaseDriver};
use storage::{BlobStore, fs::FsStore, gcs::GcsStore, s3::S3Store};

static PG_MIGRATOR: Migrator = sqlx::migrate!("./migrations/postgres");
static MYSQL_MIGRATOR: Migrator = sqlx::migrate!("./migrations/mysql");
static SQLITE_MIGRATOR: Migrator = sqlx::migrate!("./migrations/sqlite");

#[derive(Parser)]
struct Cli {
    /// Run migrations and exit
    #[arg(long)]
    migrate_only: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    obs::init_tracing();
    let cfg = Config::from_env()?;

    // DB
    let pool = AnyPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await?;

    if matches!(cfg.database_driver, DatabaseDriver::Sqlite) {
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&pool)
            .await?;
    }

    run_migrations(&pool, cfg.database_driver).await?;
    if cli.migrate_only {
        return Ok(());
    }

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
    let app: Router = build_router(pool.clone(), store.clone(), &cfg);

    // Background cleanup loop
    let cleanup_settings = cfg.cleanup.clone();
    let cleanup_pool = pool.clone();
    let cleanup_store = store.clone();
    let cleanup_task = tokio::spawn(async move {
        cleanup::run_cleanup_loop(cleanup_pool, cleanup_store, cleanup_settings).await;
    });

    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), cfg.port);
    tracing::info!(%addr, "listening");
    let server = axum::serve(tokio::net::TcpListener::bind(addr).await?, app);
    let result = server.await;

    cleanup_task.abort();
    if let Err(err) = cleanup_task.await
        && err.is_panic()
    {
        std::panic::resume_unwind(err.into_panic());
    }

    result?;
    Ok(())
}

async fn run_migrations(pool: &AnyPool, driver: DatabaseDriver) -> anyhow::Result<()> {
    match driver {
        DatabaseDriver::Postgres => PG_MIGRATOR.run(pool).await?,
        DatabaseDriver::Mysql => MYSQL_MIGRATOR.run(pool).await?,
        DatabaseDriver::Sqlite => SQLITE_MIGRATOR.run(pool).await?,
    }
    Ok(())
}
