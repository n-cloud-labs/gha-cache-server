use std::sync::Arc;

use chrono::Utc;
use sqlx::AnyPool;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, error, info, warn};

use crate::config::{CleanupSettings, DatabaseDriver};
use crate::meta::{self, CacheEntry};
use crate::storage::BlobStore;

pub async fn run_cleanup_loop(
    pool: AnyPool,
    store: Arc<dyn BlobStore>,
    settings: CleanupSettings,
    driver: DatabaseDriver,
) {
    let mut ticker = interval(settings.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        if let Err(err) = run_iteration(&pool, store.clone(), &settings, driver).await {
            error!(?err, "cleanup iteration failed");
        }
    }
}

async fn run_iteration(
    pool: &AnyPool,
    store: Arc<dyn BlobStore>,
    settings: &CleanupSettings,
    driver: DatabaseDriver,
) -> anyhow::Result<()> {
    let now = Utc::now();

    let expired = meta::expired_entries(pool, driver, now, settings.max_entry_age).await?;
    if !expired.is_empty() {
        info!(count = expired.len(), "removing expired cache entries");
    }
    for entry in expired {
        if remove_entry(pool, driver, store.clone(), &entry).await {
            debug!(entry_id = %entry.id, "deleted expired cache entry");
        }
    }

    if let Some(limit) = settings.max_total_bytes {
        let mut usage = meta::total_occupancy(pool, driver).await?.max(0) as u64;
        if usage > limit {
            info!(current = usage, limit, "cache usage exceeds threshold");
            let entries = meta::list_entries_ordered(pool, driver, None).await?;
            for entry in entries {
                if usage <= limit {
                    break;
                }

                if remove_entry(pool, driver, store.clone(), &entry).await {
                    let size = clamp_size(entry.size_bytes);
                    usage = usage.saturating_sub(size);
                    debug!(entry_id = %entry.id, size, usage, limit, "deleted entry to reclaim space");
                }
            }

            if usage > limit {
                warn!(
                    current = usage,
                    limit, "cleanup loop could not reduce usage below threshold"
                );
            }
        }
    }

    Ok(())
}

async fn remove_entry(
    pool: &AnyPool,
    driver: DatabaseDriver,
    store: Arc<dyn BlobStore>,
    entry: &CacheEntry,
) -> bool {
    if let Err(err) = store.delete(&entry.storage_key).await {
        error!(entry_id = %entry.id, storage_key = %entry.storage_key, ?err, "failed to delete blob");
        return false;
    }

    if let Err(err) = meta::delete_entry(pool, driver, entry.id).await {
        error!(entry_id = %entry.id, ?err, "failed to delete cache entry metadata");
        return false;
    }

    true
}

fn clamp_size(value: i64) -> u64 {
    if value < 0 { 0 } else { value as u64 }
}
