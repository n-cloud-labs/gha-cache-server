use std::{fs, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Debug)]
pub enum BlobStoreSelector {
    Fs,
    S3,
    Gcs,
}

impl FromStr for BlobStoreSelector {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "fs" => Ok(Self::Fs),
            "s3" => Ok(Self::S3),
            "gcs" => Ok(Self::Gcs),
            other => anyhow::bail!("unsupported blob store '{other}'"),
        }
    }
}

#[derive(Clone)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint_url: Option<String>,
    pub force_path_style: bool,
}

#[derive(Clone)]
pub struct FsConfig {
    pub root: PathBuf,
    pub file_mode: Option<u32>,
    pub dir_mode: Option<u32>,
}

#[derive(Clone)]
pub struct GcsCredentials {
    pub raw_json: Value,
    pub service_account: ServiceAccountKeyConfig,
}

#[derive(Clone)]
pub struct GcsConfig {
    pub bucket: String,
    pub credentials: GcsCredentials,
    pub endpoint: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct ServiceAccountKeyConfig {
    #[serde(rename = "client_email")]
    pub client_email: String,
    #[serde(rename = "private_key")]
    pub private_key: String,
    #[serde(rename = "private_key_id")]
    pub private_key_id: String,
}

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub enable_direct_downloads: bool,
    pub request_timeout: Duration,
    pub max_concurrency: usize,

    pub database_url: String,

    pub blob_store: BlobStoreSelector,

    pub s3: Option<S3Config>,
    pub fs: Option<FsConfig>,
    pub gcs: Option<GcsConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let blob_store = std::env::var("BLOB_STORE")
            .unwrap_or_else(|_| "s3".to_string())
            .parse()?;

        let s3 = if matches!(blob_store, BlobStoreSelector::S3) {
            Some(S3Config {
                bucket: std::env::var("S3_BUCKET")
                    .context("S3_BUCKET is required when BLOB_STORE=s3")?,
                region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into()),
                endpoint_url: std::env::var("AWS_ENDPOINT_URL").ok(),
                force_path_style: std::env::var("S3_FORCE_PATH_STYLE")
                    .map(|v| v == "true")
                    .unwrap_or(true),
            })
        } else {
            None
        };

        let fs = if matches!(blob_store, BlobStoreSelector::Fs) {
            let root = std::env::var("FS_ROOT")
                .context("FS_ROOT is required when BLOB_STORE=fs")?
                .into();
            Some(FsConfig {
                root,
                file_mode: parse_mode("FS_FILE_MODE")?,
                dir_mode: parse_mode("FS_DIR_MODE")?,
            })
        } else {
            None
        };

        let gcs = if matches!(blob_store, BlobStoreSelector::Gcs) {
            let bucket = std::env::var("GCS_BUCKET")
                .context("GCS_BUCKET is required when BLOB_STORE=gcs")?;
            let bucket = bucket.trim().to_string();
            if bucket.is_empty() {
                bail!("GCS_BUCKET may not be empty");
            }

            let credentials_json = if let Ok(inline) = std::env::var("GCS_SERVICE_ACCOUNT_JSON") {
                if inline.trim().is_empty() {
                    bail!("GCS_SERVICE_ACCOUNT_JSON may not be empty");
                }
                serde_json::from_str::<Value>(&inline)
                    .context("GCS_SERVICE_ACCOUNT_JSON must contain valid JSON")?
            } else {
                let path = std::env::var("GCS_SERVICE_ACCOUNT_PATH").context(
                    "set GCS_SERVICE_ACCOUNT_JSON or GCS_SERVICE_ACCOUNT_PATH when BLOB_STORE=gcs",
                )?;
                let contents = fs::read_to_string(&path).with_context(|| {
                    format!("failed to read GCS service account file at {path}")
                })?;
                serde_json::from_str::<Value>(&contents).with_context(|| {
                    format!("invalid JSON in GCS service account file at {path}")
                })?
            };

            let service_account: ServiceAccountKeyConfig =
                serde_json::from_value(credentials_json.clone())
                    .context("GCS service account JSON is missing required fields")?;

            let endpoint = std::env::var("GCS_ENDPOINT")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty());

            Some(GcsConfig {
                bucket,
                credentials: GcsCredentials {
                    raw_json: credentials_json,
                    service_account,
                },
                endpoint,
            })
        } else {
            None
        };

        Ok(Self {
            port: std::env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            enable_direct_downloads: std::env::var("ENABLE_DIRECT_DOWNLOADS")
                .map(|v| v == "true")
                .unwrap_or(true),
            request_timeout: std::env::var("REQUEST_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(3600)),
            max_concurrency: std::env::var("MAX_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64),

            database_url: std::env::var("DATABASE_URL").expect("DATABASE_URL is required"),

            blob_store,

            s3,
            fs,
            gcs,
        })
    }
}

fn parse_mode(var: &str) -> Result<Option<u32>> {
    match std::env::var(var) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let digits = trimmed
                .strip_prefix("0o")
                .or_else(|| trimmed.strip_prefix("0O"))
                .unwrap_or(trimmed)
                .trim_start_matches('0');
            let digits = if digits.is_empty() { "0" } else { digits };
            let mode = u32::from_str_radix(digits, 8)
                .with_context(|| format!("{var} must be a valid octal number"))?;
            Ok(Some(mode))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{var} contains invalid UTF-8")
        }
    }
}
