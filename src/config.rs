use std::time::Duration;

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub enable_direct_downloads: bool,
    pub request_timeout: Duration,
    pub max_concurrency: usize,

    pub database_url: String,

    pub s3_bucket: String,
    pub aws_region: String,
    pub aws_endpoint_url: Option<String>,
    pub force_path_style: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
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

            s3_bucket: std::env::var("S3_BUCKET").expect("S3_BUCKET is required"),
            aws_region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into()),
            aws_endpoint_url: std::env::var("AWS_ENDPOINT_URL").ok(),
            force_path_style: std::env::var("S3_FORCE_PATH_STYLE")
                .map(|v| v == "true")
                .unwrap_or(true),
        })
    }
}
