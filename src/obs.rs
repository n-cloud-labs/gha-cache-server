use tracing_subscriber::{EnvFilter, fmt};

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .compact()
        .init();
}
