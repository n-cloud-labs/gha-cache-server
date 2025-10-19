use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
};
use bytes::Bytes;
use futures::stream;
use gha_cache_server::api::path::encode_path_segment;
use gha_cache_server::api::proto::cache;
use gha_cache_server::api::proxy::ProxyHttpClient;
use gha_cache_server::api::twirp::TwirpRequest;
use gha_cache_server::api::types::TwirpGetUrlReq;
use gha_cache_server::api::{download, twirp, upload};
use gha_cache_server::config::DatabaseDriver;
use gha_cache_server::http::AppState;
use gha_cache_server::meta::{self, CacheEntry};
use gha_cache_server::storage::{BlobDownloadStream, BlobStore, PresignedUrl};
use http::{HeaderMap, HeaderValue, Request, header};
use http_body_util::BodyExt;
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;
use url::Url;
use uuid::Uuid;

const TEST_VERSION: &str = "v1";
const TEST_URL: &str = "https://example.com/archive.tgz";

struct TestStore {
    url: Url,
    body: Bytes,
    presign: bool,
}

impl TestStore {
    fn new(url: &str) -> Self {
        Self {
            url: Url::parse(url).expect("url"),
            body: Bytes::from_static(b"payload"),
            presign: true,
        }
    }

    fn without_presign(url: &str) -> Self {
        Self {
            presign: false,
            ..Self::new(url)
        }
    }
}

#[async_trait]
impl BlobStore for TestStore {
    async fn create_multipart(&self, _key: &str) -> anyhow::Result<String> {
        unimplemented!("not used in tests");
    }

    async fn upload_part(
        &self,
        _key: &str,
        _upload_id: &str,
        _part_number: i32,
        _body: gha_cache_server::storage::BlobUploadPayload,
    ) -> anyhow::Result<String> {
        unimplemented!("not used in tests");
    }

    async fn complete_multipart(
        &self,
        _key: &str,
        _upload_id: &str,
        _parts: Vec<(i32, String)>,
    ) -> anyhow::Result<()> {
        unimplemented!("not used in tests");
    }

    async fn presign_get(
        &self,
        _key: &str,
        _ttl: Duration,
    ) -> anyhow::Result<Option<PresignedUrl>> {
        if self.presign {
            Ok(Some(PresignedUrl {
                url: self.url.clone(),
            }))
        } else {
            Ok(None)
        }
    }

    async fn get(&self, _key: &str) -> anyhow::Result<Option<BlobDownloadStream>> {
        let body = self.body.clone();
        let stream = stream::once(async move { Ok::<Bytes, anyhow::Error>(body) });
        Ok(Some(Box::pin(stream)))
    }

    async fn delete(&self, _key: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct DummyProxyClient;

#[async_trait]
impl ProxyHttpClient for DummyProxyClient {
    async fn execute(
        &self,
        _request: Request<axum::body::Body>,
    ) -> std::result::Result<axum::response::Response, axum::BoxError> {
        panic!("proxy client should not be used in tests");
    }
}

async fn setup_pool() -> AnyPool {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:?cache=shared")
        .await
        .expect("connect sqlite");
    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .expect("run migrations");
    pool
}

async fn create_entry(pool: &AnyPool) -> CacheEntry {
    meta::create_entry(
        pool,
        DatabaseDriver::Sqlite,
        "org",
        "repo",
        "cache-key",
        TEST_VERSION,
        "_",
        "storage-key",
    )
    .await
    .expect("create entry")
}

async fn set_last_access(pool: &AnyPool, id: Uuid, value: i64) {
    sqlx::query("UPDATE cache_entries SET last_access_at = ? WHERE id = ?")
        .bind(value)
        .bind(id.to_string())
        .execute(pool)
        .await
        .expect("set last access");
}

async fn fetch_last_access(pool: &AnyPool, id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT last_access_at FROM cache_entries WHERE id = ?")
        .bind(id.to_string())
        .fetch_one(pool)
        .await
        .expect("fetch last access")
}

fn build_state(pool: AnyPool, store: TestStore, enable_direct: bool) -> AppState {
    AppState {
        pool,
        store: Arc::new(store),
        enable_direct,
        defer_finalize_in_background: true,
        proxy_client: Arc::new(DummyProxyClient),
        database_driver: DatabaseDriver::Sqlite,
    }
}

#[tokio::test]
async fn touch_entry_updates_last_access() {
    let pool = setup_pool().await;
    let entry = create_entry(&pool).await;
    set_last_access(&pool, entry.id, 0).await;

    meta::touch_entry(&pool, DatabaseDriver::Sqlite, entry.id)
        .await
        .expect("touch entry");

    let updated = fetch_last_access(&pool, entry.id).await;
    assert!(updated > 0);
}

#[tokio::test]
async fn get_cache_entry_updates_last_access() {
    let pool = setup_pool().await;
    let entry = create_entry(&pool).await;
    set_last_access(&pool, entry.id, 1).await;

    let state = build_state(pool.clone(), TestStore::without_presign(TEST_URL), false);
    let mut query_params = HashMap::new();
    query_params.insert("keys".to_string(), entry.key.clone());
    query_params.insert("version".to_string(), entry.version.clone());

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("example.com"));

    let _ = upload::get_cache_entry(State(state), headers, Query(query_params))
        .await
        .expect("cache hit");

    let updated = fetch_last_access(&pool, entry.id).await;
    assert!(updated > 1);
}

#[tokio::test]
async fn twirp_download_url_updates_last_access() {
    let pool = setup_pool().await;
    let entry = create_entry(&pool).await;
    set_last_access(&pool, entry.id, 2).await;

    let state = build_state(pool.clone(), TestStore::without_presign(TEST_URL), false);
    let request = TwirpGetUrlReq {
        metadata: None,
        key: entry.key.clone(),
        restore_keys: Vec::new(),
        version: entry.version.clone(),
    };

    let request = TwirpRequest::<_, cache::GetCacheEntryDownloadUrlRequest>::from_json(request);

    let response = twirp::get_cache_entry_download_url(State(state), request)
        .await
        .expect("twirp cache hit");

    let http_response = response.into_response();
    assert_eq!(http_response.status(), http::StatusCode::OK);
    let body = BodyExt::collect(http_response.into_body())
        .await
        .expect("collect twirp body")
        .to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("parse twirp body");
    assert_eq!(payload["ok"].as_bool(), Some(true));
    assert_eq!(payload["matched_key"].as_str(), Some(entry.key.as_str()));
    let expected_url = format!(
        "http://localhost/download/{}/{}",
        encode_path_segment(&entry.key),
        encode_path_segment(&format!("{}.tgz", entry.id))
    );
    assert_eq!(
        payload["signed_download_url"].as_str(),
        Some(expected_url.as_str())
    );

    let updated = fetch_last_access(&pool, entry.id).await;
    assert!(updated > 2);
}

#[tokio::test]
async fn download_proxy_updates_last_access() {
    let pool = setup_pool().await;
    let entry = create_entry(&pool).await;
    set_last_access(&pool, entry.id, 3).await;

    let state = build_state(pool.clone(), TestStore::new(TEST_URL), true);
    let response = download::download_proxy(
        State(state),
        Path((entry.key.clone(), format!("{}.tgz", entry.id))),
    )
    .await
    .expect("download redirect");

    assert_eq!(response.status(), http::StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(http::header::LOCATION)
        .expect("location header");
    assert_eq!(location, "https://example.com/archive.tgz");

    let updated = fetch_last_access(&pool, entry.id).await;
    assert!(updated > 3);
}

#[tokio::test]
async fn download_proxy_streams_when_direct_disabled() {
    let pool = setup_pool().await;
    let entry = create_entry(&pool).await;
    set_last_access(&pool, entry.id, 4).await;

    let state = build_state(pool.clone(), TestStore::without_presign(TEST_URL), false);
    let response = download::download_proxy(
        State(state),
        Path((entry.key.clone(), format!("{}.tgz", entry.id))),
    )
    .await
    .expect("streaming download");

    assert_eq!(response.status(), http::StatusCode::OK);
    let bytes = BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    assert_eq!(bytes, Bytes::from_static(b"payload"));

    let updated = fetch_last_access(&pool, entry.id).await;
    assert!(updated > 4);
}
