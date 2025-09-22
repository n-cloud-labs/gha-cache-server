use axum::{
    Router,
    routing::{get, patch, post, put},
};
use sqlx::PgPool;
use std::sync::Arc;

use crate::api::{download, proxy, twirp, upload, upload_compat};
use crate::config::Config;
use crate::storage::BlobStore;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub store: Arc<dyn BlobStore>,
    pub enable_direct: bool,
    pub proxy_client: Arc<dyn proxy::ProxyHttpClient>,
}

pub fn build_router(pool: PgPool, store: Arc<dyn BlobStore>, cfg: &Config) -> Router {
    let proxy_client: Arc<dyn proxy::ProxyHttpClient> = Arc::new(proxy::HyperProxyClient::new());

    build_router_with_proxy(pool, store, cfg, proxy_client)
}

pub(crate) fn build_router_with_proxy(
    pool: PgPool,
    store: Arc<dyn BlobStore>,
    cfg: &Config,
    proxy_client: Arc<dyn proxy::ProxyHttpClient>,
) -> Router {
    let app_state = AppState {
        pool: pool.clone(),
        store,
        enable_direct: cfg.enable_direct_downloads,
        proxy_client,
    };

    Router::new()
        .without_v07_checks()
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
        .fallback(proxy::proxy_unknown)
        .with_state(app_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{HeaderMap, Method, Request, StatusCode},
        response::Response,
    };
    use bytes::Bytes;
    use http::Uri;
    use http_body_util::BodyExt;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    use crate::api::proxy::{self, ProxyHttpClient, RESULTS_RECEIVER_ORIGIN};
    use crate::config::Config;
    use crate::storage::{BlobStore, PresignedUrl};

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    }

    #[derive(Clone)]
    struct MockProxyClient {
        calls: Arc<Mutex<Vec<RecordedRequest>>>,
        responder: Arc<dyn Fn() -> Response + Send + Sync>,
    }

    impl MockProxyClient {
        fn with_response<F>(responder: F) -> Self
        where
            F: Fn() -> Response + Send + Sync + 'static,
        {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                responder: Arc::new(responder),
            }
        }

        fn with_body(status: StatusCode, body: &'static str) -> Self {
            Self::with_response(move || {
                Response::builder()
                    .status(status)
                    .body(Body::from(body))
                    .expect("proxy response")
            })
        }

        async fn take_calls(&self) -> Vec<RecordedRequest> {
            let mut calls = self.calls.lock().await;
            let recorded = calls.clone();
            calls.clear();
            recorded
        }
    }

    #[async_trait]
    impl ProxyHttpClient for MockProxyClient {
        async fn execute(
            &self,
            request: Request<Body>,
        ) -> std::result::Result<Response, axum::BoxError> {
            let (parts, body) = request.into_parts();
            let collected = body
                .collect()
                .await
                .map_err(|err| -> axum::BoxError { Box::new(err) })?;

            let record = RecordedRequest {
                method: parts.method,
                uri: parts.uri,
                headers: parts.headers,
                body: collected.to_bytes(),
            };

            self.calls.lock().await.push(record);

            Ok((self.responder)())
        }
    }

    #[derive(Clone)]
    struct NoopStore;

    #[async_trait]
    impl BlobStore for NoopStore {
        async fn create_multipart(&self, _key: &str) -> anyhow::Result<String> {
            unimplemented!("not required for tests")
        }

        async fn upload_part(
            &self,
            _key: &str,
            _upload_id: &str,
            _part_number: i32,
            _body: aws_sdk_s3::primitives::ByteStream,
        ) -> anyhow::Result<String> {
            unimplemented!("not required for tests")
        }

        async fn complete_multipart(
            &self,
            _key: &str,
            _upload_id: &str,
            _parts: Vec<(i32, String)>,
        ) -> anyhow::Result<()> {
            unimplemented!("not required for tests")
        }

        async fn presign_get(
            &self,
            _key: &str,
            _ttl: Duration,
        ) -> anyhow::Result<Option<PresignedUrl>> {
            Ok(None)
        }
    }

    fn test_config() -> Config {
        Config {
            port: 8080,
            enable_direct_downloads: true,
            request_timeout: Duration::from_secs(30),
            max_concurrency: 16,
            database_url: "postgres://localhost/test".into(),
            s3_bucket: "bucket".into(),
            aws_region: "us-east-1".into(),
            aws_endpoint_url: None,
            force_path_style: true,
        }
    }

    #[tokio::test]
    async fn proxies_unknown_paths_via_results_receiver() {
        let mock = MockProxyClient::with_body(StatusCode::ACCEPTED, "proxied body");
        let proxy_arc: Arc<dyn proxy::ProxyHttpClient> = Arc::new(mock.clone());
        let pool = PgPool::connect_lazy("postgres://postgres@localhost/test").expect("lazy pool");
        let store: Arc<dyn BlobStore> = Arc::new(NoopStore);
        let cfg = test_config();

        let router = build_router_with_proxy(pool, store, &cfg, proxy_arc);

        let request = Request::builder()
            .method(Method::POST)
            .uri("/unknown/path?foo=bar")
            .header("x-sample", "demo")
            .body(Body::from("payload"))
            .expect("request");

        let response = router.oneshot(request).await.expect("router response");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(body_bytes, Bytes::from_static(b"proxied body"));

        let calls = mock.take_calls().await;
        assert_eq!(calls.len(), 1, "expected exactly one proxied request");
        let recorded = &calls[0];

        assert_eq!(recorded.method, Method::POST);
        assert_eq!(
            recorded.uri,
            format!("{RESULTS_RECEIVER_ORIGIN}/unknown/path?foo=bar")
                .parse::<Uri>()
                .unwrap()
        );
        assert_eq!(recorded.body, Bytes::from_static(b"payload"));

        let host_header = recorded
            .headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok());
        assert_eq!(host_header, Some(proxy::RESULTS_RECEIVER_HOST));
        assert_eq!(
            recorded
                .headers
                .get("x-sample")
                .and_then(|v| v.to_str().ok()),
            Some("demo")
        );
    }

    #[tokio::test]
    async fn known_routes_bypass_proxy() {
        let mock = MockProxyClient::with_body(StatusCode::IM_A_TEAPOT, "unused");
        let proxy_arc: Arc<dyn proxy::ProxyHttpClient> = Arc::new(mock.clone());
        let pool = PgPool::connect_lazy("postgres://postgres@localhost/test").expect("lazy pool");
        let store: Arc<dyn BlobStore> = Arc::new(NoopStore);
        let cfg = test_config();

        let router = build_router_with_proxy(pool, store, &cfg, proxy_arc);

        let request = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .expect("request");

        let response = router.oneshot(request).await.expect("router response");

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        assert_eq!(body_bytes, Bytes::from_static(b"ok"));

        let calls = mock.take_calls().await;
        assert!(
            calls.is_empty(),
            "proxy should not be invoked for known routes"
        );
    }
}
