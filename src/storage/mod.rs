use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use std::time::Duration;

pub mod fs;
pub mod gcs;
pub mod s3;

pub struct PresignedUrl {
    pub url: url::Url,
}

/// Stream of bytes representing a multipart upload part.
///
/// The stream yields the raw body of a single part and propagates failures via
/// [`anyhow::Error`]. Implementations must consume the stream at most once and
/// either upload the entire payload or report an error.
pub type BlobStream = BoxStream<'static, anyhow::Result<Bytes>>;
pub type BlobUploadPayload = BlobStream;
pub type BlobDownloadStream = BlobStream;

#[async_trait]
pub trait BlobStore: Send + Sync + 'static {
    async fn create_multipart(&self, key: &str) -> anyhow::Result<String>; // returns upload_id
    /// Upload a single multipart part from the provided stream.
    ///
    /// Implementations should exhaust the stream exactly once, uploading its
    /// complete contents or failing with an error.
    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: BlobUploadPayload,
    ) -> anyhow::Result<String>; // returns etag

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> anyhow::Result<()>;

    async fn presign_get(&self, key: &str, ttl: Duration) -> anyhow::Result<Option<PresignedUrl>>;

    async fn get(&self, key: &str) -> anyhow::Result<Option<BlobDownloadStream>>;

    async fn delete(&self, key: &str) -> anyhow::Result<()>;
}
