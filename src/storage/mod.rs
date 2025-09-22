use async_trait::async_trait;
use std::time::Duration;

pub mod s3;

pub struct PresignedUrl {
    pub url: url::Url,
}

#[async_trait]
pub trait BlobStore: Send + Sync + 'static {
    async fn create_multipart(&self, key: &str) -> anyhow::Result<String>; // returns upload_id
    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: aws_sdk_s3::primitives::ByteStream,
    ) -> anyhow::Result<String>; // returns etag

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> anyhow::Result<()>;

    async fn presign_get(&self, key: &str, ttl: Duration) -> anyhow::Result<Option<PresignedUrl>>;
}
