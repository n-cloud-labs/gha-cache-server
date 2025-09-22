use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{
    Client,
    config::{Builder as S3ConfigBuilder, Region},
    types::{CompletedMultipartUpload, CompletedPart},
};
use axum::body::{Body, to_bytes};
use std::time::Duration;

use crate::storage::{BlobStore, PresignedUrl};

#[derive(Clone)]
pub struct S3Store {
    client: Client,
    bucket: String,
}

impl S3Store {
    pub async fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        force_path_style: bool,
    ) -> anyhow::Result<Self> {
        let mut loader =
            aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region));
        if let Some(ep) = &endpoint {
            loader = loader.endpoint_url(ep);
        }
        let shared = loader.load().await;
        let mut b = S3ConfigBuilder::from(&shared);
        if force_path_style {
            b = b.force_path_style(true);
        }
        let cfg = b.build();
        let client = Client::from_conf(cfg);
        Ok(Self { client, bucket })
    }

    pub async fn bytestream_from_reader(r: Body) -> Result<ByteStream, axum::Error> {
        Ok(ByteStream::from(to_bytes(r, usize::MAX).await?))
    }
}

#[async_trait::async_trait]
impl BlobStore for S3Store {
    async fn create_multipart(&self, key: &str) -> anyhow::Result<String> {
        let out = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(out.upload_id().unwrap_or_default().to_string())
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: ByteStream,
    ) -> anyhow::Result<String> {
        let out = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(body)
            .send()
            .await?;
        Ok(out
            .e_tag()
            .unwrap_or_default()
            .trim_matches('"')
            .to_string())
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> anyhow::Result<()> {
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(
                parts
                    .into_iter()
                    .map(|(n, etag)| CompletedPart::builder().part_number(n).e_tag(etag).build())
                    .collect(),
            ))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await?;
        Ok(())
    }

    async fn presign_get(&self, key: &str, ttl: Duration) -> anyhow::Result<Option<PresignedUrl>> {
        use aws_sdk_s3::presigning::PresigningConfig;
        let req = self.client.get_object().bucket(&self.bucket).key(key);
        let presigned = req.presigned(PresigningConfig::expires_in(ttl)?).await?;
        let url: url::Url = presigned.uri().to_string().parse()?;
        Ok(Some(PresignedUrl { url }))
    }
}
