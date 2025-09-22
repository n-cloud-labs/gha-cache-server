use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{
    Client,
    config::{Builder as S3ConfigBuilder, Region},
    types::{CompletedMultipartUpload, CompletedPart},
};
use aws_smithy_types::body::Error as SdkBodyError;
use futures::TryStreamExt;
use http_body::Frame;
use pin_project_lite::pin_project;
use std::time::Duration;
use sync_wrapper::SyncWrapper;

#[cfg(test)]
use axum::body::Body;

use crate::storage::{BlobStore, BlobUploadPayload, PresignedUrl};

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

    #[cfg(test)]
    pub fn bytestream_from_reader(r: Body) -> ByteStream {
        let stream = r
            .into_data_stream()
            .map_err(|err| -> SdkBodyError { err.into() });
        Self::bytestream_from_stream(stream)
    }

    fn bytestream_from_stream<S, E>(stream: S) -> ByteStream
    where
        S: futures::Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
        E: Into<SdkBodyError> + 'static,
    {
        ByteStream::from_body_1_x(SyncDataBody::new(stream))
    }
}

pin_project! {
    struct SyncDataBody<S> {
        #[pin]
        stream: SyncWrapper<S>,
    }
}

impl<S> SyncDataBody<S> {
    fn new(stream: S) -> Self {
        Self {
            stream: SyncWrapper::new(stream),
        }
    }
}

impl<S, E> http_body::Body for SyncDataBody<S>
where
    S: futures::Stream<Item = Result<bytes::Bytes, E>> + Send,
    E: Into<SdkBodyError> + 'static,
{
    type Data = bytes::Bytes;
    type Error = E;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project().stream.get_pin_mut().poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(bytes))) => {
                std::task::Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            std::task::Poll::Ready(Some(Err(err))) => std::task::Poll::Ready(Some(Err(err))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
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
        body: BlobUploadPayload,
    ) -> anyhow::Result<String> {
        let body = Self::bytestream_from_stream(body.map_err(|err| -> SdkBodyError { err.into() }));
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

#[cfg(test)]
mod tests {
    use super::S3Store;
    use axum::body::Body;
    use bytes::Bytes;
    use futures::stream;
    use std::convert::Infallible;
    use std::error::Error as _;
    use std::io;

    #[tokio::test]
    async fn bytestream_from_reader_streams_large_payloads() {
        let chunk = Bytes::from(vec![42u8; 128 * 1024]);
        let chunk_len = chunk.len();
        let chunks = 64;
        let chunk_for_stream = chunk.clone();
        let body = Body::from_stream(stream::iter(
            (0..chunks).map(move |_| Ok::<_, Infallible>(chunk_for_stream.clone())),
        ));

        let collected = S3Store::bytestream_from_reader(body)
            .collect()
            .await
            .expect("collect succeeds")
            .into_bytes();

        assert_eq!(collected.len(), chunk_len * chunks);
        assert!(collected.iter().all(|&b| b == 42));
    }

    #[tokio::test]
    async fn bytestream_from_reader_propagates_stream_errors() {
        let body = Body::from_stream(stream::iter([
            Ok::<_, io::Error>(Bytes::from_static(b"ok")),
            Err(io::Error::other("boom")),
        ]));

        let err = S3Store::bytestream_from_reader(body)
            .collect()
            .await
            .expect_err("collect should report stream error");

        let source = err.source().expect("streaming error should expose source");
        assert!(source.to_string().contains("boom"));
    }
}
