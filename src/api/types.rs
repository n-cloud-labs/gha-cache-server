use serde::de::{Deserializer, Error as DeError, Visitor};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use uuid::Uuid;

use crate::api::proto::cache;
use crate::error::ApiError;

fn deserialize_i64_from_string_or_number<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    struct I64Visitor;

    impl<'de> Visitor<'de> for I64Visitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an integer or a string containing an integer")
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            i64::try_from(value).map_err(|_| E::custom("integer overflow"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            value
                .parse::<i64>()
                .map_err(|_| E::custom("invalid integer string"))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(I64Visitor)
}

fn deserialize_option_i64_from_string_or_number<'de, D>(
    deserializer: D,
) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptionVisitor;

    impl<'de> Visitor<'de> for OptionVisitor {
        type Value = Option<i64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an integer, string containing an integer, or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_i64_from_string_or_number(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(OptionVisitor)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TwirpCacheScope {
    pub scope: String,
    #[serde(deserialize_with = "deserialize_i64_from_string_or_number")]
    pub permission: i64,
}

impl From<cache::CacheScope> for TwirpCacheScope {
    fn from(value: cache::CacheScope) -> Self {
        Self {
            scope: value.scope,
            permission: value.permission,
        }
    }
}

impl From<TwirpCacheScope> for cache::CacheScope {
    fn from(value: TwirpCacheScope) -> Self {
        Self {
            scope: value.scope,
            permission: value.permission,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TwirpCacheMetadata {
    #[serde(
        default,
        deserialize_with = "deserialize_option_i64_from_string_or_number"
    )]
    pub repository_id: Option<i64>,
    #[serde(default)]
    pub scope: Vec<TwirpCacheScope>,
}

impl From<cache::CacheMetadata> for TwirpCacheMetadata {
    fn from(value: cache::CacheMetadata) -> Self {
        let repository_id = if value.repository_id == 0 {
            None
        } else {
            Some(value.repository_id)
        };
        Self {
            repository_id,
            scope: value.scope.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<TwirpCacheMetadata> for cache::CacheMetadata {
    fn from(value: TwirpCacheMetadata) -> Self {
        Self {
            repository_id: value.repository_id.unwrap_or_default(),
            scope: value.scope.into_iter().map(Into::into).collect(),
        }
    }
}

// TWIRP messages
#[derive(Clone, Debug, Deserialize)]
pub struct TwirpCreateReq {
    #[expect(
        dead_code,
        reason = "Field required by the Twirp schema even when currently unused by the server"
    )]
    #[allow(unfulfilled_lint_expectations)]
    #[serde(default)]
    metadata: Option<TwirpCacheMetadata>,
    pub key: String,
    pub version: String,
}

impl TryFrom<cache::CreateCacheEntryRequest> for TwirpCreateReq {
    type Error = ApiError;

    fn try_from(value: cache::CreateCacheEntryRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            metadata: value.metadata.map(Into::into),
            key: value.key,
            version: value.version,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TwirpCreateResp {
    pub ok: bool,
    pub signed_upload_url: String,
}

impl From<TwirpCreateResp> for cache::CreateCacheEntryResponse {
    fn from(value: TwirpCreateResp) -> Self {
        Self {
            ok: value.ok,
            signed_upload_url: value.signed_upload_url,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TwirpFinalizeReq {
    #[expect(
        dead_code,
        reason = "Field required by the Twirp schema even when currently unused by the server"
    )]
    #[serde(default)]
    metadata: Option<TwirpCacheMetadata>,
    pub key: String,
    #[expect(
        dead_code,
        reason = "Field required by the Twirp schema even when currently unused by the server"
    )]
    #[allow(unfulfilled_lint_expectations)]
    #[serde(
        default,
        deserialize_with = "deserialize_option_i64_from_string_or_number"
    )]
    size_bytes: Option<i64>,
    pub version: String,
}

impl TryFrom<cache::FinalizeCacheEntryUploadRequest> for TwirpFinalizeReq {
    type Error = ApiError;

    fn try_from(value: cache::FinalizeCacheEntryUploadRequest) -> Result<Self, Self::Error> {
        let size_bytes = if value.size_bytes == 0 {
            None
        } else {
            Some(value.size_bytes)
        };
        Ok(Self {
            metadata: value.metadata.map(Into::into),
            key: value.key,
            size_bytes,
            version: value.version,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TwirpFinalizeResp {
    pub ok: bool,
    pub entry_id: i64,
}

pub(crate) fn uuid_to_i64(uuid: Uuid) -> i64 {
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&uuid.into_bytes()[0..8]);
    i64::from_be_bytes(buf)
}

impl From<TwirpFinalizeResp> for cache::FinalizeCacheEntryUploadResponse {
    fn from(value: TwirpFinalizeResp) -> Self {
        Self {
            ok: value.ok,
            entry_id: value.entry_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TwirpGetUrlReq {
    #[expect(
        dead_code,
        reason = "Field required by the Twirp schema even when currently unused by the server"
    )]
    #[allow(unfulfilled_lint_expectations)]
    #[serde(default)]
    metadata: Option<TwirpCacheMetadata>,
    pub key: String,
    #[serde(default)]
    pub restore_keys: Vec<String>,
    pub version: String,
}

impl TwirpGetUrlReq {
    #[expect(dead_code, reason = "Helper only used in integration tests")]
    #[allow(unfulfilled_lint_expectations)]
    pub(crate) fn for_tests(key: String, version: String) -> Self {
        Self {
            metadata: None,
            key,
            restore_keys: Vec::new(),
            version,
        }
    }
}

impl TryFrom<cache::GetCacheEntryDownloadUrlRequest> for TwirpGetUrlReq {
    type Error = ApiError;

    fn try_from(value: cache::GetCacheEntryDownloadUrlRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            metadata: value.metadata.map(Into::into),
            key: value.key,
            restore_keys: value.restore_keys,
            version: value.version,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TwirpGetUrlResp {
    pub ok: bool,
    pub signed_download_url: String,
    pub matched_key: String,
}

impl From<TwirpGetUrlResp> for cache::GetCacheEntryDownloadUrlResponse {
    fn from(value: TwirpGetUrlResp) -> Self {
        Self {
            ok: value.ok,
            signed_download_url: value.signed_download_url,
            matched_key: value.matched_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_conversion_is_stable() {
        let uuid = Uuid::parse_str("8c7bfc6b-3b8e-4f71-80c2-19ecc2dc2d1f").unwrap();
        let numeric = uuid_to_i64(uuid);
        assert_ne!(numeric, 0);
    }

    #[test]
    fn twirp_cache_scope_accepts_numeric_string_permission() {
        let json = r#"{"scope":"repo","permission":"42"}"#;
        let scope: TwirpCacheScope = serde_json::from_str(json).expect("deserialize scope");
        assert_eq!(scope.permission, 42);
    }

    #[test]
    fn metadata_accepts_string_repository_id() {
        let json = r#"{"repository_id":"123","scope":[]}"#;
        let metadata: TwirpCacheMetadata =
            serde_json::from_str(json).expect("deserialize metadata");
        assert_eq!(metadata.repository_id, Some(123));
    }

    #[test]
    fn finalize_request_accepts_string_size_bytes() {
        let json = r#"{"metadata":null,"key":"key","size_bytes":"2048","version":"v1"}"#;
        let req: TwirpFinalizeReq = serde_json::from_str(json).expect("deserialize finalize");
        assert_eq!(req.size_bytes, Some(2048));
    }
}
