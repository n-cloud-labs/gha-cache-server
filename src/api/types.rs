use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::proto::cache;
use crate::error::ApiError;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TwirpCacheScope {
    pub scope: String,
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
    #[serde(default)]
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
    #[allow(dead_code)]
    #[serde(default)]
    pub metadata: Option<TwirpCacheMetadata>,
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
    #[allow(dead_code)]
    #[serde(default)]
    pub metadata: Option<TwirpCacheMetadata>,
    pub key: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub size_bytes: Option<i64>,
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
    pub entry_id: String,
}

fn uuid_to_i64(value: &str) -> i64 {
    Uuid::parse_str(value)
        .map(|uuid| {
            let bytes = uuid.into_bytes();
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(&bytes[0..8]);
            i64::from_be_bytes(buf)
        })
        .unwrap_or_default()
}

impl From<TwirpFinalizeResp> for cache::FinalizeCacheEntryUploadResponse {
    fn from(value: TwirpFinalizeResp) -> Self {
        let entry_id = match value.entry_id.parse::<i64>() {
            Ok(id) => id,
            Err(_) => uuid_to_i64(&value.entry_id),
        };
        Self {
            ok: value.ok,
            entry_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TwirpGetUrlReq {
    #[allow(dead_code)]
    #[serde(default)]
    pub metadata: Option<TwirpCacheMetadata>,
    pub key: String,
    #[serde(default)]
    pub restore_keys: Vec<String>,
    pub version: String,
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
        let numeric = uuid_to_i64(&uuid.to_string());
        assert_ne!(numeric, 0);
    }
}
