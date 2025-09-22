use serde::{Deserialize, Serialize};

// TWIRP messages
#[derive(Deserialize)]
pub struct TwirpCreateReq {
    pub key: String,
    pub version: String,
}
#[derive(Serialize)]
pub struct TwirpCreateResp {
    pub cache_id: String,
}

#[derive(Deserialize)]
pub struct TwirpFinalizeReq {
    pub cache_id: String,
    pub size_bytes: i64,
}
#[derive(Serialize)]
pub struct TwirpFinalizeResp {
    pub ok: bool,
}

#[derive(Deserialize)]
pub struct TwirpGetUrlReq {
    pub cache_id: String,
}
#[derive(Serialize)]
pub struct TwirpGetUrlResp {
    pub archive_location: String,
}
