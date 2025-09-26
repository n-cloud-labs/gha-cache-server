use serde::{Deserialize, Serialize};

// TWIRP messages
#[derive(Deserialize)]
pub struct TwirpCreateReq {
    pub key: String,
    pub version: String,
}
#[derive(Serialize)]
pub struct TwirpCreateResp {
    pub ok: bool,
    pub signed_upload_url: String,
}

#[derive(Deserialize)]
pub struct TwirpFinalizeReq {
    pub key: String,
    pub version: String,
}
#[derive(Serialize)]
pub struct TwirpFinalizeResp {
    pub ok: bool,
    pub entry_id: String,
}

#[derive(Deserialize)]
pub struct TwirpGetUrlReq {
    pub key: String,
    #[serde(default)]
    pub restore_keys: Vec<String>,
    pub version: String,
}
#[derive(Serialize)]
pub struct TwirpGetUrlResp {
    pub ok: bool,
    pub signed_download_url: String,
    pub matched_key: String,
}
