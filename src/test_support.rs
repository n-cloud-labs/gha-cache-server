use crate::api::proto::cache;
use crate::api::twirp::TwirpRequest;
use crate::api::types::TwirpGetUrlReq;

pub fn twirp_get_url_request(
    key: String,
    version: String,
) -> TwirpRequest<TwirpGetUrlReq, cache::GetCacheEntryDownloadUrlRequest> {
    TwirpRequest::from_json(TwirpGetUrlReq::for_tests(key, version))
}
