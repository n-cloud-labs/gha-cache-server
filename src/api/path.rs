use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub fn encode_path_segment(value: &str) -> String {
    percent_encode(value.as_bytes(), PATH_SEGMENT_ENCODE_SET).to_string()
}
