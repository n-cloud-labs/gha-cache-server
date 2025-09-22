# Configuration

## Blob storage backend

The server supports pluggable blob storage. Select the implementation via the
`BLOB_STORE` environment variable:

* `s3` *(default)* – store cache archives in an S3-compatible bucket. When this
  mode is active the following variables must be provided:
  * `S3_BUCKET`
  * `AWS_REGION` (defaults to `us-east-1`)
  * `AWS_ENDPOINT_URL` (optional)
  * `S3_FORCE_PATH_STYLE` (defaults to `true`)
* `fs` – persist cache archives on the local filesystem. This mode requires a
  dedicated root directory and supports optional POSIX permissions.

## Filesystem store settings

When `BLOB_STORE=fs` the process reads additional options:

* `FS_ROOT` – absolute or relative path used as the storage root. Multipart
  uploads are written to a temporary directory under this root and atomically
  renamed into place when completed.
* `FS_FILE_MODE` – optional octal file permission (for example `0640` or
  `0o640`). When set, the mode is applied to uploaded artifacts.
* `FS_DIR_MODE` – optional octal directory permission. When provided it is
  applied to directories created within `FS_ROOT`.

When the filesystem backend is active, direct-download URLs are not generated;
callers should stream downloads through the HTTP API instead.
