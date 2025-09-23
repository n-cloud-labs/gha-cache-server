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
* `gcs` – store cache archives in Google Cloud Storage. This mode requires a
  dedicated bucket and service account credentials (see below).

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

## Google Cloud Storage settings

When `BLOB_STORE=gcs`, configure the following environment variables:

* `GCS_BUCKET` – name of the bucket that should receive cache archives.
* Authentication credentials. Provide either:
  * `GCS_SERVICE_ACCOUNT_JSON` – inline JSON for a service account key.
  * `GCS_SERVICE_ACCOUNT_PATH` – path to a file containing the service account
    key JSON.
* `GCS_ENDPOINT` – optional custom endpoint (for example an emulator). When
  omitted the client uses `https://storage.googleapis.com`.

The GCS backend composes multipart uploads from temporary objects inside the
target bucket and automatically issues V4-signed download URLs when direct
downloads are enabled.

## Cleanup settings

The server periodically scans stored cache entries and deletes expired data. The
following environment variables control this background job:

* `CLEANUP_INTERVAL_SECS` – frequency of the cleanup loop in seconds. Defaults
  to `300`. Values lower than `1` are coerced to `1` to avoid busy looping.
* `CACHE_ENTRY_MAX_AGE_SECS` – optional override for the maximum age of a cache
  entry. When set, entries are considered expired after the minimum between the
  stored TTL and this value, regardless of the default TTL configured in the
  database.
* `CACHE_STORAGE_MAX_BYTES` – optional soft limit for the total size (in bytes)
  of all cache entries. When the limit is exceeded, the cleanup loop removes the
  least recently accessed entries until usage drops below the threshold.
