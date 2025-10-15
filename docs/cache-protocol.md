# Cache service protocol

This server implements the subset of the GitHub Actions cache service that is
required by the official runner. The behaviour is intentionally close to the
hosted service, but a few details (such as direct upload destinations) are
specific to this project.

## REST API

### `GET /_apis/artifactcache/cache`

Query parameters:

- `keys` &mdash; comma separated list that starts with the primary key and can be
  followed by restore keys.
- `version` &mdash; required version fingerprint.

The server evaluates each key in order and returns the first cache entry that
matches both the key and the version. A successful lookup yields `200 OK` and a
payload with the following fields:

- `cacheKey` &mdash; the matched key.
- `scope` &mdash; scope recorded with the cache entry (currently `_`).
- `creationTime` &mdash; ISO timestamp of the cache creation time.
- `archiveLocation` &mdash; direct download URL when direct downloads are enabled,
  otherwise an empty string.

If none of the keys matches, the response is `204 No Content`.

### `POST /_apis/artifactcache/caches`

Body:

```json
{ "key": "primary", "version": "v1" }
```

The server validates the key and version, reserves metadata for a new cache
entry, and returns the generated identifier:

```json
{ "cacheId": "uuid" }
```

The version string is now stored in the cache metadata and participates in
lookups.

## TWIRP API

The runner uses a TWIRP transport when the GitHub cache service proxy is in
front of this server. The following endpoints are available under the
`/twirp/github.actions.results.api.v1.CacheService` prefix.

### `CreateCacheEntry`

Request:

```json
{ "key": "primary", "version": "v1" }
```

Response:

```json
{ "ok": true, "signed_upload_url": "/upload/<cache-id>" }
```

The returned URL is local to the server and can be used to upload the cache via
`PUT`.

### `GetCacheEntryDownloadURL`

Request:

```json
{
  "key": "primary",
  "restore_keys": ["restore"],
  "version": "v1"
}
```

Response on success:

```json
{
  "ok": true,
  "signed_download_url": "https://<host>/download/<cache-key>/<cache-id>.tgz",
  "matched_key": "primary"
}
```

When direct downloads are enabled and the backing blob store can issue
presigned URLs, the `signed_download_url` field instead contains the direct
link to the object.

The handler evaluates `key` followed by the optional `restore_keys` array until
it finds a cache entry with the matching version. When nothing matches the
response is `ok: false` with empty strings.

### `CreateCacheEntry` -> upload -> `FinalizeCacheEntryUpload`

After uploading all data to the provided URL, the runner completes the multipart
upload by calling:

```json
{ "key": "primary", "version": "v1" }
```

Response:

```json
{ "ok": true, "entry_id": 123456789 }
```

The lookup is performed against the key/version pair and succeeds when the cache
entry exists and has an associated upload session. When the lookup fails the
server returns `ok: false` with a zero identifier. A successful response now
indicates that the finalization job was enqueued. Clients can poll by issuing
additional finalize requests while the background job runs; the server
short-circuits those calls without re-queuing work.

The REST `POST /_apis/artifactcache/caches/{id}` endpoint mirrors this
behaviour. It immediately returns `201 Created` with an empty body once the
finalize job is queued. Callers can retry the commit request to observe when the
background job finishes; additional attempts acknowledge the in-flight job with
the same status code without starting duplicate work.

## Upload state machine

The cache metadata keeps track of the multipart upload lifecycle inside the
`cache_uploads.state` column. API handlers use optimistic transitions to gate
concurrent operations through `transition_upload_state`, and the active part
counter plus the `pending_finalize` flag complement the state machine when the
commit endpoint waits for in-flight parts to finish. Finalization now happens in
an asynchronous job that clears the `pending_finalize` flag on completion and
updates the cache entry size when an explicit value is provided.【F:src/meta/mod.rs†L136-L200】【F:src/api/upload.rs†L333-L470】【F:src/jobs/finalize.rs†L13-L138】

### States

- `reserved` &mdash; created alongside the cache entry metadata before any data is
  sent.【F:src/api/upload.rs†L321-L340】
- `uploading` &mdash; at least one client is streaming a part. Additional clients can
  attach while the session remains active, and the upload stays in this state
  until the commit endpoint finalizes the session.【F:src/api/upload.rs†L333-L470】【F:src/meta/mod.rs†L153-L230】
- `ready` &mdash; transitional idle state retained for compatibility before any
  streaming starts. Once an upload enters `uploading` it remains there until it
  is finalized or reset administratively.【F:src/api/upload.rs†L333-L470】
- `finalizing` &mdash; the commit endpoint reserved the upload and is validating the
  recorded parts before completing the multipart upload in the blob store. The
  asynchronous job enters this state once no active parts remain.【F:src/jobs/finalize.rs†L36-L111】
- `completed` &mdash; the backing store acknowledged the multipart completion and no
  more writes are accepted.【F:src/api/upload.rs†L665-L687】

### Transitions

| From         | To          | Trigger |
|--------------|-------------|---------|
| `reserved`   | `uploading` | First part upload request reserves the session. |
| `ready`      | `uploading` | Additional part uploads before streaming begins. |
| `reserved`   | `finalizing`| Commit request when no parts ever streamed. |
| `ready`      | `finalizing`| Commit request when the session never left idle. |
| `uploading`  | `finalizing`| Commit request after all active parts finished. |
| `finalizing` | `uploading` | Finalization failed validation or blob completion and the session reopens for uploads. |
| `finalizing` | `completed` | Blob store multipart completion succeeded. |

Calls to upload additional parts are rejected once the session is flagged for
finalization or has entered the `finalizing` or `completed` states. Otherwise,
uploads already in the `uploading` state remain eligible to stream new parts in
parallel until the commit endpoint runs.【F:src/api/upload.rs†L333-L470】【F:src/api/upload.rs†L600-L687】

## Database schema

Cache versions are persisted in the `cache_entries.cache_version` column. All
lookups now filter on both `cache_key` and `cache_version`, and an index on that
pair keeps queries efficient.
