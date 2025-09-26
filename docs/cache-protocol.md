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
{ "ok": true, "entry_id": "uuid" }
```

The lookup is performed against the key/version pair and succeeds when the cache
entry exists and has an associated upload session. When the lookup fails the
server returns `ok: false` with an empty identifier.

## Database schema

Cache versions are persisted in the `cache_entries.cache_version` column. All
lookups now filter on both `cache_key` and `cache_version`, and an index on that
pair keeps queries efficient.
