# Container image

The project ships a container image published on GitHub Container Registry
(`ghcr.io/n-cloud-labs/gha-cache-server`). The image is based on minideb and
includes the compiled `gha-cache-server` binary together with the SQL migration
files required at runtime.

## Runtime configuration

Environment variables are used to configure the server. The Dockerfile sets
sensible defaults to help local development:

- `PORT` (default `8080`) – HTTP listening port exposed by the container.
- `RUST_LOG` – tracing filter used by the application.
- `MAX_CONCURRENCY` – maximum number of concurrent API requests.
- `REQUEST_TIMEOUT_SECS` – request timeout applied by the tower middleware.
- `ENABLE_DIRECT_DOWNLOADS` – toggle direct download URLs when supported by the
  blob backend.
- `DEFER_FINALIZE_IN_BACKGROUND` – controls whether upload finalization runs in
  the background. Set to `false` to finalize uploads synchronously.
- `BLOB_STORE` – selects the blob storage backend (`fs`, `s3` or `gcs`).
- `FS_ROOT` – storage path used by the filesystem backend. A persistent volume is
  declared for `/var/lib/gha-cache-server` so that `BLOB_STORE=fs` survives
  container restarts.
- `FS_UPLOAD_ROOT` – optional staging directory for multipart uploads. Mount an
  additional volume when the staging area should live on persistent storage.
- `DATABASE_URL` – connection string for the SQL database. The default assumes a
  Postgres server named `postgres` inside the same Docker Compose project.

Override these values with your own configuration when running the container.

## Docker Compose example

The repository includes a `compose.yaml` file that wires the application with
Postgres and MinIO (S3-compatible) services:

```sh
docker compose up --build
```

The stack exposes the following services on the host machine:

- `gha-cache-server` on port `8080` (HTTP API).
- `postgres` on port `5432` (PostgreSQL).
- `minio` on ports `9000` (S3 endpoint) and `9001` (console UI).

When switching to the filesystem backend (`BLOB_STORE=fs`), mount a persistent
volume on `/var/lib/gha-cache-server` to retain cache artifacts:

```yaml
services:
  gha-cache-server:
    image: ghcr.io/n-cloud-labs/gha-cache-server:latest
    environment:
      BLOB_STORE: fs
      FS_ROOT: /var/lib/gha-cache-server
      FS_UPLOAD_ROOT: /var/lib/gha-cache-uploads
    volumes:
      - gha-cache-data:/var/lib/gha-cache-server
      - gha-cache-uploads:/var/lib/gha-cache-uploads

volumes:
  gha-cache-data:
  gha-cache-uploads:
```
