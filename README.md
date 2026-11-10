# OIDC-Drop

A small upload server for artifacts published by GitHub Actions. It verifies
GitHub OIDC tokens, checks the allowed owner, repository, branch and artifact
variant, then streams files to disk and verifies their SHA-256.

A separate web server such as Caddy serves the finished downloads.

## Docker setup

You need Docker with Compose, a checkout of this repository, and a published
image accessible from the deployment host.

1. Copy the example configuration:

   ```sh
   cp .env.example .env
   ```

2. Edit `.env` with your GitHub IDs, repository, branch and variants. The example
   IDs are placeholders. With GitHub CLI, find your real IDs using:

   ```sh
   gh api repos/YOUR_OWNER/YOUR_REPO --jq '{owner_id: .owner.id, repository_id: .id}'
   ```

   For example, `ASSET_PREFIXES=987654321=myapp` maps repository `987654321`
   to the file prefix `myapp`. A `main` branch upload with variant `linux-amd64`
   becomes `myapp-main-linux-amd64`, with a matching `.sha256` file.
   Commas separate multiple prefixes, subjects or variants.

3. Create the storage directories and make them writable by the container user:

   ```sh
   mkdir -p data uploads
   ```

   The image runs as UID/GID `65532:65532` by default. For rootless Docker,
   uncomment `user: "0:0"` in `docker-compose.yml` to use the host daemon user's
   permissions for these bind mounts. For rootful Docker, keep the nonroot
   default and grant UID 65532 write access to both directories.

4. Validate and start:

   ```sh
   docker compose config --quiet
   docker compose pull
   docker compose up -d
   curl -i http://127.0.0.1:8080/healthz
   ```

   The health endpoint returns `204 No Content`. View logs with
   `docker compose logs -f oidc-drop`. To update to the latest published image,
   run `docker compose pull` followed by `docker compose up -d` again.

Compose reads `.env` automatically. It requires all four variables in the
example. The audience (`oidc-drop`), listen address and upload limit are set
in `docker-compose.yml`; edit that file to change them. Adding those settings
to `.env` alone does not override the literal Compose values.

The current port mapping publishes port 8080 on all host interfaces. When using
a reverse proxy on the same host, change it to `127.0.0.1:8080:8080`.

## Storage and downloads

- `./data` holds published files and their `.sha256` sidecars.
- `./uploads` holds unfinished chunks. Its persistent mount preserves chunks
  across container restarts. Keep it outside the public download directory.

Run one server instance per storage directory. Upload writes are serialized.
Allow space for staged chunks, the assembled file and the previous published
file. Other staging directories older than 24 hours are removed when a chunk
arrives; the current upload is kept.

For Caddy running on the host, use a configuration like this. Replace the domain
and absolute path with your own:

```caddyfile
downloads.example.com {
    handle /upload/* {
        request_body {
            max_size 300MB
        }
        reverse_proxy 127.0.0.1:8080
    }

    handle {
        root * /absolute/path/to/oidc-drop/data
        file_server {
            hide .* *.incoming
        }
    }
}
```

`handle` preserves the upload path. The hidden files are temporary files used
while publishing. If Caddy also runs in Docker, connect it to the same network,
proxy to `oidc-drop:8080`, and mount `./data` read-only into Caddy instead.

## Uploading from GitHub Actions

The publishing job needs `id-token: write` to request a GitHub OIDC token.
Request it with audience `oidc-drop` (or your configured `OIDC_AUDIENCE`), then
send it as `Authorization: Bearer <token>` over HTTPS.

Each request, including retries and completion, needs a fresh token. A token ID
can only be used once. `ALLOWED_SUBS` must match the token's exact subject, for
example `repo:YOUR_OWNER/YOUR_REPO:ref:refs/heads/main`. This server requires
branch subjects; tags, pull requests and environment subjects are not supported.
Branch names used in file names may contain only ASCII letters, digits, `.`, `_`
and `-`, and must not start with `.`.

For a single request, send `PUT /upload/{variant}` with the file as the body and
`X-Content-SHA256` containing its hex SHA-256. Success returns `204 No Content`.

For larger files, use 64 MiB chunks:

1. Send each chunk with `PUT /upload/{variant}/chunks/{index}`, starting at index
   zero. Include `Authorization`, `X-Content-SHA256` (the complete file digest),
   `X-Upload-Size` (the complete file size in bytes), and `X-Chunk-SHA256`.
2. Finish with `PUT /upload/{variant}/complete`, an empty body, and the same
   complete file digest and size headers, plus a fresh bearer token.

All chunks must be exactly 64 MiB except the final one. Successful requests
return 204. Retrying a chunk replaces it; retrying completion verifies the
already published file. The server assembles chunks in order inside `DATA_DIR`,
verifies the complete digest, then replaces the published file by atomic rename.
The checksum sidecar is published separately.

The default maximum **complete file size** is 256 MiB, including chunked uploads.
Increase `MAX_UPLOAD_BYTES` in Compose if needed. Any proxy must also allow each
individual request body.

## Building the Docker image on GitHub

`.github/workflows/docker.yml` builds AMD64 and ARM64 images on pushes to `main`
and publishes `ghcr.io/<owner>/<repository>:main` and `:latest` (lowercase).
It uses GitHub-hosted runners and the automatic `GITHUB_TOKEN`; no custom secret
is required. GitHub Actions must be enabled and allowed to publish packages.

Compose uses `ghcr.io/engo150/oidc-drop:latest` by default (adjust for forks).
To download the latest image and start or update the service, run:

```sh
docker compose pull
docker compose up -d
```

The image must already be published and accessible to the deployment host.
Private packages require registry authentication.

To build locally instead, replace `image: ghcr.io/engo150/oidc-drop:latest` with
`build: .` and run `docker compose up -d --build`.

## Running without Docker

Set these environment variables before running `cargo run --release --locked`:

| Variable | Meaning |
| --- | --- |
| `LISTEN_ADDR` | Bind address, such as `127.0.0.1:8080` |
| `DATA_DIR` | Writable directory for published files |
| `UPLOAD_DIR` | Writable directory for unfinished chunks |
| `OIDC_AUDIENCE` | Expected token audience, such as `oidc-drop` |
| `REPOSITORY_OWNER_ID` | Allowed numeric GitHub owner ID |
| `ASSET_PREFIXES` | Comma-separated `repository_id=prefix` pairs |
| `ALLOWED_SUBS` | Comma-separated exact branch subjects |
| `ALLOWED_VARIANTS` | Comma-separated artifact variants |
| `MAX_UPLOAD_BYTES` | Optional complete file limit; defaults to 268435456 bytes |

The Rust binary does not load `.env` automatically. Export the values in your
shell or provide them through your service manager. Use a current stable Rust
toolchain to build the project.

## Build checks

```sh
cargo check --all-targets --locked
cargo test --locked
```
