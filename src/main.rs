use std::
{
    fs,
    sync::Arc,
    net::SocketAddr,
    collections::{ HashMap, HashSet },
    time::{ Duration, Instant },
    path::
    {
        PathBuf,
        Path as FsPath,
    },
};

use axum::
{
    Router,
    body::Body,
    extract::{ Path, State },
    http::{ HeaderMap, StatusCode },
    routing,
};

use futures_util::stream::StreamExt;

use jsonwebtoken::
{
    jwk,
    DecodingKey,
    Validation,
};

use serde::Deserialize;
use sha2::{ Digest, Sha256 };

use tokio::
{
    fs as afs,
    io::AsyncWriteExt,
    sync::Mutex,
};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const JWKS_MIN_REFRESH: Duration = Duration::from_secs(300);
const JTI_TTL: Duration = Duration::from_secs(30 * 60);

struct Config
{
    listen: SocketAddr,
    data_dir: PathBuf,
    audience: String,
    repository_owner_id: String,
    prefixes: HashMap<String, String>,
    allowed_subs: HashSet<String>,
    allowed_variants: HashSet<String>,
    max_bytes: u64,
}

struct Keys
{
    keys: HashMap<String, DecodingKey>,
    fetched: Option<Instant>,
}

struct App
{
    config: Config,
    http: reqwest::Client,
    keys: Mutex<Keys>,
    seen_jti: Mutex<HashMap<String, Instant>>,
}

#[derive(Deserialize)]
struct Claims
{
    sub: String,
    jti: String,
    repository_id: String,
    repository_owner_id: String,
}

type Fail = (StatusCode, &'static str);

fn env_var(name: &str) -> String
{
    std::env::var(name).unwrap_or_else(|_| panic!("missing environment variable {name}"))
}

fn env_set(name: &str) -> HashSet<String>
{
    env_var(name)
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn env_map(name: &str) -> HashMap<String, String>
{
    env_var(name)
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|pair|
        {
            let (id, prefix) = pair
                .split_once('=')
                .unwrap_or_else(|| panic!("{name} entry {pair:?} is not id=prefix"));

            (id.trim().to_owned(), prefix.trim().to_owned())
        })
        .collect()
}

impl App
{
    async fn key_for(&self, kid: &str) -> Result<DecodingKey, Fail>
    {
        let mut keys = self.keys.lock().await;

        if let Some(key) = keys.keys.get(kid)
        {
            return Ok(key.clone());
        }

        let stale = keys
            .fetched
            .is_none_or(|at| at.elapsed() >= JWKS_MIN_REFRESH);

        if !stale
        {
            return Err((StatusCode::UNAUTHORIZED, "unknown key id"));
        }

        let set: jwk::JwkSet = self
            .http
            .get(JWKS_URL)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|_| (StatusCode::BAD_GATEWAY, "cannot reach the issuer"))?
            .json()
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "malformed key set"))?;

        keys.fetched = Some(Instant::now());
        keys.keys = set
            .keys
            .iter()
            .filter_map(|k|
            {
                let id = k.common.key_id.clone()?;
                Some((id, DecodingKey::from_jwk(k).ok()?))
            })
            .collect();

        keys.keys
            .get(kid)
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "unknown key id"))
    }

    async fn claim_jti(&self, jti: &str) -> Result<(), Fail>
    {
        let mut seen = self.seen_jti.lock().await;

        seen.retain(|_, at| at.elapsed() < JTI_TTL);

        if seen.insert(jti.to_owned(), Instant::now()).is_some()
        {
            return Err((StatusCode::UNAUTHORIZED, "token already used"));
        }

        Ok(())
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<(String, String), Fail>
    {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;

        let header = jsonwebtoken::decode_header(token).map_err(|_| (StatusCode::UNAUTHORIZED, "bad token"))?;
        let kid = header
            .kid
            .ok_or((StatusCode::UNAUTHORIZED, "token has no key id"))?;
        let key = self.key_for(&kid).await?;

        // Algorithm, audience, issuer and expiry are all checked here; anything
        // left to the body below is a claim jsonwebtoken does not know about.
        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![jsonwebtoken::Algorithm::RS256];
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[ISSUER]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        validation.leeway = 30;

        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "token rejected"))?
            .claims;

        // The numeric ids are the identity that survives a rename: `repository`
        // is a name somebody else could claim if a repo were ever deleted.
        if claims.repository_owner_id != self.config.repository_owner_id
        {
            return Err((StatusCode::FORBIDDEN, "wrong owner"));
        }

        // Which project this is, and therefore what its files are called, is the
        // token's to say and never the request's.
        let prefix = self
            .config
            .prefixes
            .get(&claims.repository_id)
            .cloned()
            .ok_or((StatusCode::FORBIDDEN, "wrong repository"))?;

        // Pins the workflow to an exact branch: a run on any other ref, on a
        // pull request or in a fork carries a different `sub`.
        if !self.config.allowed_subs.contains(&claims.sub)
        {
            return Err((StatusCode::FORBIDDEN, "subject not allowed"));
        }

        self.claim_jti(&claims.jti).await?;

        let branch = claims
            .sub
            .split_once(":ref:refs/heads/")
            .map(|(_, b)| b.to_owned())
            .ok_or((StatusCode::FORBIDDEN, "subject carries no branch"))?;

        // A branch reaches a filename, so it may only be the characters a
        // filename should hold — no separators, no leading dot.
        if branch.is_empty()
            || branch.starts_with('.')
            || !branch.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            return Err((StatusCode::FORBIDDEN, "unusable branch name"));
        }

        Ok((prefix, branch))
    }
}

async fn upload
(
    State(app): State<Arc<App>>,
    Path(variant): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, Fail>
{
    let (prefix, branch) = app.authenticate(&headers).await?;

    // The destination is never built out of caller-supplied text: the variant
    // comes from a fixed list and the branch from the verified token, so there
    // is no path to traverse out of.
    if !app.config.allowed_variants.contains(&variant)
    {
        return Err((StatusCode::BAD_REQUEST, "unknown variant"));
    }

    let asset = format!("{prefix}-{branch}-{variant}");

    let declared = headers
        .get("x-content-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing X-Content-SHA256"))?
        .to_ascii_lowercase();

    let dir = app.config.data_dir.clone();

    afs::create_dir_all(&dir)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "cannot open the data directory"))?;

    // The body goes to disk as it arrives and is never held whole: a desktop
    // bundle is hundreds of megabytes and the container is capped far below that.
    let temp_path = dir.join(format!(".{asset}.incoming"));
    let received = receive(&temp_path, body, app.config.max_bytes).await;

    let (size, actual) = match received
    {
        Ok(v) => v,
        Err(err) =>
        {
            let _ = afs::remove_file(&temp_path).await;
            return Err(err);
        }
    };

    if declared != actual
    {
        let _ = afs::remove_file(&temp_path).await;
        return Err((StatusCode::BAD_REQUEST, "digest mismatch"));
    }

    let name = asset.clone();
    let digest = actual.clone();

    tokio::task::spawn_blocking(move || publish_atomically(&dir, &name, &digest))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write task failed"))?
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;

    println!("published {asset} ({size} bytes, {actual})");

    Ok(StatusCode::NO_CONTENT)
}

async fn receive(path: &FsPath, body: Body, max_bytes: u64) -> Result<(u64, String), Fail>
{
    let mut file = afs::File::create(path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "cannot open the temporary file"))?;

    let mut stream = body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;

    while let Some(chunk) = stream.next().await
    {
        let chunk = chunk.map_err(|_| (StatusCode::BAD_REQUEST, "upload interrupted"))?;

        size += chunk.len() as u64;

        if size > max_bytes
        {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "upload too large"));
        }

        hasher.update(&chunk);

        file.write_all(&chunk)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;
    }

    file.sync_all()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "sync failed"))?;

    Ok((size, hex::encode(hasher.finalize())))
}

fn publish_atomically(dir: &FsPath, name: &str, digest: &str) -> std::io::Result<()>
{
    let final_path = dir.join(name);
    let temp_path = dir.join(format!(".{name}.incoming"));

    fs::rename(&temp_path, &final_path)?;

    // Publish the digest beside the binary so downloads can be checked.
    let sums_path = dir.join(format!("{name}.sha256"));
    let temp_sums = dir.join(format!(".{name}.sha256.incoming"));

    fs::write(&temp_sums, format!("{digest}  {name}\n"))?;
    fs::rename(&temp_sums, &sums_path)?;

    // Durability of the directory entries themselves.
    fs::File::open(dir)?.sync_all()
}

async fn healthz() -> StatusCode
{
    StatusCode::NO_CONTENT
}

#[tokio::main]
async fn main()
{
    let config = Config
    {
        listen: env_var("LISTEN_ADDR").parse().expect("LISTEN_ADDR is not an address"),
        data_dir: PathBuf::from(env_var("DATA_DIR")),
        audience: env_var("OIDC_AUDIENCE"),
        repository_owner_id: env_var("REPOSITORY_OWNER_ID"),
        prefixes: env_map("ASSET_PREFIXES"),
        allowed_subs: env_set("ALLOWED_SUBS"),
        allowed_variants: env_set("ALLOWED_VARIANTS"),
        max_bytes: std::env::var("MAX_UPLOAD_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256 * 1024 * 1024),
    };

    let listen = config.listen;

    let app = Arc::new(App
    {
        config,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("cannot build an HTTP client"),
        keys: Mutex::new(Keys { keys: HashMap::new(), fetched: None }),
        seen_jti: Mutex::new(HashMap::new()),
    });

    let router = Router::new()
        .route("/upload/{variant}", routing::put(upload))
        .route("/healthz", routing::get(healthz))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .expect("cannot bind the listener");

    println!("listening on {listen}");

    axum::serve(listener, router).with_graceful_shutdown(async
    {
        let _ = tokio::signal::ctrl_c().await;
    }).await.expect("server failed");
}
