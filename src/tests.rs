use std::
{
    fs,
    env,
    process,
    io::Error,
    task::Poll,
    collections::HashMap,
    time::{ Instant, Duration },
    sync::
    {
        Arc,
        Mutex as StdMutex,
    },
    path::
    {
        PathBuf,
        Path as FsPath,
    },
    sync::atomic::{ Ordering, AtomicU64 },
};

use tokio::
{
    net::TcpListener,
    sync::
    {
        Mutex,
        Notify,
        RwLock,
        Semaphore,
    },
};

use axum::
{
    body::{ Body, Bytes },
    extract::{ Path, State },
    http::{ HeaderMap, StatusCode },
};

use reqwest::Client;
use futures_util::stream;
use serde_json::{ json, Value };
use sha2::{ Digest, Sha256 };

use jsonwebtoken::
{
    Header,
    Algorithm,
    DecodingKey,
    EncodingKey,
};

use crate::
{
    consts,
    upload,
    chunked,
    config::Config,
    app::{ App, Keys },
    storage::{ self, Replay, Staging },
};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Temp(PathBuf);

impl Temp
{
    pub(crate) fn new() -> Self
    {
        let root = env::temp_dir().join(format!(
            "oidc-drop-tests-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    pub(crate) fn path(&self) -> &FsPath
    {
        &self.0
    }
}

impl Drop for Temp
{
    fn drop(&mut self)
    {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn config(root: &FsPath) -> Config
{
    Config
    {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: root.join("data"),
        upload_dir: root.join("uploads"),
        audience: "oidc-drop".into(),
        repository_owner_id: "1".into(),
        prefixes: HashMap::from([("2".into(), "app".into())]),
        allowed_subs: ["repo:owner/repo:ref:refs/heads/main".into()].into(),
        allowed_variants: ["linux-amd64".into(), "linux-arm64".into()].into(),
        max_bytes: 1024,
        staging_bytes: 2048,
        staging_uploads: 2,
        concurrency: 2,
        idle_timeout: Duration::from_secs(1),
        upload_timeout: Duration::from_secs(5),
        staging_ttl: Duration::from_secs(60),
        min_free_bytes: 1,
    }
}

pub(crate) fn app(root: &FsPath) -> Arc<App>
{
    let config = config(root);
    fs::create_dir_all(&config.data_dir).unwrap();

    let replay = Replay::open(config.data_dir.join(".replay")).unwrap();

    let staging = Staging::open
    (
        config.upload_dir.clone(),
        config.staging_bytes,
        config.staging_uploads,
        config.staging_ttl,
        config.max_bytes,
    ).unwrap();

    let mut keys = Keys::default();
    keys.keys.insert
    (
        "test".into(),
        DecodingKey::from_rsa_der(include_bytes!("../tests/fixtures/test-public.der")),
    );
    keys.fetched = Some(Instant::now());
    Arc::new(App
    {
        directory_locks: Arc::new(Vec::new()),
        config,
        http: Client::new(),
        keys: RwLock::new(keys),
        refresh: Mutex::new(()),
        replay: Arc::new(StdMutex::new(replay)),
        staging: Arc::new(StdMutex::new(staging)),
        slots: Arc::new(Semaphore::new(2)),
        assets: StdMutex::new(HashMap::new()),
    })
}

fn claims(jti: &str) -> Value
{
    let now = storage::now();
    json!
    (
        {
            "sub": "repo:owner/repo:ref:refs/heads/main",
            "jti": jti,
            "repository_id": "2",
            "repository_owner_id": "1",
            "aud": "oidc-drop",
            "iss": consts::ISSUER,
            "iat": now,
            "nbf": now,
            "exp": now + 300
        }
    )
}

fn headers(value: Value, data: &[u8]) -> HeaderMap
{
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test".into());

    let token = jsonwebtoken::encode
    (
        &header,
        &value,
        &EncodingKey::from_rsa_der(include_bytes!("../tests/fixtures/test-private.der")),
    ).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    headers.insert
    (
        "x-content-sha256",
        hex::encode(Sha256::digest(data)).parse().unwrap(),
    );
    headers
}

#[test]
fn reject_unsafe_and_colliding_names()
{
    let temp = Temp::new();

    let mut config = config(temp.path());
    assert!(config.validate().is_ok());
    config.prefixes.insert("2".into(), "../../outside".into());
    assert!(config.validate().is_err());
    config.prefixes.insert("2".into(), "app".into());
    config.allowed_variants.insert("../escape".into());
    assert!(config.validate().is_err());
    config.allowed_variants.remove("../escape");
    config.allowed_variants.insert("amd64".into());
    config.allowed_subs.insert("repo:owner/repo:ref:refs/heads/main-linux".into());
    assert!(config.validate().is_err());
    config.allowed_subs.remove("repo:owner/repo:ref:refs/heads/main-linux");
    config.allowed_variants.insert("linux-amd64.sha256".into());
    assert!(config.validate().is_err());
    config.allowed_variants.clear();
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn signed_token_policy_and_persistent_replay()
{
    let temp = Temp::new();

    let state = app(temp.path());

    let good = headers(claims("replay"), b"ok");
    assert!(state.authenticate(&good).await.is_ok());
    assert_eq!
    (
        state.authenticate(&good).await.unwrap_err().0,
        StatusCode::UNAUTHORIZED
    );

    let restarted = app(temp.path());
    assert_eq!
    (
        restarted.authenticate(&good).await.unwrap_err().0,
        StatusCode::UNAUTHORIZED
    );

    for (field, value) in
    [
        ("aud", json!("wrong")),
        ("iss", json!("https://attacker.invalid")),
        ("nbf", json!(storage::now() + 1000)),
        ("exp", json!(storage::now() - 100)),
        ("iat", json!(storage::now() + 1000)),
        ("exp", json!(storage::now() + 7200)),
        ("jti", json!("")),
    ]
    {
        let mut value_claims = claims(field);
        value_claims[field] = value;
        assert!
        (
            state.authenticate(&headers(value_claims, b"ok")).await.is_err(),
            "accepted {field}"
        );
    }

    for field in ["exp", "nbf", "iat", "jti"]
    {
        let mut value = claims(field);
        value.as_object_mut().unwrap().remove(field);
        assert!(state.authenticate(&headers(value, b"ok")).await.is_err());
    }

    for (field, value) in
    [
        ("repository_owner_id", "9"),
        ("repository_id", "9"),
        ("sub", "repo:owner/repo:ref:refs/heads/other"),
    ]
    {
        let mut value_claims = claims(field);
        value_claims[field] = json!(value);
        assert_eq!
        (
            state.authenticate(&headers(value_claims, b"ok")).await.unwrap_err().0,
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn bounded_concurrency_and_independent_assets()
{
    let temp = Temp::new();

    let app = app(temp.path());

    let first = app.admit().unwrap();

    let second = app.admit().unwrap();
    assert_eq!(app.admit().unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
    drop(first);
    assert!(app.admit().is_ok());
    drop(second);

    let guard = app.lock_asset("a").unwrap();
    assert_eq!(app.lock_asset("a").unwrap_err().0, StatusCode::CONFLICT);
    assert!(app.lock_asset("b").is_ok());
    drop(guard);
    assert!(app.lock_asset("a").is_ok());
}

#[tokio::test]
async fn receive_limits_integrity_and_timeouts()
{
    let temp = Temp::new();

    let path = temp.path().join("incoming");

    let idle = Duration::from_millis(10);

    let total = Duration::from_secs(5);

    let (size, hash) = upload::receive(&path, Body::from("hello"), 5, idle, total).await.unwrap();
    assert_eq!(size, 5);
    assert_eq!(hash, hex::encode(Sha256::digest(b"hello")));
    assert_eq!
    (
        upload::receive(&path, Body::from("too big"), 1, idle, total).await.unwrap_err().0,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let pending = ||
    {
        Body::from_stream(stream::pending::<
            Result<Bytes, Error>,
        >())
    };
    assert_eq!
    (
        upload::receive(&path, pending(), 5, idle, total).await.unwrap_err().0,
        StatusCode::REQUEST_TIMEOUT
    );
    assert_eq!
    (
        upload::receive(&path, pending(), 5, total, idle).await.unwrap_err().0,
        StatusCode::REQUEST_TIMEOUT
    );
    assert_eq!
    (
        upload::receive(&path, Body::empty(), 5, idle, total).await.unwrap_err().0,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn atomic_publication_and_legacy_migration()
{
    let temp = Temp::new();

    let root = temp.path();
    fs::write(root.join("asset"), b"old").unwrap();
    fs::write(root.join("asset.sha256"), b"legacy").unwrap();

    let first = hex::encode(Sha256::digest(b"first"));

    let second = hex::encode(Sha256::digest(b"second"));
    fs::write(root.join(".asset.incoming"), b"first").unwrap();
    upload::publish_atomically(root, "asset", &first).unwrap();
    assert_eq!(fs::read(root.join("asset")).unwrap(), b"first");
    assert_eq!
    (
        fs::read_to_string(root.join("asset.sha256")).unwrap(),
        format!("{first}  asset\n")
    );
    //FAIL BEFORE SWITCHING THE POINTER
    fs::write(root.join(".versions/asset").join(&second), b"blocker").unwrap();
    fs::write(root.join(".asset.incoming"), b"second").unwrap();
    assert!(upload::publish_atomically(root, "asset", &second).is_err());
    assert_eq!(fs::read(root.join("asset")).unwrap(), b"first");
    assert_eq!
    (
        fs::read_to_string(root.join("asset.sha256")).unwrap(),
        format!("{first}  asset\n")
    );
    fs::remove_file(root.join(".versions/asset").join(&second)).unwrap();
    fs::write(root.join(".asset.incoming"), b"second").unwrap();
    upload::publish_atomically(root, "asset", &second).unwrap();
    assert_eq!(fs::read(root.join("asset")).unwrap(), b"second");
    assert_eq!
    (
        fs::read_to_string(root.join("asset.sha256")).unwrap(),
        format!("{second}  asset\n")
    );
    assert!(!root.join(".versions/asset").join(first).exists());
}

#[tokio::test]
async fn staging_quotas_restart_cleanup_and_active_protection()
{
    let temp = Temp::new();

    let open = ||
    {
        Staging::open(temp.path().to_owned(), 10, 2, Duration::from_secs(60), 10).unwrap()
    };

    let staging = Arc::new(StdMutex::new(open()));

    let active = Staging::begin(staging.clone(), "one".into(), 6).await.unwrap();
    assert_eq!
    (
        Staging::begin(staging.clone(), "two".into(), 5).await.err().unwrap().0,
        StatusCode::INSUFFICIENT_STORAGE
    );
    staging.lock().unwrap().cleanup().unwrap();
    assert!(active.path.exists());
    drop(active);
    assert_eq!
    (
        Staging::begin(staging.clone(), "one".into(), 3).await.err().unwrap().0,
        StatusCode::CONFLICT
    );
    drop(staging);

    let staging = Arc::new(StdMutex::new(open()));
    assert_eq!
    (
        Staging::begin(staging.clone(), "two".into(), 5).await.err().unwrap().0,
        StatusCode::INSUFFICIENT_STORAGE
    );
    drop(staging);

    let metadata = temp.path().join("one/.session");

    let mut session: Value = serde_json::from_slice(&fs::read(&metadata).unwrap()).unwrap();
    session["touched"] = json!(storage::now() - 120);
    fs::write(metadata, serde_json::to_vec(&session).unwrap()).unwrap();

    let staging = Arc::new(StdMutex::new(open()));
    staging.lock().unwrap().cleanup().unwrap();
    assert!(!temp.path().join("one").exists());
    assert!
    (
        Staging::begin(staging, "two".into(), 5).await.is_ok()
    );
}

#[test]
fn directory_lock_and_incomplete_replay_record_fail_closed()
{
    let temp = Temp::new();

    let lock = storage::lock_directory(temp.path()).unwrap();
    assert!(storage::lock_directory(temp.path()).is_err());
    drop(lock);
    assert!(storage::lock_directory(temp.path()).is_ok());

    let root = temp.path().join("replay");

    let mut replay = Replay::open(root.clone()).unwrap();
    replay.claim("once", storage::now() + 300).unwrap();
    drop(replay);

    let path = root.join(hex::encode(Sha256::digest(b"once")));
    fs::write(path, [1u8, 2]).unwrap();

    let mut replay = Replay::open(root).unwrap();
    assert_eq!
    (
        replay.claim("once", storage::now() + 300).unwrap_err().0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn upload_and_chunk_completion_round_trip()
{
    let temp = Temp::new();

    let app = app(temp.path());

    let data = b"artifact";

    let result = upload::upload
    (
        State(app.clone()),
        Path("linux-amd64".into()),
        headers(claims("single"), data),
        Body::from(data.as_slice()),
    ).await;
    assert_eq!(result.unwrap(), StatusCode::NO_CONTENT);

    let path = app.config.data_dir.join("app-main-linux-amd64");
    assert_eq!(fs::read(&path).unwrap(), data);

    let result = upload::upload
    (
        State(app.clone()),
        Path("linux-amd64".into()),
        headers(claims("bad-digest"), b"other"),
        Body::from(data.as_slice()),
    ).await;
    assert_eq!(result.unwrap_err().0, StatusCode::BAD_REQUEST);
    assert_eq!(fs::read(path).unwrap(), data);

    let make_headers = |id|
    {
        let mut value = headers(claims(id), data);
        value.insert("x-upload-size", data.len().to_string().parse().unwrap());
        value.insert
        (
            "x-chunk-sha256",
            hex::encode(Sha256::digest(data)).parse().unwrap(),
        );
        value
    };
    assert_eq!
    (
        chunked::part
    (
            State(app.clone()),
            Path(("linux-arm64".into(), u64::MAX)),
            make_headers("bad-index"),
            Body::from(data.as_slice())
        ).await.unwrap_err().0,
        StatusCode::BAD_REQUEST
    );
    chunked::part
    (
        State(app.clone()),
        Path(("linux-arm64".into(), 0)),
        make_headers("chunk"),
        Body::from(data.as_slice()),
    ).await.unwrap();
    chunked::complete
    (
        State(app.clone()),
        Path("linux-arm64".into()),
        make_headers("complete"),
    ).await.unwrap();
    assert_eq!
    (
        fs::read(app.config.data_dir.join("app-main-linux-arm64")).unwrap(),
        data
    );
    chunked::complete
    (
        State(app.clone()),
        Path("linux-arm64".into()),
        make_headers("retry"),
    ).await.unwrap();
}

#[tokio::test]
async fn stalled_upload_does_not_block_another_artifact_and_releases_capacity()
{
    let temp = Temp::new();

    let mut app = app(temp.path());
    Arc::get_mut(&mut app).unwrap().config.idle_timeout = Duration::from_millis(200);

    let polled = Arc::new(Notify::new());

    let signal = polled.clone();

    let body = Body::from_stream(stream::poll_fn(move |_|
    {
        signal.notify_one();
        Poll::Pending::<Option<Result<Bytes, Error>>>
    }));

    let stalled_app = app.clone();

    let stalled = tokio::spawn(async move
    {
        upload::upload
        (
            State(stalled_app),
            Path("linux-amd64".into()),
            headers(claims("stalled"), b"data"),
            body,
        ).await
    });
    polled.notified().await;
    assert_eq!
    (
        upload::upload
    (
            State(app.clone()),
            Path("linux-arm64".into()),
            headers(claims("parallel"), b"ok"),
            Body::from("ok")
        ).await.unwrap(),
        StatusCode::NO_CONTENT
    );
    assert_eq!
    (
        stalled.await.unwrap().unwrap_err().0,
        StatusCode::REQUEST_TIMEOUT
    );
    assert_eq!
    (
        upload::upload
    (
            State(app.clone()),
            Path("linux-amd64".into()),
            headers(claims("after-timeout"), b"ok"),
            Body::from("ok")
        ).await.unwrap(),
        StatusCode::NO_CONTENT
    );
    assert!
    (
        !app.config.data_dir.join(".app-main-linux-amd64.incoming").exists()
    );
}

#[tokio::test]
async fn http_routes_stream_large_upload_and_reject_unauthenticated_body()
{
    let temp = Temp::new();

    let mut app = app(temp.path());
    Arc::get_mut(&mut app).unwrap().config.max_bytes = 4 * 1024 * 1024;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let base = format!("http://{}", listener.local_addr().unwrap());

    let server_app = app.clone();

    let server = tokio::spawn(async move
    {
        axum::serve(listener, crate::router(server_app)).await.unwrap();
    });

    let client = Client::new();
    assert_eq!
    (
        client.get(format!("{base}/healthz")).send().await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!
    (
        client.get(format!("{base}/readyz")).send().await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!
    (
        client.put(format!("{base}/upload/linux-amd64")).body("no token").send().await.unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let data = vec![42u8; 3 * 1024 * 1024];

    let response = client.put(format!("{base}/upload/linux-amd64"))
        .headers(headers(claims("http-large"), &data)).body(data.clone()).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!
    (
        fs::read(app.config.data_dir.join("app-main-linux-amd64")).unwrap(),
        data
    );
    server.abort();
}

#[tokio::test]
async fn incomplete_chunks_cannot_publish_and_retries_preserve_quota()
{
    let temp = Temp::new();

    let app = app(temp.path());

    let data = b"artifact";

    let make = |id|
    {
        let mut value = headers(claims(id), data);
        value.insert("x-upload-size", data.len().to_string().parse().unwrap());
        value.insert(
            "x-chunk-sha256",
            hex::encode(Sha256::digest(data)).parse().unwrap(),
        );
        value
    };

    let digest = hex::encode(Sha256::digest(data));

    let name = format!("app-main-linux-amd64-{digest}");

    let lease = Staging::begin(app.staging.clone(), name, data.len() as u64).await.unwrap();
    drop(lease);
    assert_eq!
    (
        chunked::complete
    (
            State(app.clone()),
            Path("linux-amd64".into()),
            make("missing-chunk")
        ).await.unwrap_err().0,
        StatusCode::CONFLICT
    );
    assert!(!app.config.data_dir.join("app-main-linux-amd64").exists());

    for id in ["first-chunk", "replace-chunk"]
    {
        chunked::part
        (
            State(app.clone()),
            Path(("linux-amd64".into(), 0)),
            make(id),
            Body::from(data.as_slice()),
        ).await.unwrap();
    }

    chunked::complete
    (
        State(app.clone()),
        Path("linux-amd64".into()),
        make("complete-after-retry"),
    ).await.unwrap();
    assert_eq!
    (
        fs::read(app.config.data_dir.join("app-main-linux-amd64")).unwrap(),
        data
    );
}
