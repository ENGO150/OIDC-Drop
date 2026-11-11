use std::
{
    sync::Arc,
    time::Instant,
    sync::atomic::{ Ordering, AtomicUsize },
};

use tokio::
{
    net::TcpListener,
    task::JoinHandle,
};

use axum::
{
    Router,
    routing,
    http::StatusCode,
};

use crate::
{
    consts,
    tests::{ Temp, self },
};

async fn issuer
(
    status: StatusCode,
    body: &'static str,
) -> (String, Arc<AtomicUsize>, JoinHandle<()>)
{
    let calls = Arc::new(AtomicUsize::new(0));

    let counter = calls.clone();

    let router = Router::new().route
    (
        "/",
        routing::get(move ||
        {
            counter.fetch_add(1, Ordering::Relaxed);
            async move { (status, body) }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let url = format!("http://{}/", listener.local_addr().unwrap());

    let server = tokio::spawn(async move
    {
        axum::serve(listener, router).await.unwrap();
    });
    (url, calls, server)
}

#[tokio::test]
async fn expired_key_is_removed_on_refresh()
{
    let temp = Temp::new();

    let app = tests::app(temp.path());
    app.keys.write().await.fetched = Some(Instant::now() - consts::JWKS_MIN_REFRESH);

    let (url, calls, server) = issuer
    (
        StatusCode::OK,
        include_str!("../../tests/fixtures/test-jwks.json"),
    ).await;

    assert_eq!
    (
        app.key_for_url("test", &url).await.err().unwrap().0,
        StatusCode::UNAUTHORIZED
    );
    assert!(app.key_for_url("rotated", &url).await.is_ok());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn failed_refresh_backs_off_and_never_uses_stale_keys()
{
    let temp = Temp::new();

    let app = tests::app(temp.path());
    app.keys.write().await.fetched = Some(Instant::now() - consts::JWKS_MIN_REFRESH);

    let (url, calls, server) = issuer(StatusCode::INTERNAL_SERVER_ERROR, "offline").await;
    assert_eq!
    (
        app.key_for_url("test", &url).await.err().unwrap().0,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!
    (
        app.key_for_url("test", &url).await.err().unwrap().0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    server.abort();
}

#[tokio::test]
async fn refresh_does_not_queue_authentication_requests()
{
    let temp = Temp::new();

    let app = tests::app(temp.path());

    let refresh = app.refresh.lock().await;
    assert!(app.key_for("test").await.is_ok());
    app.keys.write().await.fetched = None;
    assert_eq!
    (
        app.key_for("test").await.err().unwrap().0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(refresh);
}
