use std::
{
    sync::{ Arc, Mutex },
    io::
    {
        Write,
        Result as IoResult,
    },
};

use axum::
{
    body::Body,
    http::{ Request, StatusCode },
};

use tower::ServiceExt;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::EnvFilter;

use crate::tests::{ Temp, self };

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture
{
    fn write(&mut self, bytes: &[u8]) -> IoResult<usize>
    {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> IoResult<()>
    {
        Ok(())
    }
}

#[tokio::test]
async fn request_logs_include_context_without_credentials()
{
    let temp = Temp::new();

    let output = Arc::new(Mutex::new(Vec::new()));

    let capture = Capture(output.clone());

    let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false)
        .with_env_filter(EnvFilter::new("oidc_drop=debug"))
        .with_writer(move || capture.clone()).finish();

    let request = Request::builder().method("PUT")
        .uri("/upload/linux-amd64?token=query-secret")
        .header("authorization", "Bearer super-secret-jwt")
        .body(Body::from("private artifact contents")).unwrap();

    let response = crate::router(tests::app(temp.path())).oneshot(request)
        .with_subscriber(subscriber).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();

    for expected in ["request_id=", "method=PUT", "/upload/{variant}", "status=401", "elapsed_ms=", "bad token"]
    {
        assert!(logs.contains(expected), "missing {expected}: {logs}");
    }

    for secret in ["query-secret", "super-secret-jwt", "authorization", "private artifact contents"]
    {
        assert!(!logs.contains(secret), "sensitive request data appeared in logs");
    }
}
