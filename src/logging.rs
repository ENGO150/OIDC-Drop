use std::
{
    io,
    time::Instant,
    sync::atomic::{ Ordering, AtomicU64 },
};

use axum::
{
    http::StatusCode,
    middleware::Next,
    response::Response,
    extract::{ Request, MatchedPath },
};

use tracing::Instrument;
use tracing_subscriber::EnvFilter;

use crate::app::Fail;

#[cfg(test)]
#[path = "tests/logging.rs"]
mod tests;

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

pub(crate) fn init()
{
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,oidc_drop=info"));

    tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false)
        .with_target(false).with_writer(io::stderr).init();
}

pub(crate) fn reject(status: StatusCode, reason: &'static str) -> Fail
{
    if status.is_server_error()
        && status != StatusCode::SERVICE_UNAVAILABLE
        && status != StatusCode::INSUFFICIENT_STORAGE
    {
        tracing::error!(status = status.as_u16(), reason, "request rejected");
    }
    else
    {
        tracing::warn!(status = status.as_u16(), reason, "request rejected");
    }

    (status, reason)
}

pub(crate) async fn request(request: Request, next: Next) -> Response
{
    let request_id = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);

    //LOG ROUTE TEMPLATES, NEVER HEADERS OR QUERIES
    let route = request.extensions().get::<MatchedPath>()
        .map(|path| path.as_str()).unwrap_or("<unmatched>");

    let probe = matches!(route, "/healthz" | "/readyz");

    let span = tracing::info_span!("request", request_id, method = %request.method(), route);

    async move
    {
        let started = Instant::now();

        if probe
        {
            tracing::debug!("request started");
        }
        else
        {
            tracing::info!("request started");
        }

        let response = next.run(request).await;

        let status = response.status().as_u16();

        let elapsed_ms = started.elapsed().as_millis() as u64;

        if response.status().is_client_error() || response.status().is_server_error()
        {
            tracing::warn!(status, elapsed_ms, "request failed");
        }
        else if probe
        {
            tracing::debug!(status, elapsed_ms, "request completed");
        }
        else
        {
            tracing::info!(status, elapsed_ms, "request completed");
        }

        response
    }.instrument(span).await
}
