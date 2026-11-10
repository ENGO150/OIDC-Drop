mod app;
mod chunked;
mod config;
mod consts;
mod upload;

use std::
{
    sync::Arc,
    collections::HashMap,
    time::Duration,
};

use tokio::
{
    signal,
    net::TcpListener,
    sync::Mutex,
};

use axum::
{
    Router,
    http::StatusCode,
    routing,
};

use reqwest::Client;

use app::{ App, Keys };
use config::Config;

async fn healthz() -> StatusCode
{
    StatusCode::NO_CONTENT
}

#[tokio::main]
async fn main()
{
    let config = Config::from_env();

    let listen = config.listen;

    let app = Arc::new(App
    {
        config,
        http: Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("cannot build an HTTP client"),
        keys: Mutex::new(Keys { keys: HashMap::new(), fetched: None }),
        seen_jti: Mutex::new(HashMap::new()),
    });

    let router = Router::new()
        .route("/upload/{variant}", routing::put(upload::upload))
        .route("/upload/{variant}/chunks/{index}", routing::put(chunked::part))
        .route("/upload/{variant}/complete", routing::put(chunked::complete))
        .route("/healthz", routing::get(healthz))
        .with_state(app);

    let listener = TcpListener::bind(listen)
        .await
        .expect("cannot bind the listener");

    println!("listening on {listen}");

    axum::serve(listener, router).with_graceful_shutdown(async
    {
        let _ = signal::ctrl_c().await;
    }).await.expect("server failed");
}
