mod app;
mod chunked;
mod config;
mod consts;
mod storage;
mod upload;
#[cfg(test)]
mod tests;

use std::
{
    fs,
    time::Duration,
    collections::HashMap,
    sync::
    {
        Arc,
        Mutex as StdMutex,
    },
    io::
    {
        ErrorKind,
        Result as IoResult,
    },
};

use tokio::
{
    task,
    time,
    signal,
    fs as afs,
    net::TcpListener,
    runtime::Builder,
    sync::{ Mutex, RwLock, Semaphore },
};

use axum::
{
    Router,
    routing,
    extract::State,
    http::StatusCode,
};

use reqwest::
{
    Client,
    redirect::Policy,
};

use app::{ App, Fail, Keys };
use config::Config;
use storage::{ Replay, Staging };

#[cfg(unix)]
use tokio::signal::unix::{ self, SignalKind };

async fn readyz
(
    State(app): State<Arc<App>>,
) -> Result<StatusCode, Fail>
{
    let _slot = app.admit()?;
    storage::ensure_space(app.config.data_dir.clone(), app.config.min_free_bytes).await?;
    storage::ensure_space(app.config.upload_dir.clone(), app.config.min_free_bytes).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn healthz() -> StatusCode
{
    StatusCode::NO_CONTENT
}

fn router(app: Arc<App>) -> Router
{
    Router::new()
        .route("/upload/{variant}", routing::put(upload::upload))
        .route("/upload/{variant}/chunks/{index}", routing::put(chunked::part))
        .route("/upload/{variant}/complete", routing::put(chunked::complete))
        .route("/healthz", routing::get(healthz))
        .route("/readyz", routing::get(readyz))
        .with_state(app)
}

async fn shutdown()
{
    #[cfg(unix)]
    {
        let mut term = unix::signal(SignalKind::terminate())
            .expect("cannot install SIGTERM handler");
        tokio::select! { _ = signal::ctrl_c() => {}, _ = term.recv() => {} }
    }

    #[cfg(not(unix))]
    let _ = signal::ctrl_c().await;
}

fn main()
{
    Builder::new_multi_thread().worker_threads(2).max_blocking_threads(16).enable_all().build()
        .expect("cannot build runtime").block_on(run());
}

async fn run()
{
    let config = Config::from_env();

    let listen = config.listen;
    fs::create_dir_all(&config.data_dir).expect("cannot create DATA_DIR");
    fs::create_dir_all(&config.upload_dir).expect("cannot create UPLOAD_DIR");

    let data = config.data_dir.canonicalize().expect("cannot resolve DATA_DIR");

    let uploads = config.upload_dir.canonicalize().expect("cannot resolve UPLOAD_DIR");
    assert!(
        !data.starts_with(&uploads) && !uploads.starts_with(&data),
        "DATA_DIR and UPLOAD_DIR must not overlap"
    );

    let _data_lock = storage::lock_directory(&data).expect("DATA_DIR is in use or not writable");

    let _upload_lock =
        storage::lock_directory(&uploads).expect("UPLOAD_DIR is in use or not writable");

    let replay = Replay::open(data.join(".replay")).expect("cannot open replay storage");

    let staging = Staging::open
    (
        uploads,
        config.staging_bytes,
        config.staging_uploads,
        config.staging_ttl,
        config.max_bytes,
    ).expect("cannot open staging storage");

    let slots = Arc::new(Semaphore::new(config.concurrency));

    let app = Arc::new(App
    {
        directory_locks: Arc::new(vec![_data_lock, _upload_lock]),
        config,
        http: Client::builder().timeout(Duration::from_secs(10)).redirect(Policy::none()).build()
            .expect("cannot build HTTP client"),
        keys: RwLock::new(Keys::default()),
        refresh: Mutex::new(()),
        replay: Arc::new(StdMutex::new(replay)),
        staging: Arc::new(StdMutex::new(staging)),
        slots,
        assets: StdMutex::new(HashMap::new()),
    });

    let maintenance = app.clone();
    tokio::spawn(async move
    {
        loop
        {
            let staging = maintenance.staging.clone();

            let replay = maintenance.replay.clone();

            match task::spawn_blocking(move || -> IoResult<()>
            {
                staging.lock().expect("staging lock poisoned").cleanup()?;
                replay.lock().expect("replay lock poisoned").cleanup()
            }).await
            {
                Ok(Ok(())) =>
                {}
                result => eprintln!("maintenance failed: {result:?}"),
            }

            let versions = maintenance.config.data_dir.join(".versions");

            if let Ok(mut entries) = afs::read_dir(versions).await
            {
                while let Ok(Some(entry)) = entries.next_entry().await
                {
                    let name = entry.file_name().to_string_lossy().into_owned();

                    if let Ok(guard) = maintenance.lock_asset(&name)
                    {
                        let path = entry.path();

                        let _ = task::spawn_blocking(move ||
                        {
                            let _guard = guard;
                            upload::cleanup_versions(&path)
                        }).await;
                    }
                }
            }

            if let Ok(mut entries) = afs::read_dir(&maintenance.config.data_dir).await
            {
                while let Ok(Some(entry)) = entries.next_entry().await
                {
                    let filename = entry.file_name().to_string_lossy().into_owned();

                    if let Some(asset) = filename.strip_prefix('.')
                        .and_then(|name| name.strip_suffix(".incoming"))
                        && let Ok(guard) = maintenance.lock_asset(asset)
                    {
                        let path = entry.path();

                        let _ = task::spawn_blocking(move ||
                        {
                            let _guard = guard;

                            match fs::remove_file(path)
                            {
                                Ok(()) => {}
                                Err(error) if error.kind() == ErrorKind::NotFound => {}
                                Err(error) => eprintln!("temporary file cleanup failed: {error}"),
                            }
                        }).await;
                    }
                }
            }

            time::sleep(Duration::from_secs(60)).await;
        }
    });

    let listener = TcpListener::bind(listen).await.expect("cannot bind listener");
    println!("listening on {listen}");
    //DRAIN REQUESTS BEFORE SHUTDOWN
    axum::serve(listener, router(app)).with_graceful_shutdown(shutdown()).await
        .expect("server failed");
}
