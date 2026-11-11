use std::
{
    sync::Arc,
    time::Duration,
    fs::{ File, self },
    os::unix::fs as unix_fs,
    path::
    {
        PathBuf,
        Path as FsPath,
    },
    io::
    {
        Read,
        Write,
        ErrorKind,
        Result as IoResult,
    },
};

use tokio::
{
    task,
    io::AsyncWriteExt,
    time::{ self, Instant },
    fs::
    {
        self as afs,
        File as AFile,
    },
    sync::{ OwnedMutexGuard, OwnedSemaphorePermit },
};

use axum::
{
    body::Body,
    extract::{ Path, State },
    http::{ HeaderMap, StatusCode },
};

use sha2::{ Digest, Sha256 };
use futures_util::StreamExt;
use tracing::Span;

use crate::
{
    logging,
    storage,
    app::{ App, Fail },
};

//FUNCTIONS
pub(crate) fn digest_header(headers: &HeaderMap, name: &str) -> Result<String, Fail>
{
    headers.get(name).and_then(|v| v.to_str().ok())
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase).ok_or_else(|| logging::reject(StatusCode::BAD_REQUEST, "invalid SHA-256 digest"))
}

pub(crate) async fn upload
(
    State(app): State<Arc<App>>,
    Path(variant): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, Fail>
{
    let _slot = app.admit()?;

    let (prefix, branch) = app.authenticate(&headers).await?;

    if !app.config.allowed_variants.contains(&variant)
    {
        return Err(logging::reject(StatusCode::BAD_REQUEST, "unknown variant"));
    }

    let asset = format!("{prefix}-{branch}-{variant}");

    let declared = digest_header(&headers, "x-content-sha256")?;

    let _guard = app.lock_asset(&asset)?;
    storage::ensure_space
    (
        app.config.data_dir.clone(),
        app.config.max_bytes.saturating_add(app.config.min_free_bytes),
    ).await?;

    tracing::info!(%asset, max_bytes = app.config.max_bytes, "receiving artifact");

    let temp = app.config.data_dir.join(format!(".{asset}.incoming"));

    let result = receive
    (
        &temp,
        body,
        app.config.max_bytes,
        app.config.idle_timeout,
        app.config.upload_timeout,
    ).await;

    let (size, actual) = match result
    {
        Ok(value) => value,
        Err(error) =>
        {
            let _ = afs::remove_file(&temp).await;

            return Err(error);
        }
    };

    if actual != declared
    {
        let _ = afs::remove_file(&temp).await;

        return Err(logging::reject(StatusCode::BAD_REQUEST, "digest mismatch"));
    }

    publish(&app, &asset, &actual, _guard, _slot).await?;
    tracing::info!(%asset, bytes = size, sha256 = %actual, "artifact published");

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn receive
(
    path: &FsPath,
    body: Body,
    max_bytes: u64,
    idle: Duration,
    total: Duration,
) -> Result<(u64, String), Fail>
{
    let deadline = Instant::now() + total;
    time::timeout_at(deadline, async
    {
        let mut file = AFile::create(path).await.map_err(storage::disk_error)?;
        let mut stream = body.into_data_stream();
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut next_progress = 16 * 1024 * 1024;
        let started = Instant::now();

        loop
        {
            let chunk = time::timeout(idle, stream.next()).await
                .map_err(|_| logging::reject(StatusCode::REQUEST_TIMEOUT, "upload idle timeout"))?;

            let Some(chunk) = chunk
            else
            {
                break;
            };

            let chunk = chunk.map_err(|_| logging::reject(StatusCode::BAD_REQUEST, "upload interrupted"))?;
            size = size.checked_add(chunk.len() as u64).filter(|size| *size <= max_bytes)
                .ok_or_else(|| logging::reject(StatusCode::PAYLOAD_TOO_LARGE, "upload too large"))?;
            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(storage::disk_error)?;

            if size >= next_progress
            {
                tracing::info!(bytes_received = size, max_bytes, elapsed_ms = started.elapsed().as_millis(),
                    "upload progress");
                next_progress = size.saturating_add(16 * 1024 * 1024);
            }
        }

        if size == 0
        {
            return Err(logging::reject(StatusCode::BAD_REQUEST, "empty upload"));
        }

        file.sync_all().await.map_err(storage::disk_error)?;

        tracing::info!(bytes_received = size, elapsed_ms = started.elapsed().as_millis(), "body received and synced");

        Ok((size, hex::encode(hasher.finalize())))
    }).await.map_err(|_| logging::reject(StatusCode::REQUEST_TIMEOUT, "upload total timeout"))?
}

pub(crate) async fn publish
(
    app: &Arc<App>,
    asset: &str,
    digest: &str,
    guard: OwnedMutexGuard<()>,
    slot: OwnedSemaphorePermit,
) -> Result<(), Fail>
{
    tracing::info!(%asset, "publishing verified artifact");
    let span = Span::current();

    let root = app.config.data_dir.clone();

    let locks = app.directory_locks.clone();

    let name = asset.to_owned();

    let digest = digest.to_owned();
    task::spawn_blocking(move ||
    {
        let _entered = span.enter();

        let _guard = guard;

        let _slot = slot;

        let _directory_locks = locks;
        publish_atomically(&root, &name, &digest)
    }).await.map_err(|_| logging::reject(StatusCode::INTERNAL_SERVER_ERROR, "publication task failed"))?
    .map_err(storage::disk_error)
}

#[cfg(unix)]
fn replace_link(target: &FsPath, path: &FsPath, temporary: &FsPath) -> IoResult<()>
{
    match fs::remove_file(temporary)
    {
        Ok(()) =>
        {}
        Err(e) if e.kind() == ErrorKind::NotFound =>
        {}
        Err(e) => return Err(e),
    }

    unix_fs::symlink(target, temporary)?;
    fs::rename(temporary, path)
}

//SWITCH BOTH PUBLIC LINKS TOGETHER
//SEPARATE REQUESTS CAN STRADDLE UPDATES
pub(crate) fn publish_atomically(dir: &FsPath, name: &str, digest: &str) -> IoResult<()>
{
    let versions_root = dir.join(".versions");

    let versions = versions_root.join(name);
    fs::create_dir_all(&versions)?;
    storage::sync_dir(dir)?;
    storage::sync_dir(&versions_root)?;

    let current = versions.join("current");

    let incoming = dir.join(format!(".{name}.incoming"));

    let pending = versions.join(".pending");

    let generation = versions.join(digest);

    if pending.exists()
    {
        fs::remove_dir_all(&pending)?;
    }

    fs::create_dir(&pending)?;
    fs::rename(&incoming, pending.join("artifact"))?;

    let mut checksum = File::create(pending.join("checksum"))?;
    writeln!(checksum, "{digest}  {name}")?;
    checksum.sync_all()?;
    storage::sync_dir(&pending)?;

    if current_version(&versions)?.as_deref() == Some(FsPath::new(digest))
    {
        //REPAIR PUBLIC LINKS ON RETRY
        fs::remove_dir_all(&pending)?;
    }
    else
    {
        if generation.exists()
        {
            fs::remove_dir_all(&generation)?;
        }

        fs::rename(&pending, &generation)?;
        storage::sync_dir(&versions)?;
    }

    let public = dir.join(name);

    let public_sum = dir.join(format!("{name}.sha256"));
    //PRESERVE LEGACY FILES BEFORE SWITCHING
    if !current.exists() && public.symlink_metadata().is_ok_and(|m| m.is_file())
    {
        tracing::info!(asset = name, "migrating legacy artifact");

        let legacy = versions.join(".legacy");

        if legacy.exists()
        {
            fs::remove_dir_all(&legacy)?;
        }

        fs::create_dir(&legacy)?;
        fs::hard_link(&public, legacy.join("artifact"))?;

        let old_digest =
        {

            let mut file = File::open(&public)?;
            let mut hash = Sha256::new();
            let mut buffer = vec![0; 1024 * 1024];

            loop
            {
                let count = file.read(&mut buffer)?;

                if count == 0
                {
                    break;
                }

                hash.update(&buffer[..count]);
            }

            hex::encode(hash.finalize())
        };

        let mut file = File::create(legacy.join("checksum"))?;
        writeln!(file, "{old_digest}  {name}")?;
        file.sync_all()?;
        storage::sync_dir(&legacy)?;
        replace_link(
            FsPath::new(".legacy"),
            &current,
            &versions.join(".current.tmp"),
        )?;
        storage::sync_dir(&versions)?;
    }

    replace_link(
        &FsPath::new(".versions").join(name).join("current/artifact"),
        &public,
        &dir.join(format!(".{name}.link")),
    )?;
    replace_link(
        &FsPath::new(".versions").join(name).join("current/checksum"),
        &public_sum,
        &dir.join(format!(".{name}.sum-link")),
    )?;
    storage::sync_dir(dir)?;
    replace_link(
        FsPath::new(digest),
        &current,
        &versions.join(".current.tmp"),
    )?;
    storage::sync_dir(&versions)?;
    //OPEN READERS KEEP THE OLD INODE
    //CLEANUP MUST NOT FAIL A COMMIT
    if let Err(error) = cleanup_versions(&versions)
    {
        tracing::error!(%error, asset = name, "version cleanup failed");
    }

    Ok(())
}

pub(crate) fn cleanup_versions(versions: &FsPath) -> IoResult<()>
{
    let current = current_version(versions)?;

    for entry in fs::read_dir(versions)?
    {
        let entry = entry?;

        if entry.file_type()?.is_dir()
            && current.as_deref() != Some(FsPath::new(&entry.file_name()))
        {
            fs::remove_dir_all(entry.path())?;
            tracing::info!(asset_dir = %versions.display(), "removed obsolete artifact version");
        }
    }

    storage::sync_dir(versions)
}

fn current_version(versions: &FsPath) -> IoResult<Option<PathBuf>>
{
    match fs::read_link(versions.join("current"))
    {
        Ok(path) => Ok(Some(path)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
