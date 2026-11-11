use std::
{
    io::Error,
    sync::Arc,
    path::
    {
        PathBuf,
        Path as FsPath,
    },
};

use tokio::
{
    task,
    time,
    fs::
    {
        self as afs,
        File as AFile,
    },
    io::{ AsyncReadExt, AsyncWriteExt },
};

use axum::
{
    body::Body,
    extract::{ Path, State },
    http::{ HeaderMap, StatusCode },
};

use sha2::{ Digest, Sha256 };

use crate::
{
    consts,
    upload,
    app::{ App, Fail },
    storage::{ self, Staging },
};

//FUNCTIONS
//PRIVATE
fn metadata(headers: &HeaderMap, max: u64) -> Result<(String, u64), Fail> //COMPLETE FILE DIGEST AND SIZE
{
    let digest = headers.get("x-content-sha256").and_then(|v| v.to_str().ok())
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or((StatusCode::BAD_REQUEST, "invalid digest"))?.to_ascii_lowercase();

    let size = headers.get("x-upload-size").and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or((StatusCode::BAD_REQUEST, "invalid upload size"))?;

    if size == 0 || size > max
    {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "upload size exceeds limit"));
    }

    Ok((digest, size))
}

fn chunk_size(size: u64, index: u64) -> Result<u64, Fail>
{
    //REJECT OVERFLOW AND CHUNKS PAST THE END
    let offset = index.checked_mul(consts::CHUNK_BYTES).filter(|offset| *offset < size)
        .ok_or((StatusCode::BAD_REQUEST, "invalid chunk index"))?;

    Ok((size - offset).min(consts::CHUNK_BYTES)) //THE FINAL CHUNK MAY BE SMALLER
}

async fn location
(
    app: &App,
    variant: &str,
    headers: &HeaderMap,
) -> Result<(String, String, u64, PathBuf), Fail>
{
    let (prefix, branch) = app.authenticate(headers).await?;

    if !app.config.allowed_variants.contains(variant)
    {
        return Err((StatusCode::BAD_REQUEST, "unknown variant"));
    }

    let (digest, size) = metadata(headers, app.config.max_bytes)?;

    let asset = format!("{prefix}-{branch}-{variant}");

    let dir = app.config.upload_dir.join(format!("{asset}-{digest}")); //SEPARATE EACH FILE VERSION

    Ok((asset, digest, size, dir))
}

fn disk_error(_: Error) -> Fail
{
    (StatusCode::INTERNAL_SERVER_ERROR, "upload storage error")
}

async fn assemble(dir: &FsPath, path: PathBuf, size: u64, digest: &str) -> Result<PathBuf, Fail>
{
    let mut output = AFile::create(&path).await.map_err(disk_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];

    //JOIN CHUNKS IN ORDER WITH A FIXED SIZE BUFFER
    for index in 0..size.div_ceil(consts::CHUNK_BYTES)
    {
        let mut input = AFile::open(dir.join(index.to_string())).await
            .map_err(|_| (StatusCode::CONFLICT, "missing chunk"))?;

        let expected = chunk_size(size, index)?;

        if input.metadata().await.map_err(disk_error)?.len() != expected
        {
            return Err((StatusCode::CONFLICT, "incorrect chunk size"));
        }

        loop
        {
            let count = input.read(&mut buffer).await.map_err(disk_error)?;

            if count == 0
            {
                break;
            }

            hasher.update(&buffer[..count]);
            output.write_all(&buffer[..count]).await.map_err(disk_error)?;
        }
    }

    //VERIFY THE COMPLETE FILE BEFORE PUBLISHING
    if hex::encode(hasher.finalize()) != digest
    {
        return Err((StatusCode::BAD_REQUEST, "full digest mismatch"));
    }

    output.sync_all().await.map_err(disk_error)?;

    Ok(path)
}

//PUBLIC
pub(crate) async fn part
(
    State(app): State<Arc<App>>,
    Path((variant, index)): Path<(String, u64)>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, Fail>
{
    let _slot = app.admit()?;

    let (asset, _, size, dir) = location(&app, &variant, &headers).await?;

    let expected = chunk_size(size, index)?;

    let declared = upload::digest_header(&headers, "x-chunk-sha256")?;

    let _guard = app.lock_asset(&asset)?;

    let name = dir.file_name().unwrap().to_str().unwrap().to_owned();

    let session = Staging::begin(app.staging.clone(), name, size).await?;

    let dir = &session.path;

    storage::ensure_space
    (
        app.config.upload_dir.clone(),
        expected.saturating_add(app.config.min_free_bytes),
    ).await?;

    let temp = dir.join("incoming");

    let result = upload::receive
    (
        &temp,
        body,
        expected,
        app.config.idle_timeout,
        app.config.upload_timeout,
    ).await;

    let (received, actual) = match result
    {
        Ok(value) => value,
        Err(err) =>
        {
            let _ = afs::remove_file(&temp).await;

            return Err(err);
        }
    };

    //REQUIRE THE EXACT CHUNK SIZE AND DIGEST
    if received != expected || !actual.eq_ignore_ascii_case(&declared)
    {
        let _ = afs::remove_file(&temp).await;

        return Err((StatusCode::BAD_REQUEST, "chunk size or digest mismatch"));
    }

    afs::rename(temp, dir.join(index.to_string())).await
        .map_err(disk_error)?; //RETRIES REPLACE THE CHUNK

    let sync_path = dir.to_owned();
    task::spawn_blocking(move || storage::sync_dir(&sync_path)).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "chunk sync task failed"))?
        .map_err(disk_error)?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn complete
(
    State(app): State<Arc<App>>,
    Path(variant): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, Fail>
{
    let _slot = app.admit()?;

    let (asset, digest, size, dir) = location(&app, &variant, &headers).await?;

    let _guard = app.lock_asset(&asset)?;

    //A COMPLETION RETRY MAY FIND THE FILE ALREADY PUBLISHED
    if !afs::try_exists(&dir).await.map_err(disk_error)?
    {
        let matches = time::timeout(app.config.upload_timeout, async
        {
            let Ok(mut file) = AFile::open(app.config.data_dir.join(&asset)).await
            else
            {
                return Ok(false);
            };

            if file.metadata().await.map_err(disk_error)?.len() != size
            {
                return Ok(false);
            }

            let mut hash = Sha256::new();
            let mut buffer = vec![0u8; 1024 * 1024];

            loop
            {
                let count = file.read(&mut buffer).await.map_err(disk_error)?;

                if count == 0
                {
                    break;
                }

                hash.update(&buffer[..count]);
            }

            Ok::<_, Fail>(hex::encode(hash.finalize()) == digest)
        }).await.map_err(|_| (StatusCode::REQUEST_TIMEOUT, "verification timeout"))??;

        if matches
        {
            return Ok(StatusCode::NO_CONTENT);
        }

        return Err((StatusCode::CONFLICT, "upload not found"));
    }

    let name = dir.file_name().unwrap().to_str().unwrap().to_owned();

    let _session = Staging::begin(app.staging.clone(), name.clone(), size).await?;

    storage::ensure_space
    (
        app.config.data_dir.clone(),
        size.saturating_add(app.config.min_free_bytes),
    ).await?;
    //ASSEMBLE ON THE DESTINATION FILESYSTEM FOR ATOMIC RENAME
    let incoming = app.config.data_dir.join(format!(".{asset}.incoming"));

    match time::timeout
    (
        app.config.upload_timeout,
        assemble(&dir, incoming.clone(), size, &digest),
    ).await.unwrap_or(Err((StatusCode::REQUEST_TIMEOUT, "assembly timeout")))
    {
        Ok(_) => {}
        Err(err) =>
        {
            let _ = afs::remove_file(&incoming).await;

            return Err(err);
        }
    }

    upload::publish(&app, &asset, &digest, _guard, _slot).await?;

    let staging = app.staging.clone();
    task::spawn_blocking(move ||
    {
        staging.lock().expect("staging lock poisoned").remove(&name)
    }).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "cleanup task failed"))?
    .map_err(disk_error)?;

    println!("published {asset} ({size} bytes, {digest}, chunked)");

    Ok(StatusCode::NO_CONTENT)
}
