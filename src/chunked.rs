use std::
{
    sync::Arc,
    io::Error,
    time::Duration,
    path::{ Path as FsPath, PathBuf },
};

use tokio::
{
    fs as afs,
    task,
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
};

//FUNCTIONS
//PRIVATE
fn metadata(headers: &HeaderMap, max: u64) -> Result<(String, u64), Fail> //COMPLETE FILE DIGEST AND SIZE
{
    let digest = headers
        .get("x-content-sha256")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or((StatusCode::BAD_REQUEST, "invalid digest"))?
        .to_ascii_lowercase();

    let size = headers
        .get("x-upload-size")
        .and_then(|v| v.to_str().ok())
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
    let offset = index
        .checked_mul(consts::CHUNK_BYTES)
        .filter(|offset| *offset < size)
        .ok_or((StatusCode::BAD_REQUEST, "invalid chunk index"))?;

    Ok((size - offset).min(consts::CHUNK_BYTES)) //THE FINAL CHUNK MAY BE SMALLER
}

async fn location(app: &App, variant: &str, headers: &HeaderMap) -> Result<(String, String, u64, PathBuf), Fail>
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

async fn prepare(dir: &FsPath) -> Result<(), Fail>
{
    let root = dir.parent().unwrap();

    afs::create_dir_all(root).await.map_err(disk_error)?;

    let mut entries = afs::read_dir(root).await.map_err(disk_error)?;

    while let Some(entry) = entries.next_entry().await.map_err(disk_error)?
    {
        if entry.path() == dir //KEEP THE CURRENT UPLOAD
        {
            continue;
        }

        let info = entry.metadata().await.map_err(disk_error)?;

        //REMOVE OTHER STAGING DIRECTORIES OLDER THAN A DAY
        if info.is_dir() && info.modified().ok().and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > Duration::from_secs(24 * 60 * 60))
        {
            afs::remove_dir_all(entry.path()).await.map_err(disk_error)?;
        }
    }

    afs::create_dir_all(dir).await.map_err(disk_error)
}

async fn assemble(dir: &FsPath, path: PathBuf, size: u64, digest: &str) -> Result<PathBuf, Fail>
{
    let mut output = afs::File::create(&path).await.map_err(disk_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];

    //JOIN CHUNKS IN ORDER WITH A FIXED SIZE BUFFER
    for index in 0..size.div_ceil(consts::CHUNK_BYTES)
    {
        let mut input = afs::File::open(dir.join(index.to_string()))
            .await
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
pub(crate) async fn part //RECEIVE ONE NUMBERED CHUNK
(
    State(app): State<Arc<App>>,
    Path((variant, index)): Path<(String, u64)>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, Fail>
{
    let (_, _, size, dir) = location(&app, &variant, &headers).await?;
    let expected = chunk_size(size, index)?;
    let declared = headers
        .get("x-chunk-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing chunk digest"))?;

    let _guard = upload::UPLOAD_LOCK.lock().await;

    prepare(&dir).await?;

    let temp = dir.join("incoming");
    let result = upload::receive(&temp, body, expected).await;

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
    if received != expected || !actual.eq_ignore_ascii_case(declared)
    {
        let _ = afs::remove_file(&temp).await;
        return Err((StatusCode::BAD_REQUEST, "chunk size or digest mismatch"));
    }

    afs::rename(temp, dir.join(index.to_string())).await.map_err(disk_error)?; //RETRIES REPLACE THE CHUNK

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn complete //ASSEMBLE AND PUBLISH THE FILE
(
    State(app): State<Arc<App>>,
    Path(variant): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, Fail>
{
    let (asset, digest, size, dir) = location(&app, &variant, &headers).await?;
    let _guard = upload::UPLOAD_LOCK.lock().await;

    //A COMPLETION RETRY MAY FIND THE FILE ALREADY PUBLISHED
    if !afs::try_exists(&dir).await.map_err(disk_error)?
    {
        if let Ok(mut file) = afs::File::open(app.config.data_dir.join(&asset)).await
        {
            if file.metadata().await.map_err(disk_error)?.len() == size
            {
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

                if hex::encode(hash.finalize()) == digest
                {
                    return Ok(StatusCode::NO_CONTENT);
                }
            }
        }

        return Err((StatusCode::CONFLICT, "upload not found"));
    }

    afs::create_dir_all(&app.config.data_dir).await.map_err(disk_error)?;

    //ASSEMBLE ON THE DESTINATION FILESYSTEM FOR ATOMIC RENAME
    let incoming = app.config.data_dir.join(format!(".{asset}.incoming"));

    match assemble(&dir, incoming.clone(), size, &digest).await
    {
        Ok(_) => {},
        Err(err) =>
        {
            let _ = afs::remove_file(&incoming).await;
            return Err(err);
        }
    }

    let root = app.config.data_dir.clone();
    let name = asset.clone();
    let sum = digest.clone();

    task::spawn_blocking(move ||
    {
        upload::publish_atomically(&root, &name, &sum)
    }).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write task failed"))?
        .map_err(disk_error)?;

    let _ = afs::remove_dir_all(dir).await; //REMOVE CHUNKS AFTER PUBLISHING

    println!("published {asset} ({size} bytes, {digest}, chunked)");

    Ok(StatusCode::NO_CONTENT)
}
