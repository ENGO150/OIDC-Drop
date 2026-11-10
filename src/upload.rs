use std::
{
    io,
    sync::Arc,
    fs::{ self, File },
    path::Path as FsPath,
};

use tokio::
{
    task,
    sync::Mutex,
    io::AsyncWriteExt,
    fs::
    {
        self as afs,
        File as AFile,
    },
};

use axum::
{
    body::Body,
    extract::{ Path, State },
    http::{ HeaderMap, StatusCode },
};

use sha2::{ Digest, Sha256 };
use futures_util::stream::StreamExt;

use crate::app::{ App, Fail };

pub(crate) static UPLOAD_LOCK: Mutex<()> = Mutex::const_new(());

pub(crate) async fn upload
(
    State(app): State<Arc<App>>,
    Path(variant): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, Fail>
{
    let (prefix, branch) = app.authenticate(&headers).await?;

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

    let _guard = UPLOAD_LOCK.lock().await;
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

    task::spawn_blocking(move || publish_atomically(&dir, &name, &digest))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write task failed"))?
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;

    println!("published {asset} ({size} bytes, {actual})");

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn receive(path: &FsPath, body: Body, max_bytes: u64) -> Result<(u64, String), Fail>
{
    let mut file = AFile::create(path)
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

pub(crate) fn publish_atomically(dir: &FsPath, name: &str, digest: &str) -> io::Result<()>
{
    let final_path = dir.join(name);
    let temp_path = dir.join(format!(".{name}.incoming"));

    fs::rename(&temp_path, &final_path)?;

    let sums_path = dir.join(format!("{name}.sha256"));
    let temp_sums = dir.join(format!(".{name}.sha256.incoming"));

    fs::write(&temp_sums, format!("{digest}  {name}\n"))?;
    fs::rename(&temp_sums, &sums_path)?;

    File::open(dir)?.sync_all()
}
