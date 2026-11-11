use std::
{
    time,
    ffi::CString,
    mem::MaybeUninit,
    collections::HashMap,
    sync::{ Arc, Mutex },
    os::unix::ffi::OsStrExt,
    path::{ Path, PathBuf },
    time::{ Duration, SystemTime },
    fs::{ File, self, OpenOptions },
    io::
    {
        Error,
        Write,
        ErrorKind,
        Result as IoResult,
    },
};

use tokio::task;
use axum::http::StatusCode;
use serde::{ Serialize, Deserialize };
use sha2::{ Digest, Sha256 };

use crate::
{
    consts,
    app::Fail,
};

#[cfg(test)]
#[path = "tests/storage.rs"]
mod tests;

pub(crate) fn now() -> u64
{
    SystemTime::now().duration_since(time::UNIX_EPOCH).expect("clock before epoch").as_secs()
}

pub(crate) fn disk_error(error: Error) -> Fail
{
    eprintln!("storage error: {error}");
    (StatusCode::INTERNAL_SERVER_ERROR, "storage error")
}

pub(crate) fn sync_dir(path: &Path) -> IoResult<()>
{
    File::open(path)?.sync_all()
}

//KEEP LOCK FILES; THE OS RELEASES LOCKS
pub(crate) fn lock_directory(path: &Path) -> IoResult<File>
{
    fs::create_dir_all(path)?;

    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(path.join(".oidc-drop.lock"))?;
    file.try_lock().map_err(Error::other)?;

    Ok(file)
}

pub(crate) struct Replay
{
    root: PathBuf,
    entries: usize,
}

impl Replay
{
    pub(crate) fn open(root: PathBuf) -> IoResult<Self>
    {
        fs::create_dir_all(&root)?;

        let mut replay = Self { root, entries: 0 };
        replay.cleanup()?;

        if let Some(parent) = replay.root.parent()
        {
            sync_dir(parent)?;
        }

        Ok(replay)
    }

    pub(crate) fn cleanup(&mut self) -> IoResult<()>
    {
        let now = now();
        self.entries = 0;

        for entry in fs::read_dir(&self.root)?
        {
            let path = entry?.path();
            //KEEP INCOMPLETE CLAIMS UNTIL EXPIRY
            let value = fs::read(&path)?;

            let expired = match <[u8; 8]>::try_from(value.as_slice())
            {
                Ok(bytes) => u64::from_be_bytes(bytes) < now,
                Err(_) =>
                {
                    fs::metadata(&path)?.modified()?.elapsed().unwrap_or_default()
                        > Duration::from_secs(consts::MAX_TOKEN_LIFETIME + 2 * consts::CLOCK_LEEWAY)
                }
            };

            if expired
            {
                fs::remove_file(path)?;
            }
            else
            {
                self.entries += 1;
            }
        }

        sync_dir(&self.root)
    }

    pub(crate) fn claim(&mut self, jti: &str, expiry: u64) -> Result<(), Fail>
    {
        if self.entries >= consts::MAX_REPLAY_ENTRIES
        {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "token replay storage full"));
        }

        let name = hex::encode(Sha256::digest(jti.as_bytes()));

        let mut file = OpenOptions::new().write(true).create_new(true).open(self.root.join(name))
            .map_err(|e|
            {
                if e.kind() == ErrorKind::AlreadyExists
                {
                    (StatusCode::UNAUTHORIZED, "token already used")
                }
                else
                {
                    disk_error(e)
                }
            })?;
        self.entries += 1;
        file.write_all(&expiry.to_be_bytes()).map_err(disk_error)?;
        file.sync_all().map_err(disk_error)?;
        sync_dir(&self.root).map_err(disk_error)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Session
{
    size: u64,
    #[serde(default)]
    declared: u64,
    touched: u64,
    #[serde(skip)]
    active: bool,
}

pub(crate) struct Staging
{
    root: PathBuf,
    sessions: HashMap<String, Session>,
    limit: u64,
    max_sessions: usize,
    ttl: Duration,
}

pub(crate) struct SessionLease
{
    staging: Arc<Mutex<Staging>>,
    name: String,
    pub(crate) path: PathBuf,
}

impl Drop for SessionLease
{
    fn drop(&mut self)
    {
        if let Ok(mut staging) = self.staging.lock()
            && let Some(session) = staging.sessions.get_mut(&self.name)
        {
            session.active = false;
            session.touched = now();
        }
    }
}

impl Staging
{
    pub(crate) fn open
    (
        root: PathBuf,
        limit: u64,
        max_sessions: usize,
        ttl: Duration,
        max_bytes: u64,
    ) -> IoResult<Self>
    {
        fs::create_dir_all(&root)?;

        let mut sessions = HashMap::new();

        for entry in fs::read_dir(&root)?
        {
            let entry = entry?;

            if !entry.file_type()?.is_dir()
            {
                continue;
            }

            let name = entry.file_name().into_string()
                .map_err(|_| Error::other("invalid staging name"))?;

            let path = entry.path().join(".session");

            let session = if path.exists()
            {
                serde_json::from_slice::<Session>(&fs::read(path)?).map_err(Error::other)?
            }
            else
            {
                //RESERVE SPACE FOR LEGACY UPLOADS
                let mut bytes = 0u64;

                for file in fs::read_dir(entry.path())?
                {
                    bytes = bytes.saturating_add(file?.metadata()?.len());
                }

                Session
                {
                    size: max_bytes.max(bytes),
                    declared: 0,
                    touched: now().saturating_sub
                    (
                        entry.metadata()?.modified()?.elapsed().unwrap_or_default().as_secs(),
                    ),
                    active: false,
                }
            };
            sessions.insert(name, session);
        }

        let mut staging = Self
        {
            root,
            sessions,
            limit,
            max_sessions,
            ttl,
        };
        staging.cleanup()?;

        Ok(staging)
    }

    pub(crate) async fn begin
    (
        shared: Arc<Mutex<Self>>,
        name: String,
        size: u64,
    ) -> Result<SessionLease, Fail>
    {
        let state = shared.clone();
        task::spawn_blocking(move ||
        {
            let mut staging = state.lock().expect("staging lock poisoned");

            let existing = staging.sessions.get(&name);

            if existing.is_some_and(|s| s.active)
            {
                return Err((StatusCode::CONFLICT, "upload busy"));
            }

            if existing.is_some_and(|s| s.declared != 0 && s.declared != size)
            {
                return Err((StatusCode::CONFLICT, "upload size changed"));
            }

            let old_size = existing.map_or(0, |s| s.size);

            let reserved = old_size.max(size);

            let used = staging.sessions.values().fold(0u64, |sum, s| sum.saturating_add(s.size));

            if used.saturating_sub(old_size).saturating_add(reserved) > staging.limit
                || (existing.is_none() && staging.sessions.len() >= staging.max_sessions)
            {
                return Err((StatusCode::INSUFFICIENT_STORAGE, "staging quota exceeded"));
            }

            let path = staging.root.join(&name);
            //PERSIST BEFORE RECEIVING DATA
            fs::create_dir_all(&path).map_err(disk_error)?;

            let session = Session
            {
                size: reserved,
                declared: size,
                touched: now(),
                active: true,
            };

            let temp = path.join(".session.tmp");

            let mut file = File::create(&temp).map_err(disk_error)?;
            file.write_all(&serde_json::to_vec(&session).expect("serialize session"))
                .map_err(disk_error)?;
            file.sync_all().map_err(disk_error)?;
            fs::rename(temp, path.join(".session")).map_err(disk_error)?;
            sync_dir(&path).map_err(disk_error)?;
            sync_dir(&staging.root).map_err(disk_error)?;
            staging.sessions.insert(name.clone(), session);

            Ok(SessionLease
            {
                staging: shared,
                name,
                path,
            })
        }).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "storage task failed"))?
    }

    pub(crate) fn remove(&mut self, name: &str) -> IoResult<()>
    {
        match fs::remove_dir_all(self.root.join(name))
        {
            Ok(()) =>
            {}
            Err(e) if e.kind() == ErrorKind::NotFound =>
            {}
            Err(e) => return Err(e),
        }

        self.sessions.remove(name);
        sync_dir(&self.root)
    }

    pub(crate) fn cleanup(&mut self) -> IoResult<()>
    {
        let expired: Vec<_> = self.sessions.iter()
            .filter(|(_, s)| !s.active && now().saturating_sub(s.touched) >= self.ttl.as_secs())
            .map(|(n, _)| n.clone()).collect();

        for name in expired
        {
            self.remove(&name)?;
        }

        Ok(())
    }
}

//CHECK SPACE AVAILABLE TO THIS USER
#[cfg(unix)]
pub(crate) fn available_bytes(path: &Path) -> IoResult<u64>
{

    let path = CString::new(path.as_os_str().as_bytes()).map_err(Error::other)?;

    let mut info = MaybeUninit::uninit();
    //SAFETY: NUL PATH AND WRITABLE OUTPUT
    if unsafe { libc::statvfs(path.as_ptr(), info.as_mut_ptr()) } != 0
    {
        return Err(Error::last_os_error());
    }

    //SAFETY: STATVFS INITIALIZED THE OUTPUT
    let info = unsafe { info.assume_init() };

    Ok(u64::try_from(u128::from(info.f_bavail) * u128::from(info.f_frsize)).unwrap_or(u64::MAX))
}

pub(crate) async fn ensure_space(path: PathBuf, required: u64) -> Result<(), Fail>
{
    let available = task::spawn_blocking(move || available_bytes(&path)).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "disk check task failed"))?
        .map_err(disk_error)?;

    if available < required
    {
        return Err
        ((
            StatusCode::INSUFFICIENT_STORAGE,
            "insufficient free disk space",
        ));
    }

    Ok(())
}
