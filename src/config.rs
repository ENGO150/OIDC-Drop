use std::
{
    env,
    env::VarError,
    path::PathBuf,
    time::Duration,
    net::SocketAddr,
    collections::{ HashMap, HashSet },
};

//STRUCTS
pub(crate) struct Config
{
    pub(crate) listen: SocketAddr,
    pub(crate) data_dir: PathBuf, //PUBLISHED FILES
    pub(crate) upload_dir: PathBuf, //UNFINISHED CHUNKS
    pub(crate) audience: String,
    pub(crate) repository_owner_id: String,
    pub(crate) prefixes: HashMap<String, String>, //REPOSITORY PREFIXES
    pub(crate) allowed_subs: HashSet<String>,
    pub(crate) allowed_variants: HashSet<String>,
    pub(crate) max_bytes: u64, //COMPLETE FILE LIMIT
    pub(crate) staging_bytes: u64,
    pub(crate) staging_uploads: usize,
    pub(crate) concurrency: usize,
    pub(crate) idle_timeout: Duration,
    pub(crate) upload_timeout: Duration,
    pub(crate) staging_ttl: Duration,
    pub(crate) min_free_bytes: u64,
}

//IMPLEMENTATIONS
impl Config
{
    pub(crate) fn from_env() -> Self //READ SERVER SETTINGS
    {
        let config = Self
        {
            listen: env_var("LISTEN_ADDR").parse().expect("invalid LISTEN_ADDR"),
            data_dir: PathBuf::from(env_var("DATA_DIR")),
            upload_dir: PathBuf::from(env_var("UPLOAD_DIR")),
            audience: env_var("OIDC_AUDIENCE"),
            repository_owner_id: env_var("REPOSITORY_OWNER_ID"),
            prefixes: env_map("ASSET_PREFIXES"),
            allowed_subs: env_set("ALLOWED_SUBS"),
            allowed_variants: env_set("ALLOWED_VARIANTS"),
            max_bytes: number("MAX_UPLOAD_BYTES", 256 * 1024 * 1024),
            staging_bytes: number("MAX_STAGING_BYTES", 1024 * 1024 * 1024),
            staging_uploads: number("MAX_STAGING_UPLOADS", 128).try_into()
                .expect("MAX_STAGING_UPLOADS too large"),
            concurrency: number("MAX_CONCURRENT_UPLOADS", 4).try_into()
                .expect("MAX_CONCURRENT_UPLOADS too large"),
            idle_timeout: Duration::from_secs(number("UPLOAD_IDLE_TIMEOUT_SECS", 30)),
            upload_timeout: Duration::from_secs(number("UPLOAD_TIMEOUT_SECS", 900)),
            staging_ttl: Duration::from_secs(number("STAGING_TTL_SECS", 86400)),
            min_free_bytes: number("MIN_FREE_DISK_BYTES", 64 * 1024 * 1024),
        };
        config.validate().unwrap_or_else(|err| panic!("invalid configuration: {err}"));
        config
    }

    pub(crate) fn validate(&self) -> Result<(), String>
    {
        if !numeric(&self.repository_owner_id) || self.audience.trim().is_empty()
        {
            return Err("owner ID must be numeric and audience must not be empty".into());
        }

        if self.prefixes.is_empty()
            || self.allowed_subs.is_empty()
            || self.allowed_variants.is_empty()
        {
            return Err("allowlists must not be empty".into());
        }

        let mut prefixes = HashSet::new();

        for (id, prefix) in &self.prefixes
        {
            if !numeric(id) || !safe_component(prefix) || !prefixes.insert(prefix)
            {
                return Err(
                    "repository IDs must be numeric; prefixes must be safe and unique".into(),
                );
            }
        }

        let mut branches = HashSet::new();

        for sub in &self.allowed_subs
        {
            let (repo, branch) = sub.split_once(":ref:refs/heads/")
                .ok_or("only branch subjects are supported")?;

            let repo = repo.strip_prefix("repo:").ok_or("invalid subject")?;

            if repo.split('/').count() != 2
                || repo.split('/').any(str::is_empty)
                || repo.contains(':')
                || !safe_component(branch)
            {
                return Err("invalid repository subject or unsafe branch name".into());
            }

            branches.insert(branch);
        }

        if self.allowed_variants.iter().any(|v| !safe_component(v))
        {
            return Err("unsafe variant".into());
        }

        //REJECT ARTIFACT AND CHECKSUM COLLISIONS
        let mut names = HashSet::new();

        for prefix in prefixes
        {
            for branch in &branches
            {
                for variant in &self.allowed_variants
                {
                    let asset = format!("{prefix}-{branch}-{variant}");

                    if asset.len() > 180
                        || !names.insert(asset.clone())
                        || !names.insert(format!("{asset}.sha256"))
                    {
                        return Err(concat!
                        (
                            "artifact names collide or exceed 180 bytes; change ",
                            "prefixes/branches/variants",
                        ).into());
                    }
                }
            }
        }

        if self.max_bytes == 0
            || self.staging_bytes < self.max_bytes
            || self.concurrency == 0
            || self.concurrency > 32
            || self.staging_uploads == 0
            || self.staging_uploads > 10000
        {
            return Err(concat!
            (
                "invalid storage/concurrency limits (concurrency 1..32, staging uploads ",
                "1..10000, staging bytes >= upload bytes > 0)",
            ).into());
        }

        if self.idle_timeout.is_zero()
            || self.upload_timeout.is_zero()
            || self.idle_timeout > self.upload_timeout
            || self.upload_timeout > Duration::from_secs(86400)
            || self.staging_ttl.is_zero()
            || self.staging_ttl > Duration::from_secs(366 * 86400)
        {
            return Err(concat!
            (
                "timeouts require 0 < idle <= total <= 86400 seconds; staging TTL must be ",
                "1..31622400 seconds",
            ).into());
        }

        Ok(())
    }
}

//FUNCTIONS
pub(crate) fn safe_component(value: &str) -> bool
{
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn numeric(value: &str) -> bool
{
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

fn env_var(name: &str) -> String //REQUIRE A VALUE
{
    env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

fn env_set(name: &str) -> HashSet<String> //COMMA SEPARATED VALUES
{
    env_var(name).split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

fn number(name: &str, default: u64) -> u64
{
    match env::var(name)
    {
        Ok(value) => value.parse::<u64>().ok().filter(|n| *n > 0)
            .unwrap_or_else(|| panic!("{name} must be a positive integer")),
        Err(VarError::NotPresent) => default,
        Err(_) => panic!("invalid {name}"),
    }
}

fn env_map(name: &str) -> HashMap<String, String> //ID=PREFIX PAIRS
{
    env_var(name).split(',').map(str::trim).filter(|s| !s.is_empty())
        .map(|pair|
        {
            let (id, prefix) = pair.split_once('=')
                .unwrap_or_else(|| panic!("{name} entry {pair:?} is not id=prefix"));

            (id.trim().to_owned(), prefix.trim().to_owned())
        })
        .fold(HashMap::new(), |mut map, (id, prefix)|
        {
            assert!(map.insert(id, prefix).is_none(), "duplicate repository ID");
            map
        })
}
