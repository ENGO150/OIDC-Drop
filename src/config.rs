use std::
{
    env,
    net::SocketAddr,
    path::PathBuf,
    collections::{ HashMap, HashSet },
};

pub(crate) struct Config
{
    pub(crate) listen: SocketAddr,
    pub(crate) data_dir: PathBuf,
    pub(crate) upload_dir: PathBuf,
    pub(crate) audience: String,
    pub(crate) repository_owner_id: String,
    pub(crate) prefixes: HashMap<String, String>,
    pub(crate) allowed_subs: HashSet<String>,
    pub(crate) allowed_variants: HashSet<String>,
    pub(crate) max_bytes: u64,
}

impl Config
{
    pub(crate) fn from_env() -> Self
    {
        Self
        {
            listen: env_var("LISTEN_ADDR").parse().expect("LISTEN_ADDR is not an address"),
            data_dir: PathBuf::from(env_var("DATA_DIR")),
            upload_dir: PathBuf::from(env_var("UPLOAD_DIR")),
            audience: env_var("OIDC_AUDIENCE"),
            repository_owner_id: env_var("REPOSITORY_OWNER_ID"),
            prefixes: env_map("ASSET_PREFIXES"),
            allowed_subs: env_set("ALLOWED_SUBS"),
            allowed_variants: env_set("ALLOWED_VARIANTS"),
            max_bytes: env::var("MAX_UPLOAD_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256 * 1024 * 1024),
        }
    }
}

fn env_var(name: &str) -> String
{
    env::var(name).unwrap_or_else(|_| panic!("missing environment variable {name}"))
}

fn env_set(name: &str) -> HashSet<String>
{
    env_var(name)
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn env_map(name: &str) -> HashMap<String, String>
{
    env_var(name)
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|pair|
        {
            let (id, prefix) = pair
                .split_once('=')
                .unwrap_or_else(|| panic!("{name} entry {pair:?} is not id=prefix"));

            (id.trim().to_owned(), prefix.trim().to_owned())
        }).collect()
}
