use std::time::Duration;

pub(crate) const ISSUER: &str                   = "https://token.actions.githubusercontent.com";
pub(crate) const JWKS_URL: &str                 = "https://token.actions.githubusercontent.com/.well-known/jwks";
pub(crate) const JWKS_MIN_REFRESH: Duration     = Duration::from_secs(300);
pub(crate) const JWKS_FAILURE_BACKOFF: Duration = Duration::from_secs(30);
pub(crate) const CHUNK_BYTES: u64               = 64 * 1024 * 1024;
pub(crate) const CLOCK_LEEWAY: u64              = 30;
pub(crate) const MAX_TOKEN_LIFETIME: u64        = 3600;
pub(crate) const MAX_REPLAY_ENTRIES: usize      = 100_000;
