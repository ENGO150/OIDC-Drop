use std::time::Duration;

pub(crate) const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub(crate) const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
pub(crate) const JWKS_MIN_REFRESH: Duration = Duration::from_secs(300);
pub(crate) const JTI_TTL: Duration = Duration::from_secs(30 * 60);
pub(crate) const CHUNK_BYTES: u64 = 64 * 1024 * 1024;
