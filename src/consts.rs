use std::time::Duration;

pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
pub const JWKS_MIN_REFRESH: Duration = Duration::from_secs(300);
pub const JTI_TTL: Duration = Duration::from_secs(30 * 60);
