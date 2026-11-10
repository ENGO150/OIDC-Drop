use std::
{
    collections::HashMap,
    time::Instant,
};

use jsonwebtoken::
{
    Algorithm,
    DecodingKey,
    Validation,
    jwk::JwkSet,
};

use tokio::sync::Mutex;
use serde::Deserialize;
use reqwest::{ Client, Response };
use axum::http::{ HeaderMap, StatusCode };

use crate::
{
    consts,
    config::Config,
};

pub(crate) struct Keys
{
    pub(crate) keys: HashMap<String, DecodingKey>,
    pub(crate) fetched: Option<Instant>,
}

pub(crate) struct App
{
    pub(crate) config: Config,
    pub(crate) http: Client,
    pub(crate) keys: Mutex<Keys>,
    pub(crate) seen_jti: Mutex<HashMap<String, Instant>>,
}

#[derive(Deserialize)]
struct Claims
{
    sub: String,
    jti: String,
    repository_id: String,
    repository_owner_id: String,
}

pub(crate) type Fail = (StatusCode, &'static str);

impl App
{
    async fn key_for(&self, kid: &str) -> Result<DecodingKey, Fail>
    {
        let mut keys = self.keys.lock().await;

        if let Some(key) = keys.keys.get(kid)
        {
            return Ok(key.clone());
        }

        let stale = keys
            .fetched
            .is_none_or(|at| at.elapsed() >= consts::JWKS_MIN_REFRESH);

        if !stale
        {
            return Err((StatusCode::UNAUTHORIZED, "unknown key id"));
        }

        let set: JwkSet = self
            .http
            .get(consts::JWKS_URL)
            .send()
            .await
            .and_then(Response::error_for_status)
            .map_err(|_| (StatusCode::BAD_GATEWAY, "cannot reach the issuer"))?
            .json()
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "malformed key set"))?;

        keys.fetched = Some(Instant::now());
        keys.keys = set
            .keys
            .iter()
            .filter_map(|k|
            {
                let id = k.common.key_id.clone()?;
                Some((id, DecodingKey::from_jwk(k).ok()?))
            })
            .collect();

        keys.keys
            .get(kid)
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "unknown key id"))
    }

    async fn claim_jti(&self, jti: &str) -> Result<(), Fail>
    {
        let mut seen = self.seen_jti.lock().await;

        seen.retain(|_, at| at.elapsed() < consts::JTI_TTL);

        if seen.insert(jti.to_owned(), Instant::now()).is_some()
        {
            return Err((StatusCode::UNAUTHORIZED, "token already used"));
        }

        Ok(())
    }

    pub(crate) async fn authenticate(&self, headers: &HeaderMap) -> Result<(String, String), Fail>
    {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;

        let header = jsonwebtoken::decode_header(token).map_err(|_| (StatusCode::UNAUTHORIZED, "bad token"))?;
        let kid = header
            .kid
            .ok_or((StatusCode::UNAUTHORIZED, "token has no key id"))?;
        let key = self.key_for(&kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![Algorithm::RS256];
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[consts::ISSUER]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        validation.leeway = 30;

        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "token rejected"))?
            .claims;

        if claims.repository_owner_id != self.config.repository_owner_id
        {
            return Err((StatusCode::FORBIDDEN, "wrong owner"));
        }

        let prefix = self
            .config
            .prefixes
            .get(&claims.repository_id)
            .cloned()
            .ok_or((StatusCode::FORBIDDEN, "wrong repository"))?;

        if !self.config.allowed_subs.contains(&claims.sub)
        {
            return Err((StatusCode::FORBIDDEN, "subject not allowed"));
        }

        self.claim_jti(&claims.jti).await?;

        let branch = claims
            .sub
            .split_once(":ref:refs/heads/")
            .map(|(_, b)| b.to_owned())
            .ok_or((StatusCode::FORBIDDEN, "subject carries no branch"))?;

        if branch.is_empty() || branch.starts_with('.') ||
            !branch.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            return Err((StatusCode::FORBIDDEN, "unusable branch name"));
        }

        Ok((prefix, branch))
    }
}
