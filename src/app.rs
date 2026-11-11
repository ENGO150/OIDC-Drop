use std::
{
    fs::File,
    time::Instant,
    collections::HashMap,
    sync::
    {
        Arc,
        Mutex as StdMutex,
    },
};

use tokio::
{
    task,
    sync::
    {
        Mutex,
        RwLock,
        Semaphore,
        OwnedMutexGuard,
        OwnedSemaphorePermit,
    },
};

use axum::http::{ HeaderMap, StatusCode };
use reqwest::{ Client, Response };
use serde::Deserialize;
use futures_util::StreamExt;

use jsonwebtoken::
{
    Algorithm,
    Validation,
    DecodingKey,
    jwk::
    {
        JwkSet,
        KeyAlgorithm,
        PublicKeyUse,
        KeyOperations,
        AlgorithmParameters,
    },
};

use crate::
{
    consts,
    config::{ self, Config },
    storage::{ self, Replay, Staging },
};

#[cfg(test)]
#[path = "tests/app.rs"]
mod tests;

//STRUCTS
#[derive(Default)]
pub(crate) struct Keys
{
    pub(crate) keys: HashMap<String, DecodingKey>,
    pub(crate) fetched: Option<Instant>,
    attempted: Option<Instant>,
}

pub(crate) struct App
{
    pub(crate) config: Config,
    pub(crate) directory_locks: Arc<Vec<File>>,
    pub(crate) http: Client,
    pub(crate) keys: RwLock<Keys>,
    pub(crate) refresh: Mutex<()>,
    pub(crate) replay: Arc<StdMutex<Replay>>,
    pub(crate) staging: Arc<StdMutex<Staging>>,
    pub(crate) slots: Arc<Semaphore>,
    pub(crate) assets: StdMutex<HashMap<String, Arc<Mutex<()>>>>,
}

#[derive(Deserialize)]
struct Claims
{
    sub: String,
    jti: String,
    repository_id: String,
    repository_owner_id: String,
    exp: u64,
    iat: u64,
    nbf: u64,
}

//TYPES
pub(crate) type Fail = (StatusCode, &'static str);

//IMPLEMENTATIONS
impl App
{
    pub(crate) fn admit(&self) -> Result<OwnedSemaphorePermit, Fail>
    {
        self.slots.clone().try_acquire_owned()
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "upload capacity reached"))
    }

    pub(crate) fn lock_asset(&self, asset: &str) -> Result<OwnedMutexGuard<()>, Fail>
    {
        let mut assets = self.assets.lock().expect("asset lock poisoned");
        assets.retain(|_, lock| Arc::strong_count(lock) > 1);
        assets.entry(asset.to_owned()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
            .try_lock_owned().map_err(|_| (StatusCode::CONFLICT, "artifact upload busy"))
    }

    async fn key_for(&self, kid: &str) -> Result<DecodingKey, Fail>
    {
        self.key_for_url(kid, consts::JWKS_URL).await
    }

    async fn key_for_url(&self, kid: &str, url: &str) -> Result<DecodingKey, Fail>
    {
        {
            let keys = self.keys.read().await;

            if keys.fetched.is_some_and(|at| at.elapsed() < consts::JWKS_MIN_REFRESH)
            {
                return keys.keys.get(kid).cloned()
                    .ok_or((StatusCode::UNAUTHORIZED, "unknown key id"));
            }
        }

        let _refresh = self.refresh.try_lock()
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "issuer keys refreshing"))?;
        {
            let mut keys = self.keys.write().await;
            //RECHECK AFTER ACQUIRING REFRESH
            if keys.fetched.is_some_and(|at| at.elapsed() < consts::JWKS_MIN_REFRESH)
            {
                return keys.keys.get(kid).cloned()
                    .ok_or((StatusCode::UNAUTHORIZED, "unknown key id"));
            }

            if keys.attempted.is_some_and(|at| at.elapsed() < consts::JWKS_FAILURE_BACKOFF)
            {
                return Err((StatusCode::SERVICE_UNAVAILABLE, "issuer keys unavailable"));
            }

            keys.attempted = Some(Instant::now());
        }

        //REFRESH WITHOUT THE CACHE LOCK
        let response = self.http.get(url).send().await.and_then(Response::error_for_status)
            .map_err(|_| (StatusCode::BAD_GATEWAY, "cannot reach the issuer"))?;

        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();

        while let Some(chunk) = stream.next().await
        {
            let chunk = chunk.map_err(|_| (StatusCode::BAD_GATEWAY, "cannot read issuer keys"))?;

            if bytes.len() + chunk.len() > 256 * 1024
            {
                return Err((StatusCode::BAD_GATEWAY, "issuer key set too large"));
            }

            bytes.extend_from_slice(&chunk);
        }

        let set: JwkSet = serde_json::from_slice(&bytes)
            .map_err(|_| (StatusCode::BAD_GATEWAY, "malformed key set"))?;

        let fresh: HashMap<_, _> = set.keys.iter()
            .filter(|key|
            {
                matches!(key.algorithm, AlgorithmParameters::RSA(_))
                    && key.common.key_algorithm.is_none_or(|alg| alg == KeyAlgorithm::RS256)
                    && key.common.public_key_use.as_ref()
                        .is_none_or(|usage| *usage == PublicKeyUse::Signature)
                    && key.common.key_operations.as_ref()
                        .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
            })
            .filter_map(|key| Some((key.common.key_id.clone()?, DecodingKey::from_jwk(key).ok()?)))
            .collect();

        if fresh.is_empty()
        {
            return Err((StatusCode::BAD_GATEWAY, "empty key set"));
        }

        let mut keys = self.keys.write().await;
        keys.keys = fresh;
        keys.fetched = Some(Instant::now());
        keys.keys.get(kid).cloned().ok_or((StatusCode::UNAUTHORIZED, "unknown key id"))
    }

    pub(crate) async fn authenticate(&self, headers: &HeaderMap) -> Result<(String, String), Fail>
    {
        let token = headers.get("authorization").and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ")).filter(|token| token.len() <= 16384).ok_or
            ((
                StatusCode::UNAUTHORIZED,
                "missing or oversized bearer token",
            ))?;

        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "bad token"))?;

        if header.alg != Algorithm::RS256
        {
            return Err((StatusCode::UNAUTHORIZED, "unsupported token algorithm"));
        }

        let kid = header.kid.filter(|kid| kid.len() <= 256)
            .ok_or((StatusCode::UNAUTHORIZED, "invalid key id"))?;

        let key = self.key_for(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[consts::ISSUER]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = consts::CLOCK_LEEWAY;

        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "token rejected"))?.claims;

        let now = storage::now();

        if claims.jti.is_empty()
            || claims.jti.len() > 256
            || claims.iat > now.saturating_add(consts::CLOCK_LEEWAY)
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > consts::MAX_TOKEN_LIFETIME
            || claims.nbf > claims.exp
        {
            return Err((StatusCode::UNAUTHORIZED, "invalid token lifetime or ID"));
        }

        if claims.repository_owner_id != self.config.repository_owner_id
        {
            return Err((StatusCode::FORBIDDEN, "wrong owner"));
        }

        let prefix = self.config.prefixes.get(&claims.repository_id).cloned()
            .ok_or((StatusCode::FORBIDDEN, "wrong repository"))?;

        if !self.config.allowed_subs.contains(&claims.sub)
        {
            return Err((StatusCode::FORBIDDEN, "subject not allowed"));
        }

        let branch = claims.sub.split_once(":ref:refs/heads/").map(|(_, b)| b.to_owned())
            .filter(|b| config::safe_component(b))
            .ok_or((StatusCode::FORBIDDEN, "unusable branch name"))?;

        let replay = self.replay.clone();
        task::spawn_blocking(move ||
        {
            replay.lock().expect("replay lock poisoned")
                .claim(&claims.jti, claims.exp.saturating_add(consts::CLOCK_LEEWAY))
        }).await.map_err(|_|
        {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "token storage task failed",
            )
        })??;

        Ok((prefix, branch))
    }
}
