//! argon2id password hashing. Hashing and verification run on the blocking pool (they are CPU-bound by
//! design).

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::config::AccountsConfig;
use crate::util::random_bytes;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("argon2: {0}")]
    Hash(argon2::password_hash::Error),
    #[error("argon2 parameters: {0}")]
    Params(argon2::Error),
    #[error("CSPRNG: {0}")]
    Random(#[from] openssl::error::ErrorStack),
    #[error("password task: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub struct Passwords {
    params: Params,
    /// Hash of a random password, verified against when the username is unknown so that unknown-user and
    /// wrong-password take the same work.
    dummy_hash: String,
}

impl Passwords {
    pub fn new(cfg: &AccountsConfig) -> Result<Passwords, PasswordError> {
        let params = Params::new(cfg.argon2_memory_kib, cfg.argon2_iterations, cfg.argon2_parallelism, None)
            .map_err(PasswordError::Params)?;
        let dummy_password = random_bytes(32)?;
        let dummy_hash = hash_with(&params, &dummy_password)?;
        Ok(Passwords { params, dummy_hash })
    }

    pub async fn hash(&self, password: String) -> Result<String, PasswordError> {
        let params = self.params.clone();
        tokio::task::spawn_blocking(move || hash_with(&params, password.as_bytes())).await?
    }

    /// Verifies `password` against `stored`, or against the dummy hash when `stored` is `None`
    /// (in which case the result is always false).
    pub async fn verify(&self, password: String, stored: Option<String>) -> Result<bool, PasswordError> {
        let known = stored.is_some();
        let target = stored.unwrap_or_else(|| self.dummy_hash.clone());
        let params = self.params.clone();
        let ok = tokio::task::spawn_blocking(move || {
            let parsed = PasswordHash::new(&target).map_err(PasswordError::Hash)?;
            match argon2(&params).verify_password(password.as_bytes(), &parsed) {
                Ok(()) => Ok(true),
                Err(argon2::password_hash::Error::Password) => Ok(false),
                Err(e) => Err(PasswordError::Hash(e)),
            }
        })
        .await??;
        Ok(known && ok)
    }
}

fn argon2(params: &Params) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone())
}

fn hash_with(params: &Params, password: &[u8]) -> Result<String, PasswordError> {
    let salt_bytes = random_bytes(16)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(PasswordError::Hash)?;
    let hash = argon2(params).hash_password(password, &salt).map_err(PasswordError::Hash)?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap() -> AccountsConfig {
        AccountsConfig { session_ttl_secs: 60, argon2_memory_kib: 64, argon2_iterations: 1, argon2_parallelism: 1 }
    }

    #[tokio::test]
    async fn hash_and_verify() {
        let p = Passwords::new(&cheap()).unwrap();
        let h = p.hash("correct horse".into()).await.unwrap();
        assert!(h.starts_with("$argon2id$v=19$"));
        assert!(p.verify("correct horse".into(), Some(h.clone())).await.unwrap());
        assert!(!p.verify("wrong horse".into(), Some(h)).await.unwrap());
        assert!(!p.verify("anything".into(), None).await.unwrap());
    }
}
