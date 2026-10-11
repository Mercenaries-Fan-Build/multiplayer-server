//! REST endpoints. Errors are returned as [`crate::ApiError`] JSON with a matching HTTP status.

use serde::{Deserialize, Serialize};

use crate::UserId;

/// `POST /v1/accounts` — from the game's `acct AddAccount`. The ASI forwards only these two fields; the
/// email / date-of-birth / zip / country / mail-flag fields the game also sends never leave the machine.
/// 201 on success; 409 `name_taken`; 422 `invalid_field`; 429 `rate_limited`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccount {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCreated {
    pub user_id: UserId,
    pub username: String,
}

/// Identifies the client build in every session request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    /// sha256 (hex) of the game executable's identifying sections, as the ASI computed it.
    pub build_sha256: String,
    /// The ASI's own version string.
    pub asi_version: String,
}

/// `POST /v1/sessions` — from the game's `acct Login` (`name` + `password`).
/// 200 on success; 401 `bad_credentials`; 422 `invalid_field`; 429 `rate_limited`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSession {
    pub username: String,
    pub password: String,
    pub client: ClientInfo,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCreated {
    /// Bearer token for `GET /v1/ws`. Opaque to the client.
    pub token: String,
    pub user_id: UserId,
    /// Canonical spelling of the username (becomes the game's `displayName`).
    pub display_name: String,
    /// Unix seconds.
    pub expires_at: i64,
}
