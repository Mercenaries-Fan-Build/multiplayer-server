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
/// 200 on success, with `Cache-Control: no-store`; 401 `bad_credentials`; 422 `invalid_field`; 429 `rate_limited`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSession {
    pub username: String,
    pub password: String,
    pub client: ClientInfo,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCreated {
    /// Bearer token for `GET /v1/ws` and `GET /v1/sessions/current`. Opaque to the client.
    pub token: String,
    pub user_id: UserId,
    /// Canonical spelling of the username (becomes the game's `displayName`).
    pub display_name: String,
    /// Unix seconds.
    pub expires_at: i64,
}

/// `GET /v1/sessions/current` with `Authorization: Bearer <token>` (the [`SessionCreated::token`]); no body.
/// Names the account a session token belongs to, for services that verify a player's token. Read-only: the
/// session's expiry and state are unchanged. 200 on success, with `Cache-Control: no-store`; 401 `unauthorized`
/// (with a `WWW-Authenticate: Bearer` challenge) when the header is missing or malformed, or the token is unknown
/// or expired; 429 `rate_limited`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentSession {
    /// The account's server-assigned id ([`AccountCreated::user_id`], [`SessionCreated::user_id`]).
    pub account_id: UserId,
    /// Canonical spelling of the account's username.
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_session_wire_shape() {
        let s = CurrentSession { account_id: UserId(5), username: "Chris".into() };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"account_id":5,"username":"Chris"}"#);
        assert_eq!(serde_json::from_str::<CurrentSession>(&json).unwrap(), s);
    }

    #[test]
    fn current_session_requires_both_fields() {
        assert!(serde_json::from_str::<CurrentSession>(r#"{"account_id":5}"#).is_err());
        assert!(serde_json::from_str::<CurrentSession>(r#"{"username":"Chris"}"#).is_err());
        assert!(serde_json::from_str::<CurrentSession>(r#"{"account_id":"5","username":"Chris"}"#).is_err());
    }
}
