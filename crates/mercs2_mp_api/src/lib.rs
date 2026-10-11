//! Control-plane API (v1) between the multiplayer ASI and the multiplayer server.
//!
//! The ASI terminates the game's FESL / Theater protocol locally (see `mercs2_plasma_proto` and
//! `docs/reverse_engineer/multiplayer_txn_catalogue.md`) and talks to the server only through this API:
//!
//! * [`rest`] — `POST /v1/accounts` and `POST /v1/sessions` (JSON over HTTPS).
//! * [`ws`] — one authenticated WebSocket at `GET /v1/ws` carrying every other request and all server pushes.
//! * [`relay`] — the datagram format inside each client's DTLS association with the relay.
//! * [`rules`] — field limits, most of them taken from the game client's own buffer sizes.

pub mod relay;
pub mod rest;
pub mod rules;
pub mod ws;

/// Version segment used in every route (`/v1/...`).
pub const API_VERSION: u32 = 1;

/// Machine-readable error codes shared by REST responses and WebSocket error replies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// A field failed a [`rules`] check; `message` names the field and rule.
    InvalidField,
    /// Username already registered.
    NameTaken,
    /// Wrong username or password (deliberately not distinguished).
    BadCredentials,
    /// Missing, expired or revoked session token.
    Unauthorized,
    /// Too many attempts from this client; retry later.
    RateLimited,
    /// The referenced game, user or join request does not exist (or is not visible to the caller).
    NotFound,
    /// The caller is not allowed to perform this action (e.g. not the host).
    Forbidden,
    /// The game has no free player slot (EGAM `'jden'` `REASON=f`).
    GameFull,
    /// The game is closed to joins (EGAM `'jden'` `REASON=c`).
    GameClosed,
    /// The host declined the join request.
    JoinDenied,
    /// The client sent a message type or version the server does not support.
    Unsupported,
    /// Server-side failure; `message` carries the reason.
    Internal,
}

/// Error body used by both REST and WebSocket replies.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError { code, message: message.into() }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

/// Server-assigned user id. Sent to the game as the 64-bit `userId` / `UID` it parses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct UserId(pub i64);

/// Server-assigned game id (`GID`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct GameId(pub i64);
