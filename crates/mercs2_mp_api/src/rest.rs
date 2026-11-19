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
/// 200 on success, with `Cache-Control: no-store`; 400 `bad_credentials`; 422 `invalid_field`; 429 `rate_limited`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSession {
    pub username: String,
    pub password: String,
    pub client: ClientInfo,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCreated {
    /// Bearer token for `GET /v1/ws` and the leaderboard push and `me` routes. Opaque to the client.
    pub token: String,
    pub user_id: UserId,
    /// Canonical spelling of the username (becomes the game's `displayName`).
    pub display_name: String,
    /// Unix seconds.
    pub expires_at: i64,
}

// Leaderboards. `{board}` is any name passing [`crate::rules::check_board_name`]; scores are
// 0..=[`crate::rules::LEADERBOARD_SCORE_MAX`]. A board orders its entries by score descending, then `updated_at`
// ascending (who reached the score first), then user id ascending; a rank is the 1-based position in that order.
// Accounts banned from leaderboards are left out of every list, rank and total.

/// `PUT /v1/leaderboards/{board}/score` with `Authorization: Bearer <token>` (the [`SessionCreated::token`]).
/// The server keeps each player's best score per board: a push equal to or below the stored score leaves the
/// stored row (and its `updated_at`) unchanged. 200 [`LeaderboardEntry`] (the player's standing after the push),
/// with `Cache-Control: no-store`; 401 `unauthorized` (with a `WWW-Authenticate: Bearer` challenge) when the header
/// is missing or malformed, or the token is unknown or expired; 422 `invalid_field` (board or score); 403
/// `forbidden` when the account is banned from leaderboards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushScore {
    pub score: u32,
}

/// A player's standing on one board: the body of `PUT /v1/leaderboards/{board}/score` and of
/// `GET /v1/leaderboards/{board}/me`.
///
/// `GET /v1/leaderboards/{board}/me` with `Authorization: Bearer <token>`; no body. 200 with
/// `Cache-Control: no-store`; `rank: 0, score: 0` means the player has no entry on the board (also the answer for
/// a banned account, which is left out of every rank). 401 `unauthorized` and 422 `invalid_field` as for the push.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub rank: u32,
    pub score: u32,
}

/// `GET /v1/leaderboards/{board}?from=<rank>&count=<n>` — public, no authentication. `from` is the 1-based rank
/// of the first row (default 1); `count` is 1-100 rows (default 30). 200 [`LeaderboardPage`]; 422 `invalid_field`
/// for the board, `from` or `count`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderboardPage {
    pub board: String,
    /// Entries on the board from unbanned accounts.
    pub total: u32,
    /// Ranks `from` onward, in board order; empty past the last entry.
    pub rows: Vec<LeaderboardRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderboardRow {
    pub rank: u32,
    pub user_id: UserId,
    /// Canonical spelling of the account's username.
    pub display_name: String,
    pub score: u32,
    /// Unix seconds when the player first reached this score.
    pub updated_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaderboard_wire_shapes() {
        assert_eq!(serde_json::to_string(&PushScore { score: 7 }).unwrap(), r#"{"score":7}"#);
        assert_eq!(serde_json::to_string(&LeaderboardEntry { rank: 2, score: 9 }).unwrap(), r#"{"rank":2,"score":9}"#);
        let page = LeaderboardPage {
            board: "DlcCon001".into(),
            total: 1,
            rows: vec![LeaderboardRow {
                rank: 1,
                user_id: UserId(5),
                display_name: "Chris".into(),
                score: 1000,
                updated_at: 1_800_000_000,
            }],
        };
        let json = serde_json::to_string(&page).unwrap();
        assert_eq!(
            json,
            r#"{"board":"DlcCon001","total":1,"rows":[{"rank":1,"user_id":5,"display_name":"Chris","score":1000,"updated_at":1800000000}]}"#
        );
        assert_eq!(serde_json::from_str::<LeaderboardPage>(&json).unwrap(), page);
    }

    #[test]
    fn push_score_rejects_non_u32() {
        for bad in [r#"{"score":-1}"#, r#"{"score":1.5}"#, r#"{"score":"7"}"#, r#"{"score":4294967296}"#, "{}"] {
            assert!(serde_json::from_str::<PushScore>(bad).is_err(), "{bad}");
        }
    }
}
