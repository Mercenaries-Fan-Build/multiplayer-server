//! WebSocket protocol at `GET /v1/ws` (Bearer token from [`crate::rest::SessionCreated`]).
//!
//! Every client message is a [`ClientFrame`] with a client-chosen `id`; the server answers each with exactly
//! one [`ServerFrame::Reply`] or [`ServerFrame::Error`] carrying the same id. [`ServerFrame::Push`] frames are
//! unsolicited. Text frames, one JSON object each.
//!
//! The comments name the game message each item stands in for (see
//! `docs/reverse_engineer/multiplayer_txn_catalogue.md`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ApiError, GameId, UserId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientFrame {
    pub id: u64,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerFrame {
    Reply { id: u64, response: Response },
    Error { id: u64, error: ApiError },
    Push { push: Push },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRef {
    pub user_id: UserId,
    pub name: String,
}

/// Theater `JOIN` / GDAT `J`: open, wait (host approval), closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Joinability {
    Open,
    Wait,
    Closed,
}

/// Who may see and join a hosted game.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Privacy {
    /// Room key ([`crate::rules::check_room_key`]). Keys are not unique: any number of live games may share
    /// one. A keyed game is listed, fetched and joinable only by clients presenting exactly the same key
    /// (case-sensitive byte comparison); a keyless game only by clients presenting no key. Comes from the
    /// host's ASI ini.
    pub room_key: Option<String>,
    /// When true, only the host's mutual friends see and may join the game. Applies on top of `room_key`.
    pub friends_only: bool,
}

/// A game as listed (Theater GDAT).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameSummary {
    pub game_id: GameId,
    /// GDAT `N`.
    pub name: String,
    /// GDAT `HN` / `HU`.
    pub host: UserRef,
    /// GDAT `MP`.
    pub max_players: u8,
    /// GDAT `AP`.
    pub players: u8,
    /// GDAT `J`.
    pub joinable: Joinability,
    /// GDAT `B-version`.
    pub version: String,
    /// GDAT `B-U-*` attributes, keys including the `B-U-` prefix.
    pub attrs: BTreeMap<String, String>,
    /// True when the game has a room key or is friends-only.
    pub private: bool,
}

/// One player in a game (Theater PDAT).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayerInfo {
    pub user: UserRef,
    /// PDAT `PID`.
    pub pid: u32,
    /// PDAT `P-*` attributes, keys including the `P-` prefix.
    pub attrs: BTreeMap<String, String>,
}

/// A game with its details and players (Theater GDAT + GDET + PDAT).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameDetail {
    pub summary: GameSummary,
    /// GDET `UGID`.
    pub ugid: String,
    /// GDET `D-*` attributes, keys including the `D-` prefix.
    pub details: BTreeMap<String, String>,
    pub players: Vec<PlayerInfo>,
}

/// Where and how a client reaches the relay for one game.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAssignment {
    pub host: String,
    pub port: u16,
    /// sha256 (hex) of the relay's DTLS certificate; the ASI pins it.
    pub cert_sha256: String,
    /// Authenticates this client's DTLS association ([`crate::relay::Datagram::Hello`]).
    pub session_token: String,
    /// This client's slot in the game. Peers are addressed by their slots.
    pub local_slot: u8,
    /// The relay closes an association after this many seconds without a datagram from it; clients send
    /// [`crate::relay::Datagram::Keepalive`] well within it while a game is quiet.
    pub idle_timeout_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateGame {
    /// CGAM `NAME`.
    pub name: String,
    /// CGAM `MAX-PLAYERS`.
    pub max_players: u8,
    /// CGAM `B-version`.
    pub version: String,
    /// CGAM `JOIN`.
    pub joinable: Joinability,
    /// CGAM `B-U-*`.
    pub attrs: BTreeMap<String, String>,
    pub privacy: Privacy,
}

/// Reply to [`Request::GamesCreate`] — becomes the CGAM reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameCreated {
    pub game_id: GameId,
    /// Host's own PID.
    pub pid: u32,
    /// ProtoTunnel key, exactly [`crate::rules::EKEY_LEN`] characters, CSPRNG per game.
    pub ekey: String,
    pub secret: String,
    pub ugid: String,
    pub relay: RelayAssignment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateGame {
    pub game_id: GameId,
    pub name: Option<String>,
    pub max_players: Option<u8>,
    pub joinable: Option<Joinability>,
    /// Replaces the whole `B-U-*` set when present.
    pub attrs: Option<BTreeMap<String, String>>,
    /// Replaces the whole `D-*` set when present (UGDE).
    pub details: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatValue {
    pub owner: UserId,
    pub key: String,
    /// Kept as the text the game sent (rank UpdateStats writes `%.4f`).
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Friend {
    pub user: UserRef,
    /// True when both users have added each other.
    pub mutual: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FriendOp {
    Add,
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum Request {
    /// Keepalive.
    Ping,
    /// Theater GLST / pnow browse. Only games visible to the caller are returned: with `room_key` set, only
    /// games hosted with exactly that key; without it, only keyless games (see [`Privacy::room_key`]).
    GamesList { joinable_only: bool, room_key: Option<String> },
    /// Theater GDAT (+GDET/PDAT). `room_key` must match the game's, as for [`Request::GamesList`]; the
    /// game's own players and pending joiners see it regardless.
    GamesGet { game_id: GameId, room_key: Option<String> },
    /// Theater CGAM.
    GamesCreate(CreateGame),
    /// Theater UGAM / UGDE.
    GamesUpdate(UpdateGame),
    /// Theater RGAM (host only).
    GamesClose { game_id: GameId },
    /// Theater EGAM. Answered with [`Response::JoinPending`]; the outcome arrives as a push. `room_key` must
    /// match the game's exactly (both absent, or both the same key); otherwise the game is not found.
    GamesJoin { game_id: GameId, room_key: Option<String> },
    /// Theater EGRS (host only), answering a [`Push::JoinRequest`]. `reason` is required when denying and
    /// refused when allowing; a host may send only [`JoinDenyReason::HostDenied`] or
    /// [`JoinDenyReason::MeshUnsupported`] (the other variants are the server's own).
    JoinRespond { join_id: u64, allowed: bool, reason: Option<JoinDenyReason> },
    /// Theater PENT (host confirms the player entered).
    PlayerEntered { game_id: GameId, user_id: UserId },
    /// Theater PLVT (host) or ECNL (joiner leaving).
    PlayerLeft { game_id: GameId, user_id: UserId },
    /// asso GetAssociations.
    FriendsList,
    /// asso AddAssociations.
    FriendsAdd { username: String },
    /// asso DeleteAssociations.
    FriendsRemove { user_id: UserId },
    /// rank GetRankedStats.
    StatsGet { owner: UserId, keys: Vec<String> },
    /// rank UpdateStats. Allowed for the caller and players sharing a game with the caller.
    StatsUpdate { entries: Vec<StatValue> },
    /// acct LookupUserInfo.
    UsersLookup { user_ids: Vec<UserId>, names: Vec<String> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum Response {
    Pong,
    Ok,
    Games(Vec<GameSummary>),
    Game(GameDetail),
    GameCreated(GameCreated),
    JoinPending { join_id: u64 },
    Friends(Vec<Friend>),
    Stats(Vec<StatValue>),
    Users(Vec<UserRef>),
}

/// Why a join request was denied, carried by [`Request::JoinRespond`] and [`Push::JoinDenied`]. The joiner's
/// ASI turns it into the `REASON` of the game's `'jden'` EGEG; no free text reaches the game.
///
/// The game's reason space is one integer (`docs/reverse_engineer/multiplayer_rewrite_re.md`, join-deny
/// reasons): the EGEG parser `FUN_00981490` maps the letters `f`→0, `r`→1, `c`→2, `t`→5, `q`→9, `h`→10 and
/// reads anything else as `%d`; the host's EGRS builder `FUN_0097b380` writes its reason as `%d`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JoinDenyReason {
    /// The host's game answered EGRS `ALLOWED=0`; `code` is its `REASON` integer, verbatim (e.g. 2 from the
    /// host's own gate `FUN_0098fc80`: participant denied because the game is closed). The joiner's game gets
    /// the same integer, as the exe's LAN Theater relays it (`FUN_009a0e80` → `FUN_0099cae0`).
    HostDenied { code: i32 },
    /// The host's ASI refused a second joiner: it links only host↔joiner, with no joiner↔joiner relay mesh.
    /// The joiner's game is told `f` (the game is full for this ASI).
    MeshUnsupported,
    /// The host closed or left the game while the request was pending (server-generated). The game has no
    /// evidenced code for this; the joiner's game is told `c` (closed), the closest one.
    GameRemoved,
}

/// Sent to the joiner when the host accepts — becomes EGEG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinAccepted {
    pub join_id: u64,
    pub game_id: GameId,
    pub host: UserRef,
    /// The host's relay slot (the joiner's ASI presents it as a loopback alias).
    pub host_slot: u8,
    /// The joiner's PID.
    pub pid: u32,
    pub ekey: String,
    pub ugid: String,
    pub relay: RelayAssignment,
    /// Players in the game once this joiner is in, the host included. The ASI links only host↔joiner, so it
    /// refuses an acceptance reporting more than 2.
    pub players: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum Push {
    /// To the host — becomes EGRQ. `slot` is the joiner's relay slot; `pid` is the PID the joiner gets if
    /// accepted (the same value [`JoinAccepted::pid`] carries), assigned when the request is made, as the
    /// game's own LAN Theater does in its EGRQ (`FUN_009aa140`).
    JoinRequest { join_id: u64, game_id: GameId, user: UserRef, slot: u8, pid: u32 },
    /// To the joiner — becomes EGEG.
    JoinAccepted(JoinAccepted),
    /// To the joiner — becomes a `'jden'` EGEG with the `REASON` [`JoinDenyReason`] maps to.
    JoinDenied { join_id: u64, game_id: GameId, reason: JoinDenyReason },
    /// To everyone else in the game.
    PlayerLeft { game_id: GameId, user_id: UserId },
    /// To a removed player — becomes KICK.
    Kicked { game_id: GameId },
    /// To remaining players when the host closed the game — becomes GREM.
    GameRemoved { game_id: GameId },
    /// asso NotifyAssociationUpdate.
    FriendsUpdated { op: FriendOp, friend: Friend },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_frame_wire_shape() {
        let cases = [
            (
                ClientFrame { id: 7, request: Request::GamesJoin { game_id: GameId(5), room_key: Some("venezuela-42".into()) } },
                r#"{"id":7,"type":"games_join","body":{"game_id":5,"room_key":"venezuela-42"}}"#,
            ),
            (
                ClientFrame { id: 8, request: Request::GamesJoin { game_id: GameId(5), room_key: None } },
                r#"{"id":8,"type":"games_join","body":{"game_id":5,"room_key":null}}"#,
            ),
            (
                ClientFrame { id: 9, request: Request::GamesList { joinable_only: true, room_key: Some("venezuela-42".into()) } },
                r#"{"id":9,"type":"games_list","body":{"joinable_only":true,"room_key":"venezuela-42"}}"#,
            ),
            (
                ClientFrame { id: 10, request: Request::GamesList { joinable_only: false, room_key: None } },
                r#"{"id":10,"type":"games_list","body":{"joinable_only":false,"room_key":null}}"#,
            ),
        ];
        for (f, expected) in cases {
            let json = serde_json::to_string(&f).unwrap();
            assert_eq!(json, expected);
            assert_eq!(serde_json::from_str::<ClientFrame>(&json).unwrap(), f);
        }
    }

    #[test]
    fn privacy_wire_shape() {
        let p = Privacy { room_key: Some("venezuela-42".into()), friends_only: true };
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, r#"{"room_key":"venezuela-42","friends_only":true}"#);
        assert_eq!(serde_json::from_str::<Privacy>(&json).unwrap(), p);
    }

    #[test]
    fn unit_request_has_no_body() {
        let json = serde_json::to_string(&ClientFrame { id: 1, request: Request::Ping }).unwrap();
        assert_eq!(json, r#"{"id":1,"type":"ping"}"#);
    }

    #[test]
    fn server_frames_round_trip() {
        let frames = vec![
            ServerFrame::Reply { id: 3, response: Response::JoinPending { join_id: 9 } },
            ServerFrame::Error { id: 4, error: ApiError::new(crate::ErrorCode::GameFull, "2/2 players") },
            ServerFrame::Push {
                push: Push::JoinRequest {
                    join_id: 9,
                    game_id: GameId(5),
                    user: UserRef { user_id: UserId(2), name: "Jen".into() },
                    slot: 1,
                    pid: 2,
                },
            },
        ];
        for f in frames {
            let json = serde_json::to_string(&f).unwrap();
            assert_eq!(serde_json::from_str::<ServerFrame>(&json).unwrap(), f, "{json}");
        }
    }

    #[test]
    fn join_deny_reason_wire_shape() {
        let cases = [
            (
                ClientFrame {
                    id: 11,
                    request: Request::JoinRespond { join_id: 9, allowed: false, reason: Some(JoinDenyReason::HostDenied { code: 2 }) },
                },
                r#"{"id":11,"type":"join_respond","body":{"join_id":9,"allowed":false,"reason":{"kind":"host_denied","code":2}}}"#,
            ),
            (
                ClientFrame {
                    id: 12,
                    request: Request::JoinRespond { join_id: 9, allowed: false, reason: Some(JoinDenyReason::MeshUnsupported) },
                },
                r#"{"id":12,"type":"join_respond","body":{"join_id":9,"allowed":false,"reason":{"kind":"mesh_unsupported"}}}"#,
            ),
            (
                ClientFrame { id: 13, request: Request::JoinRespond { join_id: 9, allowed: true, reason: None } },
                r#"{"id":13,"type":"join_respond","body":{"join_id":9,"allowed":true,"reason":null}}"#,
            ),
        ];
        for (f, expected) in cases {
            let json = serde_json::to_string(&f).unwrap();
            assert_eq!(json, expected);
            assert_eq!(serde_json::from_str::<ClientFrame>(&json).unwrap(), f);
        }
        let push = ServerFrame::Push {
            push: Push::JoinDenied { join_id: 9, game_id: GameId(5), reason: JoinDenyReason::GameRemoved },
        };
        let json = serde_json::to_string(&push).unwrap();
        assert_eq!(json, r#"{"kind":"push","push":{"type":"join_denied","body":{"join_id":9,"game_id":5,"reason":{"kind":"game_removed"}}}}"#);
        assert_eq!(serde_json::from_str::<ServerFrame>(&json).unwrap(), push);
        assert!(
            serde_json::from_str::<ClientFrame>(r#"{"id":1,"type":"join_respond","body":{"join_id":9,"allowed":false,"reason":"full"}}"#).is_err(),
            "free-text reasons are not part of the protocol"
        );
    }

    #[test]
    fn unknown_request_type_is_rejected() {
        assert!(serde_json::from_str::<ClientFrame>(r#"{"id":1,"type":"drop_tables"}"#).is_err());
    }
}
