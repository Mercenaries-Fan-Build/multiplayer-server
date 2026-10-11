//! End-to-end tests against an in-process server (proxied TLS mode, ephemeral ports).

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::*;
use mp_api::relay::{Channel, Datagram};
use mp_api::ws::{
    CreateGame, FriendOp, GameCreated, GameSummary, JoinDenyReason, Joinability, Privacy, Push, Request, Response,
    StatValue, UpdateGame,
};
use mp_api::{ErrorCode, GameId, UserId, rules};
use openssl::ssl::ErrorCode as SslErrorCode;

fn create(name: &str, privacy: Privacy) -> Request {
    Request::GamesCreate(CreateGame {
        name: name.into(),
        max_players: 2,
        version: "1.1".into(),
        joinable: Joinability::Open,
        attrs: BTreeMap::from([("B-U-level".to_string(), "venezuela".to_string())]),
        privacy,
    })
}

fn created(r: Response) -> GameCreated {
    match r {
        Response::GameCreated(g) => g,
        other => panic!("expected game_created, got {other:?}"),
    }
}

fn join_id(r: Response) -> u64 {
    match r {
        Response::JoinPending { join_id } => join_id,
        other => panic!("expected join_pending, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn accounts_201_409_422_400() {
    let s = TestServer::start().await;
    let ip = Some("198.51.100.7");
    let (status, body) = s.post("/v1/accounts", r#"{"username":"Mattias","password":"hunter2hunter2"}"#, ip).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["username"], "Mattias");

    let (status, body) = s.post("/v1/accounts", r#"{"username":"mattias","password":"another-password"}"#, ip).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["code"], "name_taken");

    let (status, body) = s.post("/v1/accounts", r#"{"username":"has space","password":"long-enough"}"#, ip).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["code"], "invalid_field");
    let (status, body) = s.post("/v1/accounts", r#"{"username":"Jennifer","password":"short"}"#, ip).await;
    assert_eq!(status, 422, "{body}");

    let (status, body) = s.post("/v1/accounts", "not json", ip).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "invalid_field");
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_200_401_same_error_for_unknown_user() {
    let s = TestServer::start().await;
    let uid = s.create_account("Chris").await;
    let build = "ab".repeat(32);
    let lower = format!(r#"{{"username":"chris","password":"password-Chris","client":{{"build_sha256":"{build}","asi_version":"t"}}}}"#);
    let (status, body) = s.post("/v1/sessions", &lower, Some("198.51.100.1")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user_id"].as_i64(), Some(uid), "username lookup is case-insensitive");
    assert_eq!(body["display_name"], "Chris", "display name is the registered spelling");
    assert_eq!(body["token"].as_str().unwrap().len(), 64);

    let bad_pw = format!(r#"{{"username":"Chris","password":"wrong-password","client":{{"build_sha256":"{build}","asi_version":"t"}}}}"#);
    let unknown = format!(r#"{{"username":"Nobody","password":"wrong-password","client":{{"build_sha256":"{build}","asi_version":"t"}}}}"#);
    let (s1, b1) = s.post("/v1/sessions", &bad_pw, Some("198.51.100.1")).await;
    let (s2, b2) = s.post("/v1/sessions", &unknown, Some("198.51.100.1")).await;
    assert_eq!((s1, s2), (401, 401));
    assert_eq!(b1, b2, "unknown user and wrong password are indistinguishable");
    assert_eq!(b1["code"], "bad_credentials");

    let bad_build = r#"{"username":"Chris","password":"password-Chris","client":{"build_sha256":"xyz","asi_version":"t"}}"#;
    let (status, _) = s.post("/v1/sessions", bad_build, Some("198.51.100.1")).await;
    assert_eq!(status, 422);
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_is_per_forwarded_client_ip() {
    let s = TestServer::start_with(|c| {
        c.rate_limit.accounts = mp_server::config::BucketConfig { burst: 2, refill_per_minute: 1 };
    })
    .await;
    let body = |n: &str| format!(r#"{{"username":"{n}","password":"long-enough"}}"#);
    assert_eq!(s.post("/v1/accounts", &body("aaa"), Some("203.0.113.1")).await.0, 201);
    assert_eq!(s.post("/v1/accounts", &body("bbb"), Some("203.0.113.1")).await.0, 201);
    let (status, b) = s.post("/v1/accounts", &body("ccc"), Some("203.0.113.1")).await;
    assert_eq!(status, 429);
    assert_eq!(b["code"], "rate_limited");
    assert_eq!(s.post("/v1/accounts", &body("ddd"), Some("203.0.113.2")).await.0, 201, "other client unaffected");
}

#[tokio::test(flavor = "multi_thread")]
async fn trusted_proxy_request_without_forwarded_for_is_rejected() {
    let s = TestServer::start().await;
    let (status, body) = s.post("/v1/accounts", r#"{"username":"abc","password":"long-enough"}"#, None).await;
    assert_eq!(status, 400, "{body}");
    assert!(body["message"].as_str().unwrap().contains("X-Forwarded-For"));
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_requires_a_valid_bearer_token() {
    let s = TestServer::start().await;
    for auth in [None, Some("Bearer nope"), Some("Basic abc")] {
        let Err((status, body)) = s.ws_raw(auth).await else { panic!("upgrade accepted with {auth:?}") };
        assert_eq!(status, 401);
        let err: mp_api::ApiError = serde_json::from_str(&body).unwrap();
        assert_eq!(err.code, ErrorCode::Unauthorized);
    }
    let (mut ws, _) = s.user("Valid").await;
    assert_eq!(ws.request(Request::Ping).await.unwrap(), Response::Pong);
}

#[tokio::test(flavor = "multi_thread")]
async fn host_and_join_flow_with_pushes() {
    let s = TestServer::start().await;
    let (mut host, host_id) = s.user("Host").await;
    let (mut joiner, joiner_id) = s.user("Joiner").await;
    let (mut third, _) = s.user("Third").await;

    let game = created(host.request(create("Caracas run", Privacy::default())).await.unwrap());
    assert_eq!(game.ekey.len(), rules::EKEY_LEN);
    assert!(game.ekey.chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(!game.secret.is_empty() && game.secret.len() <= rules::SECRET_MAX);
    assert!(game.ugid.len() <= rules::UGID_MAX);
    assert_eq!(game.pid, 1);
    assert_eq!(game.relay.local_slot, 0);
    assert_eq!(game.relay.cert_sha256, s.relay_fingerprint);
    assert_eq!((game.relay.host.as_str(), game.relay.port), ("127.0.0.1", 1));
    assert_eq!(game.relay.idle_timeout_secs, 30);

    // A second game for the same host is refused.
    assert_eq!(host.request(create("again", Privacy::default())).await.unwrap_err().code, ErrorCode::Forbidden);

    let Response::Games(list) = joiner.request(Request::GamesList { joinable_only: true, room_key: None }).await.unwrap() else {
        panic!("expected games")
    };
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].host.user_id, UserId(host_id));
    assert!(!list[0].private);

    // Only the host may answer join requests.
    let jid = join_id(joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    let Push::JoinRequest { join_id: pushed_jid, game_id, user, slot, pid } = host.push().await else { panic!("expected join_request") };
    assert_eq!((pushed_jid, game_id, user.user_id, slot, pid), (jid, game.game_id, UserId(joiner_id), 1, 2));
    let err = joiner.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);

    // The game holds 2: the pending join reserves the second slot.
    assert_eq!(
        third.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap_err().code,
        ErrorCode::GameFull
    );

    assert_eq!(host.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap(), Response::Ok);
    let Push::JoinAccepted(acc) = joiner.push().await else { panic!("expected join_accepted") };
    assert_eq!(acc.game_id, game.game_id);
    assert_eq!(acc.host.user_id, UserId(host_id));
    assert_eq!(acc.host_slot, 0);
    assert_eq!(acc.pid, 2);
    assert_eq!(acc.ekey, game.ekey);
    assert_eq!(acc.ugid, game.ugid);
    assert_eq!(acc.relay.local_slot, 1);
    assert_ne!(acc.relay.session_token, game.relay.session_token);
    assert_eq!(acc.players, 2, "host and this joiner");

    assert_eq!(host.request(Request::PlayerEntered { game_id: game.game_id, user_id: UserId(joiner_id) }).await.unwrap(), Response::Ok);
    let Response::Game(detail) = joiner.request(Request::GamesGet { game_id: game.game_id, room_key: None }).await.unwrap() else {
        panic!("expected game")
    };
    assert_eq!(detail.players.len(), 2);
    assert_eq!(detail.summary.players, 2);

    // Host-only update; then the joiner leaves and the host is told.
    let upd = UpdateGame {
        game_id: game.game_id,
        name: None,
        max_players: None,
        joinable: Some(Joinability::Closed),
        attrs: None,
        details: Some(BTreeMap::from([("D-map".to_string(), "x".to_string())])),
    };
    assert_eq!(joiner.request(Request::GamesUpdate(upd.clone())).await.unwrap_err().code, ErrorCode::Forbidden);
    assert_eq!(host.request(Request::GamesUpdate(upd)).await.unwrap(), Response::Ok);
    assert_eq!(
        joiner.request(Request::PlayerLeft { game_id: game.game_id, user_id: UserId(joiner_id) }).await.unwrap(),
        Response::Ok
    );
    assert_eq!(host.push().await, Push::PlayerLeft { game_id: game.game_id, user_id: UserId(joiner_id) });
    assert_eq!(
        third.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap_err().code,
        ErrorCode::GameClosed,
        "closed to joins"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn join_denied_and_kick() {
    let s = TestServer::start().await;
    let (mut host, _) = s.user("Host").await;
    let (mut joiner, joiner_id) = s.user("Joiner").await;
    let game = created(host.request(create("g", Privacy::default())).await.unwrap());

    let jid = join_id(joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    host.push().await;
    let err = host.request(Request::JoinRespond { join_id: jid, allowed: false, reason: None }).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidField, "denying requires a reason");
    let err = host
        .request(Request::JoinRespond { join_id: jid, allowed: false, reason: Some(JoinDenyReason::GameRemoved) })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidField, "game_removed is the server's own reason");
    let err = host
        .request(Request::JoinRespond { join_id: jid, allowed: true, reason: Some(JoinDenyReason::MeshUnsupported) })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidField, "a reason only goes with a denial");
    let host_denied = JoinDenyReason::HostDenied { code: 2 };
    host.request(Request::JoinRespond { join_id: jid, allowed: false, reason: Some(host_denied) }).await.unwrap();
    assert_eq!(joiner.push().await, Push::JoinDenied { join_id: jid, game_id: game.game_id, reason: host_denied });
    assert_eq!(
        host.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap_err().code,
        ErrorCode::NotFound
    );

    let jid = join_id(joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    host.push().await;
    host.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap();
    joiner.push().await;
    host.request(Request::PlayerLeft { game_id: game.game_id, user_id: UserId(joiner_id) }).await.unwrap();
    assert_eq!(joiner.push().await, Push::Kicked { game_id: game.game_id });

    // The host's ASI refusing a second joiner (no relay mesh) reaches the joiner as mesh_unsupported.
    let jid = join_id(joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    host.push().await;
    host.request(Request::JoinRespond { join_id: jid, allowed: false, reason: Some(JoinDenyReason::MeshUnsupported) })
        .await
        .unwrap();
    assert_eq!(
        joiner.push().await,
        Push::JoinDenied { join_id: jid, game_id: game.game_id, reason: JoinDenyReason::MeshUnsupported }
    );

    // A request still pending when the host closes the game is denied with the server's game_removed.
    let jid = join_id(joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    host.push().await;
    host.request(Request::GamesClose { game_id: game.game_id }).await.unwrap();
    assert_eq!(
        joiner.push().await,
        Push::JoinDenied { join_id: jid, game_id: game.game_id, reason: JoinDenyReason::GameRemoved }
    );
}

const KEY: &str = "venezuela-42";

fn keyed(key: &str, friends_only: bool) -> Privacy {
    Privacy { room_key: Some(key.into()), friends_only }
}

async fn list(ws: &mut WsClient, room_key: Option<&str>) -> Vec<GameSummary> {
    match ws.request(Request::GamesList { joinable_only: false, room_key: room_key.map(String::from) }).await.unwrap() {
        Response::Games(games) => games,
        other => panic!("expected games, got {other:?}"),
    }
}

fn ids(games: &[GameSummary]) -> Vec<GameId> {
    games.iter().map(|g| g.game_id).collect()
}

fn join(game_id: GameId, room_key: Option<&str>) -> Request {
    Request::GamesJoin { game_id, room_key: room_key.map(String::from) }
}

#[tokio::test(flavor = "multi_thread")]
async fn games_sharing_a_room_key_are_listed_only_for_that_key() {
    let s = TestServer::start().await;
    let (mut host_a, _) = s.user("HostA").await;
    let (mut host_b, _) = s.user("HostB").await;
    let (mut host_c, _) = s.user("HostC").await;
    let (mut host_d, _) = s.user("HostD").await;
    let (mut viewer, _) = s.user("Viewer").await;

    // Keys are not unique: two live games share one.
    let a = created(host_a.request(create("keyed a", keyed(KEY, false))).await.unwrap());
    let b = created(host_b.request(create("keyed b", keyed(KEY, false))).await.unwrap());
    let c = created(host_c.request(create("public", Privacy::default())).await.unwrap());
    let d = created(host_d.request(create("other case", keyed("Venezuela-42", false))).await.unwrap());

    let same_key = list(&mut viewer, Some(KEY)).await;
    assert_eq!(ids(&same_key), vec![a.game_id, b.game_id], "both games hosted with the key, nothing else");
    assert!(same_key.iter().all(|g| g.private));

    let public = list(&mut viewer, None).await;
    assert_eq!(ids(&public), vec![c.game_id], "keyed games are absent from the keyless list");
    assert!(!public[0].private);

    assert_eq!(ids(&list(&mut viewer, Some("Venezuela-42")).await), vec![d.game_id], "keys are case-sensitive");
    assert!(list(&mut viewer, Some("no-such-room")).await.is_empty());

    let err = viewer.request(Request::GamesList { joinable_only: false, room_key: Some("abc".into()) }).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidField, "keys follow rules::check_room_key");
    let (mut host_e, _) = s.user("HostE").await;
    assert_eq!(host_e.request(create("bad key", keyed("no spaces!", false))).await.unwrap_err().code, ErrorCode::InvalidField);

    // GamesGet follows the same key rule; members see their own game regardless.
    let get = |game_id: GameId, key: Option<&str>| Request::GamesGet { game_id, room_key: key.map(String::from) };
    assert_eq!(viewer.request(get(a.game_id, None)).await.unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(viewer.request(get(a.game_id, Some("wrong-key"))).await.unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(viewer.request(get(c.game_id, Some(KEY))).await.unwrap_err().code, ErrorCode::NotFound);
    let Response::Game(detail) = viewer.request(get(a.game_id, Some(KEY))).await.unwrap() else { panic!() };
    assert_eq!(detail.summary.game_id, a.game_id);
    assert_eq!(ids(&list(&mut host_a, None).await), vec![a.game_id, c.game_id], "the host sees its own keyed game");
}

#[tokio::test(flavor = "multi_thread")]
async fn room_key_join_requires_the_exact_key() {
    let s = TestServer::start().await;
    let (mut host, host_id) = s.user("Host").await;
    let (mut public_host, _) = s.user("Public").await;
    let (mut joiner, joiner_id) = s.user("Joiner").await;
    let game = created(host.request(create("keyed", keyed(KEY, false))).await.unwrap());
    let public = created(public_host.request(create("public", Privacy::default())).await.unwrap());

    for key in [None, Some("wrong-key"), Some("VENEZUELA-42")] {
        let err = joiner.request(join(game.game_id, key)).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound, "joining the keyed game with {key:?}");
    }
    assert_eq!(
        joiner.request(join(public.game_id, Some(KEY))).await.unwrap_err().code,
        ErrorCode::NotFound,
        "a key only reaches games hosted with that key"
    );
    assert_eq!(joiner.request(join(game.game_id, Some("abc"))).await.unwrap_err().code, ErrorCode::InvalidField);
    host.assert_no_push().await;

    let jid = join_id(joiner.request(join(game.game_id, Some(KEY))).await.unwrap());
    let Push::JoinRequest { join_id: pushed, game_id, user, slot, .. } = host.push().await else { panic!("expected join_request") };
    assert_eq!((pushed, game_id, user.user_id, slot), (jid, game.game_id, UserId(joiner_id), 1));
    assert_eq!(host.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap(), Response::Ok);
    let Push::JoinAccepted(acc) = joiner.push().await else { panic!("expected join_accepted") };
    assert_eq!((acc.join_id, acc.game_id, acc.host.user_id, acc.host_slot, acc.pid), (jid, game.game_id, UserId(host_id), 0, 2));
    assert_eq!(acc.ekey, game.ekey);
    assert_eq!(acc.ugid, game.ugid);
    assert_eq!(acc.relay.local_slot, 1);

    assert_eq!(host.request(Request::PlayerEntered { game_id: game.game_id, user_id: UserId(joiner_id) }).await.unwrap(), Response::Ok);
    let Response::Game(detail) =
        joiner.request(Request::GamesGet { game_id: game.game_id, room_key: None }).await.unwrap()
    else {
        panic!("a player sees its game without presenting the key")
    };
    assert_eq!(detail.players.len(), 2);
    assert!(detail.summary.private);
}

#[tokio::test(flavor = "multi_thread")]
async fn friends_only_applies_on_top_of_the_room_key() {
    let s = TestServer::start().await;
    let (mut host, host_id) = s.user("Alpha").await;
    let (mut b, b_id) = s.user("Bravo").await;
    let game = created(host.request(create("keyed friends", keyed(KEY, true))).await.unwrap());

    assert!(list(&mut b, Some(KEY)).await.is_empty(), "the key alone does not reveal a friends-only game");
    assert_eq!(b.request(join(game.game_id, Some(KEY))).await.unwrap_err().code, ErrorCode::NotFound);

    host.request(Request::FriendsAdd { username: "Bravo".into() }).await.unwrap();
    b.push().await;
    b.request(Request::FriendsAdd { username: "Alpha".into() }).await.unwrap();
    host.push().await;

    assert!(list(&mut b, None).await.is_empty(), "friendship alone does not reveal a keyed game");
    assert_eq!(b.request(join(game.game_id, None)).await.unwrap_err().code, ErrorCode::NotFound);
    let listed = list(&mut b, Some(KEY)).await;
    assert_eq!(ids(&listed), vec![game.game_id]);
    assert_eq!(listed[0].host.user_id, UserId(host_id));

    let jid = join_id(b.request(join(game.game_id, Some(KEY))).await.unwrap());
    let Push::JoinRequest { join_id: pushed, user, .. } = host.push().await else { panic!("expected join_request") };
    assert_eq!((pushed, user.user_id), (jid, UserId(b_id)));
}

#[tokio::test(flavor = "multi_thread")]
async fn friends_push_mutual_and_friends_only_visibility() {
    let s = TestServer::start().await;
    let (mut a, a_id) = s.user("Alpha").await;
    let (mut b, b_id) = s.user("Bravo").await;
    let game = created(a.request(create("friends", Privacy { room_key: None, friends_only: true })).await.unwrap());

    let Response::Games(list) = b.request(Request::GamesList { joinable_only: false, room_key: None }).await.unwrap() else { panic!() };
    assert!(list.is_empty(), "not friends yet");

    let Response::Friends(added) = a.request(Request::FriendsAdd { username: "bravo".into() }).await.unwrap() else { panic!() };
    assert_eq!(added.len(), 1);
    assert_eq!((added[0].user.user_id, added[0].mutual), (UserId(b_id), false));
    let Push::FriendsUpdated { op, friend } = b.push().await else { panic!() };
    assert_eq!((op, friend.user.user_id, friend.mutual), (FriendOp::Add, UserId(a_id), false));

    let Response::Games(list) = b.request(Request::GamesList { joinable_only: false, room_key: None }).await.unwrap() else { panic!() };
    assert!(list.is_empty(), "one-way friendship does not reveal friends-only games");

    b.request(Request::FriendsAdd { username: "Alpha".into() }).await.unwrap();
    let Push::FriendsUpdated { op, friend } = a.push().await else { panic!() };
    assert_eq!((op, friend.user.user_id, friend.mutual), (FriendOp::Add, UserId(b_id), true));

    let Response::Friends(list) = a.request(Request::FriendsList).await.unwrap() else { panic!() };
    assert_eq!(list.len(), 1);
    assert!(list[0].mutual);
    let Response::Games(games) = b.request(Request::GamesList { joinable_only: false, room_key: None }).await.unwrap() else { panic!() };
    assert_eq!(games.len(), 1);
    assert_eq!(games[0].game_id, game.game_id);

    assert_eq!(a.request(Request::FriendsAdd { username: "alpha".into() }).await.unwrap_err().code, ErrorCode::InvalidField);
    assert_eq!(a.request(Request::FriendsAdd { username: "ghost".into() }).await.unwrap_err().code, ErrorCode::NotFound);

    a.request(Request::FriendsRemove { user_id: UserId(b_id) }).await.unwrap();
    let Push::FriendsUpdated { op, .. } = b.push().await else { panic!() };
    assert_eq!(op, FriendOp::Remove);
    assert_eq!(a.request(Request::FriendsRemove { user_id: UserId(b_id) }).await.unwrap_err().code, ErrorCode::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_writes_are_limited_to_self_and_game_mates() {
    let s = TestServer::start().await;
    let (mut host, host_id) = s.user("Host").await;
    let (mut mate, mate_id) = s.user("Mate").await;
    let (mut stranger, stranger_id) = s.user("Stranger").await;
    let stat = |owner: i64, v: &str| StatValue { owner: UserId(owner), key: "kills".into(), value: v.into() };

    host.request(Request::StatsUpdate { entries: vec![stat(host_id, "1.0000")] }).await.unwrap();
    let err = host.request(Request::StatsUpdate { entries: vec![stat(mate_id, "2.0000")] }).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden, "not in a game together");

    let game = created(host.request(create("g", Privacy::default())).await.unwrap());
    let jid = join_id(mate.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    host.push().await;
    host.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap();
    mate.push().await;

    host.request(Request::StatsUpdate { entries: vec![stat(mate_id, "2.0000")] }).await.unwrap();
    let err = stranger.request(Request::StatsUpdate { entries: vec![stat(host_id, "9.0000")] }).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    let err = host
        .request(Request::StatsUpdate { entries: vec![stat(host_id, "3.0000"), stat(stranger_id, "9.0000")] })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden, "one forbidden entry rejects the whole update");

    let Response::Stats(v) = stranger.request(Request::StatsGet { owner: UserId(mate_id), keys: vec!["kills".into()] }).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(v, vec![stat(mate_id, "2.0000")]);
    let Response::Stats(v) = stranger.request(Request::StatsGet { owner: UserId(host_id), keys: vec!["kills".into()] }).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(v, vec![stat(host_id, "1.0000")]);

    let Response::Users(users) = stranger
        .request(Request::UsersLookup { user_ids: vec![UserId(host_id), UserId(999)], names: vec!["MATE".into()] })
        .await
        .unwrap()
    else {
        panic!()
    };
    let names: Vec<&str> = users.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(names, vec!["Host", "Mate"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn host_disconnect_removes_game_and_player_disconnect_notifies() {
    let s = TestServer::start().await;
    let (mut host, _) = s.user("Host").await;
    let (mut joiner, joiner_id) = s.user("Joiner").await;
    let game = created(host.request(create("g", Privacy::default())).await.unwrap());
    let jid = join_id(joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    host.push().await;
    host.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap();
    joiner.push().await;

    joiner.ws.close(None).await.unwrap();
    assert_eq!(host.push().await, Push::PlayerLeft { game_id: game.game_id, user_id: UserId(joiner_id) });

    // Rejoin as a fresh connection, then the host drops.
    let (token, _) = s.login("Joiner").await;
    let mut joiner = s.ws_raw(Some(&format!("Bearer {token}"))).await.unwrap();
    let jid = join_id(joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    host.push().await;
    host.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap();
    joiner.push().await;
    drop(host);
    assert_eq!(joiner.push().await, Push::GameRemoved { game_id: game.game_id });
    assert_eq!(joiner.request(Request::GamesGet { game_id: game.game_id, room_key: None }).await.unwrap_err().code, ErrorCode::NotFound);
    joiner.assert_no_push().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_and_garbage_frames() {
    let s = TestServer::start().await;
    let (mut ws, _) = s.user("Probe").await;
    ws.send_text(r#"{"id":41,"type":"drop_tables"}"#).await;
    match ws.next_frame().await.unwrap() {
        mp_api::ws::ServerFrame::Error { id, error } => {
            assert_eq!(id, 41);
            assert_eq!(error.code, ErrorCode::Unsupported);
        }
        other => panic!("expected error frame, got {other:?}"),
    }
    ws.send_text("this is not json").await;
    let close = loop {
        match tokio::time::timeout(TIMEOUT, futures_util::StreamExt::next(&mut ws.ws)).await.unwrap() {
            Some(Ok(tokio_tungstenite::tungstenite::Message::Close(frame))) => break frame,
            Some(Ok(_)) => continue,
            other => panic!("expected a close frame, got {other:?}"),
        }
    };
    assert_eq!(u16::from(close.expect("close frame carries a code").code), 1008);
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnect_takes_over_the_previous_connection() {
    let s = TestServer::start().await;
    let (mut first, _) = s.user("Twice").await;
    created(first.request(create("g", Privacy::default())).await.unwrap());
    let (token, _) = s.login("Twice").await;
    let mut second = s.ws_raw(Some(&format!("Bearer {token}"))).await.unwrap();
    assert_eq!(second.request(Request::Ping).await.unwrap(), Response::Pong);
    assert!(first.next_frame().await.is_none(), "old connection is closed");
    let Response::Games(list) = second.request(Request::GamesList { joinable_only: false, room_key: None }).await.unwrap() else { panic!() };
    assert!(list.is_empty(), "the old connection's game went with it");
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_round_trip_rewrites_slot_and_drops_unauthenticated_data() {
    let s = TestServer::start().await;
    let (mut host, _) = s.user("Host").await;
    let (mut joiner, _) = s.user("Joiner").await;
    let game = created(host.request(create("relay", Privacy::default())).await.unwrap());
    let jid = join_id(joiner.request(Request::GamesJoin { game_id: game.game_id, room_key: None }).await.unwrap());
    host.push().await;
    host.request(Request::JoinRespond { join_id: jid, allowed: true, reason: None }).await.unwrap();
    let Push::JoinAccepted(acc) = joiner.push().await else { panic!() };

    let relay = s.relay_addr;
    let fp = game.relay.cert_sha256.clone();
    let host_token = game.relay.session_token.clone();
    let joiner_token = acc.relay.session_token.clone();
    let (host_slot, joiner_slot) = (acc.host_slot, acc.relay.local_slot);

    let (host_rx, joiner_rx) = tokio::task::spawn_blocking(move || {
        let mut a = dtls_connect(relay, &fp).unwrap();
        a.ssl_write(&Datagram::Hello { token: host_token.as_bytes() }.encode().unwrap()).unwrap();

        let mut b = dtls_connect(relay, &fp).unwrap();
        // Before Hello: must not be forwarded; a keepalive before Hello is counted too.
        b.ssl_write(&Datagram::Keepalive.encode().unwrap()).unwrap();
        b.ssl_write(&Datagram::Data { slot: host_slot, channel: Channel::Tunnel, payload: b"early" }.encode().unwrap())
            .unwrap();
        b.ssl_write(&Datagram::Hello { token: joiner_token.as_bytes() }.encode().unwrap()).unwrap();
        // A bound keepalive is accepted silently (no drop, nothing forwarded).
        b.ssl_write(&Datagram::Keepalive.encode().unwrap()).unwrap();
        // Unknown slot and garbage: dropped.
        b.ssl_write(&Datagram::Data { slot: 9, channel: Channel::Tunnel, payload: b"nobody" }.encode().unwrap()).unwrap();
        b.ssl_write(b"\x7fgarbage").unwrap();
        b.ssl_write(&Datagram::Data { slot: host_slot, channel: Channel::Tunnel, payload: b"from-b" }.encode().unwrap())
            .unwrap();

        let host_rx = dtls_recv(&mut a).unwrap().expect("host receives the joiner's datagram");
        a.ssl_write(&Datagram::Data { slot: joiner_slot, channel: Channel::Voice, payload: b"from-a" }.encode().unwrap())
            .unwrap();
        let joiner_rx = dtls_recv(&mut b).unwrap().expect("joiner receives the host's datagram");
        assert_eq!(dtls_recv(&mut a).unwrap(), None, "nothing else reached the host");
        (host_rx, (joiner_rx, a, b))
    })
    .await
    .unwrap();
    let (joiner_rx, a, b) = joiner_rx;

    assert_eq!(
        Datagram::decode(&host_rx).unwrap(),
        Datagram::Data { slot: joiner_slot, channel: Channel::Tunnel, payload: b"from-b" },
        "first datagram at the host is the post-hello one, with the sender's slot"
    );
    assert_eq!(
        Datagram::decode(&joiner_rx).unwrap(),
        Datagram::Data { slot: host_slot, channel: Channel::Voice, payload: b"from-a" }
    );
    let drops = s.relay.drop_counts().await.unwrap();
    assert_eq!(drops.get("data_before_hello"), Some(&1), "{drops:?}");
    assert_eq!(drops.get("unknown_slot"), Some(&1), "{drops:?}");
    assert_eq!(drops.get("unknown_tag"), Some(&1), "{drops:?}");
    assert_eq!(drops.get("keepalive_before_hello"), Some(&1), "{drops:?}");
    assert_eq!(drops.values().sum::<u64>(), 4, "the bound keepalive is not a drop: {drops:?}");

    // Closing the game tears the associations down: the joiner gets close_notify.
    host.request(Request::GamesClose { game_id: game.game_id }).await.unwrap();
    assert_eq!(joiner.push().await, Push::GameRemoved { game_id: GameId(game.game_id.0) });
    let joiner_after = tokio::task::spawn_blocking(move || {
        let mut b = b;
        let _keep_host_open = a;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match dtls_recv(&mut b) {
                Err(code) => return code,
                Ok(Some(d)) => panic!("unexpected datagram after close: {d:?}"),
                Ok(None) if std::time::Instant::now() < deadline => continue,
                Ok(None) => panic!("no close_notify within 5s"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(joiner_after, SslErrorCode::ZERO_RETURN);
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_rejects_wrong_certificate_pin() {
    let s = TestServer::start().await;
    let relay = s.relay_addr;
    let result = tokio::task::spawn_blocking(move || dtls_connect(relay, &"00".repeat(32)).map(|_| ())).await.unwrap();
    assert!(result.is_err(), "a client pinning another fingerprint must fail the handshake");
    let good = s.relay_fingerprint.clone();
    tokio::task::spawn_blocking(move || dtls_connect(relay, &good).map(|_| ())).await.unwrap().unwrap();
}
