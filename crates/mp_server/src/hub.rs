//! The lobby: online connections, the in-memory game model (games are ephemeral), and every WebSocket
//! request from `mp_api::ws`. Friends and stats live in SQLite; everything else here lives only as long as
//! the server process.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use mp_api::ws::{
    CreateGame, Friend, FriendOp, GameCreated, GameDetail, GameSummary, JoinAccepted, JoinDenyReason, Joinability,
    PlayerInfo, Privacy, Push, RelayAssignment, Request, Response, ServerFrame, StatValue, UpdateGame, UserRef,
};
use mp_api::{ApiError, ErrorCode, GameId, UserId, rules};
use tokio::sync::{mpsc, watch};

use crate::db::{Db, DbError};
use crate::relay::{Binding, RelayHandle};
use crate::util::{hex, now_unix, random_alnum, random_bytes, random_uuid};

/// WebSocket close code and reason a connection is told to close with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kill {
    pub code: u16,
    pub reason: &'static str,
}

/// RFC 6455 policy-violation close code.
pub const CLOSE_POLICY: u16 = 1008;

/// Length of the per-game `SECRET` (CGAM reply buffer holds up to [`rules::SECRET_MAX`]).
const SECRET_LEN: usize = 64;
/// Bytes of CSPRNG output in a relay session token (sent as hex).
const RELAY_TOKEN_BYTES: usize = 32;

struct Conn {
    conn_id: u64,
    pushes: mpsc::Sender<ServerFrame>,
    kill: watch::Sender<Option<Kill>>,
}

struct Player {
    user: UserRef,
    pid: u32,
    slot: u8,
}

struct PendingJoin {
    user: UserRef,
    slot: u8,
    /// Assigned with the request (EGRQ carries it) and kept on acceptance (EGEG carries the same value).
    pid: u32,
}

struct Game {
    id: GameId,
    host: UserId,
    name: String,
    max_players: u8,
    version: String,
    joinable: Joinability,
    attrs: BTreeMap<String, String>,
    details: BTreeMap<String, String>,
    privacy: Privacy,
    ekey: String,
    ugid: String,
    players: BTreeMap<UserId, Player>,
    pending: BTreeMap<u64, PendingJoin>,
    next_pid: u32,
}

impl Game {
    fn host_player(&self) -> &Player {
        self.players.get(&self.host).expect("game invariant: the host is always a player")
    }

    fn occupancy(&self) -> usize {
        self.players.len() + self.pending.len()
    }

    fn free_slot(&self) -> Option<u8> {
        let used: HashSet<u8> =
            self.players.values().map(|p| p.slot).chain(self.pending.values().map(|p| p.slot)).collect();
        (0..self.max_players).find(|s| !used.contains(s))
    }

    fn is_member(&self, user: UserId) -> bool {
        self.players.contains_key(&user) || self.pending.values().any(|p| p.user.user_id == user)
    }

    /// Members always see their game. Anyone else must present exactly the game's room key (both absent, or
    /// byte-identical keys) and, for a friends-only game, be a mutual friend of the host.
    fn visible_to(&self, user: UserId, room_key: Option<&str>, mutual_friends: &HashSet<UserId>) -> bool {
        if self.is_member(user) {
            return true;
        }
        if self.privacy.room_key.as_deref() != room_key {
            return false;
        }
        !self.privacy.friends_only || mutual_friends.contains(&self.host)
    }

    fn summary(&self) -> GameSummary {
        GameSummary {
            game_id: self.id,
            name: self.name.clone(),
            host: self.host_player().user.clone(),
            max_players: self.max_players,
            players: u8::try_from(self.players.len()).expect("player count is bounded by max_players (u8)"),
            joinable: self.joinable,
            version: self.version.clone(),
            attrs: self.attrs.clone(),
            private: self.privacy.room_key.is_some() || self.privacy.friends_only,
        }
    }

    fn detail(&self) -> GameDetail {
        GameDetail {
            summary: self.summary(),
            ugid: self.ugid.clone(),
            details: self.details.clone(),
            players: self
                .players
                .values()
                .map(|p| PlayerInfo { user: p.user.clone(), pid: p.pid, attrs: BTreeMap::new() })
                .collect(),
        }
    }
}

#[derive(Default)]
struct State {
    next_conn_id: u64,
    next_game_id: i64,
    next_join_id: u64,
    online: HashMap<UserId, Conn>,
    games: HashMap<GameId, Game>,
    /// The one game each user is hosting, playing in, or waiting to join.
    user_game: HashMap<UserId, GameId>,
    /// join_id → game.
    joins: HashMap<u64, GameId>,
}

pub struct Hub {
    state: Mutex<State>,
    db: Db,
    relay: RelayHandle,
    max_players_limit: u8,
}

fn api(code: ErrorCode, message: impl Into<String>) -> ApiError {
    ApiError::new(code, message)
}

fn db_error(e: DbError) -> ApiError {
    tracing::error!(error = %e, "database operation failed");
    api(ErrorCode::Internal, e.to_string())
}

fn rng_error(e: openssl::error::ErrorStack) -> ApiError {
    tracing::error!(error = %e, "CSPRNG failed");
    api(ErrorCode::Internal, format!("CSPRNG: {e}"))
}

fn check_prefixed(field: &str, prefix: &str, map: &BTreeMap<String, String>) -> Result<(), ApiError> {
    for key in map.keys() {
        if !key.starts_with(prefix) || key.len() == prefix.len() {
            return Err(api(ErrorCode::InvalidField, format!("{field}: key `{key}` must be `{prefix}` followed by a name")));
        }
    }
    Ok(())
}

fn check_non_empty(field: &str, value: &str) -> Result<(), ApiError> {
    if value.trim().is_empty() {
        return Err(api(ErrorCode::InvalidField, format!("{field}: must not be empty")));
    }
    Ok(())
}

/// An absent room key is always valid (public games); a present one must pass [`rules::check_room_key`].
fn check_room_key(key: Option<&str>) -> Result<(), ApiError> {
    key.map_or(Ok(()), rules::check_room_key)
}

impl Hub {
    pub fn new(db: Db, relay: RelayHandle, max_players_limit: u8) -> Hub {
        Hub { state: Mutex::new(State { next_game_id: 1, next_join_id: 1, ..State::default() }), db, relay, max_players_limit }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("hub state mutex poisoned by an earlier panic")
    }

    /// Registers a new connection for `user`. An existing connection for the same user is closed and its
    /// game state cleaned up first (reconnect takes over).
    pub fn register(
        &self,
        user: &UserRef,
        pushes: mpsc::Sender<ServerFrame>,
        kill: watch::Sender<Option<Kill>>,
    ) -> Result<u64, ApiError> {
        let mut st = self.lock();
        if let Some(old) = st.online.remove(&user.user_id) {
            old.kill.send_replace(Some(Kill { code: CLOSE_POLICY, reason: "superseded by a newer connection" }));
            self.cleanup_user(&mut st, user.user_id)?;
        }
        st.next_conn_id += 1;
        let conn_id = st.next_conn_id;
        st.online.insert(user.user_id, Conn { conn_id, pushes, kill });
        Ok(conn_id)
    }

    /// The connection `conn_id` of `user` ended.
    pub fn disconnect(&self, user: UserId, conn_id: u64) -> Result<(), ApiError> {
        let mut st = self.lock();
        if st.online.get(&user).is_some_and(|c| c.conn_id == conn_id) {
            st.online.remove(&user);
            self.cleanup_user(&mut st, user)?;
        }
        Ok(())
    }

    fn ensure_current(st: &State, user: UserId, conn_id: u64) -> Result<(), ApiError> {
        match st.online.get(&user) {
            Some(c) if c.conn_id == conn_id => Ok(()),
            _ => Err(api(ErrorCode::Unauthorized, "this connection was superseded by a newer one")),
        }
    }

    fn push(st: &State, to: UserId, push: Push) {
        let kind = push_kind(&push);
        let Some(conn) = st.online.get(&to) else {
            tracing::info!(user = to.0, push = kind, "push not delivered: user has no connection");
            return;
        };
        match conn.pushes.try_send(ServerFrame::Push { push }) {
            Ok(()) => tracing::info!(user = to.0, conn_id = conn.conn_id, push = kind, "push queued"),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(user = to.0, "outbound queue full; closing the connection");
                conn.kill.send_replace(Some(Kill { code: CLOSE_POLICY, reason: "outbound queue overflow" }));
            }
            // The receiver is gone only while that connection is shutting down; its `disconnect` runs the
            // cleanup that reflects this user's departure, so there is nobody left to deliver to.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    fn cleanup_user(&self, st: &mut State, user: UserId) -> Result<(), ApiError> {
        let Some(&game_id) = st.user_game.get(&user) else {
            return Ok(());
        };
        let game = st.games.get(&game_id).expect("user_game points at a live game");
        if game.host == user {
            self.remove_game(st, game_id)
        } else if game.players.contains_key(&user) {
            self.remove_player(st, game_id, user, false)
        } else {
            let join_id = game
                .pending
                .iter()
                .find(|(_, p)| p.user.user_id == user)
                .map(|(id, _)| *id)
                .expect("user_game points at a game where the user is a player or pending");
            Self::remove_pending(st, game_id, join_id);
            Ok(())
        }
    }

    fn remove_pending(st: &mut State, game_id: GameId, join_id: u64) -> PendingJoin {
        let game = st.games.get_mut(&game_id).expect("join index points at a live game");
        let pending = game.pending.remove(&join_id).expect("join index points at a pending join");
        st.joins.remove(&join_id);
        st.user_game.remove(&pending.user.user_id);
        pending
    }

    fn remove_game(&self, st: &mut State, game_id: GameId) -> Result<(), ApiError> {
        let game = st.games.remove(&game_id).expect("remove_game on a live game");
        for (uid, _) in game.players.iter() {
            st.user_game.remove(uid);
            if *uid != game.host {
                Self::push(st, *uid, Push::GameRemoved { game_id });
            }
        }
        for (join_id, pending) in game.pending.iter() {
            st.joins.remove(join_id);
            st.user_game.remove(&pending.user.user_id);
            Self::push(
                st,
                pending.user.user_id,
                Push::JoinDenied { join_id: *join_id, game_id, reason: JoinDenyReason::GameRemoved },
            );
        }
        self.relay.revoke_game(game_id).map_err(|e| api(ErrorCode::Internal, e.to_string()))
    }

    fn remove_player(&self, st: &mut State, game_id: GameId, user: UserId, kicked: bool) -> Result<(), ApiError> {
        let game = st.games.get_mut(&game_id).expect("remove_player on a live game");
        game.players.remove(&user).expect("remove_player on a player of the game");
        let others: Vec<UserId> = game.players.keys().copied().collect();
        st.user_game.remove(&user);
        if kicked {
            Self::push(st, user, Push::Kicked { game_id });
        }
        for other in others {
            Self::push(st, other, Push::PlayerLeft { game_id, user_id: user });
        }
        self.relay.revoke_user(game_id, user).map_err(|e| api(ErrorCode::Internal, e.to_string()))
    }

    fn relay_assignment(&self, game_id: GameId, user: UserId, slot: u8) -> Result<RelayAssignment, ApiError> {
        let token = hex(&random_bytes(RELAY_TOKEN_BYTES).map_err(rng_error)?);
        self.relay
            .register(token.clone().into_bytes(), Binding { game_id, user_id: user, slot })
            .map_err(|e| api(ErrorCode::Internal, e.to_string()))?;
        let info = self.relay.public();
        Ok(RelayAssignment {
            host: info.host.clone(),
            port: info.port,
            cert_sha256: info.cert_sha256.clone(),
            session_token: token,
            local_slot: slot,
            idle_timeout_secs: info.idle_timeout_secs,
        })
    }

    fn check_max_players(&self, max: u8) -> Result<(), ApiError> {
        if !(1..=self.max_players_limit).contains(&max) {
            return Err(api(ErrorCode::InvalidField, format!("max_players: must be 1-{}", self.max_players_limit)));
        }
        Ok(())
    }

    /// Answers one WebSocket request from `user` on connection `conn_id`, logging the request kind and its
    /// outcome (pings at debug, everything else at info) so an operator can follow a session from the log.
    pub async fn handle(&self, user: &UserRef, conn_id: u64, request: Request) -> Result<Response, ApiError> {
        let kind = request_kind(&request);
        let result = self.handle_inner(user, conn_id, request).await;
        let uid = user.user_id.0;
        match (&result, kind) {
            (Ok(_), "ping") => tracing::debug!(user = uid, conn_id, request = kind, "request answered"),
            (Ok(rsp), _) => tracing::info!(user = uid, conn_id, request = kind, response = response_kind(rsp), "request answered"),
            (Err(e), _) => tracing::info!(user = uid, conn_id, request = kind, code = ?e.code, error = %e.message, "request refused"),
        }
        result
    }

    async fn handle_inner(&self, user: &UserRef, conn_id: u64, request: Request) -> Result<Response, ApiError> {
        let uid = user.user_id;
        Self::ensure_current(&self.lock(), uid, conn_id)?;
        match request {
            Request::Ping => Ok(Response::Pong),
            Request::GamesList { joinable_only, room_key } => {
                check_room_key(room_key.as_deref())?;
                let friends = self.db.mutual_friends(uid).await.map_err(db_error)?;
                let st = self.lock();
                let mut games: Vec<GameSummary> = st
                    .games
                    .values()
                    .filter(|g| g.visible_to(uid, room_key.as_deref(), &friends))
                    .filter(|g| {
                        !joinable_only || (g.joinable != Joinability::Closed && g.occupancy() < g.max_players as usize)
                    })
                    .map(Game::summary)
                    .collect();
                games.sort_by_key(|g| g.game_id);
                Ok(Response::Games(games))
            }
            Request::GamesGet { game_id, room_key } => {
                check_room_key(room_key.as_deref())?;
                let friends = self.db.mutual_friends(uid).await.map_err(db_error)?;
                let st = self.lock();
                match st.games.get(&game_id) {
                    Some(g) if g.visible_to(uid, room_key.as_deref(), &friends) => Ok(Response::Game(g.detail())),
                    _ => Err(api(ErrorCode::NotFound, format!("game {}", game_id.0))),
                }
            }
            Request::GamesCreate(create) => self.create_game(user, conn_id, create),
            Request::GamesUpdate(update) => self.update_game(uid, conn_id, update),
            Request::GamesClose { game_id } => {
                let mut st = self.lock();
                Self::ensure_current(&st, uid, conn_id)?;
                let game = st.games.get(&game_id).ok_or_else(|| api(ErrorCode::NotFound, format!("game {}", game_id.0)))?;
                if game.host != uid {
                    return Err(api(ErrorCode::Forbidden, "only the host may close the game"));
                }
                self.remove_game(&mut st, game_id)?;
                Ok(Response::Ok)
            }
            Request::GamesJoin { game_id, room_key } => {
                check_room_key(room_key.as_deref())?;
                let friends = self.db.mutual_friends(uid).await.map_err(db_error)?;
                self.join_game(user, conn_id, game_id, room_key.as_deref(), &friends)
            }
            Request::JoinRespond { join_id, allowed, reason } => self.join_respond(uid, conn_id, join_id, allowed, reason),
            Request::PlayerEntered { game_id, user_id } => {
                let st = self.lock();
                Self::ensure_current(&st, uid, conn_id)?;
                let game = st.games.get(&game_id).ok_or_else(|| api(ErrorCode::NotFound, format!("game {}", game_id.0)))?;
                if game.host != uid {
                    return Err(api(ErrorCode::Forbidden, "only the host reports players entering"));
                }
                // PENT is the host confirming a joiner it already accepted; the only server-side check is that
                // the user is indeed a player of this game.
                if !game.players.contains_key(&user_id) {
                    return Err(api(ErrorCode::NotFound, format!("user {} is not in game {}", user_id.0, game_id.0)));
                }
                Ok(Response::Ok)
            }
            Request::PlayerLeft { game_id, user_id } => self.player_left(uid, conn_id, game_id, user_id),
            Request::FriendsList => {
                let friends = self.db.friends(uid).await.map_err(db_error)?;
                Ok(Response::Friends(friends.into_iter().map(|(user, mutual)| Friend { user, mutual }).collect()))
            }
            Request::FriendsAdd { username } => {
                let target = self
                    .db
                    .user_by_name(&username)
                    .await
                    .map_err(db_error)?
                    .ok_or_else(|| api(ErrorCode::NotFound, format!("user `{username}`")))?;
                if target.id == uid {
                    return Err(api(ErrorCode::InvalidField, "username: cannot add yourself"));
                }
                let mutual = self.db.add_friend(uid, target.id, now_unix()).await.map_err(db_error)?;
                Self::push(
                    &self.lock(),
                    target.id,
                    Push::FriendsUpdated { op: FriendOp::Add, friend: Friend { user: user.clone(), mutual } },
                );
                Ok(Response::Friends(vec![Friend {
                    user: UserRef { user_id: target.id, name: target.username },
                    mutual,
                }]))
            }
            Request::FriendsRemove { user_id } => {
                if !self.db.remove_friend(uid, user_id).await.map_err(db_error)? {
                    return Err(api(ErrorCode::NotFound, format!("user {} is not on your friend list", user_id.0)));
                }
                Self::push(
                    &self.lock(),
                    user_id,
                    Push::FriendsUpdated { op: FriendOp::Remove, friend: Friend { user: user.clone(), mutual: false } },
                );
                Ok(Response::Ok)
            }
            Request::StatsGet { owner, keys } => {
                if keys.is_empty() {
                    return Err(api(ErrorCode::InvalidField, "keys: must not be empty"));
                }
                if self.db.user_by_id(owner).await.map_err(db_error)?.is_none() {
                    return Err(api(ErrorCode::NotFound, format!("user {}", owner.0)));
                }
                Ok(Response::Stats(self.db.stats(owner, &keys).await.map_err(db_error)?))
            }
            Request::StatsUpdate { entries } => self.stats_update(uid, conn_id, entries).await,
            Request::UsersLookup { user_ids, names } => {
                if user_ids.is_empty() && names.is_empty() {
                    return Err(api(ErrorCode::InvalidField, "user_ids/names: at least one is required"));
                }
                Ok(Response::Users(self.db.lookup_users(&user_ids, &names).await.map_err(db_error)?))
            }
        }
    }

    fn create_game(&self, user: &UserRef, conn_id: u64, c: CreateGame) -> Result<Response, ApiError> {
        let uid = user.user_id;
        check_non_empty("name", &c.name)?;
        check_non_empty("version", &c.version)?;
        self.check_max_players(c.max_players)?;
        check_prefixed("attrs", "B-U-", &c.attrs)?;
        check_room_key(c.privacy.room_key.as_deref())?;
        let mut st = self.lock();
        Self::ensure_current(&st, uid, conn_id)?;
        if let Some(g) = st.user_game.get(&uid) {
            return Err(api(ErrorCode::Forbidden, format!("already in game {}", g.0)));
        }
        let ekey = random_alnum(rules::EKEY_LEN).map_err(rng_error)?;
        let secret = random_alnum(SECRET_LEN).map_err(rng_error)?;
        let ugid = random_uuid().map_err(rng_error)?;
        let game_id = GameId(st.next_game_id);
        st.next_game_id += 1;
        let host_slot = 0;
        let pid = 1;
        let relay = self.relay_assignment(game_id, uid, host_slot)?;
        let mut players = BTreeMap::new();
        players.insert(uid, Player { user: user.clone(), pid, slot: host_slot });
        st.games.insert(
            game_id,
            Game {
                id: game_id,
                host: uid,
                name: c.name,
                max_players: c.max_players,
                version: c.version,
                joinable: c.joinable,
                attrs: c.attrs,
                details: BTreeMap::new(),
                privacy: c.privacy,
                ekey: ekey.clone(),
                ugid: ugid.clone(),
                players,
                pending: BTreeMap::new(),
                next_pid: pid + 1,
            },
        );
        st.user_game.insert(uid, game_id);
        Ok(Response::GameCreated(GameCreated { game_id, pid, ekey, secret, ugid, relay }))
    }

    fn update_game(&self, uid: UserId, conn_id: u64, u: UpdateGame) -> Result<Response, ApiError> {
        if let Some(name) = &u.name {
            check_non_empty("name", name)?;
        }
        if let Some(max) = u.max_players {
            self.check_max_players(max)?;
        }
        if let Some(attrs) = &u.attrs {
            check_prefixed("attrs", "B-U-", attrs)?;
        }
        if let Some(details) = &u.details {
            check_prefixed("details", "D-", details)?;
        }
        let mut st = self.lock();
        Self::ensure_current(&st, uid, conn_id)?;
        let game = st.games.get_mut(&u.game_id).ok_or_else(|| api(ErrorCode::NotFound, format!("game {}", u.game_id.0)))?;
        if game.host != uid {
            return Err(api(ErrorCode::Forbidden, "only the host may update the game"));
        }
        if let Some(max) = u.max_players {
            let highest_slot = game.players.values().map(|p| p.slot).chain(game.pending.values().map(|p| p.slot)).max();
            if game.occupancy() > max as usize || highest_slot.is_some_and(|s| s >= max) {
                return Err(api(ErrorCode::InvalidField, "max_players: below the players and pending joins in the game"));
            }
            game.max_players = max;
        }
        if let Some(name) = u.name {
            game.name = name;
        }
        if let Some(j) = u.joinable {
            game.joinable = j;
        }
        if let Some(attrs) = u.attrs {
            game.attrs = attrs;
        }
        if let Some(details) = u.details {
            game.details = details;
        }
        Ok(Response::Ok)
    }

    fn join_game(
        &self,
        user: &UserRef,
        conn_id: u64,
        game_id: GameId,
        room_key: Option<&str>,
        friends: &HashSet<UserId>,
    ) -> Result<Response, ApiError> {
        let uid = user.user_id;
        let mut st = self.lock();
        Self::ensure_current(&st, uid, conn_id)?;
        if let Some(g) = st.user_game.get(&uid) {
            return Err(api(ErrorCode::Forbidden, format!("already in game {}", g.0)));
        }
        let join_id = st.next_join_id;
        let game = match st.games.get_mut(&game_id) {
            Some(g) if g.visible_to(uid, room_key, friends) => g,
            _ => return Err(api(ErrorCode::NotFound, format!("game {}", game_id.0))),
        };
        if game.joinable == Joinability::Closed {
            return Err(api(ErrorCode::GameClosed, "game is closed to joins"));
        }
        let slot = match game.free_slot() {
            Some(slot) if game.occupancy() < game.max_players as usize => slot,
            _ => return Err(api(ErrorCode::GameFull, format!("{}/{} players", game.occupancy(), game.max_players))),
        };
        let pid = game.next_pid;
        game.next_pid += 1;
        game.pending.insert(join_id, PendingJoin { user: user.clone(), slot, pid });
        let host = game.host;
        st.next_join_id += 1;
        st.joins.insert(join_id, game_id);
        st.user_game.insert(uid, game_id);
        Self::push(&st, host, Push::JoinRequest { join_id, game_id, user: user.clone(), slot, pid });
        Ok(Response::JoinPending { join_id })
    }

    fn join_respond(
        &self,
        uid: UserId,
        conn_id: u64,
        join_id: u64,
        allowed: bool,
        reason: Option<JoinDenyReason>,
    ) -> Result<Response, ApiError> {
        let mut st = self.lock();
        Self::ensure_current(&st, uid, conn_id)?;
        let game_id = *st.joins.get(&join_id).ok_or_else(|| api(ErrorCode::NotFound, format!("join request {join_id}")))?;
        if st.games[&game_id].host != uid {
            return Err(api(ErrorCode::Forbidden, "only the host may answer join requests"));
        }
        match (allowed, reason) {
            (true, Some(_)) => Err(api(ErrorCode::InvalidField, "reason: only allowed when denying")),
            (false, None) => Err(api(ErrorCode::InvalidField, "reason: required when denying")),
            (false, Some(JoinDenyReason::GameRemoved)) => {
                Err(api(ErrorCode::InvalidField, "reason: game_removed is sent only by the server"))
            }
            (false, Some(reason @ (JoinDenyReason::HostDenied { .. } | JoinDenyReason::MeshUnsupported))) => {
                let pending = Self::remove_pending(&mut st, game_id, join_id);
                Self::push(&st, pending.user.user_id, Push::JoinDenied { join_id, game_id, reason });
                Ok(Response::Ok)
            }
            (true, None) => {
                let game = &st.games[&game_id];
                let joiner = game.pending[&join_id].user.user_id;
                let slot = game.pending[&join_id].slot;
                let relay = self.relay_assignment(game_id, joiner, slot)?;
                let pending = {
                    let game = st.games.get_mut(&game_id).expect("checked above");
                    game.pending.remove(&join_id).expect("checked above")
                };
                st.joins.remove(&join_id);
                let game = st.games.get_mut(&game_id).expect("checked above");
                let pid = pending.pid;
                game.players.insert(joiner, Player { user: pending.user, pid, slot });
                let players = u8::try_from(game.players.len()).expect("player count is bounded by max_players (u8)");
                let host = game.host_player();
                let accepted = JoinAccepted {
                    join_id,
                    game_id,
                    host: host.user.clone(),
                    host_slot: host.slot,
                    pid,
                    ekey: game.ekey.clone(),
                    ugid: game.ugid.clone(),
                    relay,
                    players,
                };
                Self::push(&st, joiner, Push::JoinAccepted(accepted));
                Ok(Response::Ok)
            }
        }
    }

    fn player_left(&self, uid: UserId, conn_id: u64, game_id: GameId, user_id: UserId) -> Result<Response, ApiError> {
        let mut st = self.lock();
        Self::ensure_current(&st, uid, conn_id)?;
        let game = match st.games.get(&game_id) {
            Some(g) if g.is_member(uid) => g,
            _ => return Err(api(ErrorCode::NotFound, format!("game {}", game_id.0))),
        };
        if user_id == game.host {
            if uid != game.host {
                return Err(api(ErrorCode::Forbidden, "only the host may remove the host"));
            }
            self.remove_game(&mut st, game_id)?;
            return Ok(Response::Ok);
        }
        if uid != user_id && uid != game.host {
            return Err(api(ErrorCode::Forbidden, "only the host may remove another player"));
        }
        if game.players.contains_key(&user_id) {
            let kicked = uid != user_id;
            self.remove_player(&mut st, game_id, user_id, kicked)?;
            return Ok(Response::Ok);
        }
        if uid == user_id
            && let Some(join_id) = game.pending.iter().find(|(_, p)| p.user.user_id == uid).map(|(id, _)| *id)
        {
            // ECNL before the host answered: withdraw the join request.
            Self::remove_pending(&mut st, game_id, join_id);
            return Ok(Response::Ok);
        }
        Err(api(ErrorCode::NotFound, format!("user {} is not in game {}", user_id.0, game_id.0)))
    }

    async fn stats_update(&self, uid: UserId, conn_id: u64, entries: Vec<StatValue>) -> Result<Response, ApiError> {
        if entries.is_empty() {
            return Err(api(ErrorCode::InvalidField, "entries: must not be empty"));
        }
        for e in &entries {
            check_non_empty("entries.key", &e.key)?;
        }
        {
            let st = self.lock();
            Self::ensure_current(&st, uid, conn_id)?;
            let my_game = st.user_game.get(&uid).and_then(|g| st.games.get(g)).filter(|g| g.players.contains_key(&uid));
            for e in &entries {
                let allowed = e.owner == uid || my_game.is_some_and(|g| g.players.contains_key(&e.owner));
                if !allowed {
                    return Err(api(
                        ErrorCode::Forbidden,
                        format!("stats of user {} may only be written by that user or a player in their game", e.owner.0),
                    ));
                }
            }
        }
        self.db.update_stats(&entries, now_unix()).await.map_err(db_error)?;
        Ok(Response::Ok)
    }
}

/// The wire name of a request (`ws::Request`'s serde tag), for logs.
fn request_kind(r: &Request) -> &'static str {
    match r {
        Request::Ping => "ping",
        Request::GamesList { .. } => "games_list",
        Request::GamesGet { .. } => "games_get",
        Request::GamesCreate(_) => "games_create",
        Request::GamesUpdate(_) => "games_update",
        Request::GamesClose { .. } => "games_close",
        Request::GamesJoin { .. } => "games_join",
        Request::JoinRespond { .. } => "join_respond",
        Request::PlayerEntered { .. } => "player_entered",
        Request::PlayerLeft { .. } => "player_left",
        Request::FriendsList => "friends_list",
        Request::FriendsAdd { .. } => "friends_add",
        Request::FriendsRemove { .. } => "friends_remove",
        Request::StatsGet { .. } => "stats_get",
        Request::StatsUpdate { .. } => "stats_update",
        Request::UsersLookup { .. } => "users_lookup",
    }
}

/// The wire name of a push (`ws::Push`'s serde tag), for logs.
fn push_kind(p: &Push) -> &'static str {
    match p {
        Push::JoinRequest { .. } => "join_request",
        Push::JoinAccepted(_) => "join_accepted",
        Push::JoinDenied { .. } => "join_denied",
        Push::PlayerLeft { .. } => "player_left",
        Push::Kicked { .. } => "kicked",
        Push::GameRemoved { .. } => "game_removed",
        Push::FriendsUpdated { .. } => "friends_updated",
    }
}

/// The wire name of a response (`ws::Response`'s serde tag), for logs.
fn response_kind(r: &Response) -> &'static str {
    match r {
        Response::Pong => "pong",
        Response::Ok => "ok",
        Response::Games(_) => "games",
        Response::Game(_) => "game",
        Response::GameCreated(_) => "game_created",
        Response::JoinPending { .. } => "join_pending",
        Response::Friends(_) => "friends",
        Response::Stats(_) => "stats",
        Response::Users(_) => "users",
    }
}
