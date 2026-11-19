//! SQLite persistence: accounts, sessions, friends, stats. Migrations are embedded in the binary.

use std::collections::HashSet;
use std::path::Path;

use mercs2_mp_api::UserId;
use mercs2_mp_api::rest::{LeaderboardEntry, LeaderboardPage, LeaderboardRow};
use mercs2_mp_api::ws::{StatValue, UserRef};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use sqlx::Row;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("database migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("username already registered")]
    NameTaken,
    #[error("database value {what} = {value} does not fit its API type")]
    OutOfRange { what: &'static str, value: i64 },
}

/// One leaderboard ban.
pub struct LeaderboardBan {
    pub reason: String,
    pub created_at: i64,
}

/// Unbanned entries of a board, in board order: score descending, then who reached it first, then user id.
/// `leaderboard_scores_order` (migration 0002) serves the filter and the order.
const BOARD_ORDER_SQL: &str = "SELECT s.user_id, u.username, s.score, s.updated_at FROM leaderboard_scores s \
     JOIN users u ON u.id = s.user_id \
     WHERE s.board = ? AND NOT EXISTS (SELECT 1 FROM leaderboard_bans b WHERE b.user_id = s.user_id) \
     ORDER BY s.score DESC, s.updated_at ASC, s.user_id ASC LIMIT ? OFFSET ?";

/// One player's unbanned entry and its rank (1 + the unbanned entries ahead of it in board order).
const STANDING_SQL: &str = "SELECT s.score, 1 + (SELECT count(*) FROM leaderboard_scores o \
         WHERE o.board = s.board \
           AND NOT EXISTS (SELECT 1 FROM leaderboard_bans b WHERE b.user_id = o.user_id) \
           AND (o.score > s.score \
                OR (o.score = s.score AND (o.updated_at < s.updated_at \
                    OR (o.updated_at = s.updated_at AND o.user_id < s.user_id))))) AS rank \
     FROM leaderboard_scores s \
     WHERE s.board = ? AND s.user_id = ? AND NOT EXISTS (SELECT 1 FROM leaderboard_bans b WHERE b.user_id = s.user_id)";

fn to_u32(what: &'static str, value: i64) -> Result<u32, DbError> {
    u32::try_from(value).map_err(|_| DbError::OutOfRange { what, value })
}

/// The standing of `user` on `board`; `rank: 0, score: 0` when the player has no unbanned entry.
async fn standing<'e, E: sqlx::SqliteExecutor<'e>>(e: E, board: &str, user: UserId) -> Result<LeaderboardEntry, DbError> {
    let row = sqlx::query(STANDING_SQL).bind(board).bind(user.0).fetch_optional(e).await?;
    match row {
        None => Ok(LeaderboardEntry { rank: 0, score: 0 }),
        Some(r) => Ok(LeaderboardEntry {
            rank: to_u32("leaderboard rank", r.try_get("rank")?)?,
            score: to_u32("leaderboard_scores.score", r.try_get("score")?)?,
        }),
    }
}

#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
}

pub struct StoredUser {
    pub id: UserId,
    pub username: String,
    pub password_hash: String,
}

pub struct SessionRow {
    pub user: UserRef,
    pub expires_at: i64,
}

impl Db {
    pub async fn open(path: &Path) -> Result<Db, DbError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new().connect_with(options).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Db { pool })
    }

    pub async fn create_user(&self, username: &str, password_hash: &str, now: i64) -> Result<UserId, DbError> {
        let result = sqlx::query("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)")
            .bind(username)
            .bind(password_hash)
            .bind(now)
            .execute(&self.pool)
            .await;
        match result {
            Ok(done) => Ok(UserId(done.last_insert_rowid())),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(DbError::NameTaken),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn user_by_name(&self, username: &str) -> Result<Option<StoredUser>, DbError> {
        let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| {
            Ok(StoredUser {
                id: UserId(r.try_get("id")?),
                username: r.try_get("username")?,
                password_hash: r.try_get("password_hash")?,
            })
        })
        .transpose()
    }

    pub async fn user_by_id(&self, id: UserId) -> Result<Option<UserRef>, DbError> {
        let row = sqlx::query("SELECT id, username FROM users WHERE id = ?").bind(id.0).fetch_optional(&self.pool).await?;
        row.map(|r| user_ref(&r)).transpose()
    }

    /// Users matching any of the ids or (case-insensitive) names, each user once, ordered by id.
    pub async fn lookup_users(&self, ids: &[UserId], names: &[String]) -> Result<Vec<UserRef>, DbError> {
        let mut found = std::collections::BTreeMap::new();
        for id in ids {
            if let Some(u) = self.user_by_id(*id).await? {
                found.insert(u.user_id, u);
            }
        }
        for name in names {
            if let Some(u) = self.user_by_name(name).await? {
                found.insert(u.id, UserRef { user_id: u.id, name: u.username });
            }
        }
        Ok(found.into_values().collect())
    }

    pub async fn create_session(
        &self,
        token_sha256: &[u8],
        user_id: UserId,
        now: i64,
        expires_at: i64,
        build_sha256: &str,
        asi_version: &str,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?").bind(now).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO sessions (token_sha256, user_id, created_at, expires_at, build_sha256, asi_version) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(token_sha256)
        .bind(user_id.0)
        .bind(now)
        .bind(expires_at)
        .bind(build_sha256)
        .bind(asi_version)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The session for a token hash, if it exists and has not expired at `now`.
    pub async fn session(&self, token_sha256: &[u8], now: i64) -> Result<Option<SessionRow>, DbError> {
        let row = sqlx::query(
            "SELECT u.id, u.username, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.token_sha256 = ? AND s.expires_at > ?",
        )
        .bind(token_sha256)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| Ok(SessionRow { user: user_ref(&r)?, expires_at: r.try_get("expires_at")? })).transpose()
    }

    /// Adds `friend` to `user`'s list (idempotent). Returns whether the friendship is now mutual.
    pub async fn add_friend(&self, user: UserId, friend: UserId, now: i64) -> Result<bool, DbError> {
        sqlx::query(
            "INSERT INTO friends (user_id, friend_id, created_at) VALUES (?, ?, ?) \
             ON CONFLICT (user_id, friend_id) DO NOTHING",
        )
        .bind(user.0)
        .bind(friend.0)
        .bind(now)
        .execute(&self.pool)
        .await?;
        self.has_friend(friend, user).await
    }

    /// Removes `friend` from `user`'s list. Returns false when it was not on the list.
    pub async fn remove_friend(&self, user: UserId, friend: UserId) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM friends WHERE user_id = ? AND friend_id = ?")
            .bind(user.0)
            .bind(friend.0)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn has_friend(&self, user: UserId, friend: UserId) -> Result<bool, DbError> {
        let row = sqlx::query("SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?")
            .bind(user.0)
            .bind(friend.0)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// `user`'s friend list with the mutual flag.
    pub async fn friends(&self, user: UserId) -> Result<Vec<(UserRef, bool)>, DbError> {
        let rows = sqlx::query(
            "SELECT u.id, u.username, \
                    EXISTS (SELECT 1 FROM friends r WHERE r.user_id = f.friend_id AND r.friend_id = f.user_id) AS mutual \
             FROM friends f JOIN users u ON u.id = f.friend_id WHERE f.user_id = ? ORDER BY u.id",
        )
        .bind(user.0)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok((user_ref(r)?, r.try_get::<bool, _>("mutual")?))).collect()
    }

    /// Users who are mutual friends of `user`.
    pub async fn mutual_friends(&self, user: UserId) -> Result<HashSet<UserId>, DbError> {
        let rows = sqlx::query(
            "SELECT f.friend_id FROM friends f \
             JOIN friends r ON r.user_id = f.friend_id AND r.friend_id = f.user_id WHERE f.user_id = ?",
        )
        .bind(user.0)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(UserId(r.try_get("friend_id")?))).collect()
    }

    pub async fn stats(&self, owner: UserId, keys: &[String]) -> Result<Vec<StatValue>, DbError> {
        let mut out = Vec::new();
        for key in keys {
            let row = sqlx::query("SELECT value FROM stats WHERE owner_id = ? AND key = ?")
                .bind(owner.0)
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
            if let Some(r) = row {
                out.push(StatValue { owner, key: key.clone(), value: r.try_get("value")? });
            }
        }
        Ok(out)
    }

    /// Writes all entries in one transaction.
    pub async fn update_stats(&self, entries: &[StatValue], now: i64) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        for e in entries {
            sqlx::query(
                "INSERT INTO stats (owner_id, key, value, updated_at) VALUES (?, ?, ?, ?) \
                 ON CONFLICT (owner_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(e.owner.0)
            .bind(&e.key)
            .bind(&e.value)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Records `score` for `user` on `board` if it beats the stored one (an equal or lower score leaves the row
    /// and its `updated_at` unchanged) and returns the player's standing. None, with nothing written, when the
    /// account is banned from leaderboards.
    pub async fn push_leaderboard_score(
        &self,
        board: &str,
        user: UserId,
        score: u32,
        now: i64,
    ) -> Result<Option<LeaderboardEntry>, DbError> {
        let mut tx = self.pool.begin().await?;
        let banned = sqlx::query("SELECT 1 FROM leaderboard_bans WHERE user_id = ?").bind(user.0).fetch_optional(&mut *tx).await?;
        if banned.is_some() {
            return Ok(None);
        }
        sqlx::query(
            "INSERT INTO leaderboard_scores (board, user_id, score, updated_at) VALUES (?, ?, ?, ?) \
             ON CONFLICT (board, user_id) DO UPDATE SET score = excluded.score, updated_at = excluded.updated_at \
             WHERE excluded.score > leaderboard_scores.score",
        )
        .bind(board)
        .bind(user.0)
        .bind(i64::from(score))
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let entry = standing(&mut *tx, board, user).await?;
        tx.commit().await?;
        Ok(Some(entry))
    }

    /// The standing of `user` on `board`; `rank: 0, score: 0` when the player has no unbanned entry.
    pub async fn leaderboard_standing(&self, board: &str, user: UserId) -> Result<LeaderboardEntry, DbError> {
        standing(&self.pool, board, user).await
    }

    /// Up to `count` unbanned entries of `board` from 1-based rank `from`, and the board's unbanned total.
    pub async fn leaderboard_page(&self, board: &str, from: u32, count: u32) -> Result<LeaderboardPage, DbError> {
        let mut tx = self.pool.begin().await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM leaderboard_scores s \
             WHERE s.board = ? AND NOT EXISTS (SELECT 1 FROM leaderboard_bans b WHERE b.user_id = s.user_id)",
        )
        .bind(board)
        .fetch_one(&mut *tx)
        .await?;
        let offset = i64::from(from) - 1;
        let rows = sqlx::query(BOARD_ORDER_SQL).bind(board).bind(i64::from(count)).bind(offset).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let rows = rows
            .iter()
            .zip(offset + 1..)
            .map(|(r, rank)| {
                Ok(LeaderboardRow {
                    rank: to_u32("leaderboard rank", rank)?,
                    user_id: UserId(r.try_get("user_id")?),
                    display_name: r.try_get("username")?,
                    score: to_u32("leaderboard_scores.score", r.try_get("score")?)?,
                    updated_at: r.try_get("updated_at")?,
                })
            })
            .collect::<Result<Vec<_>, DbError>>()?;
        Ok(LeaderboardPage { board: board.to_string(), total: to_u32("leaderboard total", total)?, rows })
    }

    /// The account's leaderboard ban, if any.
    pub async fn leaderboard_ban(&self, user: UserId) -> Result<Option<LeaderboardBan>, DbError> {
        let row = sqlx::query("SELECT reason, created_at FROM leaderboard_bans WHERE user_id = ?")
            .bind(user.0)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| Ok(LeaderboardBan { reason: r.try_get("reason")?, created_at: r.try_get("created_at")? })).transpose()
    }

    /// Bans the account from leaderboards. False when it already was (the existing ban is unchanged).
    pub async fn ban_from_leaderboards(&self, user: UserId, reason: &str, now: i64) -> Result<bool, DbError> {
        let done = sqlx::query(
            "INSERT INTO leaderboard_bans (user_id, reason, created_at) VALUES (?, ?, ?) ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(user.0)
        .bind(reason)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Lifts the account's leaderboard ban. False when it had none.
    pub async fn unban_from_leaderboards(&self, user: UserId) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM leaderboard_bans WHERE user_id = ?").bind(user.0).execute(&self.pool).await?;
        Ok(done.rows_affected() == 1)
    }

    /// Deletes the player's entry on `board`, returning the score it held; None when there was none.
    pub async fn delete_leaderboard_score(&self, board: &str, user: UserId) -> Result<Option<u32>, DbError> {
        let row = sqlx::query("DELETE FROM leaderboard_scores WHERE board = ? AND user_id = ? RETURNING score")
            .bind(board)
            .bind(user.0)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| to_u32("leaderboard_scores.score", r.try_get("score")?)).transpose()
    }
}

fn user_ref(r: &sqlx::sqlite::SqliteRow) -> Result<UserRef, DbError> {
    Ok(UserRef { user_id: UserId(r.try_get("id")?), name: r.try_get("username")? })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("mp.sqlite")).await.unwrap();
        (db, dir)
    }

    async fn users(db: &Db, names: &[&str]) -> Vec<UserId> {
        let mut ids = Vec::new();
        for n in names {
            ids.push(db.create_user(n, "hash", 0).await.unwrap());
        }
        ids
    }

    fn row(rank: u32, user: UserId, name: &str, score: u32, updated_at: i64) -> LeaderboardRow {
        LeaderboardRow { rank, user_id: user, display_name: name.into(), score, updated_at }
    }

    fn entry(rank: u32, score: u32) -> LeaderboardEntry {
        LeaderboardEntry { rank, score }
    }

    #[tokio::test]
    async fn board_order_is_score_then_first_reached_then_user_id() {
        let (db, _dir) = open().await;
        let [a, b, c, d] = users(&db, &["Aaa", "Bbb", "Ccc", "Ddd"]).await[..] else { unreachable!() };
        db.push_leaderboard_score("B1", a, 100, 10).await.unwrap();
        db.push_leaderboard_score("B1", b, 100, 5).await.unwrap();
        db.push_leaderboard_score("B1", c, 200, 20).await.unwrap();
        db.push_leaderboard_score("B1", d, 100, 5).await.unwrap();
        db.push_leaderboard_score("Other", a, 999, 1).await.unwrap();

        let page = db.leaderboard_page("B1", 1, 10).await.unwrap();
        assert_eq!(page.total, 4);
        assert_eq!(
            page.rows,
            [row(1, c, "Ccc", 200, 20), row(2, b, "Bbb", 100, 5), row(3, d, "Ddd", 100, 5), row(4, a, "Aaa", 100, 10)]
        );
        for r in &page.rows {
            assert_eq!(db.leaderboard_standing("B1", r.user_id).await.unwrap(), entry(r.rank, r.score));
        }
        let window = db.leaderboard_page("B1", 2, 2).await.unwrap();
        assert_eq!((window.total, window.rows), (4, vec![row(2, b, "Bbb", 100, 5), row(3, d, "Ddd", 100, 5)]));
        assert!(db.leaderboard_page("B1", 5, 10).await.unwrap().rows.is_empty());
        assert_eq!(db.leaderboard_page("dlccon001", 1, 10).await.unwrap().total, 0, "board names are case-sensitive");
        assert_eq!(db.leaderboard_standing("Nope", a).await.unwrap(), entry(0, 0));
    }

    #[tokio::test]
    async fn best_score_is_kept_with_the_time_it_was_first_reached() {
        let (db, _dir) = open().await;
        let [a, b] = users(&db, &["Aaa", "Bbb"]).await[..] else { unreachable!() };
        assert_eq!(db.push_leaderboard_score("B1", a, 100, 1).await.unwrap(), Some(entry(1, 100)));
        assert_eq!(db.push_leaderboard_score("B1", b, 100, 2).await.unwrap(), Some(entry(2, 100)));
        assert_eq!(db.push_leaderboard_score("B1", a, 50, 3).await.unwrap(), Some(entry(1, 100)), "lower push");
        assert_eq!(db.push_leaderboard_score("B1", a, 100, 4).await.unwrap(), Some(entry(1, 100)), "equal push");
        assert_eq!(db.leaderboard_page("B1", 1, 1).await.unwrap().rows, [row(1, a, "Aaa", 100, 1)]);
        assert_eq!(db.push_leaderboard_score("B1", b, 150, 5).await.unwrap(), Some(entry(1, 150)));
        assert_eq!(db.leaderboard_page("B1", 1, 2).await.unwrap().rows, [row(1, b, "Bbb", 150, 5), row(2, a, "Aaa", 100, 1)]);
    }

    #[tokio::test]
    async fn banned_accounts_are_left_out_and_cannot_push() {
        let (db, _dir) = open().await;
        let [a, b, c] = users(&db, &["Aaa", "Bbb", "Ccc"]).await[..] else { unreachable!() };
        db.push_leaderboard_score("B1", a, 300, 1).await.unwrap();
        db.push_leaderboard_score("B1", b, 200, 1).await.unwrap();
        db.push_leaderboard_score("B1", c, 100, 1).await.unwrap();

        assert!(db.ban_from_leaderboards(a, "edited save", 7).await.unwrap());
        assert!(!db.ban_from_leaderboards(a, "again", 8).await.unwrap(), "already banned");
        let ban = db.leaderboard_ban(a).await.unwrap().unwrap();
        assert_eq!((ban.reason.as_str(), ban.created_at), ("edited save", 7), "the first ban stands");
        let page = db.leaderboard_page("B1", 1, 10).await.unwrap();
        assert_eq!((page.total, page.rows), (2, vec![row(1, b, "Bbb", 200, 1), row(2, c, "Ccc", 100, 1)]));
        assert_eq!(db.leaderboard_standing("B1", a).await.unwrap(), entry(0, 0));
        assert_eq!(db.leaderboard_standing("B1", c).await.unwrap(), entry(2, 100));
        assert_eq!(db.push_leaderboard_score("B1", a, 999, 9).await.unwrap(), None);
        assert_eq!(db.push_leaderboard_score("B2", a, 1, 9).await.unwrap(), None);
        assert_eq!(db.leaderboard_page("B2", 1, 10).await.unwrap().total, 0, "a refused push writes nothing");

        assert!(db.unban_from_leaderboards(a).await.unwrap());
        assert!(!db.unban_from_leaderboards(a).await.unwrap());
        assert_eq!(db.leaderboard_standing("B1", a).await.unwrap(), entry(1, 300), "the score row was kept");
    }

    #[tokio::test]
    async fn delete_score_removes_one_entry() {
        let (db, _dir) = open().await;
        let [a] = users(&db, &["Aaa"]).await[..] else { unreachable!() };
        db.push_leaderboard_score("B1", a, 300, 1).await.unwrap();
        db.push_leaderboard_score("B2", a, 5, 1).await.unwrap();
        assert_eq!(db.delete_leaderboard_score("B1", a).await.unwrap(), Some(300));
        assert_eq!(db.delete_leaderboard_score("B1", a).await.unwrap(), None);
        assert_eq!(db.leaderboard_standing("B2", a).await.unwrap(), entry(1, 5));
        assert_eq!(db.push_leaderboard_score("B1", a, 10, 2).await.unwrap(), Some(entry(1, 10)), "not a ban");
    }

    async fn plan(db: &Db, sql: &str, binds: &[&str]) -> Vec<String> {
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let mut q = sqlx::query(&explain);
        for b in binds {
            q = q.bind(*b);
        }
        q.fetch_all(&db.pool).await.unwrap().iter().map(|r| r.get::<String, _>("detail")).collect()
    }

    #[tokio::test]
    async fn board_queries_walk_the_order_index() {
        let (db, _dir) = open().await;
        let page = plan(&db, BOARD_ORDER_SQL, &["B1", "30", "0"]).await;
        assert!(
            page.iter().any(|d| d.starts_with("SEARCH s USING") && d.ends_with("INDEX leaderboard_scores_order (board=?)")),
            "{page:#?}"
        );
        assert!(!page.iter().any(|d| d.contains("TEMP B-TREE")), "the order must come from the index: {page:#?}");
        let standing = plan(&db, STANDING_SQL, &["B1", "1"]).await;
        assert!(standing.iter().any(|d| d.contains("leaderboard_scores_order")), "{standing:#?}");
        assert!(!standing.iter().any(|d| d.contains("TEMP B-TREE") || d.starts_with("SCAN")), "{standing:#?}");
    }

    #[tokio::test]
    async fn migration_0002_keeps_a_0001_database() {
        let dir = tempfile::tempdir().unwrap();
        let only_0001 = dir.path().join("migrations");
        std::fs::create_dir(&only_0001).unwrap();
        std::fs::write(only_0001.join("0001_init.sql"), include_str!("../migrations/0001_init.sql")).unwrap();
        let path = dir.path().join("mp.sqlite");
        let options =
            SqliteConnectOptions::new().filename(&path).create_if_missing(true).foreign_keys(true).journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new().connect_with(options).await.unwrap();
        let migrator = sqlx::migrate::Migrator::new(only_0001.as_path()).await.unwrap();
        assert_eq!(migrator.iter().count(), 1);
        migrator.run(&pool).await.unwrap();
        for sql in [
            "INSERT INTO users (id, username, password_hash, created_at) VALUES (1, 'Aaa', 'h', 1), (2, 'Bbb', 'h', 2)",
            "INSERT INTO sessions VALUES (x'00', 1, 1, 99, 'b', 'a')",
            "INSERT INTO friends VALUES (1, 2, 3)",
            "INSERT INTO stats VALUES (2, 'score', '7', 4)",
        ] {
            sqlx::query(sql).execute(&pool).await.unwrap();
        }
        pool.close().await;

        let db = Db::open(&path).await.unwrap();
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version").fetch_all(&db.pool).await.unwrap();
        assert_eq!(versions, [1, 2]);
        for (table, n) in [("users", 2), ("sessions", 1), ("friends", 1), ("stats", 1), ("leaderboard_scores", 0), ("leaderboard_bans", 0)] {
            let count = format!("SELECT count(*) FROM {table}");
            let got: i64 = sqlx::query_scalar(&count).fetch_one(&db.pool).await.unwrap();
            assert_eq!(got, n, "{table}");
        }
        let violations = sqlx::query("PRAGMA foreign_key_check").fetch_all(&db.pool).await.unwrap();
        assert!(violations.is_empty());
        assert_eq!(db.session(&[0], 0).await.unwrap().unwrap().user.name, "Aaa");
        assert_eq!(db.push_leaderboard_score("B1", UserId(2), 5, 5).await.unwrap(), Some(entry(1, 5)));
    }
}
