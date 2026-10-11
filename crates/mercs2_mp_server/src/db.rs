//! SQLite persistence: accounts, sessions, friends, stats. Migrations are embedded in the binary.

use std::collections::HashSet;
use std::path::Path;

use mercs2_mp_api::UserId;
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
}

fn user_ref(r: &sqlx::sqlite::SqliteRow) -> Result<UserRef, DbError> {
    Ok(UserRef { user_id: UserId(r.try_get("id")?), name: r.try_get("username")? })
}
