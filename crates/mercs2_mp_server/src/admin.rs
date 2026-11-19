//! Leaderboard moderation subcommands of the `mp-server` binary, run against the configured database:
//! `mp-server --config <path> <subcommand> …`.
//!
//! A ban leaves the account out of every leaderboard list and rank at once and refuses its score pushes; its
//! score rows are kept, so lifting the ban restores them. Deleting a score removes one board entry and does not
//! ban: the player can push again.

use mercs2_mp_api::rules;

use crate::db::{Db, DbError, StoredUser};

pub const USAGE: &str = "usage: mp-server --config <path to config.toml> [<subcommand>]\n\
    subcommands (leaderboard moderation; without one the server runs):\n  \
    leaderboards-ban <username> <reason>       leave the account out of every leaderboard and refuse its pushes\n  \
    leaderboards-unban <username>              lift that ban\n  \
    leaderboards-delete-score <board> <username>  delete the account's score on one board";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Ban { username: String, reason: String },
    Unban { username: String },
    DeleteScore { board: String, username: String },
}

impl Command {
    /// The subcommand and its arguments (everything after `--config <path>`).
    pub fn parse(args: &[String]) -> Result<Command, String> {
        match args {
            [cmd, username, reason] if cmd == "leaderboards-ban" => {
                if reason.trim().is_empty() {
                    return Err("leaderboards-ban: the reason must not be empty".into());
                }
                Ok(Command::Ban { username: username.clone(), reason: reason.clone() })
            }
            [cmd, username] if cmd == "leaderboards-unban" => Ok(Command::Unban { username: username.clone() }),
            [cmd, board, username] if cmd == "leaderboards-delete-score" => {
                rules::check_board_name(board).map_err(|e| format!("leaderboards-delete-score: {}", e.message))?;
                Ok(Command::DeleteScore { board: board.clone(), username: username.clone() })
            }
            _ => Err(USAGE.into()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The command was understood but changes nothing (no such account, already banned, no score, …).
    #[error("{0}")]
    Refused(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

async fn account(db: &Db, username: &str) -> Result<StoredUser, AdminError> {
    db.user_by_name(username).await?.ok_or_else(|| AdminError::Refused(format!("No account is named `{username}`.")))
}

/// Runs one subcommand; Ok carries the line to print.
pub async fn run(db: &Db, command: Command, now: i64) -> Result<String, AdminError> {
    match command {
        Command::Ban { username, reason } => {
            let user = account(db, &username).await?;
            if db.ban_from_leaderboards(user.id, &reason, now).await? {
                return Ok(format!("Banned {} (account {}) from leaderboards: {reason}", user.username, user.id.0));
            }
            let ban = db.leaderboard_ban(user.id).await?;
            let since = ban.map_or_else(|| "a ban lifted meanwhile".to_string(), |b| {
                format!("unix time {} for: {}", b.created_at, b.reason)
            });
            Err(AdminError::Refused(format!(
                "{} (account {}) has been banned from leaderboards since {since}; nothing changed.",
                user.username, user.id.0
            )))
        }
        Command::Unban { username } => {
            let user = account(db, &username).await?;
            if db.unban_from_leaderboards(user.id).await? {
                return Ok(format!("Unbanned {} (account {}) from leaderboards.", user.username, user.id.0));
            }
            Err(AdminError::Refused(format!(
                "{} (account {}) is not banned from leaderboards; nothing changed.",
                user.username, user.id.0
            )))
        }
        Command::DeleteScore { board, username } => {
            let user = account(db, &username).await?;
            match db.delete_leaderboard_score(&board, user.id).await? {
                Some(score) => {
                    Ok(format!("Deleted {}'s score of {score} on {board} (account {}).", user.username, user.id.0))
                }
                None => Err(AdminError::Refused(format!(
                    "{} (account {}) has no score on {board}; nothing was deleted.",
                    user.username, user.id.0
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_each_subcommand_and_rejects_the_rest() {
        assert_eq!(
            Command::parse(&args(&["leaderboards-ban", "Aaa", "edited save"])),
            Ok(Command::Ban { username: "Aaa".into(), reason: "edited save".into() })
        );
        assert_eq!(Command::parse(&args(&["leaderboards-unban", "Aaa"])), Ok(Command::Unban { username: "Aaa".into() }));
        assert_eq!(
            Command::parse(&args(&["leaderboards-delete-score", "DlcCon001", "Aaa"])),
            Ok(Command::DeleteScore { board: "DlcCon001".into(), username: "Aaa".into() })
        );
        assert!(Command::parse(&args(&["leaderboards-ban", "Aaa", "  "])).unwrap_err().contains("reason"));
        assert!(Command::parse(&args(&["leaderboards-delete-score", "Dlc-Con", "Aaa"])).unwrap_err().contains("board"));
        for bad in [&["leaderboards-ban", "Aaa"][..], &["leaderboards-unban"], &["nope", "x"], &["leaderboards-unban", "a", "b"]] {
            assert_eq!(Command::parse(&args(bad)), Err(USAGE.to_string()), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn moderation_commands() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("mp.sqlite")).await.unwrap();
        let a = db.create_user("Aaa", "h", 0).await.unwrap();
        db.push_leaderboard_score("B1", a, 40, 1).await.unwrap();
        let ban = |reason: &str| Command::Ban { username: "aaa".into(), reason: reason.into() };

        let refused = |r: Result<String, AdminError>| match r {
            Err(AdminError::Refused(m)) => m,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert_eq!(refused(run(&db, Command::Unban { username: "Nobody".into() }, 2).await), "No account is named `Nobody`.");
        assert_eq!(run(&db, ban("edited save"), 5).await.unwrap(), "Banned Aaa (account 1) from leaderboards: edited save");
        assert_eq!(
            refused(run(&db, ban("again"), 6).await),
            "Aaa (account 1) has been banned from leaderboards since unix time 5 for: edited save; nothing changed."
        );
        assert_eq!(db.push_leaderboard_score("B1", a, 50, 7).await.unwrap(), None);
        assert_eq!(run(&db, Command::Unban { username: "Aaa".into() }, 8).await.unwrap(), "Unbanned Aaa (account 1) from leaderboards.");
        assert_eq!(
            refused(run(&db, Command::Unban { username: "Aaa".into() }, 9).await),
            "Aaa (account 1) is not banned from leaderboards; nothing changed."
        );
        let delete = || Command::DeleteScore { board: "B1".into(), username: "Aaa".into() };
        assert_eq!(run(&db, delete(), 10).await.unwrap(), "Deleted Aaa's score of 40 on B1 (account 1).");
        assert_eq!(refused(run(&db, delete(), 11).await), "Aaa (account 1) has no score on B1; nothing was deleted.");
    }
}
