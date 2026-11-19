//! The leaderboard moderation subcommands, run through the `mp-server` binary against a configured database.

use std::path::Path;
use std::process::Output;

use mercs2_mp_api::rest::LeaderboardEntry;
use mercs2_mp_server::db::Db;

/// A config that passes validation; only `database.path` is used by the subcommands.
fn write_config(dir: &Path) -> std::path::PathBuf {
    let text = format!(
        r#"[log]
filter = "info"
format = "text"
[server]
https_listen = "127.0.0.1:0"
tls_handshake_timeout_secs = 10
[database]
path = "{db}"
[accounts]
session_ttl_secs = 3600
argon2_memory_kib = 256
argon2_iterations = 1
argon2_parallelism = 1
[rate_limit]
accounts = {{ burst = 5, refill_per_minute = 5 }}
sessions = {{ burst = 10, refill_per_minute = 20 }}
[websocket]
max_message_bytes = 65536
outbound_queue = 256
ping_interval_secs = 20
idle_timeout_secs = 60
[games]
max_players_limit = 2
[relay]
listen = "127.0.0.1:0"
public_host = "127.0.0.1"
public_port = 3659
cert_pem = "/nonexistent/relay-cert.pem"
key_pem = "/nonexistent/relay-key.pem"
idle_timeout_secs = 60
handshake_timeout_secs = 10
max_pending_handshakes = 16
mtu = 1200
tick_millis = 250
[tls]
mode = "proxied"
cert_pem = "/nonexistent/https-cert.pem"
key_pem = "/nonexistent/https-key.pem"
trusted_proxies = ["127.0.0.1/32"]
"#,
        db = dir.join("mp.sqlite").display()
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, text).unwrap();
    path
}

fn mp_server(config: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_mp-server"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .unwrap()
}

/// Exit code, stdout and stderr, trimmed.
fn result(out: &Output) -> (Option<i32>, String, String) {
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn ban_unban_and_delete_score_through_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    let db = Db::open(&dir.path().join("mp.sqlite")).await.unwrap();
    let a = db.create_user("Aaa", "h", 0).await.unwrap();
    let b = db.create_user("Bbb", "h", 0).await.unwrap();
    db.push_leaderboard_score("DlcCon001", a, 500, 1).await.unwrap();
    db.push_leaderboard_score("DlcCon001", b, 100, 1).await.unwrap();

    let ok = |line: &str| (Some(0), line.to_string(), String::new());
    let refused = |line: &str| (Some(1), String::new(), line.to_string());

    assert_eq!(
        result(&mp_server(&config, &["leaderboards-ban", "aaa", "edited save"])),
        ok("Banned Aaa (account 1) from leaderboards: edited save")
    );
    assert_eq!(db.leaderboard_standing("DlcCon001", b).await.unwrap(), LeaderboardEntry { rank: 1, score: 100 });
    assert_eq!(db.push_leaderboard_score("DlcCon001", a, 900, 2).await.unwrap(), None);
    let again = result(&mp_server(&config, &["leaderboards-ban", "Aaa", "twice"]));
    assert_eq!(again.0, Some(1));
    assert!(again.2.ends_with("for: edited save; nothing changed."), "{again:?}");

    assert_eq!(result(&mp_server(&config, &["leaderboards-unban", "Aaa"])), ok("Unbanned Aaa (account 1) from leaderboards."));
    assert_eq!(
        result(&mp_server(&config, &["leaderboards-unban", "Aaa"])),
        refused("Aaa (account 1) is not banned from leaderboards; nothing changed.")
    );
    assert_eq!(db.leaderboard_standing("DlcCon001", a).await.unwrap(), LeaderboardEntry { rank: 1, score: 500 });

    assert_eq!(
        result(&mp_server(&config, &["leaderboards-delete-score", "DlcCon001", "Aaa"])),
        ok("Deleted Aaa's score of 500 on DlcCon001 (account 1).")
    );
    assert_eq!(
        result(&mp_server(&config, &["leaderboards-delete-score", "DlcCon001", "Aaa"])),
        refused("Aaa (account 1) has no score on DlcCon001; nothing was deleted.")
    );
    assert_eq!(
        result(&mp_server(&config, &["leaderboards-delete-score", "dlccon001", "Bbb"])),
        refused("Bbb (account 2) has no score on dlccon001; nothing was deleted."),
        "board names are case-sensitive"
    );
    assert_eq!(db.leaderboard_standing("DlcCon001", b).await.unwrap(), LeaderboardEntry { rank: 1, score: 100 });
    assert_eq!(result(&mp_server(&config, &["leaderboards-unban", "Nobody"])), refused("No account is named `Nobody`."));
}

#[test]
fn bad_arguments_exit_2_with_usage() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path());
    for args in [&["leaderboards-ban", "Aaa"][..], &["nope"], &["leaderboards-ban", "Aaa", " "], &["leaderboards-delete-score", "Dlc-Con", "Aaa"]] {
        let (code, stdout, stderr) = result(&mp_server(&config, args));
        assert_eq!((code, stdout.as_str()), (Some(2), ""), "{args:?}");
        assert!(!stderr.is_empty(), "{args:?}");
    }
    let (code, _, stderr) = result(&mp_server(&config, &["nope"]));
    assert_eq!(code, Some(2));
    assert!(stderr.starts_with("usage: mp-server --config"), "{stderr}");
    assert!(!dir.path().join("mp.sqlite").exists(), "a rejected command opens no database");
}
