//! `mp-server --config <path>` runs the server; `mp-server --config <path> <subcommand> …` runs one leaderboard
//! moderation command ([`mercs2_mp_server::admin`]) against the configured database and exits.

use std::path::PathBuf;
use std::process::ExitCode;

use mercs2_mp_server::admin::{self, AdminError};
use mercs2_mp_server::config::{Config, LogFormat};
use mercs2_mp_server::db::Db;
use mercs2_mp_server::util::now_unix;
use tracing_subscriber::EnvFilter;

fn parse_args() -> Result<(PathBuf, Option<admin::Command>), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag, path] if flag == "--config" => Ok((PathBuf::from(path), None)),
        [flag, path, rest @ ..] if flag == "--config" => Ok((PathBuf::from(path), Some(admin::Command::parse(rest)?))),
        _ => Err(admin::USAGE.into()),
    }
}

async fn run_admin(config: &Config, command: admin::Command) -> ExitCode {
    let db = match Db::open(&config.database.path).await {
        Ok(db) => db,
        Err(e) => {
            eprintln!("mp-server: {e}");
            return ExitCode::FAILURE;
        }
    };
    match admin::run(&db, command, now_unix()).await {
        Ok(done) => {
            println!("{done}");
            ExitCode::SUCCESS
        }
        Err(AdminError::Refused(why)) => {
            eprintln!("{why}");
            ExitCode::FAILURE
        }
        Err(AdminError::Db(e)) => {
            eprintln!("mp-server: {e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let (path, command) = match parse_args() {
        Ok(p) => p,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let config = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mp-server: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(command) = command {
        return run_admin(&config, command).await;
    }
    let filter = match EnvFilter::try_new(&config.log.filter) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("mp-server: config key `log.filter`: {e}");
            return ExitCode::from(2);
        }
    };
    match config.log.format {
        LogFormat::Json => tracing_subscriber::fmt().json().with_env_filter(filter).init(),
        LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }

    let running = match mercs2_mp_server::start(config).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "cannot install SIGTERM handler");
            return ExitCode::FAILURE;
        }
    };
    tokio::select! {
        e = running.wait() => {
            tracing::error!(error = %e, "server stopped");
            ExitCode::FAILURE
        }
        signal = tokio::signal::ctrl_c() => match signal {
            Ok(()) => {
                tracing::info!("SIGINT received; exiting");
                ExitCode::SUCCESS
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGINT");
                ExitCode::FAILURE
            }
        },
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received; exiting");
            ExitCode::SUCCESS
        }
    }
}
