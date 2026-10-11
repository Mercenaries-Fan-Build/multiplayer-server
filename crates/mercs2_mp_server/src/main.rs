//! `mp-server --config <path>`

use std::path::PathBuf;
use std::process::ExitCode;

use mercs2_mp_server::config::{Config, LogFormat};
use tracing_subscriber::EnvFilter;

fn config_path() -> Result<PathBuf, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag, path] if flag == "--config" => Ok(PathBuf::from(path)),
        _ => Err("usage: mp-server --config <path to config.toml>".into()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let path = match config_path() {
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
