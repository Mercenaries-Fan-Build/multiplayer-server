//! Server configuration: one TOML file, every key required unless documented otherwise. Unknown keys are
//! rejected so a misspelt key fails at startup instead of silently taking no effect.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config file {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("parsing config file {path}: {source}")]
    Parse { path: PathBuf, source: toml::de::Error },
    #[error("config key `{key}`: {rule}")]
    Invalid { key: &'static str, rule: String },
}

fn invalid(key: &'static str, rule: impl Into<String>) -> ConfigError {
    ConfigError::Invalid { key, rule: rule.into() }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub log: LogConfig,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub accounts: AccountsConfig,
    pub rate_limit: RateLimitConfig,
    pub websocket: WebSocketConfig,
    pub games: GamesConfig,
    pub relay: RelayConfig,
    pub tls: TlsConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// `tracing_subscriber::EnvFilter` directive, e.g. `"info"` or `"mercs2_mp_server=debug,info"`.
    pub filter: String,
    /// `"json"` (one JSON object per line) or `"text"`.
    pub format: LogFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address the HTTPS listener (REST + WebSocket) binds.
    pub https_listen: SocketAddr,
    /// Seconds a client gets to finish the TLS handshake on the HTTPS listener.
    pub tls_handshake_timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// SQLite database file. Created on first start; its directory must exist.
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountsConfig {
    /// Lifetime of a session token issued by `POST /v1/sessions`.
    pub session_ttl_secs: u64,
    /// argon2id memory cost in KiB.
    pub argon2_memory_kib: u32,
    /// argon2id time cost (iterations).
    pub argon2_iterations: u32,
    /// argon2id degree of parallelism.
    pub argon2_parallelism: u32,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketConfig {
    /// Requests a client may make back to back.
    pub burst: u32,
    /// Requests per minute the bucket refills at.
    pub refill_per_minute: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// `POST /v1/accounts`, per client IP.
    pub accounts: BucketConfig,
    /// `POST /v1/sessions`, per client IP.
    pub sessions: BucketConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketConfig {
    /// Largest accepted client message.
    pub max_message_bytes: usize,
    /// Frames queued to one client before the server closes that connection as too slow.
    pub outbound_queue: usize,
    /// Interval of server WebSocket pings.
    pub ping_interval_secs: u64,
    /// A connection with no inbound frame (data, ping or pong) for this long is closed.
    pub idle_timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GamesConfig {
    /// Upper bound accepted for `max_players` in games.create / games.update.
    pub max_players_limit: u8,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// UDP address the DTLS relay binds.
    pub listen: SocketAddr,
    /// Host name or address clients are told to reach the relay at.
    pub public_host: String,
    /// UDP port clients are told to reach the relay at (differs from `listen` behind port mapping).
    pub public_port: u16,
    /// PEM certificate (self-signed is fine; clients pin its sha256).
    pub cert_pem: PathBuf,
    /// PEM private key for `cert_pem`.
    pub key_pem: PathBuf,
    /// An established association with no inbound datagram for this long is torn down.
    pub idle_timeout_secs: u64,
    /// A DTLS handshake not finished within this long is abandoned.
    pub handshake_timeout_secs: u64,
    /// Upper bound on associations still in their handshake (spoofed-source flood bound).
    pub max_pending_handshakes: usize,
    /// DTLS path MTU in bytes.
    pub mtu: u32,
    /// Period of the relay housekeeping tick (DTLS retransmission timers, idle sweep).
    pub tick_millis: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum TlsConfig {
    /// The server obtains and renews its own certificate from an ACME CA (HTTP-01).
    Acme(AcmeConfig),
    /// The server sits behind a reverse proxy that terminates the public certificate.
    Proxied(ProxiedConfig),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    /// DNS names on the certificate. All must resolve to this server.
    pub domains: Vec<String>,
    /// Contact address registered with the ACME account.
    pub contact_email: String,
    /// ACME directory URL (Let's Encrypt production or staging, or any RFC 8555 CA).
    pub directory_url: String,
    /// Roots trusted for the ACME directory's own HTTPS: `"system"` for the OpenSSL default store, or a
    /// path to a PEM bundle (e.g. Pebble's test root).
    pub directory_ca: String,
    /// Directory holding the ACME account credentials and the issued certificate/key.
    pub cache_dir: PathBuf,
    /// Plain-HTTP address serving `/.well-known/acme-challenge/` (port 80 in production).
    pub http_listen: SocketAddr,
    /// Renew when the certificate expires within this many days.
    pub renew_before_days: u32,
    /// After a failed renewal, retry after this many seconds (until the certificate actually expires).
    pub retry_interval_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxiedConfig {
    /// PEM certificate chain the HTTPS listener presents to the proxy.
    pub cert_pem: PathBuf,
    /// PEM private key for `cert_pem`.
    pub key_pem: PathBuf,
    /// Peers whose `X-Forwarded-For` header is trusted for the client IP. Requests from any other peer
    /// are attributed to the peer address itself.
    pub trusted_proxies: Vec<IpNet>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
        Config::parse(path, &text)
    }

    pub fn parse(path: &Path, text: &str) -> Result<Config, ConfigError> {
        let config: Config =
            toml::from_str(text).map_err(|source| ConfigError::Parse { path: path.to_path_buf(), source })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.tls_handshake_timeout_secs == 0 {
            return Err(invalid("server.tls_handshake_timeout_secs", "must be > 0"));
        }
        if self.log.filter.trim().is_empty() {
            return Err(invalid("log.filter", "must not be empty"));
        }
        // Expiry is stored as i64 unix seconds; ten years is far beyond any sensible session.
        if !(1..=315_360_000).contains(&self.accounts.session_ttl_secs) {
            return Err(invalid("accounts.session_ttl_secs", "must be 1-315360000 (ten years)"));
        }
        argon2::Params::new(
            self.accounts.argon2_memory_kib,
            self.accounts.argon2_iterations,
            self.accounts.argon2_parallelism,
            None,
        )
        .map_err(|e| invalid("accounts.argon2_*", format!("rejected by argon2: {e}")))?;
        for (key, bucket) in
            [("rate_limit.accounts", self.rate_limit.accounts), ("rate_limit.sessions", self.rate_limit.sessions)]
        {
            if bucket.burst == 0 || bucket.refill_per_minute == 0 {
                return Err(invalid(key, "burst and refill_per_minute must both be > 0"));
            }
        }
        if self.websocket.max_message_bytes == 0 {
            return Err(invalid("websocket.max_message_bytes", "must be > 0"));
        }
        if self.websocket.outbound_queue == 0 {
            return Err(invalid("websocket.outbound_queue", "must be > 0"));
        }
        if self.websocket.ping_interval_secs == 0 {
            return Err(invalid("websocket.ping_interval_secs", "must be > 0"));
        }
        if self.websocket.idle_timeout_secs <= self.websocket.ping_interval_secs {
            return Err(invalid("websocket.idle_timeout_secs", "must be greater than websocket.ping_interval_secs"));
        }
        // Slots are u8 and the ASI presents slot N as loopback alias 127.0.0.(2+N), so at most 254 slots.
        if !(1..=254).contains(&self.games.max_players_limit) {
            return Err(invalid("games.max_players_limit", "must be 1-254"));
        }
        if self.relay.public_host.trim().is_empty() {
            return Err(invalid("relay.public_host", "must not be empty"));
        }
        if self.relay.public_port == 0 {
            return Err(invalid("relay.public_port", "must be > 0"));
        }
        if self.relay.idle_timeout_secs == 0 || self.relay.handshake_timeout_secs == 0 {
            return Err(invalid("relay.idle_timeout_secs / relay.handshake_timeout_secs", "must be > 0"));
        }
        if self.relay.max_pending_handshakes == 0 {
            return Err(invalid("relay.max_pending_handshakes", "must be > 0"));
        }
        // DTLS 1.2 needs room for its record/handshake headers; 576 is the IPv4 minimum datagram size.
        if !(576..=65507).contains(&self.relay.mtu) {
            return Err(invalid("relay.mtu", "must be 576-65507"));
        }
        if self.relay.tick_millis == 0 {
            return Err(invalid("relay.tick_millis", "must be > 0"));
        }
        match &self.tls {
            TlsConfig::Acme(acme) => {
                if acme.domains.is_empty() {
                    return Err(invalid("tls.domains", "must list at least one domain"));
                }
                if acme.domains.iter().any(|d| d.trim().is_empty() || d.contains('*')) {
                    return Err(invalid("tls.domains", "entries must be non-empty, non-wildcard DNS names (HTTP-01)"));
                }
                if !acme.contact_email.contains('@') {
                    return Err(invalid("tls.contact_email", "must be an email address"));
                }
                if !acme.directory_url.starts_with("https://") {
                    return Err(invalid("tls.directory_url", "must be an https:// URL"));
                }
                if acme.directory_ca.trim().is_empty() {
                    return Err(invalid("tls.directory_ca", "must be \"system\" or a PEM file path"));
                }
                if acme.renew_before_days == 0 {
                    return Err(invalid("tls.renew_before_days", "must be > 0"));
                }
                if acme.retry_interval_secs == 0 {
                    return Err(invalid("tls.retry_interval_secs", "must be > 0"));
                }
            }
            TlsConfig::Proxied(proxied) => {
                if proxied.trusted_proxies.is_empty() {
                    return Err(invalid(
                        "tls.trusted_proxies",
                        "must list the proxy's address range (proxied mode exists to sit behind one)",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl WebSocketConfig {
    pub fn ping_interval(&self) -> Duration {
        Duration::from_secs(self.ping_interval_secs)
    }
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXIED: &str = r#"
[log]
filter = "info"
format = "json"
[server]
https_listen = "127.0.0.1:8443"
tls_handshake_timeout_secs = 10
[database]
path = "/tmp/mp.sqlite"
[accounts]
session_ttl_secs = 3600
argon2_memory_kib = 19456
argon2_iterations = 2
argon2_parallelism = 1
[rate_limit]
accounts = { burst = 5, refill_per_minute = 5 }
sessions = { burst = 10, refill_per_minute = 20 }
[websocket]
max_message_bytes = 65536
outbound_queue = 256
ping_interval_secs = 20
idle_timeout_secs = 60
[games]
max_players_limit = 4
[relay]
listen = "0.0.0.0:3659"
public_host = "mp.example.com"
public_port = 3659
cert_pem = "/data/relay/cert.pem"
key_pem = "/data/relay/key.pem"
idle_timeout_secs = 60
handshake_timeout_secs = 10
max_pending_handshakes = 1024
mtu = 1200
tick_millis = 250
[tls]
mode = "proxied"
cert_pem = "/data/https/cert.pem"
key_pem = "/data/https/key.pem"
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
"#;

    #[test]
    fn parses_proxied_mode() {
        let c = Config::parse(Path::new("t.toml"), PROXIED).unwrap();
        match c.tls {
            TlsConfig::Proxied(p) => assert_eq!(p.trusted_proxies.len(), 2),
            other => panic!("wrong mode {other:?}"),
        }
    }

    #[test]
    fn tls_mode_is_required() {
        let text = PROXIED.replace("mode = \"proxied\"\n", "");
        assert!(Config::parse(Path::new("t.toml"), &text).is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = PROXIED.replace("mtu = 1200", "mtu = 1200\nmut = 5");
        assert!(Config::parse(Path::new("t.toml"), &text).is_err());
        let text = PROXIED.replace("trusted_proxies =", "trusted_proxys = [] \ntrusted_proxies =");
        assert!(Config::parse(Path::new("t.toml"), &text).is_err());
    }

    #[test]
    fn parses_acme_mode_and_rejects_missing_keys() {
        let tls = r#"[tls]
mode = "acme"
domains = ["mp.example.com"]
contact_email = "ops@example.com"
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
directory_ca = "system"
cache_dir = "/data/acme"
http_listen = "0.0.0.0:80"
renew_before_days = 30
retry_interval_secs = 3600
"#;
        let base = PROXIED.split("[tls]").next().unwrap();
        let c = Config::parse(Path::new("t.toml"), &format!("{base}{tls}")).unwrap();
        assert!(matches!(c.tls, TlsConfig::Acme(_)));
        let missing = tls.replace("contact_email = \"ops@example.com\"\n", "");
        let err = Config::parse(Path::new("t.toml"), &format!("{base}{missing}")).unwrap_err();
        assert!(err.to_string().contains("contact_email"), "{err}");
    }

    #[test]
    fn example_config_parses_in_both_modes() {
        let example = include_str!("../config.example.toml");
        let acme = Config::parse(Path::new("config.example.toml"), example).unwrap();
        assert!(matches!(acme.tls, TlsConfig::Acme(_)));
        let (base, rest) = example.split_once("[tls]\nmode = \"acme\"").unwrap();
        let proxied_block = rest.split_once("# [tls]\n").unwrap().1;
        let proxied_tls: String = proxied_block
            .lines()
            .filter_map(|l| l.strip_prefix("# "))
            .filter(|l| !l.starts_with('#'))
            .map(|l| format!("{l}\n"))
            .collect();
        let proxied = Config::parse(Path::new("config.example.toml"), &format!("{base}[tls]\n{proxied_tls}")).unwrap();
        assert!(matches!(proxied.tls, TlsConfig::Proxied(_)));
    }

    #[test]
    fn rejects_bad_values() {
        let text = PROXIED.replace("max_players_limit = 4", "max_players_limit = 255");
        assert!(Config::parse(Path::new("t.toml"), &text).is_err());
        let text = PROXIED.replace("trusted_proxies = [\"10.0.0.0/8\", \"172.16.0.0/12\"]", "trusted_proxies = []");
        assert!(Config::parse(Path::new("t.toml"), &text).is_err());
    }
}
