use std::env;

/// Server configuration.
///
/// Note there are no collector or worker API keys here. Those live in the
/// database and are minted and revoked through the admin socket with
/// `fossdb admin api-key`, so that revocation is effective and so the server
/// no longer refuses to start when a shared secret is absent.
#[derive(Debug, Clone)]
pub struct Config {
    pub database_path: String,
    pub server_port: u16,
    pub timeline_retention_days: u64,
    /// Address the public API binds to.
    pub bind_address: String,
    pub collector_port: u16,
    pub worker_port: u16,
    /// Address the collector and worker APIs bind to.
    ///
    /// Separate from [`Config::bind_address`] and defaulting to loopback:
    /// those APIs are guarded only by an API key, so exposing them to the
    /// network should be a deliberate act rather than the default.
    pub internal_bind_address: String,
    /// Absolute origin used to build feed links. Feed readers need absolute
    /// URLs, and the server cannot reliably infer its own public origin from
    /// a request when it sits behind a proxy.
    pub public_base_url: String,
    /// Grace period before an account that has never subscribed to anything
    /// is reaped.
    pub account_grace_hours: u64,
    /// How often the account reaper runs.
    pub account_purge_interval_secs: u64,
    /// Filesystem path for the admin control socket. Access to the admin API
    /// is governed entirely by this socket's permissions.
    pub admin_socket_path: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_path: env::var("DATABASE_PATH").unwrap_or_else(|_| "./foss.db".to_string()),
            server_port: parse_or("SERVER_PORT", 3000),
            timeline_retention_days: parse_or("TIMELINE_RETENTION_DAYS", 90),
            bind_address: env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string()),
            collector_port: parse_or("COLLECTOR_PORT", 3001),
            worker_port: parse_or("WORKER_PORT", 3002),
            internal_bind_address: env::var("INTERNAL_BIND_ADDRESS")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            public_base_url: env::var("PUBLIC_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string())
                .trim_end_matches('/')
                .to_string(),
            account_grace_hours: parse_or("ACCOUNT_GRACE_HOURS", 4),
            account_purge_interval_secs: parse_or("ACCOUNT_PURGE_INTERVAL_SECS", 300),
            admin_socket_path: env::var("ADMIN_SOCKET_PATH")
                .unwrap_or_else(|_| "/run/fossdb/admin.sock".to_string()),
        }
    }
}

/// Read a numeric env var, falling back to `default`.
///
/// A malformed value falls back rather than failing, matching the previous
/// behaviour, but it is logged - silently running on a different port than
/// the operator configured is the kind of thing that wastes an afternoon.
fn parse_or<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr + std::fmt::Display + Copy,
{
    match env::var(key) {
        Err(_) => default,
        Ok(raw) => raw.parse().unwrap_or_else(|_| {
            eprintln!("warning: {key}={raw:?} is not a valid value; using {default}");
            default
        }),
    }
}
