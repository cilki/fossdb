//! `fossdb` - command line client for a FossDB server.

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

mod client;
mod credentials;

#[cfg(feature = "admin")]
mod admin;

/// Fallback server when neither `--server` nor `FOSSDB_SERVER` is set.
const DEFAULT_SERVER: &str = "http://localhost:3000";

#[derive(Parser, Debug)]
#[command(name = "fossdb")]
#[command(version, about = "Track free software packages", long_about = None)]
struct Args {
    /// Base URL of the FossDB server.
    #[arg(long, short, global = true, env = "FOSSDB_SERVER")]
    server: Option<String>,

    /// Emit JSON instead of human-readable tables.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new account and store its id locally
    Register,

    /// Store an existing account id
    Login {
        /// The account id, as issued by `register`
        user_id: String,
    },

    /// Forget the stored account id
    Logout,

    /// Show which account is in use
    Whoami,

    /// List subscriptions
    #[command(visible_alias = "ls")]
    Subscriptions,

    /// Subscribe to a package
    Subscribe {
        /// Package name, exactly as it appears in the database
        package: String,
    },

    /// Unsubscribe from a package
    Unsubscribe { package: String },

    /// Mute or unmute notifications for one subscribed package
    Notify {
        package: String,
        /// Mute instead of unmute
        #[arg(long)]
        off: bool,
    },

    /// Print this account's feed URLs
    FeedUrl {
        /// Print only the Atom URL
        #[arg(long, conflicts_with = "rss")]
        atom: bool,
        /// Print only the RSS URL
        #[arg(long, conflicts_with = "atom")]
        rss: bool,
    },

    /// Server administration (requires the `admin` feature)
    #[cfg(feature = "admin")]
    Admin {
        /// Path to the server's admin socket
        #[arg(long, default_value = admin::DEFAULT_SOCKET, env = "FOSSDB_ADMIN_SOCKET")]
        socket: String,

        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[cfg(feature = "admin")]
#[derive(Subcommand, Debug)]
enum AdminCommand {
    /// Show collector keys and ingestion activity
    Collectors,
    /// Show worker keys, in-flight tasks and throughput
    Workers,
    /// Show server uptime and table sizes
    Status,
    /// Manage collector and worker API keys
    #[command(subcommand)]
    ApiKey(ApiKeyCommand),
}

#[cfg(feature = "admin")]
#[derive(Subcommand, Debug)]
enum ApiKeyCommand {
    /// Mint a new API key
    Create {
        /// Which internal API the key grants access to
        #[arg(long, value_parser = parse_role)]
        role: fossdb::ApiKeyRole,

        /// A note identifying the holder, e.g. the hostname
        #[arg(long)]
        label: Option<String>,
    },

    /// List API keys
    List {
        /// Include revoked keys
        #[arg(long)]
        all: bool,
    },

    /// Revoke an API key by its id
    Revoke {
        /// Key id, as shown by `api-key list`
        key_id: String,
    },
}

#[cfg(feature = "admin")]
fn parse_role(raw: &str) -> Result<fossdb::ApiKeyRole, String> {
    raw.parse()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Err(e) = run(&args).await {
        // `{:#}` renders the whole anyhow context chain, which is where the
        // actionable part of most of these errors lives.
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run(args: &Args) -> Result<()> {
    match &args.command {
        Command::Register => register(args).await,
        Command::Login { user_id } => login(args, user_id).await,
        Command::Logout => logout(),
        Command::Whoami => whoami(args),
        Command::Subscriptions => subscriptions(args).await,
        Command::Subscribe { package } => subscribe(args, package).await,
        Command::Unsubscribe { package } => unsubscribe(args, package).await,
        Command::Notify { package, off } => notify(args, package, !off).await,
        Command::FeedUrl { atom, rss } => feed_url(args, *atom, *rss),

        #[cfg(feature = "admin")]
        Command::Admin { socket, command } => admin_command(args, socket, command).await,
    }
}

/// Server for this invocation: explicit flag, then env, then the default.
fn server(args: &Args) -> String {
    args.server
        .clone()
        .unwrap_or_else(|| DEFAULT_SERVER.to_string())
}

/// Build a client carrying the stored credential.
fn authed_client(args: &Args) -> Result<(client::Client, credentials::Credentials)> {
    let stored = credentials::require()?;
    let server = args.server.clone().unwrap_or_else(|| stored.server.clone());

    // Refuse to send one deployment's credential to another. Without this,
    // `--server` against an unrelated host would silently leak the id.
    if server != stored.server {
        bail!(
            "stored credential belongs to {} but --server/FOSSDB_SERVER is {}\n\
             Run `fossdb login` against {} to use it.",
            stored.server,
            server,
            server
        );
    }

    let client = client::Client::new(&server, Some(stored.user_id.clone()))?;
    Ok((client, stored))
}

async fn register(args: &Args) -> Result<()> {
    let server = server(args);

    if let Some(existing) = credentials::load()? {
        bail!(
            "already logged in as {} on {}\n\
             Run `fossdb logout` first if you really want a second account.",
            fossdb::user_id::redact(&existing.user_id),
            existing.server
        );
    }

    let client = client::Client::new(&server, None)?;
    let registered = client.register().await?;

    credentials::store(&credentials::Credentials {
        user_id: registered.user_id.clone(),
        server: server.clone(),
    })?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&registered)?);
        return Ok(());
    }

    let path = credentials::path()?;
    println!("Account created on {server}\n");
    println!("  {}\n", registered.user_id);
    println!("This id is your ONLY credential. There is no password, no email and");
    println!("no recovery: if you lose it, the account is gone.");
    println!();
    println!("It has been saved to {}.", path.display());
    println!("Treat it like a password - it also appears in your feed URLs.");
    println!();
    println!("Accounts with no subscriptions are deleted automatically, so");
    println!("subscribe to something to keep this one:");
    println!("  fossdb subscribe <package>");

    Ok(())
}

async fn login(args: &Args, raw_user_id: &str) -> Result<()> {
    let server = server(args);

    // Normalise before validating so a retyped id with stray case or dashes
    // is accepted rather than rejected on cosmetics.
    let user_id = fossdb::user_id::normalize(raw_user_id);

    if !fossdb::user_id::is_well_formed(&user_id) {
        bail!(
            "{raw_user_id:?} is not a valid account id\n\
             Ids look like fdb_ followed by 26 characters."
        );
    }

    let client = client::Client::new(&server, Some(user_id.clone()))?;

    // Verify before storing, so a typo surfaces now rather than on the next
    // command.
    client.login(&user_id).await?;

    credentials::store(&credentials::Credentials {
        user_id: user_id.clone(),
        server: server.clone(),
    })?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({ "status": "ok", "server": server })
        );
    } else {
        println!(
            "Logged in as {} on {server}",
            fossdb::user_id::redact(&user_id)
        );
    }

    Ok(())
}

fn logout() -> Result<()> {
    if credentials::clear()? {
        println!("Logged out; stored credential removed.");
    } else {
        println!("Not logged in.");
    }
    Ok(())
}

fn whoami(args: &Args) -> Result<()> {
    let stored = credentials::require()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&stored)?);
        return Ok(());
    }

    // Print the id in full here: this command exists precisely so a user can
    // recover the id they were given at registration.
    println!("Account: {}", stored.user_id);
    println!("Server:  {}", stored.server);
    println!("Stored:  {}", credentials::path()?.display());

    Ok(())
}

async fn subscriptions(args: &Args) -> Result<()> {
    let (client, _) = authed_client(args)?;
    let subscriptions = client.subscriptions().await?;
    print_subscriptions(args, &subscriptions);
    Ok(())
}

async fn subscribe(args: &Args, package: &str) -> Result<()> {
    let (client, _) = authed_client(args)?;
    let subscriptions = client.subscribe(package).await?;

    if !args.json {
        println!("Subscribed to {package}.");
    }
    print_subscriptions(args, &subscriptions);
    Ok(())
}

async fn unsubscribe(args: &Args, package: &str) -> Result<()> {
    let (client, _) = authed_client(args)?;

    // The server answers DELETE for a package the account does not follow
    // with success and an unchanged list, so a mistyped name would otherwise
    // be reported as "Unsubscribed" while the real subscription stays put.
    let current = client.subscriptions().await?;
    if !current.iter().any(|s| s.package_name == package) {
        bail!(
            "unsubscribing from {package} failed - {}",
            client::not_subscribed(package)
        );
    }

    let subscriptions = client.unsubscribe(package).await?;

    if !args.json {
        println!("Unsubscribed from {package}.");
        if subscriptions.is_empty() {
            println!();
            println!("This account now has no subscriptions, which makes it eligible");
            println!("for automatic deletion. Subscribe to something to keep it.");
        }
    }
    print_subscriptions(args, &subscriptions);
    Ok(())
}

async fn notify(args: &Args, package: &str, enabled: bool) -> Result<()> {
    let (client, _) = authed_client(args)?;
    let subscriptions = client.set_package_notifications(package, enabled).await?;

    if !args.json {
        let state = if enabled { "enabled" } else { "muted" };
        println!("Notifications {state} for {package}.");
    }
    print_subscriptions(args, &subscriptions);
    Ok(())
}

fn feed_url(args: &Args, atom_only: bool, rss_only: bool) -> Result<()> {
    let stored = credentials::require()?;

    let atom = format!("{}/feed/{}/atom.xml", stored.server, stored.user_id);
    let rss = format!("{}/feed/{}/rss.xml", stored.server, stored.user_id);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "atom": atom, "rss": rss }))?
        );
        return Ok(());
    }

    // When one format is requested, print the bare URL so it can be piped.
    if atom_only {
        println!("{atom}");
        return Ok(());
    }
    if rss_only {
        println!("{rss}");
        return Ok(());
    }

    println!("Atom: {atom}");
    println!("RSS:  {rss}");
    println!();
    println!("These URLs contain your account id, which is also your credential.");
    println!("Anyone with the URL can read your feed and use your account.");

    Ok(())
}

fn print_subscriptions(args: &Args, subscriptions: &[fossdb::PackageSubscription]) {
    if args.json {
        match serde_json::to_string_pretty(subscriptions) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("error: could not serialise subscriptions: {e}"),
        }
        return;
    }

    if subscriptions.is_empty() {
        println!("No subscriptions.");
        return;
    }

    // Pad to the longest name so the status column lines up.
    let width = subscriptions
        .iter()
        .map(|s| s.package_name.chars().count())
        .max()
        .unwrap_or(0);

    println!();
    for subscription in subscriptions {
        let state = if subscription.notifications_enabled {
            "notifying"
        } else {
            "muted"
        };
        println!(
            "  {:<width$}  {}",
            subscription.package_name,
            state,
            width = width
        );
    }
    println!("\n{} subscription(s)", subscriptions.len());
}

#[cfg(feature = "admin")]
async fn admin_command(args: &Args, socket: &str, command: &AdminCommand) -> Result<()> {
    use fossdb_admin_types::{CollectorsReport, StatusReport, WorkerReport};

    match command {
        AdminCommand::Collectors => {
            let report: CollectorsReport = admin::get(socket, "/admin/collectors").await?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }

            print_key_table("COLLECTOR KEYS", &report.keys);

            println!();
            if report.platforms.is_empty() {
                println!("No packages ingested yet.");
            } else {
                println!("{:<24} {:>10}  {}", "PLATFORM", "PACKAGES", "LAST INGEST");
                for platform in &report.platforms {
                    println!(
                        "{:<24} {:>10}  {}",
                        platform.platform,
                        platform.packages,
                        platform
                            .seconds_since_activity
                            .map(format_age)
                            .unwrap_or_else(|| "never".to_string())
                    );
                }
            }

            print_activity_caveat(report.activity_since);
        }

        AdminCommand::Workers => {
            let report: WorkerReport = admin::get(socket, "/admin/workers").await?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }

            print_key_table("WORKER KEYS", &report.keys);
            println!();

            println!("Analyses completed: {}", report.total_analyses);
            println!(
                "Most recent:        {}",
                report
                    .seconds_since_analysis
                    .map(format_age)
                    .unwrap_or_else(|| "never".to_string())
            );
            println!(
                "Claim TTL:          {}",
                format_span(report.claim_ttl_seconds as i64)
            );
            println!();

            if report.active_claims.is_empty() {
                println!("No tasks are currently claimed; all workers are idle.");
            } else {
                println!("{} task(s) in flight:", report.active_claims.len());
                println!("{:>12}  {}", "VERSION ID", "HELD FOR");
                for claim in &report.active_claims {
                    println!(
                        "{:>12}  {}",
                        claim.version_id,
                        format_span(claim.held_for_seconds as i64)
                    );
                }
            }

            print_activity_caveat(report.activity_since);
        }

        AdminCommand::ApiKey(command) => return api_key_command(args, socket, command).await,

        AdminCommand::Status => {
            let report: StatusReport = admin::get(socket, "/admin/status").await?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }

            println!("Started:  {}", report.started_at.to_rfc3339());
            println!("Uptime:   {}", format_span(report.uptime_seconds));
            println!();
            println!("Packages:        {}", report.packages);
            println!("Versions:        {}", report.versions);
            println!("Accounts:        {}", report.accounts);
            println!("Timeline events: {}", report.timeline_events);
            println!("Analyses:        {}", report.analyses);
        }
    }

    Ok(())
}

#[cfg(feature = "admin")]
async fn api_key_command(args: &Args, socket: &str, command: &ApiKeyCommand) -> Result<()> {
    match command {
        ApiKeyCommand::Create { role, label } => {
            let response: fossdb::CreateApiKeyResponse = admin::post(
                socket,
                "/admin/api-keys",
                &fossdb::CreateApiKeyRequest {
                    role: *role,
                    label: label.clone(),
                },
            )
            .await?;

            if args.json {
                // Machine-readable output exists so provisioning scripts can
                // capture the key without scraping prose.
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            }

            println!("Created {} key {}\n", response.info.role, response.info.key_id);
            println!("  {}\n", response.key);
            println!("This is the only time the key is shown. Give it to the {} as", response.info.role);
            println!(
                "{}, or write it to a file referenced by",
                match response.info.role {
                    fossdb::ApiKeyRole::Collector => "COLLECTOR_API_KEY",
                    fossdb::ApiKeyRole::Worker => "WORKER_API_KEY",
                }
            );
            println!("the NixOS `apiKeyFile` option.");
            println!();
            println!("Revoke it with:  fossdb admin api-key revoke {}", response.info.key_id);
        }

        ApiKeyCommand::List { all } => {
            let path = if *all {
                "/admin/api-keys?all=true"
            } else {
                "/admin/api-keys"
            };
            let keys: Vec<fossdb::ApiKeyInfo> = admin::get(socket, path).await?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&keys)?);
                return Ok(());
            }

            if keys.is_empty() {
                println!("No API keys.");
                println!();
                println!("Collectors and workers cannot authenticate until one exists:");
                println!("  fossdb admin api-key create --role collector --label $(hostname)");
                println!("  fossdb admin api-key create --role worker    --label $(hostname)");
                return Ok(());
            }

            println!(
                "{:<10} {:<10} {:<22} {:<14} {}",
                "KEY ID", "ROLE", "LABEL", "LAST SEEN", "STATUS"
            );
            for key in &keys {
                println!(
                    "{:<10} {:<10} {:<22} {:<14} {}",
                    key.key_id,
                    key.role.to_string(),
                    key.label.clone().unwrap_or_else(|| "-".to_string()),
                    key.seconds_since_use
                        .map(format_age)
                        .unwrap_or_else(|| "never".to_string()),
                    match key.revoked_at {
                        Some(at) => format!("revoked {}", at.format("%Y-%m-%d")),
                        None => "active".to_string(),
                    }
                );
            }
        }

        ApiKeyCommand::Revoke { key_id } => {
            // Validate locally so an obvious typo does not look like a
            // server-side failure.
            if !fossdb::api_key::is_well_formed_id(key_id) {
                bail!(
                    "{key_id:?} is not a key id\n\
                     Key ids are {} characters. List them with `fossdb admin api-key list`.",
                    fossdb::api_key::ID_LEN
                );
            }

            let revoked: fossdb::ApiKeyInfo =
                admin::delete(socket, &format!("/admin/api-keys/{key_id}")).await?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&revoked)?);
                return Ok(());
            }

            println!("Revoked {} key {}.", revoked.role, revoked.key_id);
            println!("It stops working immediately; the holder will now get 401.");
        }
    }

    Ok(())
}

/// Render the key table shared by the collectors and workers reports.
#[cfg(feature = "admin")]
fn print_key_table(heading: &str, keys: &[fossdb::ApiKeyInfo]) {
    if keys.is_empty() {
        println!("{heading}: none issued");
        println!("  Nothing can authenticate. Create a key with:");
        println!("    fossdb admin api-key create --role <collector|worker> --label <host>");
        return;
    }

    println!("{:<10} {:<22} {}", "KEY ID", "LABEL", "LAST SEEN");
    for key in keys {
        println!(
            "{:<10} {:<22} {}",
            key.key_id,
            key.label.clone().unwrap_or_else(|| "-".to_string()),
            key.seconds_since_use
                .map(format_age)
                .unwrap_or_else(|| "never".to_string())
        );
    }
}

/// Explain the limits of what the last-seen column means.
#[cfg(feature = "admin")]
fn print_activity_caveat(activity_since: chrono::DateTime<chrono::Utc>) {
    println!();
    println!("Last-seen is tracked in memory and resets on restart; this server");
    println!("started {}.", activity_since.to_rfc3339());
    println!("It counts keys, not processes - instances sharing a key cannot be");
    println!("told apart, so issue one key per host.");
}

/// Render a span of time, e.g. an uptime or a timeout.
#[cfg(feature = "admin")]
fn format_span(seconds: i64) -> String {
    match seconds {
        s if s < 0 => "negative".to_string(),
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d {}h", s / 86_400, (s % 86_400) / 3600),
    }
}

/// Render how long ago something happened.
///
/// Kept distinct from [`format_span`]: a TTL is a duration, not an age, and
/// labelling one "30m ago" is actively misleading.
#[cfg(feature = "admin")]
fn format_age(seconds: i64) -> String {
    // Negative means the server's timestamp is in the future relative to this
    // host. Say so rather than rendering a nonsensical age.
    if seconds < 0 {
        return "in the future (clock skew?)".to_string();
    }

    format!("{} ago", format_span(seconds))
}

/// Mirrors of the server's admin report types.
///
/// Declared here rather than depending on `fossdb-server`: the CLI must build
/// without the server's database stack, and these are a stable JSON contract
/// a few fields wide.
#[cfg(feature = "admin")]
mod fossdb_admin_types {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct CollectorsReport {
        pub keys: Vec<fossdb::ApiKeyInfo>,
        pub platforms: Vec<CollectorReport>,
        pub activity_since: DateTime<Utc>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct CollectorReport {
        pub platform: String,
        pub packages: usize,
        pub last_activity: Option<DateTime<Utc>>,
        pub seconds_since_activity: Option<i64>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ClaimReport {
        pub version_id: u64,
        pub held_for_seconds: u64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct WorkerReport {
        pub keys: Vec<fossdb::ApiKeyInfo>,
        pub activity_since: DateTime<Utc>,
        pub active_claims: Vec<ClaimReport>,
        pub total_analyses: usize,
        pub last_analysis: Option<DateTime<Utc>>,
        pub seconds_since_analysis: Option<i64>,
        pub claim_ttl_seconds: u64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct StatusReport {
        pub started_at: DateTime<Utc>,
        pub uptime_seconds: i64,
        pub packages: usize,
        pub versions: usize,
        pub accounts: usize,
        pub timeline_events: usize,
        pub analyses: usize,
    }
}

#[cfg(all(test, feature = "admin"))]
mod tests {
    use super::*;

    #[test]
    fn formats_spans_by_magnitude() {
        assert_eq!(format_span(0), "0s");
        assert_eq!(format_span(45), "45s");
        assert_eq!(format_span(90), "1m");
        assert_eq!(format_span(3700), "1h 1m");
        assert_eq!(format_span(90_000), "1d 1h");
    }

    #[test]
    fn ages_are_suffixed_but_spans_are_not() {
        // A TTL rendered as "30m ago" would be actively misleading.
        assert_eq!(format_span(1800), "30m");
        assert_eq!(format_age(1800), "30m ago");
    }

    #[test]
    fn negative_ages_are_called_out() {
        // Server clock ahead of ours; must not render as a huge positive age.
        assert!(format_age(-5).contains("future"));
    }
}
