use anyhow::{Context, Result};
use axum::{
    Router,
    routing::{get, post, put},
};
use clap::Parser;
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{error, info};

use fossdb_server::{AppState, config::Config, db::Database, handlers, middleware};
use fossdb_server::{Package, PackageVersion, User, Vulnerability, TimelineEvent};
use fossdb_server::models::{ApiKey, WorkerAnalysis};

use fossdb_server::websocket;

/// FossDB - Free Software Database server
#[derive(Parser, Debug)]
#[command(name = "fossdb-server")]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Start the API server (default)
    Serve,
    /// Export database tables to JSON files
    Export {
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,
        #[arg(short, long)]
        table: Option<String>,
    },
    /// Import database table from JSON file
    Import {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long, default_value_t = false)]
        merge: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config = Config::from_env();

    match args.command {
        Some(Commands::Export { output_dir, table }) => {
            return export_database(&config, output_dir, table).await;
        }
        Some(Commands::Import { input, merge }) => {
            return import_database(&config, input, merge).await;
        }
        Some(Commands::Serve) | None => start_server(config).await,
    }
}

async fn start_server(config: Config) -> Result<()> {
    let db = open_for_serving(&config.database_path)?;
    // Refuse to start on a pre-rewrite database rather than failing later
    // with an opaque decode error from inside a request handler.
    db.preflight()?;
    let db = Arc::new(db);

    let num_packages = db.get_all_packages()?.len();
    let num_versions = db.get_all_versions()?.len();
    let num_users = db.get_all_users()?.len();
    let num_vulnerabilities = db.get_all_vulnerabilities()?.len();
    let num_timeline_events = db.get_all_timeline_events()?.len();

    info!("Database statistics:");
    info!("  Packages: {}", num_packages);
    info!("  Versions: {}", num_versions);
    info!("  Users: {}", num_users);
    info!("  Vulnerabilities: {}", num_vulnerabilities);
    info!("  Timeline Events: {}", num_timeline_events);

    let broadcaster = Arc::new(websocket::TimelineBroadcaster::new());

    if let Err(e) =
        fossdb_server::db_listener::spawn_package_version_listener(db.clone(), broadcaster.clone())
    {
        error!("Failed to initialize database listener: {}", e);
    }

    let state = AppState {
        db: db.clone(),
        broadcaster: broadcaster.clone(),
        key_activity: std::sync::Arc::new(std::sync::Mutex::new(
            fossdb_server::key_activity::KeyActivity::new(),
        )),
        claimed_versions: std::sync::Arc::new(std::sync::Mutex::new(
            fossdb_server::claims::ClaimSet::new(),
        )),
        lookalikes: std::sync::Arc::new(fossdb_server::lookalike::LookalikeTargets::new()),
        public_base_url: config.public_base_url.clone(),
        started_at: chrono::Utc::now(),
    };

    // Unsubscribed-account reaper.
    //
    // An account that never subscribes to anything is indistinguishable from
    // signup noise: it produces no events and no feed. Reaping it after a
    // grace period keeps the table proportional to real usage, which matters
    // because registration is unauthenticated and unthrottled.
    let reaper_db = db.clone();
    let grace = chrono::Duration::hours(config.account_grace_hours as i64);
    let purge_interval = config.account_purge_interval_secs;
    info!(
        "Account reaper: purging subscription-less accounts older than {}h every {}s",
        config.account_grace_hours, purge_interval
    );
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(purge_interval)).await;
            match reaper_db.purge_unsubscribed_users(grace) {
                Ok(0) => {}
                Ok(count) => info!("Purged {} account(s) with no subscriptions", count),
                Err(e) => error!("Failed to purge unsubscribed accounts: {}", e),
            }
        }
    });

    // Admin control socket. Unix-only, and optional: a failure to bind is
    // logged but must not take the API server down with it.
    #[cfg(unix)]
    {
        let admin_state = state.clone();
        let socket_path = config.admin_socket_path.clone();
        tokio::spawn(async move {
            if let Err(e) = fossdb_server::admin::serve(admin_state, &socket_path).await {
                error!("Admin socket unavailable at {}: {:#}", socket_path, e);
            }
        });
    }

    // Timeline event purge task
    let purge_db = db.clone();
    let retention_days = config.timeline_retention_days;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(24 * 60 * 60)).await;
            info!("Running timeline event purge (retention: {} days)", retention_days);
            match purge_db.purge_old_timeline_events(chrono::Duration::days(retention_days as i64)) {
                Ok(count) => {
                    if count > 0 {
                        info!("Purged {} old timeline events", count);
                    }
                }
                Err(e) => error!("Failed to purge old timeline events: {}", e),
            }
        }
    });

    // Internal worker API on separate port
    let worker_api = Router::new()
        .route("/packages/next", get(handlers::worker::get_task))
        .route("/analysis", post(handlers::worker::submit_analysis))
        .route("/packages/{package_id}/analyses", get(handlers::worker::get_package_analyses))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::worker_auth_middleware,
        ))
        .with_state(state.clone());

    let worker_bind = format!("{}:{}", config.internal_bind_address, config.worker_port);
    let worker_listener = tokio::net::TcpListener::bind(&worker_bind).await?;
    info!("Worker API running on http://{}", worker_bind);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(worker_listener, worker_api).await {
            error!("Worker API server error: {}", e);
        }
    });

    // Internal collector API on separate port
    let collector_api = Router::new()
        .route("/packages", get(handlers::collector::get_package))
        .route("/packages", post(handlers::collector::upsert_package))
        .route("/packages/{name}/timestamp", put(handlers::collector::update_package_timestamp))
        .route("/advisories", post(handlers::collector::upsert_advisory))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::collector_auth_middleware,
        ))
        .with_state(state.clone());

    let collector_bind = format!("{}:{}", config.internal_bind_address, config.collector_port);
    let collector_listener = tokio::net::TcpListener::bind(&collector_bind).await?;
    info!("Collector API running on http://{}", collector_bind);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(collector_listener, collector_api).await {
            error!("Collector API server error: {}", e);
        }
    });

    let app = fossdb_server::routes::public_router(state);

    let bind = format!("{}:{}", config.bind_address, config.server_port);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!("Server running on http://{}", bind);
    info!("Public base URL for feed links: {}", config.public_base_url);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Open (creating if need be) the database the server runs against.
///
/// redb creates the file but not its directory, and its error for a missing
/// one ("I/O error: No such file or directory") names neither. `.env.example`
/// points `DATABASE_PATH` into `./data/`, which a fresh checkout lacks, so
/// create the directory rather than refuse to start.
fn open_for_serving(path: &str) -> Result<Database> {
    create_database_dir(path)?;
    Database::new(path).with_context(|| format!("opening database at {path}"))
}

fn create_database_dir(path: &str) -> Result<()> {
    if let Some(dir) = Path::new(path).parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| {
            format!("creating {} for DATABASE_PATH={}", dir.display(), path)
        })?;
    }
    Ok(())
}

fn export_table<T: Serialize>(table_name: &str, data: Vec<T>, output_path: &Path) -> Result<()> {
    info!("Exporting {}...", table_name);
    eprintln!("Exporting {} {} to {}...", data.len(), table_name, output_path.display());
    let json = serde_json::to_string_pretty(&data)?;
    std::fs::write(output_path, json)?;
    eprintln!("✓ Exported {} {}", data.len(), table_name);
    Ok(())
}

/// Every table `export` writes by default and `import` accepts, named as the
/// file stem each is written to.
///
/// This has to cover every table holding state that cannot be recollected.
/// Analyses were missing for a while, so a backup and restore lost every
/// analysis: the worker only re-analyses the newest version of each package,
/// which left the install-hook alerts with no baseline to compare against.
/// API keys were missing too, which locked out every collector and worker.
const TABLES: &[&str] = &[
    "packages",
    "versions",
    "users",
    "vulnerabilities",
    "timeline_events",
    "analyses",
    "api_keys",
];

/// Open the database for `export`/`import`.
///
/// redb takes an exclusive lock, so this fails while the server is running.
/// The raw error ("Database already open. Cannot acquire lock.") does not say
/// which process holds it, so say so here.
fn open_offline(path: &str) -> Result<Database> {
    Database::new(path).with_context(|| {
        format!(
            "opening {path}; if fossdb-server is running against it, stop it first \
             (the database is locked while it is open)"
        )
    })
}

/// Open an existing database to export from.
///
/// redb creates a missing file, so a mistyped `DATABASE_PATH` used to leave a
/// fresh empty database behind and write a full set of empty backup files
/// under "Export completed successfully!".
fn open_for_export(path: &str) -> Result<Database> {
    if !Path::new(path).exists() {
        anyhow::bail!(
            "no database at {path}; set DATABASE_PATH to the file fossdb-server runs against"
        );
    }
    open_offline(path)
}

/// Open (creating if need be) the database to import into.
///
/// Restoring onto a fresh host is the point of `import`, and there the
/// database directory does not exist yet; redb's error for that names no path
/// and the lock hint in [`open_offline`] would send the operator looking for
/// a server that is not running.
fn open_for_import(path: &str) -> Result<Database> {
    create_database_dir(path)?;
    open_offline(path)
}

async fn export_database(config: &Config, output_dir: PathBuf, table: Option<String>) -> Result<()> {
    let db = open_for_export(&config.database_path)?;
    export_tables(&db, &output_dir, table)
}

fn export_tables(db: &Database, output_dir: &Path, table: Option<String>) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;

    let tables_to_export = if let Some(table_name) = table {
        vec![table_name]
    } else {
        TABLES.iter().map(|t| t.to_string()).collect()
    };

    for table_name in tables_to_export {
        let output_path = output_dir.join(format!("{}.json", table_name));
        match table_name.as_str() {
            "packages" => export_table("packages", db.get_all_packages()?, &output_path)?,
            "versions" => export_table("versions", db.get_all_versions()?, &output_path)?,
            "users" => {
                // The user table now stores live credentials in the clear -
                // the id *is* the password. An export is therefore a file
                // that grants access to every account in it.
                eprintln!(
                    "WARNING: users.json will contain every account's login credential \
                     in plaintext.\n         Treat it as a secret: anyone who reads it \
                     can sign in as any of those accounts."
                );
                export_table("users", db.get_all_users()?, &output_path)?
            }
            "vulnerabilities" => export_table("vulnerabilities", db.get_all_vulnerabilities()?, &output_path)?,
            "timeline_events" => export_table("timeline events", db.get_all_timeline_events()?, &output_path)?,
            "analyses" => export_table("analyses", db.get_all_analyses()?, &output_path)?,
            // Only hashes of the secrets are stored, so this file cannot be
            // used to authenticate; it lets a restored server accept the keys
            // its collectors and workers already hold.
            "api_keys" => export_table("API keys", db.get_all_api_keys()?, &output_path)?,
            _ => {
                eprintln!("Error: Unknown table '{}'", table_name);
                return Err(anyhow::anyhow!(
                    "Unknown table: {} (expected one of: {})",
                    table_name,
                    TABLES.join(", ")
                ));
            }
        }
    }

    eprintln!("\nExport completed successfully!");
    Ok(())
}

async fn import_database(config: &Config, input: PathBuf, merge: bool) -> Result<()> {
    let db = open_for_import(&config.database_path)?;
    import_file(&db, &input, merge, true).await
}

/// Import one exported table. `confirm` gives the operator a few seconds to
/// cancel before a non-merge import overwrites rows.
async fn import_file(db: &Database, input: &Path, merge: bool, confirm: bool) -> Result<()> {
    let table_name = input
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

    info!("Importing {} (merge: {})...", table_name, merge);
    eprintln!("Reading from: {}", input.display());

    let json = std::fs::read_to_string(input)?;

    // Rows keep the primary keys they were exported with. Existing rows with
    // the same key are skipped under `--merge` and overwritten otherwise.
    macro_rules! import_rows {
        ($data:expr, $type_name:expr, $key:expr) => {{
            let data = $data;
            eprintln!("Found {} {} to import", data.len(), $type_name);

            if !merge && confirm {
                eprintln!("WARNING: This will replace existing {}!", $type_name);
                eprintln!("Press Ctrl+C within 5 seconds to cancel...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }

            let counts = db.import(data, $key, merge)?;
            eprintln!(
                "✓ Imported {} {} ({} new, {} replaced, {} skipped as already present)",
                counts.inserted + counts.replaced,
                $type_name,
                counts.inserted,
                counts.replaced,
                counts.skipped
            );
        }};
    }

    match table_name {
        "packages" => {
            let data: Vec<Package> = serde_json::from_str(&json)?;
            import_rows!(data, "packages", |p: &Package| p.id);
        }
        "versions" => {
            let data: Vec<PackageVersion> = serde_json::from_str(&json)?;
            import_rows!(data, "versions", |v: &PackageVersion| v.id);
        }
        // Users are keyed by their credential rather than a numeric id.
        "users" => {
            let data: Vec<User> = serde_json::from_str(&json)?;
            import_rows!(data, "users", |u: &User| u.user_id.clone());
        }
        "vulnerabilities" => {
            let mut data: Vec<Vulnerability> = serde_json::from_str(&json)?;
            // Exports written before `source_id` existed lack it.
            for v in &mut data {
                if v.source_id.is_empty() {
                    v.inner.source_id = fossdb_server::models::legacy_source_id(v.id);
                }
            }
            import_rows!(data, "vulnerabilities", |v: &Vulnerability| v.id);
        }
        "timeline_events" => {
            let data: Vec<TimelineEvent> = serde_json::from_str(&json)?;
            import_rows!(data, "timeline events", |e: &TimelineEvent| e.id);
        }
        "analyses" => {
            let data: Vec<WorkerAnalysis> = serde_json::from_str(&json)?;
            import_rows!(data, "analyses", |a: &WorkerAnalysis| a.id);
        }
        "api_keys" => {
            let data: Vec<ApiKey> = serde_json::from_str(&json)?;
            import_rows!(data, "API keys", |k: &ApiKey| k.key_id.clone());
        }
        _ => {
            eprintln!("Error: Unknown table '{}'", table_name);
            return Err(anyhow::anyhow!(
                "Unknown table: {} (expected one of: {})",
                table_name,
                TABLES.join(", ")
            ));
        }
    }

    eprintln!("\nImport completed successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn open(dir: &tempfile::TempDir, name: &str) -> Database {
        Database::new(dir.path().join(name).to_str().unwrap()).unwrap()
    }

    /// Restore a full export into an empty database the way an operator
    /// would: one `import` per exported file.
    async fn round_trip(source: &Database, dir: &tempfile::TempDir) -> Database {
        let out = dir.path().join("export");
        export_tables(source, &out, None).unwrap();

        let target = open(dir, "restored.db");
        for table in TABLES {
            import_file(&target, &out.join(format!("{table}.json")), false, false)
                .await
                .unwrap();
        }
        target
    }

    #[tokio::test]
    async fn export_and_import_round_trip_analyses_and_api_keys() {
        let dir = tempfile::tempdir().unwrap();
        let source = open(&dir, "source.db");

        let analysis = source
            .insert_worker_analysis(WorkerAnalysis {
                inner: fossdb::WorkerAnalysis {
                    id: 0,
                    package_id: 7,
                    version_id: 11,
                    analyzed_at: Utc::now(),
                    findings: vec![fossdb::AnalysisFinding {
                        kind: fossdb::FindingKind::LicenseDetected,
                        severity: fossdb::FindingSeverity::Info,
                        description: "License file detected: MIT".to_string(),
                        location: Some("LICENSE".to_string()),
                    }],
                    checksum_verified: Some(true),
                    detected_license: Some("MIT".to_string()),
                },
            })
            .unwrap();
        source
            .insert_api_key(ApiKey {
                inner: fossdb::ApiKey {
                    key_id: "ts55a04c".to_string(),
                    role: fossdb::ApiKeyRole::Collector,
                    secret_hash: "ab".repeat(32),
                    label: Some("host".to_string()),
                    created_at: Utc::now(),
                    revoked_at: None,
                },
            })
            .unwrap();

        let restored = round_trip(&source, &dir).await;

        let analyses = restored.get_analyses_by_version(11).unwrap();
        assert_eq!(analyses.len(), 1);
        assert_eq!(analyses[0].inner, analysis.inner);

        let key = restored.get_api_key("ts55a04c").unwrap().expect("key restored");
        assert_eq!(key.secret_hash, "ab".repeat(32));
        assert_eq!(key.role, fossdb::ApiKeyRole::Collector);
    }

    #[test]
    fn serving_creates_a_missing_database_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join("nested").join("fossdb.db");

        open_for_serving(path.to_str().unwrap()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn serving_names_the_path_it_cannot_use() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file where the database directory should be.
        let blocker = dir.path().join("data");
        std::fs::write(&blocker, "").unwrap();
        let path = blocker.join("fossdb.db");

        let err = format!("{:#}", open_for_serving(path.to_str().unwrap()).err().unwrap());
        assert!(err.contains(path.to_str().unwrap()), "{err}");
    }

    #[test]
    fn export_refuses_a_missing_database_instead_of_creating_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fosdb.db");

        let err = format!("{:#}", open_for_export(path.to_str().unwrap()).err().unwrap());
        assert!(err.contains(path.to_str().unwrap()), "{err}");
        assert!(err.contains("DATABASE_PATH"), "{err}");
        assert!(!path.exists(), "export must not leave an empty database behind");
    }

    #[test]
    fn export_opens_an_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fossdb.db");
        drop(open(&dir, "fossdb.db"));

        open_for_export(path.to_str().unwrap()).unwrap();
    }

    #[test]
    fn import_creates_a_missing_database_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join("fossdb.db");

        open_for_import(path.to_str().unwrap()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn unknown_table_names_the_valid_ones() {
        let dir = tempfile::tempdir().unwrap();
        let db = open(&dir, "db");

        let err = export_tables(&db, &dir.path().join("out"), Some("analysis".to_string()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("analyses"), "{err}");
    }
}
