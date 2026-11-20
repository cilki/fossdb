//! Administrative control surface, served over a unix domain socket.
//!
//! There is no API key. Authorisation is the socket's filesystem
//! permissions: if you can open it, you are an administrator. That is the
//! right trade for a local control channel, and it avoids inventing a third
//! shared secret alongside the collector and worker keys.
//!
//! # What these reports can and cannot tell you
//!
//! Collectors and workers are anonymous, stateless HTTP clients that share
//! one API key per role. The server therefore **cannot enumerate running
//! instances** - it has no idea whether one worker is polling or twenty are.
//! What it can do is report observable evidence of activity, which is what
//! the endpoints below return:
//!
//! - collectors and workers: per-API-key last-seen timestamps. Since each
//!   collector and worker now authenticates with its own named key, this is
//!   real per-key liveness - though it still counts *keys*, not processes, so
//!   issue one key per host if you want to tell them apart.
//! - collectors additionally: per-platform package counts and the most recent
//!   `Package.updated_at`, which collectors advance as they ingest.
//! - workers additionally: live task claims from [`crate::claims::ClaimSet`],
//!   plus analysis counts and the most recent `analyzed_at`.
//!
//! Key last-seen data is in memory, so it resets on restart; the CLI says so
//! rather than presenting a freshly restarted server as an idle fleet.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path as FsPath;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},  // axum's Path extractor; FsPath is std's
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use fossdb::{ClaimReport, CollectorReport, CollectorsReport, StatusReport, WorkerReport};
use tokio::net::UnixListener;

use crate::AppState;

/// Permissions applied to the socket: owner and group only.
///
/// Explicitly set rather than left to the process umask, which would
/// otherwise decide whether this control channel is world-writable.
const SOCKET_MODE: u32 = 0o660;

/// Bind the socket and serve until the process exits.
///
/// Replaces a stale socket file left behind by an unclean shutdown; `bind`
/// fails outright on an existing path, which would otherwise make the admin
/// interface permanently unavailable after one crash.
pub async fn serve(state: AppState, socket_path: &str) -> Result<()> {
    let path = FsPath::new(socket_path);

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating admin socket directory {}", parent.display()))?;
    }

    // Only remove something that is actually a socket. If a regular file or
    // directory is sitting at this path the configuration is wrong, and
    // deleting it would be destructive.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(path).with_context(|| {
                format!("removing stale admin socket {}", path.display())
            })?;
        }
        Ok(_) => anyhow::bail!(
            "{} exists and is not a socket; refusing to replace it",
            path.display()
        ),
        Err(_) => {}
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding admin socket {}", path.display()))?;

    // Tighten permissions immediately after bind. There is an unavoidable
    // window between bind and chmod during which the umask governs; the
    // parent directory should be restricted in a hostile environment.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
        .with_context(|| format!("setting mode on {}", path.display()))?;

    tracing::info!(
        "Admin socket listening on {} (mode {:o})",
        path.display(),
        SOCKET_MODE
    );

    let app = Router::new()
        .route("/admin/status", get(status))
        .route("/admin/collectors", get(collectors))
        .route("/admin/workers", get(workers))
        .route("/admin/api-keys", get(list_api_keys))
        .route("/admin/api-keys", post(create_api_key))
        .route("/admin/api-keys/{key_id}", delete(revoke_api_key))
        .with_state(state);

    axum::serve(listener, app)
        .await
        .context("admin socket server stopped")
}

async fn status(State(state): State<AppState>) -> Result<Json<StatusReport>, StatusCode> {
    let db = &state.db;

    let report = StatusReport {
        started_at: state.started_at,
        uptime_seconds: (Utc::now() - state.started_at).num_seconds(),
        packages: count(db.get_all_packages())?,
        versions: count(db.get_all_versions())?,
        accounts: count(db.get_all_users())?,
        timeline_events: count(db.get_all_timeline_events())?,
        analyses: count(db.get_all_analyses())?,
    };

    Ok(Json(report))
}

/// Decorate stored keys of one role with their in-memory last-seen times.
fn keys_for_role(
    state: &AppState,
    role: fossdb::ApiKeyRole,
) -> Result<Vec<fossdb::ApiKeyInfo>, StatusCode> {
    let stored = state.db.get_all_api_keys().map_err(internal)?;
    let now = Utc::now();

    let activity = state.key_activity.lock().map_err(|_| {
        tracing::error!("key activity mutex poisoned");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut keys: Vec<fossdb::ApiKeyInfo> = stored
        .into_iter()
        .filter(|key| key.role == role)
        // A revoked key is not an instance; leave it out of liveness output.
        .filter(|key| key.revoked_at.is_none())
        .map(|key| {
            let last_used_at = activity.last_seen(&key.key_id);
            let mut info = fossdb::ApiKeyInfo::from(key.inner.clone());
            info.last_used_at = last_used_at;
            info.seconds_since_use = last_used_at.map(|t| (now - t).num_seconds());
            info
        })
        .collect();

    // Most recently active first; never-used keys sort last.
    keys.sort_by(|a, b| b.last_used_at.cmp(&a.last_used_at));

    Ok(keys)
}

async fn collectors(State(state): State<AppState>) -> Result<Json<CollectorsReport>, StatusCode> {
    use std::collections::HashMap;

    let keys = keys_for_role(&state, fossdb::ApiKeyRole::Collector)?;
    let packages = state.db.get_all_packages().map_err(internal)?;

    // Group by platform, tracking the newest ingest timestamp per group.
    let mut grouped: HashMap<String, (usize, Option<DateTime<Utc>>)> = HashMap::new();
    for package in &packages {
        let platform = package
            .platform
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let entry = grouped.entry(platform).or_insert((0, None));
        entry.0 += 1;
        entry.1 = entry.1.max(Some(package.updated_at));
    }

    let now = Utc::now();
    let mut reports: Vec<CollectorReport> = grouped
        .into_iter()
        .map(|(platform, (packages, last_activity))| CollectorReport {
            platform,
            packages,
            last_activity,
            seconds_since_activity: last_activity.map(|t| (now - t).num_seconds()),
        })
        .collect();

    // Most recently active first, so the interesting rows are at the top.
    reports.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

    Ok(Json(CollectorsReport {
        keys,
        platforms: reports,
        activity_since: state.started_at,
    }))
}

async fn workers(State(state): State<AppState>) -> Result<Json<WorkerReport>, StatusCode> {
    let keys = keys_for_role(&state, fossdb::ApiKeyRole::Worker)?;
    let analyses = state.db.get_all_analyses().map_err(internal)?;
    let last_analysis = analyses.iter().map(|a| a.analyzed_at).max();

    let active_claims = {
        let claimed = state.claimed_versions.lock().map_err(|_| {
            tracing::error!("claim set mutex poisoned");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let now = std::time::Instant::now();
        let mut claims: Vec<ClaimReport> = claimed
            .iter()
            .map(|(version_id, claimed_at)| ClaimReport {
                version_id: *version_id,
                held_for_seconds: now.saturating_duration_since(*claimed_at).as_secs(),
            })
            .collect();

        // Longest-held first: a claim near its TTL is the one worth noticing.
        claims.sort_by(|a, b| b.held_for_seconds.cmp(&a.held_for_seconds));
        claims
    };

    let now = Utc::now();
    Ok(Json(WorkerReport {
        keys,
        activity_since: state.started_at,
        active_claims,
        total_analyses: analyses.len(),
        last_analysis,
        seconds_since_analysis: last_analysis.map(|t| (now - t).num_seconds()),
        claim_ttl_seconds: crate::claims::CLAIM_TTL.as_secs(),
    }))
}

/// Query parameters for the key listing.
#[derive(Debug, Deserialize)]
pub struct ListKeysQuery {
    /// Include revoked keys. Off by default so routine listings show only
    /// keys that still work.
    #[serde(default)]
    all: bool,
}

async fn list_api_keys(
    State(state): State<AppState>,
    Query(params): Query<ListKeysQuery>,
) -> Result<Json<Vec<fossdb::ApiKeyInfo>>, StatusCode> {
    let stored = state.db.get_all_api_keys().map_err(internal)?;
    let now = Utc::now();

    let activity = state.key_activity.lock().map_err(|_| {
        tracing::error!("key activity mutex poisoned");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut keys: Vec<fossdb::ApiKeyInfo> = stored
        .into_iter()
        .filter(|key| params.all || key.revoked_at.is_none())
        .map(|key| {
            let last_used_at = activity.last_seen(&key.key_id);
            let mut info = fossdb::ApiKeyInfo::from(key.inner.clone());
            info.last_used_at = last_used_at;
            info.seconds_since_use = last_used_at.map(|t| (now - t).num_seconds());
            info
        })
        .collect();

    keys.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    Ok(Json(keys))
}

async fn create_api_key(
    State(state): State<AppState>,
    Json(payload): Json<fossdb::CreateApiKeyRequest>,
) -> Result<Json<fossdb::CreateApiKeyResponse>, StatusCode> {
    // Keep labels short and free of control characters: they are rendered
    // straight into terminal output by the CLI.
    let label = payload.label.map(|raw| {
        raw.chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect::<String>()
            .trim()
            .to_string()
    });

    let minted = crate::api_key::mint().map_err(|e| {
        tracing::error!("failed to mint API key: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let record = crate::models::ApiKey {
        inner: fossdb::ApiKey {
            key_id: minted.key_id.clone(),
            role: payload.role,
            secret_hash: minted.secret_hash,
            label: label.filter(|l| !l.is_empty()),
            created_at: Utc::now(),
            revoked_at: None,
        },
    };

    let stored = state.db.insert_api_key(record).map_err(|e| {
        tracing::error!("failed to persist API key: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!(
        "issued {} API key {}",
        stored.role,
        stored.key_id
    );

    Ok(Json(fossdb::CreateApiKeyResponse {
        // The only time the secret leaves this process.
        key: minted.key,
        info: fossdb::ApiKeyInfo::from(stored.inner.clone()),
    }))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<fossdb::ApiKeyInfo>, StatusCode> {
    if !fossdb::api_key::is_well_formed_id(&key_id) {
        return Err(StatusCode::NOT_FOUND);
    }

    let revoked = state
        .db
        .revoke_api_key(&key_id)
        .map_err(internal)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Drop the liveness entry so a revoked key stops showing as active.
    if let Ok(mut activity) = state.key_activity.lock() {
        activity.forget(&key_id);
    }

    tracing::info!("revoked {} API key {}", revoked.role, key_id);

    Ok(Json(fossdb::ApiKeyInfo::from(revoked.inner.clone())))
}

fn internal<E: std::fmt::Display>(e: E) -> StatusCode {
    tracing::error!("admin query failed: {e}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn count<T>(result: anyhow::Result<Vec<T>>) -> Result<usize, StatusCode> {
    result.map(|v| v.len()).map_err(internal)
}
