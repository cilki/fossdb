use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use fossdb::{WorkerAnalysis as FossdbWorkerAnalysis, WorkerTask};

use crate::db_listener::emit_install_hook_changes;
use crate::{AppState, WorkerAnalysis};

pub async fn get_task(
    State(state): State<AppState>,
) -> Result<Json<WorkerTask>, StatusCode> {
    // Packages are assigned IDs in insertion order; iterate highest-ID first so
    // we always hand out the most recently added unanalyzed package.
    let mut packages = state.db.get_all_packages().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    packages.sort_unstable_by(|a, b| b.id.cmp(&a.id));

    let now = std::time::Instant::now();
    let mut claimed = state
        .claimed_versions
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Reclaim versions abandoned by workers that never reported back.
    claimed.prune_expired(now);

    for pkg in &packages {
        let versions = state
            .db
            .get_versions_by_package(pkg.id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Pick the latest version that has a download URL
        let Some(version) = versions.into_iter().filter(|v| v.download_url.is_some()).max_by_key(|v| v.id) else {
            continue;
        };

        // Skip if a completed analysis already exists for this version
        let existing = state
            .db
            .get_analyses_by_version(version.id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !existing.is_empty() {
            continue;
        }

        // Skip if another worker holds a live claim on this version.
        if !claimed.try_claim(version.id, now) {
            continue;
        }

        return Ok(Json(WorkerTask {
            package: pkg.inner.clone(),
            version: version.inner,
        }));
    }

    Err(StatusCode::NOT_FOUND)
}

pub async fn submit_analysis(
    State(state): State<AppState>,
    Json(mut analysis): Json<FossdbWorkerAnalysis>,
) -> Result<Json<FossdbWorkerAnalysis>, StatusCode> {
    // Validate the referenced package and version exist
    state
        .db
        .get_package(analysis.package_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    let version = state
        .db
        .get_version(analysis.version_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    // The version must actually belong to the package it is submitted under,
    // otherwise an analysis would surface under an unrelated package.
    if version.package_id != analysis.package_id {
        tracing::warn!(
            "Rejecting analysis: version {} belongs to package {}, not {}",
            analysis.version_id,
            version.package_id,
            analysis.package_id
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // The primary key is ours to assign. Honouring a client-supplied id would
    // let a worker plant a duplicate key (breaking a later insert) or jump the
    // id generator to u64::MAX.
    analysis.id = 0;

    let version_id = analysis.version_id;
    let model = WorkerAnalysis { inner: analysis };
    let saved = state
        .db
        .insert_worker_analysis(model)
        .map_err(|e| {
            tracing::error!("Failed to insert worker analysis: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Release the claim only once the analysis is durably committed. Releasing
    // beforehand opens a window where the version looks neither claimed nor
    // analyzed, so a second worker would be handed the same task. If the insert
    // fails the claim is left to expire on its own.
    if let Ok(mut claimed) = state.claimed_versions.lock() {
        claimed.release(version_id);
    }

    tracing::info!(
        "Stored analysis for package_id={} version_id={} findings={}",
        saved.package_id,
        saved.version_id,
        saved.findings.len()
    );

    // The analysis is stored; failing to notify must not fail the submission,
    // or the worker would redo the whole analysis.
    if let Err(e) = emit_install_hook_changes(&state.db, &state.broadcaster, &saved.inner) {
        tracing::error!(
            "Failed to compare install hooks for analysis {}: {}",
            saved.id,
            e
        );
    }

    Ok(Json(saved.inner))
}

pub async fn get_package_analyses(
    State(state): State<AppState>,
    Path(package_id): Path<u64>,
) -> Result<Json<Vec<FossdbWorkerAnalysis>>, StatusCode> {
    let analyses = state
        .db
        .get_analyses_by_package(package_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(analyses.into_iter().map(|a| a.inner).collect()))
}
