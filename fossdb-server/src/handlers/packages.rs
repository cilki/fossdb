use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::Utc;
use fossdb::typosquat::PackageLookalike;
use fossdb::{FindingKind, InstallHook, InstallHookChange, PackageInstallHooks, PackageVulnerability};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

use crate::db::Database;
use crate::db_listener::install_hook_changes;
use crate::lookalike::LookalikeTargets;
use crate::{AppState, Package, PackageVersion};

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ListPackagesQuery {
    page: Option<u32>,
    limit: Option<u32>,
    search: Option<String>,
    tag: Option<String>,
    /// Filter by package language (case-insensitive exact match).
    language: Option<String>,
    /// Filter by declared license (case-insensitive exact match).
    license: Option<String>,
    /// Only packages updated within this window: `today`, `week`, `month`,
    /// `year`.
    updated_within: Option<String>,
}

/// Translate an `updated_within` keyword into a cutoff timestamp.
fn updated_within_cutoff(value: &str) -> Option<chrono::DateTime<Utc>> {
    let days = match value {
        "today" => 1,
        "week" => 7,
        "month" => 30,
        "year" => 365,
        _ => return None,
    };
    Some(Utc::now() - chrono::Duration::days(days))
}

pub async fn list_packages(
    Query(params): Query<ListPackagesQuery>,
    State(state): State<AppState>,
) -> Result<Json<Value>, StatusCode> {
    match state.db.get_all_packages() {
        Ok(mut packages) => {
            // Filter by search term if provided
            if let Some(search) = &params.search {
                let search_lower = search.to_lowercase();
                packages.retain(|pkg| {
                    pkg.name.to_lowercase().contains(&search_lower)
                        || pkg
                            .description
                            .as_ref()
                            .map(|d| d.to_lowercase().contains(&search_lower))
                            .unwrap_or(false)
                });
            }

            // Filter by tag if provided
            if let Some(tag) = &params.tag {
                packages.retain(|pkg| pkg.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)));
            }

            // Language / license / recency filters.
            //
            // These are applied here, before pagination, so `total` reflects the
            // filtered count. The client used to filter the already-paginated
            // page itself, which produced mostly-empty pages while the pager
            // still advertised the unfiltered page count.
            if let Some(language) = params.language.as_deref().filter(|l| !l.is_empty()) {
                packages.retain(|pkg| {
                    pkg.language
                        .as_deref()
                        .is_some_and(|l| l.eq_ignore_ascii_case(language))
                });
            }

            if let Some(license) = params.license.as_deref().filter(|l| !l.is_empty()) {
                packages.retain(|pkg| {
                    pkg.license
                        .as_deref()
                        .is_some_and(|l| l.eq_ignore_ascii_case(license))
                });
            }

            if let Some(cutoff) = params
                .updated_within
                .as_deref()
                .and_then(updated_within_cutoff)
            {
                packages.retain(|pkg| pkg.updated_at >= cutoff);
            }

            // Apply pagination.
            //
            // `page` is clamped and the arithmetic done in `usize`: the previous
            // `((page - 1) * limit as u32)` overflowed in u32 for a large `page`,
            // which panics with overflow checks enabled.
            let total = packages.len();
            let limit = params.limit.unwrap_or(50).min(100) as usize;
            let page = params.page.unwrap_or(1).max(1) as usize;
            let offset = page.saturating_sub(1).saturating_mul(limit);

            let paginated_packages: Vec<Package> =
                packages.into_iter().skip(offset).take(limit).collect();

            let lookalikes = page_lookalikes(&state.db, &state.lookalikes, &paginated_packages);

            Ok(Json(serde_json::json!({
                "packages": paginated_packages,
                "total": total,
                "page": page,
                "limit": limit,
                "lookalikes": lookalikes
            })))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_package(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Package>, StatusCode> {
    let id = id.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;

    match state.db.get_package(id) {
        Ok(Some(package)) => Ok(Json(package)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_package_versions(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Vec<PackageVersion>>, StatusCode> {
    let id = id.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;

    match state.db.get_versions_by_package(id) {
        Ok(versions) => Ok(Json(versions)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn get_package_vulnerabilities(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Vec<PackageVulnerability>>, StatusCode> {
    let id = id.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;

    match package_vulnerabilities(&state.db, id) {
        Ok(Some(list)) => Ok(Json(list)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to list vulnerabilities of package {}: {}", id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Advisories affecting any version of a package, most recently published
/// first, or `None` if there is no such package.
pub fn package_vulnerabilities(
    db: &Database,
    package_id: u64,
) -> anyhow::Result<Option<Vec<PackageVulnerability>>> {
    if db.get_package(package_id)?.is_none() {
        return Ok(None);
    }
    let versions = db.get_versions_by_package(package_id)?;

    let mut list: Vec<PackageVulnerability> = db
        .get_all_vulnerabilities()?
        .into_iter()
        .filter_map(|v| {
            let version_range = v
                .affected_packages
                .iter()
                .find(|a| a.package_id == package_id)?
                .version_range
                .clone();
            let tag = v.id.to_string();
            let affected_versions = versions
                .iter()
                .filter(|pv| pv.vulnerabilities.contains(&tag))
                .map(|pv| pv.version.clone())
                .collect();
            Some(PackageVulnerability {
                vulnerability: v.inner,
                version_range,
                affected_versions,
            })
        })
        .collect();
    list.sort_by(|a, b| b.vulnerability.discovered_at.cmp(&a.vulnerability.discovered_at));
    Ok(Some(list))
}

/// `null` when the package exists but no worker has analysed it yet.
pub async fn get_package_install_hooks(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Option<PackageInstallHooks>>, StatusCode> {
    let id = id.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;

    let result = state.db.get_package(id).and_then(|package| match package {
        Some(_) => package_install_hooks(&state.db, id).map(Some),
        None => Ok(None),
    });
    match result {
        Ok(Some(hooks)) => Ok(Json(hooks)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to list install hooks of package {}: {}", id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// The install hooks of the package's most recently analysed version, marked
/// against the analysis before it the same way subscribers are alerted (see
/// [`emit_install_hook_changes`](crate::db_listener::emit_install_hook_changes)),
/// or `None` if the package has no analysis.
pub fn package_install_hooks(
    db: &Database,
    package_id: u64,
) -> anyhow::Result<Option<PackageInstallHooks>> {
    let mut analyses = db.get_analyses_by_package(package_id)?;
    analyses.sort_by_key(|a| (a.version_id, a.id));
    let Some(latest) = analyses.pop() else {
        return Ok(None);
    };
    let baseline = analyses
        .into_iter()
        .rev()
        .find(|a| a.version_id < latest.version_id);

    let changes: HashMap<Option<&str>, InstallHookChange> = baseline
        .as_ref()
        .map(|b| install_hook_changes(&b.findings, &latest.findings))
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let change = if c.added {
                InstallHookChange::Added
            } else {
                InstallHookChange::Changed
            };
            (c.hook.location.as_deref(), change)
        })
        .collect();

    let hooks = latest
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::InstallHook)
        .map(|f| InstallHook {
            location: f.location.clone(),
            description: f.description.clone(),
            severity: f.severity.clone(),
            change: changes.get(&f.location.as_deref()).copied(),
        })
        .collect();

    let version_name = |id: u64| -> anyhow::Result<String> {
        Ok(db
            .get_version(id)?
            .map(|v| v.inner.version)
            .unwrap_or_else(|| format!("#{id}")))
    };
    Ok(Some(PackageInstallHooks {
        version: version_name(latest.version_id)?,
        analyzed_at: latest.analyzed_at,
        baseline_version: baseline.map(|b| version_name(b.version_id)).transpose()?,
        hooks,
    }))
}

/// `null` when the package's name imitates none of the popular packages of
/// its ecosystem.
pub async fn get_package_lookalike(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Option<PackageLookalike>>, StatusCode> {
    let id = id.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;

    match package_lookalike(&state.db, &state.lookalikes, id) {
        Ok(Some(lookalike)) => Ok(Json(lookalike)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Lookalike check of package {} failed: {}", id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// The popular package `package_id`'s name imitates, judged exactly as
/// [`store_package`](crate::handlers::collector::store_package) judges a new
/// arrival, or `None` if there is no such package.
///
/// Running the check on read rather than storing its result on arrival also
/// covers packages stored before lookalike detection existed, and drops the
/// warning once the package has become popular itself.
pub fn package_lookalike(
    db: &Database,
    lookalikes: &LookalikeTargets,
    package_id: u64,
) -> anyhow::Result<Option<Option<PackageLookalike>>> {
    let Some(package) = db.get_package(package_id)? else {
        return Ok(None);
    };
    Ok(Some(lookalikes.check(db, &package)?))
}

/// The lookalikes among one page of `GET /api/packages` results, keyed by
/// package id, so search results can mark them without a request per row.
///
/// A failed check leaves its package unmarked rather than failing the
/// listing: the marker is advice, the listing is what was asked for.
pub fn page_lookalikes(
    db: &Database,
    lookalikes: &LookalikeTargets,
    packages: &[Package],
) -> HashMap<u64, PackageLookalike> {
    packages
        .iter()
        .filter_map(|package| match lookalikes.check(db, package) {
            Ok(found) => found.map(|l| (package.id, l)),
            Err(e) => {
                tracing::warn!("Lookalike check of package {} failed: {}", package.id, e);
                None
            }
        })
        .collect()
}

pub async fn get_package_subscriber_count(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Value>, StatusCode> {
    let id = id.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;

    // First get the package to get its name
    let package = match state.db.get_package(id) {
        Ok(Some(pkg)) => pkg,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Get subscriber count
    match state.db.get_users_subscribed_to(&package.name) {
        Ok(subscribers) => Ok(Json(serde_json::json!({
            "package_id": id,
            "package_name": package.name,
            "subscriber_count": subscribers.len()
        }))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
