use crate::AppState;
use axum::{extract::State, http::StatusCode, response::Json};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

// `DatabaseStats` comes from the shared `fossdb` crate. A local copy used to
// shadow it here, which is the same class of drift that previously broke
// `SubscriptionResponse`.
use crate::{DatabaseStats, Package, Vulnerability, VulnerabilitySeverity};

#[derive(Serialize)]
pub struct AnalyticsResponse {
    pub total_packages: u64,
    pub programming_languages: u64,
    pub weekly_updates: u64,
    pub language_distribution: Vec<LanguageStats>,
    pub license_distribution: Vec<LicenseStats>,
    pub trending_packages: Vec<TrendingPackage>,
    pub security_overview: SecurityStats,
    pub growth_data: Vec<GrowthPoint>,
}

#[derive(Serialize)]
pub struct LanguageStats {
    pub language: String,
    pub percentage: f32,
    pub count: u64,
}

#[derive(Serialize)]
pub struct LicenseStats {
    pub license: String,
    pub percentage: f32,
    pub count: u64,
}

#[derive(Serialize)]
pub struct TrendingPackage {
    pub name: String,
    pub description: String,
    pub growth_percentage: f32,
    pub category: String,
}

#[derive(Serialize)]
pub struct SecurityStats {
    pub clean_packages: u64,
    pub minor_issues: u64,
    pub critical_vulnerabilities: u64,
    pub scan_coverage: f32,
}

#[derive(Serialize)]
pub struct GrowthPoint {
    pub date: String,
    pub packages_added: u64,
    pub cumulative_total: u64,
}

/// Count `values` and return `(value, count, percentage of total)`, most
/// common first.
fn distribution<'a>(values: impl Iterator<Item = &'a str>, total: u64) -> Vec<(String, u64, f32)> {
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    let mut dist: Vec<_> = counts
        .into_iter()
        .map(|(value, count)| {
            let percentage = if total > 0 {
                (count as f32 / total as f32) * 100.0
            } else {
                0.0
            };
            (value.to_string(), count, percentage)
        })
        .collect();
    dist.sort_by(|a, b| b.1.cmp(&a.1));
    dist
}

fn language_stats(packages: &[Package]) -> Vec<LanguageStats> {
    let languages = packages.iter().filter_map(|p| p.language.as_deref());
    distribution(languages, packages.len() as u64)
        .into_iter()
        .map(|(language, count, percentage)| LanguageStats {
            language,
            percentage,
            count,
        })
        .collect()
}

fn license_stats(packages: &[Package]) -> Vec<LicenseStats> {
    let licenses = packages.iter().filter_map(|p| p.license.as_deref());
    distribution(licenses, packages.len() as u64)
        .into_iter()
        .map(|(license, count, percentage)| LicenseStats {
            license,
            percentage,
            count,
        })
        .collect()
}

fn security_stats(total_packages: u64, vulnerabilities: &[Vulnerability]) -> SecurityStats {
    let count = |pred: fn(&VulnerabilitySeverity) -> bool| {
        vulnerabilities.iter().filter(|v| pred(&v.severity)).count() as u64
    };
    SecurityStats {
        clean_packages: total_packages.saturating_sub(vulnerabilities.len() as u64),
        minor_issues: count(|s| {
            matches!(
                s,
                VulnerabilitySeverity::Low | VulnerabilitySeverity::Medium
            )
        }),
        critical_vulnerabilities: count(|s| matches!(s, VulnerabilitySeverity::Critical)),
        scan_coverage: if total_packages > 0 { 100.0 } else { 0.0 },
    }
}

pub async fn get_analytics(
    State(state): State<AppState>,
) -> Result<Json<AnalyticsResponse>, StatusCode> {
    let packages = state
        .db
        .get_all_packages()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let vulnerabilities = state
        .db
        .get_all_vulnerabilities()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total = packages.len() as u64;
    let language_distribution = language_stats(&packages);

    // Trending packages - just get most recent packages for now
    let trending_packages: Vec<TrendingPackage> = packages
        .iter()
        .rev()
        .take(3)
        .map(|pkg| TrendingPackage {
            name: pkg.name.clone(),
            description: pkg.description.clone().unwrap_or_default(),
            growth_percentage: 0.0, // No historical data yet
            category: pkg.platform.clone().unwrap_or_else(|| "other".to_string()),
        })
        .collect();

    Ok(Json(AnalyticsResponse {
        total_packages: total,
        programming_languages: language_distribution.len() as u64,
        weekly_updates: 0, // Would need historical tracking
        language_distribution,
        license_distribution: license_stats(&packages),
        trending_packages,
        security_overview: security_stats(total, &vulnerabilities),
        growth_data: vec![], // Would need historical tracking
    }))
}

pub async fn get_language_trends(
    State(state): State<AppState>,
) -> Result<Json<Vec<LanguageStats>>, StatusCode> {
    let packages = state
        .db
        .get_all_packages()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(language_stats(&packages)))
}

pub async fn get_security_report(
    State(state): State<AppState>,
) -> Result<Json<SecurityStats>, StatusCode> {
    let packages = state
        .db
        .get_all_packages()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let vulnerabilities = state
        .db
        .get_all_vulnerabilities()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(security_stats(
        packages.len() as u64,
        &vulnerabilities,
    )))
}

pub async fn get_db_stats(
    State(state): State<AppState>,
) -> Result<Json<DatabaseStats>, StatusCode> {
    let packages = state
        .db
        .get_all_packages()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let versions = state
        .db
        .get_all_versions()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let users = state
        .db
        .get_all_users()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let vulnerabilities = state
        .db
        .get_all_vulnerabilities()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let timeline_events = state
        .db
        .get_all_timeline_events()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let stats = DatabaseStats {
        total_packages: packages.len() as u64,
        total_versions: versions.len() as u64,
        total_users: users.len() as u64,
        total_vulnerabilities: vulnerabilities.len() as u64,
        total_timeline_events: timeline_events.len() as u64,
        // Derived from ingested data rather than hardcoded: these are the
        // platforms packages have actually arrived from. The server cannot
        // enumerate running collector processes - they are anonymous HTTP
        // clients sharing one API key - so this reports evidence of
        // collection, not liveness.
        collectors_running: packages
            .iter()
            .filter_map(|p| p.platform.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    };

    Ok(Json(stats))
}
