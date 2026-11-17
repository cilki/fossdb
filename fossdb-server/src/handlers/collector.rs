use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use chrono::{DateTime, Utc};
use fossdb::{
    AdvisoryIngestResult, AffectedPackage, CollectedAdvisory, CollectedPackage, PackageLookup,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::AppState;
use crate::db::Database;
use crate::{Package, PackageVersion, Vulnerability};

#[derive(Deserialize)]
pub struct PackageQuery {
    pub name: String,
}

pub async fn get_package(
    State(state): State<AppState>,
    Query(q): Query<PackageQuery>,
) -> Result<Json<PackageLookup>, StatusCode> {
    match state.db.get_package_by_name(&q.name) {
        Ok(Some(pkg)) => {
            let version_strings = state.db
                .get_versions_by_package(pkg.id)
                .unwrap_or_default()
                .into_iter()
                .map(|v| v.version.clone())
                .collect();
            Ok(Json(PackageLookup {
                package: pkg.inner,
                version_strings,
            }))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn upsert_package(
    State(state): State<AppState>,
    Json(collected): Json<CollectedPackage>,
) -> Result<Json<fossdb::Package>, StatusCode> {
    let now = Utc::now();

    match state.db.get_package_by_name(&collected.name) {
        Ok(Some(existing)) => {
            let existing_versions: HashSet<String> = state.db
                .get_versions_by_package(existing.id)
                .unwrap_or_default()
                .into_iter()
                .map(|v| v.version.clone())
                .collect();

            for v in collected.versions {
                if !existing_versions.contains(&v.version) {
                    tracing::info!("New version detected: {} {}", existing.name, v.version);
                    let version = PackageVersion {
                        inner: fossdb::PackageVersion {
                            id: 0,
                            package_id: existing.id,
                            version: v.version,
                            release_date: v.release_date,
                            download_url: v.download_url,
                            checksum: v.checksum,
                            dependencies: v.dependencies,
                            vulnerabilities: Vec::new(),
                            changelog: v.changelog,
                            created_at: now,
                        },
                    };
                    if let Err(e) = state.db.insert_version(version) {
                        tracing::error!("Failed to insert version: {}", e);
                    }
                }
            }

            Ok(Json(existing.inner))
        }
        Ok(None) => {
            let package = Package {
                inner: fossdb::Package {
                    id: 0,
                    name: collected.name,
                    description: collected.description,
                    homepage: collected.homepage,
                    repository: collected.repository,
                    license: collected.license,
                    tags: collected.tags,
                    created_at: now,
                    updated_at: now,
                    platform: collected.platform,
                    language: collected.language,
                    status: collected.status,
                    dependents_count: collected.dependents_count,
                    rank: collected.rank,
                },
            };

            match state.db.insert_package(package) {
                Ok(saved) => {
                    tracing::info!("Saved new package: {}", saved.name);
                    for v in collected.versions {
                        let version = PackageVersion {
                            inner: fossdb::PackageVersion {
                                id: 0,
                                package_id: saved.id,
                                version: v.version,
                                release_date: v.release_date,
                                download_url: v.download_url,
                                checksum: v.checksum,
                                dependencies: v.dependencies,
                                vulnerabilities: Vec::new(),
                                changelog: v.changelog,
                                created_at: now,
                            },
                        };
                        if let Err(e) = state.db.insert_version(version) {
                            tracing::error!("Failed to insert version: {}", e);
                        }
                    }
                    Ok(Json(saved.inner))
                }
                Err(e) => {
                    tracing::error!("Failed to insert package: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Err(e) => {
            tracing::error!("DB error checking package: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn upsert_advisory(
    State(state): State<AppState>,
    Json(advisory): Json<CollectedAdvisory>,
) -> Result<Json<AdvisoryIngestResult>, StatusCode> {
    if advisory.source_id.trim().is_empty() {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let source_id = advisory.source_id.clone();
    ingest_advisory(&state.db, advisory).map(Json).map_err(|e| {
        tracing::error!("Failed to ingest advisory {}: {}", source_id, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Resolve an advisory's `affected` entries to stored packages and upsert it.
///
/// Entries that name no stored package, or a package stored under a
/// different platform, are skipped and reported back. An advisory none of
/// whose entries resolve is not stored at all, unless an earlier copy of it
/// was: then it is still updated, so the links that copy made are removed.
pub fn ingest_advisory(
    db: &Database,
    advisory: CollectedAdvisory,
) -> anyhow::Result<AdvisoryIngestResult> {
    struct Matched {
        versions: HashSet<String>,
        ranges: Vec<String>,
    }

    let mut matched: BTreeMap<u64, Matched> = BTreeMap::new();
    let mut fixed_in = None;
    let mut skipped = Vec::new();

    for affected in advisory.affected {
        let label = format!("{}/{}", affected.platform, affected.package_name);
        let package = match db.get_package_by_name(&affected.package_name)? {
            Some(p) => p,
            None => {
                skipped.push(label);
                continue;
            }
        };
        let same_platform = package
            .platform
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(&affected.platform));
        if !same_platform {
            // Package names are globally unique here, so whichever ecosystem
            // claimed a name first owns it. Log it so the gap is visible.
            tracing::warn!(
                "Advisory {} names {}, but the stored package of that name is on platform {:?}; not linking",
                advisory.source_id,
                label,
                package.platform
            );
            skipped.push(label);
            continue;
        }

        let entry = matched.entry(package.id).or_insert_with(|| Matched {
            versions: HashSet::new(),
            ranges: Vec::new(),
        });
        entry.versions.extend(affected.affected_versions);
        entry.ranges.extend(affected.ranges);
        if fixed_in.is_none() {
            fixed_in = affected.fixed_in;
        }
    }

    if matched.is_empty() && db.get_vulnerability_by_source_id(&advisory.source_id)?.is_none() {
        return Ok(AdvisoryIngestResult {
            vulnerability_id: None,
            created: false,
            linked_packages: 0,
            linked_versions: 0,
            skipped,
        });
    }

    let cve_id = std::iter::once(&advisory.source_id)
        .chain(&advisory.aliases)
        .find(|id| id.starts_with("CVE-"))
        .cloned();

    let affected_packages = matched
        .iter()
        .map(|(&package_id, m)| {
            let version_range = if m.ranges.is_empty() {
                let mut versions: Vec<&str> = m.versions.iter().map(String::as_str).collect();
                versions.sort_unstable();
                versions.join(", ")
            } else {
                m.ranges.join(", ")
            };
            AffectedPackage {
                package_id,
                version_range,
            }
        })
        .collect();

    let linked_packages = matched.len();
    let affected_versions: HashMap<u64, HashSet<String>> =
        matched.into_iter().map(|(id, m)| (id, m.versions)).collect();

    let vulnerability = Vulnerability {
        inner: fossdb::Vulnerability {
            id: 0,
            source_id: advisory.source_id,
            cve_id,
            title: advisory.title,
            description: advisory.description,
            severity: advisory.severity,
            affected_packages,
            discovered_at: advisory.published,
            fixed_in,
        },
    };

    let outcome = db.upsert_advisory(vulnerability, &affected_versions)?;
    if outcome.created {
        tracing::info!("New advisory: {}", outcome.vulnerability.source_id);
    }

    Ok(AdvisoryIngestResult {
        vulnerability_id: Some(outcome.vulnerability.id),
        created: outcome.created,
        linked_packages,
        linked_versions: outcome.linked_versions,
        skipped,
    })
}

#[derive(Deserialize)]
pub struct TimestampUpdate {
    pub updated_at: DateTime<Utc>,
}

pub async fn update_package_timestamp(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<TimestampUpdate>,
) -> StatusCode {
    match state.db.get_package_by_name(&name) {
        Ok(Some(mut pkg)) => {
            pkg.updated_at = body.updated_at;
            match state.db.update_package(pkg) {
                Ok(_) => StatusCode::OK,
                Err(e) => {
                    tracing::error!("Failed to update package timestamp: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        }
        Ok(None) => StatusCode::NOT_FOUND,
        Err(e) => {
            tracing::error!("DB error looking up package: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossdb::{CollectedAffected, VulnerabilitySeverity};

    fn open_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::new(dir.path().join("db").to_str().unwrap()).unwrap();
        (dir, db)
    }

    /// Store a package with the given versions; returns its id.
    fn add_package(db: &Database, name: &str, platform: &str, versions: &[&str]) -> u64 {
        let now = Utc::now();
        let package = db
            .insert_package(Package {
                inner: fossdb::Package {
                    id: 0,
                    name: name.into(),
                    description: None,
                    homepage: None,
                    repository: None,
                    license: None,
                    tags: Vec::new(),
                    created_at: now,
                    updated_at: now,
                    platform: Some(platform.into()),
                    language: None,
                    status: None,
                    dependents_count: None,
                    rank: None,
                },
            })
            .unwrap();
        for v in versions {
            db.insert_version(PackageVersion {
                inner: fossdb::PackageVersion {
                    id: 0,
                    package_id: package.id,
                    version: (*v).into(),
                    release_date: now,
                    download_url: None,
                    checksum: None,
                    dependencies: Vec::new(),
                    vulnerabilities: Vec::new(),
                    changelog: None,
                    created_at: now,
                },
            })
            .unwrap();
        }
        package.id
    }

    fn advisory(name: &str, platform: &str, versions: &[&str]) -> CollectedAdvisory {
        CollectedAdvisory {
            source_id: "RUSTSEC-2024-0001".into(),
            aliases: vec!["GHSA-aaaa-bbbb-cccc".into(), "CVE-2024-1234".into()],
            title: "Memory corruption".into(),
            description: "Details".into(),
            severity: VulnerabilitySeverity::High,
            published: Utc::now(),
            affected: vec![CollectedAffected {
                package_name: name.into(),
                platform: platform.into(),
                affected_versions: versions.iter().map(|v| v.to_string()).collect(),
                ranges: vec![">=0, <1.2.0".into()],
                fixed_in: Some("1.2.0".into()),
            }],
        }
    }

    /// Version string -> vulnerability ids it lists.
    fn links(db: &Database, package_id: u64) -> HashMap<String, Vec<String>> {
        db.get_versions_by_package(package_id)
            .unwrap()
            .into_iter()
            .map(|v| (v.version.clone(), v.vulnerabilities.clone()))
            .collect()
    }

    #[test]
    fn ingest_links_named_versions_only() {
        let (_dir, db) = open_db();
        let pkg = add_package(&db, "smallvec", "crates.io", &["1.0.0", "1.1.0", "1.2.0"]);

        let result = ingest_advisory(&db, advisory("smallvec", "crates.io", &["1.0.0", "1.1.0"])).unwrap();

        let id = result.vulnerability_id.unwrap();
        assert!(result.created);
        assert_eq!(result.linked_packages, 1);
        assert_eq!(result.linked_versions, 2);
        assert!(result.skipped.is_empty());

        let tag = id.to_string();
        let links = links(&db, pkg);
        assert_eq!(links["1.0.0"], vec![tag.clone()]);
        assert_eq!(links["1.1.0"], vec![tag]);
        assert!(links["1.2.0"].is_empty());

        let stored = db.get_vulnerability(id).unwrap().unwrap();
        assert_eq!(stored.source_id, "RUSTSEC-2024-0001");
        assert_eq!(stored.cve_id.as_deref(), Some("CVE-2024-1234"));
        assert_eq!(stored.fixed_in.as_deref(), Some("1.2.0"));
        assert_eq!(stored.affected_packages.len(), 1);
        assert_eq!(stored.affected_packages[0].package_id, pkg);
        assert_eq!(stored.affected_packages[0].version_range, ">=0, <1.2.0");
    }

    #[test]
    fn ingesting_twice_updates_in_place() {
        let (_dir, db) = open_db();
        let pkg = add_package(&db, "smallvec", "crates.io", &["1.0.0"]);

        let first = ingest_advisory(&db, advisory("smallvec", "crates.io", &["1.0.0"])).unwrap();
        let mut again = advisory("smallvec", "crates.io", &["1.0.0"]);
        again.title = "Memory corruption (revised)".into();
        let second = ingest_advisory(&db, again).unwrap();

        assert!(first.created);
        assert!(!second.created);
        assert_eq!(first.vulnerability_id, second.vulnerability_id);

        let all = db.get_all_vulnerabilities().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].title, "Memory corruption (revised)");
        // Linked once, not once per ingest.
        assert_eq!(links(&db, pkg)["1.0.0"].len(), 1);
    }

    #[test]
    fn revised_advisory_drops_stale_links() {
        let (_dir, db) = open_db();
        let pkg = add_package(&db, "smallvec", "crates.io", &["1.0.0", "1.1.0"]);
        let other = add_package(&db, "tinyvec", "crates.io", &["0.1.0"]);

        let mut first = advisory("smallvec", "crates.io", &["1.0.0", "1.1.0"]);
        first.affected.push(CollectedAffected {
            package_name: "tinyvec".into(),
            platform: "crates.io".into(),
            affected_versions: vec!["0.1.0".into()],
            ranges: Vec::new(),
            fixed_in: None,
        });
        ingest_advisory(&db, first).unwrap();

        // The publisher narrows the advisory: one version, one package.
        let revised = ingest_advisory(&db, advisory("smallvec", "crates.io", &["1.0.0"])).unwrap();

        assert_eq!(revised.linked_versions, 1);
        assert_eq!(links(&db, pkg)["1.0.0"].len(), 1);
        assert!(links(&db, pkg)["1.1.0"].is_empty());
        assert!(links(&db, other)["0.1.0"].is_empty());
        let stored = db.get_vulnerability(revised.vulnerability_id.unwrap()).unwrap().unwrap();
        assert_eq!(stored.affected_packages.len(), 1);
    }

    /// Names are only unique per ecosystem: a crates.io advisory must not
    /// attach itself to an npm package that happens to share the name.
    #[test]
    fn platform_mismatch_is_skipped_and_not_stored() {
        let (_dir, db) = open_db();
        let pkg = add_package(&db, "left-pad", "NPM", &["1.0.0"]);

        let result = ingest_advisory(&db, advisory("left-pad", "crates.io", &["1.0.0"])).unwrap();

        assert_eq!(result.vulnerability_id, None);
        assert_eq!(result.skipped, vec!["crates.io/left-pad".to_string()]);
        assert!(db.get_all_vulnerabilities().unwrap().is_empty());
        assert!(links(&db, pkg)["1.0.0"].is_empty());
    }

    #[test]
    fn platform_match_ignores_case() {
        let (_dir, db) = open_db();
        add_package(&db, "left-pad", "NPM", &["1.0.0"]);

        let result = ingest_advisory(&db, advisory("left-pad", "npm", &["1.0.0"])).unwrap();

        assert_eq!(result.linked_versions, 1);
    }

    #[test]
    fn unknown_package_is_skipped_and_not_stored() {
        let (_dir, db) = open_db();

        let result = ingest_advisory(&db, advisory("nonexistent", "crates.io", &["1.0.0"])).unwrap();

        assert_eq!(result.vulnerability_id, None);
        assert_eq!(result.skipped, vec!["crates.io/nonexistent".to_string()]);
        assert!(db.get_all_vulnerabilities().unwrap().is_empty());
    }
}
