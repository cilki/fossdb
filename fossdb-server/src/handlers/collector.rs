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
use crate::db_listener::{emit_lookalike_alert, emit_security_alerts, emit_yank_alert};
use crate::lookalike::LookalikeTargets;
use crate::websocket::TimelineBroadcaster;
use crate::{Package, PackageVersion, Vulnerability};

#[derive(Deserialize)]
pub struct PackageQuery {
    pub name: String,
}

pub async fn get_package(
    State(state): State<AppState>,
    Query(q): Query<PackageQuery>,
) -> Result<Json<PackageLookup>, StatusCode> {
    match package_lookup(&state.db, &q.name) {
        Ok(Some(lookup)) => Ok(Json(lookup)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// A stored package with the versions a collector need not send again, or
/// `None` if there is no package of that name.
pub fn package_lookup(db: &Database, name: &str) -> anyhow::Result<Option<PackageLookup>> {
    let Some(pkg) = db.get_package_by_name(name)? else {
        return Ok(None);
    };
    let versions = db.get_versions_by_package(pkg.id).unwrap_or_default();
    let yanked_versions = versions
        .iter()
        .filter(|v| v.yanked_at.is_some())
        .map(|v| v.version.clone())
        .collect();
    let version_strings = versions.into_iter().map(|v| v.inner.version).collect();
    Ok(Some(PackageLookup {
        package: pkg.inner,
        version_strings,
        yanked_versions,
    }))
}

pub async fn upsert_package(
    State(state): State<AppState>,
    Json(collected): Json<CollectedPackage>,
) -> Result<Json<fossdb::Package>, StatusCode> {
    store_package(&state.db, &state.broadcaster, &state.lookalikes, collected)
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to store package: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// Insert a package, or add the versions of an already stored one that are
/// new.
///
/// A package new to the database is checked against the popular names of
/// its ecosystem; if it imitates one, that package's subscribers get a
/// `SecurityAlert` (see [`crate::db_listener::emit_lookalike_alert`]).
///
/// Stored versions sent with a different [`fossdb::CollectedVersion::yanked`]
/// are marked yanked or live again; the package's subscribers hear about the
/// yanks (see [`crate::db_listener::emit_yank_alert`]).
pub fn store_package(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    lookalikes: &LookalikeTargets,
    collected: CollectedPackage,
) -> anyhow::Result<fossdb::Package> {
    let now = Utc::now();

    let existing = db.get_package_by_name(&collected.name)?;

    let (package, known_versions) = match existing {
        Some(existing) => {
            let known: HashMap<String, PackageVersion> = db
                .get_versions_by_package(existing.id)
                .unwrap_or_default()
                .into_iter()
                .map(|v| (v.version.clone(), v))
                .collect();
            (existing, known)
        }
        None => {
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
            let saved = db.insert_package(package)?;
            tracing::info!("Saved new package: {}", saved.name);
            // A failed check must not fail the ingest; the package is stored.
            match lookalikes.check(db, &saved) {
                Ok(Some(lookalike)) => emit_lookalike_alert(db, broadcaster, &saved, &lookalike),
                Ok(None) => {}
                Err(e) => tracing::error!("Lookalike check for {} failed: {}", saved.name, e),
            }
            (saved, HashMap::new())
        }
    };

    // Insert oldest first. Version ids are assigned in insertion order, and the
    // rest of the server reads a higher id as a newer release: the worker is
    // handed each package's highest-id version as its "latest", and install
    // hook alerts compare against the highest analysed id below it. Collectors
    // do not agree on an order - crates.io lists newest first - so taking the
    // batch as sent made the worker analyse the *oldest* collected release of
    // every new crate and never the current one. The sort is stable, so
    // versions sharing a date keep the order they were sent in.
    let mut versions = collected.versions;
    versions.sort_by_key(|v| v.release_date);

    // Each insert is announced by the PackageVersion watch in db_listener.
    let mut newly_yanked = Vec::new();
    for v in versions {
        if let Some(stored) = known_versions.get(&v.version) {
            let Some(yanked) = v.yanked else { continue };
            if yanked == stored.yanked_at.is_some() {
                continue;
            }
            let mut updated = stored.clone();
            updated.inner.yanked_at = yanked.then_some(now);
            match db.update_version(stored.clone(), updated) {
                Ok(()) if yanked => newly_yanked.push(v.version),
                Ok(()) => tracing::info!("{} {} is no longer yanked", package.name, v.version),
                Err(e) => tracing::error!("Failed to update yank state of {} {}: {}", package.name, v.version, e),
            }
            continue;
        }
        if v.yanked == Some(true) {
            // Nobody can have upgraded to a version that was gone before
            // FossDB saw it, so there is nothing to store or tell anyone.
            continue;
        }
        let version = PackageVersion {
            inner: fossdb::PackageVersion {
                id: 0,
                package_id: package.id,
                version: v.version,
                release_date: v.release_date,
                download_url: v.download_url,
                checksum: v.checksum,
                dependencies: v.dependencies,
                vulnerabilities: Vec::new(),
                changelog: v.changelog,
                created_at: now,
                yanked_at: None,
            },
        };
        if let Err(e) = db.insert_version(version) {
            tracing::error!("Failed to insert version: {}", e);
        }
    }

    if !newly_yanked.is_empty() {
        emit_yank_alert(db, broadcaster, &package, &newly_yanked);
    }

    Ok(package.inner)
}

pub async fn upsert_advisory(
    State(state): State<AppState>,
    Json(advisory): Json<CollectedAdvisory>,
) -> Result<Json<AdvisoryIngestResult>, StatusCode> {
    if advisory.source_id.trim().is_empty() {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let source_id = advisory.source_id.clone();
    ingest_advisory(&state.db, &state.broadcaster, advisory).map(Json).map_err(|e| {
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
///
/// Versions the advisory is newly linked to raise `SecurityAlert` events
/// for their package's subscribers; see
/// [`crate::db_listener::emit_security_alerts`].
pub fn ingest_advisory(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
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
    emit_security_alerts(db, broadcaster, &outcome.vulnerability, &outcome.newly_linked);

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
            match state.db.update(pkg) {
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
    use crate::lookalike::MIN_TARGET_POPULARITY;
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
                    yanked_at: None,
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

        let result = ingest_advisory(&db, &TimelineBroadcaster::new(), advisory("smallvec", "crates.io", &["1.0.0", "1.1.0"])).unwrap();

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

        let first = ingest_advisory(&db, &TimelineBroadcaster::new(), advisory("smallvec", "crates.io", &["1.0.0"])).unwrap();
        let mut again = advisory("smallvec", "crates.io", &["1.0.0"]);
        again.title = "Memory corruption (revised)".into();
        let second = ingest_advisory(&db, &TimelineBroadcaster::new(), again).unwrap();

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
        ingest_advisory(&db, &TimelineBroadcaster::new(), first).unwrap();

        // The publisher narrows the advisory: one version, one package.
        let revised = ingest_advisory(&db, &TimelineBroadcaster::new(), advisory("smallvec", "crates.io", &["1.0.0"])).unwrap();

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

        let result = ingest_advisory(&db, &TimelineBroadcaster::new(), advisory("left-pad", "crates.io", &["1.0.0"])).unwrap();

        assert_eq!(result.vulnerability_id, None);
        assert_eq!(result.skipped, vec!["crates.io/left-pad".to_string()]);
        assert!(db.get_all_vulnerabilities().unwrap().is_empty());
        assert!(links(&db, pkg)["1.0.0"].is_empty());
    }

    #[test]
    fn platform_match_ignores_case() {
        let (_dir, db) = open_db();
        add_package(&db, "left-pad", "NPM", &["1.0.0"]);

        let result = ingest_advisory(&db, &TimelineBroadcaster::new(), advisory("left-pad", "npm", &["1.0.0"])).unwrap();

        assert_eq!(result.linked_versions, 1);
    }

    fn subscribe(db: &Database, user_id: &str, package: &str) {
        db.insert_user(crate::User {
            inner: fossdb::User {
                user_id: user_id.into(),
                subscriptions: vec![fossdb::PackageSubscription {
                    package_name: package.into(),
                    notifications_enabled: true,
                }],
                created_at: Utc::now(),
                notifications_enabled: true,
            },
        })
        .unwrap();
    }

    fn alerts(db: &Database, user_id: &str) -> Vec<fossdb::TimelineEvent> {
        db.get_timeline_events_by_user(user_id)
            .unwrap()
            .into_iter()
            .map(|e| e.inner)
            .filter(|e| e.event_type == fossdb::EventType::SecurityAlert)
            .collect()
    }

    #[test]
    fn new_links_alert_subscribers_once() {
        let (_dir, db) = open_db();
        let broadcaster = TimelineBroadcaster::new();
        let pkg = add_package(&db, "smallvec", "crates.io", &["1.0.0", "1.1.0", "1.2.0"]);
        add_package(&db, "tinyvec", "crates.io", &["0.1.0"]);
        subscribe(&db, "subscriber", "smallvec");
        subscribe(&db, "bystander", "tinyvec");

        let result =
            ingest_advisory(&db, &broadcaster, advisory("smallvec", "crates.io", &["1.0.0", "1.1.0"]))
                .unwrap();

        let events = alerts(&db, "subscriber");
        assert_eq!(events.len(), 1, "one alert per advisory, not per version");
        let event = &events[0];
        assert_eq!(event.package_id, pkg);
        assert_eq!(event.package_name, "smallvec");
        assert_eq!(
            event.message,
            "RUSTSEC-2024-0001 (High): Memory corruption. Affects 1.0.0, 1.1.0. Fixed in 1.2.0."
        );
        let metadata: serde_json::Value =
            serde_json::from_str(event.metadata.as_deref().unwrap()).unwrap();
        assert_eq!(metadata["vulnerability_id"], result.vulnerability_id.unwrap());
        assert_eq!(metadata["source_id"], "RUSTSEC-2024-0001");
        assert_eq!(metadata["versions"], serde_json::json!(["1.0.0", "1.1.0"]));
        assert!(alerts(&db, "bystander").is_empty());

        // Re-ingesting the same advisory links nothing new.
        ingest_advisory(&db, &broadcaster, advisory("smallvec", "crates.io", &["1.0.0", "1.1.0"]))
            .unwrap();
        assert_eq!(alerts(&db, "subscriber").len(), 1);

        // A revision that widens the advisory alerts on the added version only.
        ingest_advisory(
            &db,
            &broadcaster,
            advisory("smallvec", "crates.io", &["1.0.0", "1.1.0", "1.2.0"]),
        )
        .unwrap();
        let events = alerts(&db, "subscriber");
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e.message.contains("Affects 1.2.0.")));
    }

    /// Linking a version used to remove and re-insert its row, which the
    /// `PackageVersion` watch took for a new release.
    #[test]
    fn linking_versions_does_not_look_like_a_release() {
        let (_dir, db) = open_db();
        add_package(&db, "smallvec", "crates.io", &["1.0.0", "1.1.0"]);
        let (recv, _id) = db.db.watch().scan().primary().all::<PackageVersion>().unwrap();

        ingest_advisory(
            &db,
            &TimelineBroadcaster::new(),
            advisory("smallvec", "crates.io", &["1.0.0", "1.1.0"]),
        )
        .unwrap();
        // And unlinking one again.
        ingest_advisory(
            &db,
            &TimelineBroadcaster::new(),
            advisory("smallvec", "crates.io", &["1.0.0"]),
        )
        .unwrap();

        let events: Vec<_> = recv.try_iter().collect();
        assert_eq!(events.len(), 3);
        assert!(
            events.iter().all(|e| matches!(e, native_db::watch::Event::Update(_))),
            "{events:?}"
        );
    }

    #[test]
    fn package_vulnerabilities_lists_linked_versions() {
        use crate::handlers::packages::package_vulnerabilities;

        let (_dir, db) = open_db();
        let broadcaster = TimelineBroadcaster::new();
        let pkg = add_package(&db, "smallvec", "crates.io", &["1.0.0", "1.1.0", "1.2.0"]);
        let other = add_package(&db, "tinyvec", "crates.io", &["0.1.0"]);

        let mut older = advisory("smallvec", "crates.io", &["1.0.0"]);
        older.source_id = "RUSTSEC-2020-0001".into();
        older.published = Utc::now() - chrono::Duration::days(365);
        ingest_advisory(&db, &broadcaster, older).unwrap();
        ingest_advisory(&db, &broadcaster, advisory("smallvec", "crates.io", &["1.0.0", "1.1.0"]))
            .unwrap();

        let list = package_vulnerabilities(&db, pkg).unwrap().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].vulnerability.source_id, "RUSTSEC-2024-0001", "newest first");
        assert_eq!(list[0].affected_versions, vec!["1.0.0", "1.1.0"]);
        assert_eq!(list[0].version_range, ">=0, <1.2.0");
        assert_eq!(list[1].vulnerability.source_id, "RUSTSEC-2020-0001");
        assert_eq!(list[1].affected_versions, vec!["1.0.0"]);

        // Flattened on the wire, so clients see the advisory's own fields.
        let json = serde_json::to_value(&list[0]).unwrap();
        assert_eq!(json["source_id"], "RUSTSEC-2024-0001");
        assert_eq!(json["affected_versions"], serde_json::json!(["1.0.0", "1.1.0"]));

        assert!(package_vulnerabilities(&db, other).unwrap().unwrap().is_empty());
        assert!(package_vulnerabilities(&db, 9999).unwrap().is_none());
    }

    fn collected(
        name: &str,
        platform: &str,
        dependents_count: Option<u32>,
        depends_on: &[&str],
    ) -> CollectedPackage {
        CollectedPackage {
            name: name.into(),
            description: None,
            homepage: None,
            repository: None,
            license: None,
            tags: Vec::new(),
            versions: vec![fossdb::CollectedVersion {
                version: "1.0.0".into(),
                release_date: Utc::now(),
                download_url: None,
                checksum: None,
                dependencies: depends_on
                    .iter()
                    .map(|d| fossdb::Dependency {
                        name: (*d).into(),
                        version_requirement: "*".into(),
                        dependency_type: "normal".into(),
                        optional: false,
                    })
                    .collect(),
                changelog: None,
                yanked: None,
            }],
            platform: Some(platform.into()),
            language: None,
            status: None,
            dependents_count,
            rank: None,
        }
    }

    /// Store packages that existed before the test's lookalike cache was
    /// built, so they do not go through (or warm) that cache.
    fn seed(db: &Database, packages: Vec<CollectedPackage>) {
        for p in packages {
            store_package(db, &TimelineBroadcaster::new(), &LookalikeTargets::new(), p).unwrap();
        }
    }

    /// Versions submitted newest first (as crates.io lists them) must still get
    /// ids in release order, both on first ingest and when new releases arrive
    /// for a known package, since a higher id is read as a newer release.
    #[test]
    fn versions_get_ids_in_release_order() {
        let (_dir, db) = open_db();
        let base = Utc::now() - chrono::Duration::days(30);
        let batch = |versions: &[(&str, i64)]| {
            let mut package = collected("serde", "crates.io", None, &[]);
            package.versions = versions
                .iter()
                .map(|(version, day)| fossdb::CollectedVersion {
                    version: (*version).into(),
                    release_date: base + chrono::Duration::days(*day),
                    download_url: None,
                    checksum: None,
                    dependencies: Vec::new(),
                    changelog: None,
                    yanked: None,
                })
                .collect();
            package
        };
        let order = |db: &Database, id: u64| -> Vec<String> {
            let mut versions = db.get_versions_by_package(id).unwrap();
            versions.sort_by_key(|v| v.id);
            versions.into_iter().map(|v| v.inner.version).collect()
        };

        let package = store_package(
            &db,
            &TimelineBroadcaster::new(),
            &LookalikeTargets::new(),
            batch(&[("1.2.0", 2), ("1.1.0", 1), ("1.0.0", 0)]),
        )
        .unwrap();
        assert_eq!(order(&db, package.id), ["1.0.0", "1.1.0", "1.2.0"]);

        store_package(
            &db,
            &TimelineBroadcaster::new(),
            &LookalikeTargets::new(),
            batch(&[("1.4.0", 4), ("1.3.0", 3), ("1.2.0", 2)]),
        )
        .unwrap();
        assert_eq!(
            order(&db, package.id),
            ["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]
        );
    }

    /// `serde` as crates.io would send it: each version with its yank state.
    fn crate_with(versions: &[(&str, Option<bool>)]) -> CollectedPackage {
        let base = Utc::now() - chrono::Duration::days(30);
        let mut package = collected("serde", "crates.io", None, &[]);
        package.versions = versions
            .iter()
            .enumerate()
            .map(|(day, (version, yanked))| fossdb::CollectedVersion {
                version: (*version).into(),
                release_date: base + chrono::Duration::days(day as i64),
                download_url: None,
                checksum: None,
                dependencies: Vec::new(),
                changelog: None,
                yanked: *yanked,
            })
            .collect();
        package
    }

    fn yanked(db: &Database, package_id: u64) -> Vec<String> {
        let mut versions: Vec<String> = db
            .get_versions_by_package(package_id)
            .unwrap()
            .into_iter()
            .filter(|v| v.yanked_at.is_some())
            .map(|v| v.inner.version)
            .collect();
        versions.sort();
        versions
    }

    fn behavior_changes(db: &Database, user_id: &str) -> Vec<fossdb::TimelineEvent> {
        db.get_timeline_events_by_user(user_id)
            .unwrap()
            .into_iter()
            .map(|e| e.inner)
            .filter(|e| e.event_type == fossdb::EventType::BehaviorChange)
            .collect()
    }

    #[test]
    fn yanking_a_stored_version_marks_it_and_tells_subscribers_once() {
        let (_dir, db) = open_db();
        let broadcaster = TimelineBroadcaster::new();
        let lookalikes = LookalikeTargets::new();
        let store = |p| store_package(&db, &broadcaster, &lookalikes, p).unwrap();
        let package = store(crate_with(&[("1.0.0", Some(false)), ("1.0.1", Some(false))]));
        subscribe(&db, "subscriber", "serde");
        subscribe(&db, "bystander", "tokio");
        let (recv, _id) = db.db.watch().scan().primary().all::<PackageVersion>().unwrap();

        store(crate_with(&[("1.0.1", Some(true))]));

        assert_eq!(yanked(&db, package.id), ["1.0.1"]);
        let events = behavior_changes(&db, "subscriber");
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.package_id, package.id);
        assert_eq!(event.version.as_deref(), Some("1.0.1"));
        assert_eq!(event.message, "serde 1.0.1 was yanked from crates.io");
        let metadata: serde_json::Value =
            serde_json::from_str(event.metadata.as_deref().unwrap()).unwrap();
        assert_eq!(metadata["yanked_versions"], serde_json::json!(["1.0.1"]));
        assert!(behavior_changes(&db, "bystander").is_empty());
        // Marked in place, so the release watch does not announce it again.
        let watched: Vec<_> = recv.try_iter().collect();
        assert_eq!(watched.len(), 1);
        assert!(matches!(watched[0], native_db::watch::Event::Update(_)), "{watched:?}");

        // Still yanked on the next run: nothing new to say.
        store(crate_with(&[("1.0.1", Some(true))]));
        assert_eq!(behavior_changes(&db, "subscriber").len(), 1);

        // Several yanks in one batch are one event.
        store(crate_with(&[("1.0.0", Some(true)), ("1.0.1", Some(true))]));
        let events = behavior_changes(&db, "subscriber");
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e.message == "serde 1.0.0 was yanked from crates.io"));
    }

    #[test]
    fn unyanking_clears_the_mark_without_an_event() {
        let (_dir, db) = open_db();
        let broadcaster = TimelineBroadcaster::new();
        let lookalikes = LookalikeTargets::new();
        let store = |p| store_package(&db, &broadcaster, &lookalikes, p).unwrap();
        let package = store(crate_with(&[("1.0.0", Some(false))]));
        store(crate_with(&[("1.0.0", Some(true))]));
        subscribe(&db, "subscriber", "serde");

        // A source that knows nothing of yanks leaves the mark alone.
        store(crate_with(&[("1.0.0", None)]));
        assert_eq!(yanked(&db, package.id), ["1.0.0"]);

        store(crate_with(&[("1.0.0", Some(false))]));
        assert!(yanked(&db, package.id).is_empty());
        assert!(behavior_changes(&db, "subscriber").is_empty());

        let lookup = get_package_lookup(&db, "serde");
        assert!(lookup.yanked_versions.is_empty());
    }

    #[test]
    fn versions_yanked_before_they_were_seen_are_not_stored() {
        let (_dir, db) = open_db();
        let broadcaster = TimelineBroadcaster::new();
        let lookalikes = LookalikeTargets::new();
        let store = |p| store_package(&db, &broadcaster, &lookalikes, p).unwrap();
        let package = store(crate_with(&[("1.0.0", Some(false)), ("1.0.1", Some(true))]));
        store(crate_with(&[("1.0.2", Some(true)), ("1.0.3", None)]));

        let mut versions: Vec<String> = db
            .get_versions_by_package(package.id)
            .unwrap()
            .into_iter()
            .map(|v| v.inner.version)
            .collect();
        versions.sort();
        assert_eq!(versions, ["1.0.0", "1.0.3"]);
        assert!(yanked(&db, package.id).is_empty());
    }

    #[test]
    fn lookup_lists_the_yanked_versions() {
        let (_dir, db) = open_db();
        let broadcaster = TimelineBroadcaster::new();
        let lookalikes = LookalikeTargets::new();
        let store = |p| store_package(&db, &broadcaster, &lookalikes, p).unwrap();
        store(crate_with(&[("1.0.0", Some(false)), ("1.0.1", Some(false))]));
        store(crate_with(&[("1.0.0", Some(true))]));

        let lookup = get_package_lookup(&db, "serde");
        let mut versions = lookup.version_strings.clone();
        versions.sort();
        assert_eq!(versions, ["1.0.0", "1.0.1"]);
        assert_eq!(lookup.yanked_versions, ["1.0.0"]);
    }

    fn get_package_lookup(db: &Database, name: &str) -> PackageLookup {
        package_lookup(db, name).unwrap().unwrap()
    }

    #[test]
    fn lookalike_alerts_the_imitated_packages_subscribers_once() {
        let (_dir, db) = open_db();
        let broadcaster = TimelineBroadcaster::new();
        seed(
            &db,
            vec![
                collected("colorama", "Pypi", Some(5000), &[]),
                collected("requests", "Pypi", Some(9000), &[]),
            ],
        );
        let colorama = db.get_package_by_name("colorama").unwrap().unwrap().id;
        subscribe(&db, "subscriber", "colorama");
        subscribe(&db, "bystander", "requests");
        let lookalikes = LookalikeTargets::new();

        let squat = store_package(
            &db,
            &broadcaster,
            &lookalikes,
            collected("colourama", "Pypi", Some(0), &[]),
        )
        .unwrap();

        let events = alerts(&db, "subscriber");
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.package_id, colorama);
        assert_eq!(event.package_name, "colorama");
        assert_eq!(
            event.message,
            "New Pypi package colourama closely resembles colorama (one character different). \
             Check your manifests."
        );
        let metadata: serde_json::Value =
            serde_json::from_str(event.metadata.as_deref().unwrap()).unwrap();
        assert_eq!(metadata["lookalike_package_id"], squat.id);
        assert_eq!(metadata["lookalike_name"], "colourama");
        assert_eq!(metadata["reason"], "Edit1");
        assert_eq!(metadata["severity"], "Medium");
        assert!(alerts(&db, "bystander").is_empty());

        // Collectors re-send known packages on every run; only arrival alerts.
        let mut again = collected("colourama", "Pypi", Some(0), &[]);
        again.versions[0].version = "1.0.1".into();
        store_package(&db, &broadcaster, &lookalikes, again).unwrap();
        assert_eq!(alerts(&db, "subscriber").len(), 1);
    }

    #[test]
    fn popular_or_unrelated_newcomers_are_not_flagged() {
        let (_dir, db) = open_db();
        seed(&db, vec![collected("colorama", "Pypi", Some(5000), &[])]);
        subscribe(&db, "subscriber", "colorama");
        let lookalikes = LookalikeTargets::new();
        let store = |p| store_package(&db, &TimelineBroadcaster::new(), &lookalikes, p).unwrap();

        // Popular enough to be a target itself: an established neighbour.
        store(collected("colourama", "Pypi", Some(MIN_TARGET_POPULARITY), &[]));
        // Same name under PEP 503 normalisation: the same PyPI project.
        store(collected("Colorama", "Pypi", Some(0), &[]));
        // A different ecosystem.
        store(collected("colorana", "NPM", Some(0), &[]));
        store(collected("termcolor", "Pypi", Some(0), &[]));

        assert!(alerts(&db, "subscriber").is_empty());
    }

    #[test]
    fn unpopular_packages_are_not_targets() {
        let (_dir, db) = open_db();
        seed(
            &db,
            vec![collected("colorama", "Pypi", Some(MIN_TARGET_POPULARITY - 1), &[])],
        );
        subscribe(&db, "subscriber", "colorama");

        store_package(
            &db,
            &TimelineBroadcaster::new(),
            &LookalikeTargets::new(),
            collected("colourama", "Pypi", Some(0), &[]),
        )
        .unwrap();

        assert!(alerts(&db, "subscriber").is_empty());
    }

    /// crates.io reports no dependents count, so popularity comes from the
    /// stored dependency lists instead.
    #[test]
    fn popularity_falls_back_to_stored_dependents() {
        let (_dir, db) = open_db();
        let mut seeded = vec![collected("serde_json", "crates.io", None, &[])];
        for i in 0..MIN_TARGET_POPULARITY {
            seeded.push(collected(&format!("user{i}"), "crates.io", None, &["serde_json"]));
        }
        seed(&db, seeded);
        subscribe(&db, "subscriber", "serde_json");

        store_package(
            &db,
            &TimelineBroadcaster::new(),
            &LookalikeTargets::new(),
            collected("serde-json", "crates.io", None, &[]),
        )
        .unwrap();

        let events = alerts(&db, "subscriber");
        assert_eq!(events.len(), 1);
        assert!(events[0].message.contains("(separator or case swap)"), "{}", events[0].message);
    }

    #[test]
    fn package_page_lookalike_matches_the_arrival_check() {
        use crate::handlers::packages::package_lookalike;
        use fossdb::typosquat::SquatReason;
        use fossdb::FindingSeverity;

        let (_dir, db) = open_db();
        seed(
            &db,
            vec![
                collected("colorama", "Pypi", Some(5000), &[]),
                collected("colourama", "Pypi", Some(0), &[]),
                collected("Colorama", "Pypi", Some(0), &[]),
                collected("colorama-js", "Pypi", Some(0), &[]),
                collected("termcolor", "Pypi", Some(0), &[]),
            ],
        );
        let id = |name: &str| db.get_package_by_name(name).unwrap().unwrap().id;
        let lookalikes = LookalikeTargets::new();
        let check = |name: &str| package_lookalike(&db, &lookalikes, id(name)).unwrap().unwrap();

        let found = check("colourama").expect("colourama imitates colorama");
        assert_eq!(found.target_id, id("colorama"));
        assert_eq!(found.target_name, "colorama");
        assert_eq!(found.target_dependents, 5000);
        assert_eq!(found.reason, SquatReason::Edit1);
        assert_eq!(found.severity, FindingSeverity::Medium);

        let affix = check("colorama-js").expect("an affix match is still reported");
        assert_eq!(affix.severity, FindingSeverity::Low);

        // The imitated package itself, a PEP 503 spelling of it, and an
        // unrelated name are not lookalikes.
        assert_eq!(check("colorama"), None);
        assert_eq!(check("Colorama"), None);
        assert_eq!(check("termcolor"), None);

        // No such package: the handler answers 404 rather than `null`.
        assert!(package_lookalike(&db, &lookalikes, 9999).unwrap().is_none());
    }

    #[test]
    fn search_results_mark_only_their_lookalikes() {
        use crate::handlers::packages::{package_lookalike, page_lookalikes};

        let (_dir, db) = open_db();
        seed(
            &db,
            vec![
                collected("colorama", "Pypi", Some(5000), &[]),
                collected("colourama", "Pypi", Some(0), &[]),
                collected("colorama-js", "Pypi", Some(0), &[]),
                collected("termcolor", "Pypi", Some(0), &[]),
            ],
        );
        let package = |name: &str| db.get_package_by_name(name).unwrap().unwrap();
        let lookalikes = LookalikeTargets::new();

        let page: Vec<_> = ["colorama", "colourama", "colorama-js", "termcolor"]
            .into_iter()
            .map(package)
            .collect();
        let marked = page_lookalikes(&db, &lookalikes, &page);

        let mut ids: Vec<u64> = marked.keys().copied().collect();
        ids.sort();
        let mut expected = vec![package("colourama").id, package("colorama-js").id];
        expected.sort();
        assert_eq!(ids, expected, "only the two imitations are marked");

        // Each marker is exactly what the package page shows.
        for (id, lookalike) in &marked {
            let on_page = package_lookalike(&db, &lookalikes, *id).unwrap().unwrap();
            assert_eq!(on_page.as_ref(), Some(lookalike));
        }

        // Packages outside the page are not checked or reported.
        let only_target = page_lookalikes(&db, &lookalikes, &[package("colorama")]);
        assert!(only_target.is_empty());
    }

    #[test]
    fn subscribing_to_a_lookalike_succeeds_and_names_the_target() {
        use crate::handlers::users::subscribe;

        let (_dir, db) = open_db();
        seed(
            &db,
            vec![
                collected("colorama", "Pypi", Some(5000), &[]),
                collected("colourama", "Pypi", Some(0), &[]),
            ],
        );
        let lookalikes = LookalikeTargets::new();
        let account = |subscriptions: Vec<fossdb::PackageSubscription>| crate::User {
            inner: fossdb::User {
                user_id: "subscriber".into(),
                subscriptions,
                created_at: Utc::now(),
                notifications_enabled: true,
            },
        };
        db.insert_user(account(Vec::new())).unwrap();

        let response = subscribe(&db, &lookalikes, account(Vec::new()), "colourama")
            .unwrap()
            .expect("colourama exists");
        let lookalike = response.lookalike.expect("colourama imitates colorama");
        assert_eq!(lookalike.target_name, "colorama");
        assert_eq!(lookalike.target_dependents, 5000);
        // A warning, not a refusal: the subscription is stored.
        assert_eq!(response.subscriptions.len(), 1);
        assert_eq!(response.subscriptions[0].package_name, "colourama");
        let stored = db.get_user("subscriber").unwrap().unwrap();
        assert_eq!(stored.subscriptions, response.subscriptions);

        let response = subscribe(&db, &lookalikes, stored.clone(), "colorama")
            .unwrap()
            .unwrap();
        assert_eq!(response.lookalike, None);
        assert_eq!(response.subscriptions.len(), 2);

        assert!(subscribe(&db, &lookalikes, stored, "nonexistent").unwrap().is_none());
    }

    #[test]
    fn unknown_package_is_skipped_and_not_stored() {
        let (_dir, db) = open_db();

        let result = ingest_advisory(&db, &TimelineBroadcaster::new(), advisory("nonexistent", "crates.io", &["1.0.0"])).unwrap();

        assert_eq!(result.vulnerability_id, None);
        assert_eq!(result.skipped, vec!["crates.io/nonexistent".to_string()]);
        assert!(db.get_all_vulnerabilities().unwrap().is_empty());
    }
}
