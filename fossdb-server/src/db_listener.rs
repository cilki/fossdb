use anyhow::Result;
use chrono::Utc;
use native_db::watch::Event;
use std::sync::Arc;

use crate::db::Database;
use crate::{EventType, PackageVersion, TimelineEvent};
use crate::websocket::TimelineBroadcaster;

/// Spawns a background task that listens for PackageVersion inserts
/// and automatically creates timeline events for them.
pub fn spawn_package_version_listener(
    db: Arc<Database>,
    broadcaster: Arc<TimelineBroadcaster>,
) -> Result<()> {
    // Watch for all PackageVersion inserts
    let (recv, _watch_id) = db.db.watch().scan().primary().all::<PackageVersion>()?;

    tracing::info!("Started database listener for PackageVersion events");

    // Spawn a background task to process events
    tokio::spawn(async move {
        loop {
            match recv.recv() {
                Ok(event) => {
                    if let Err(e) = handle_package_version_event(event, &db, &broadcaster) {
                        tracing::error!("Error handling package version event: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Error receiving watch event: {}", e);
                    // If the channel is disconnected, break the loop
                    break;
                }
            }
        }
        tracing::warn!("Database listener for PackageVersion events stopped");
    });

    Ok(())
}

fn handle_package_version_event(
    event: Event,
    db: &Database,
    broadcaster: &TimelineBroadcaster,
) -> Result<()> {
    // Only handle Insert events (new versions)
    let version: PackageVersion = match event {
        Event::Insert(insert_event) => insert_event.inner()?,
        Event::Update(_) | Event::Delete(_) => {
            // We don't create timeline events for updates or deletes
            return Ok(());
        }
    };

    tracing::debug!(
        "Detected new PackageVersion insert: package_id={}, version={}",
        version.package_id,
        version.version
    );

    // Get the package to retrieve its name
    let package = match db.get_package(version.package_id)? {
        Some(pkg) => pkg,
        None => {
            tracing::warn!(
                "Package {} not found for version {}",
                version.package_id,
                version.version
            );
            return Ok(());
        }
    };

    tracing::info!("New release: {} {}", package.name, version.version);
    notify_subscribers(
        db,
        broadcaster,
        fossdb::TimelineEvent {
            id: 0,
            package_id: package.id,
            user_id: None,
            event_type: EventType::NewRelease,
            package_name: package.inner.name,
            message: format!("New version {} released", version.version),
            version: Some(version.inner.version),
            metadata: None,
            created_at: Utc::now(),
        },
    );

    Ok(())
}

/// Store a copy of `event` for every account subscribed to its package and
/// broadcast each copy, then broadcast `event` itself as the global,
/// unstored event.
fn notify_subscribers(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    event: fossdb::TimelineEvent,
) {
    match db.get_users_subscribed_to(&event.package_name) {
        Ok(users) => {
            for user_id in users {
                let personal = TimelineEvent {
                    inner: fossdb::TimelineEvent {
                        user_id: Some(user_id),
                        ..event.clone()
                    },
                };
                match db.insert_timeline_event(personal) {
                    Ok(saved) => broadcaster.broadcast(saved),
                    Err(e) => tracing::error!(
                        "Failed to store timeline event for {}: {}",
                        event.package_name,
                        e
                    ),
                }
            }
        }
        Err(e) => tracing::error!(
            "Failed to get subscribed users for {}: {}",
            event.package_name,
            e
        ),
    }

    broadcaster.broadcast(TimelineEvent { inner: event });
}

/// How many affected versions a `SecurityAlert` message names before it
/// summarises the rest as "and N more".
const ALERT_VERSIONS_SHOWN: usize = 10;

/// Record and broadcast `SecurityAlert` timeline events for an advisory.
///
/// `newly_linked` maps package ids to the versions the advisory has just
/// been linked to (see [`crate::db::AdvisoryUpsert::newly_linked`]). Each
/// package with at least one such version gets one event per subscriber
/// with notifications on, stored like a release event so it reaches the
/// websocket and the feeds, plus one global, unstored event. Re-ingesting an
/// advisory that links nothing new therefore alerts nobody.
///
/// Called directly by the ingest path rather than from a database watch:
/// the watch only sees individual rows, so it could not tell which versions
/// one advisory added, and would alert once per version instead of once per
/// advisory.
pub fn emit_security_alerts(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    vulnerability: &fossdb::Vulnerability,
    newly_linked: &std::collections::BTreeMap<u64, Vec<String>>,
) {
    for (&package_id, versions) in newly_linked {
        if versions.is_empty() {
            continue;
        }
        let package = match db.get_package(package_id) {
            Ok(Some(p)) => p,
            Ok(None) => {
                tracing::warn!(
                    "Advisory {} links package {} which no longer exists",
                    vulnerability.source_id,
                    package_id
                );
                continue;
            }
            Err(e) => {
                tracing::error!("Failed to load package {}: {}", package_id, e);
                continue;
            }
        };

        tracing::info!(
            "Security alert for {}: {} affects {} version(s)",
            package.name,
            vulnerability.source_id,
            versions.len()
        );
        let metadata = serde_json::json!({
            "vulnerability_id": vulnerability.id,
            "source_id": vulnerability.source_id,
            "cve_id": vulnerability.cve_id,
            "severity": vulnerability.severity,
            "versions": versions,
        });
        notify_subscribers(
            db,
            broadcaster,
            fossdb::TimelineEvent {
                id: 0,
                package_id,
                user_id: None,
                event_type: EventType::SecurityAlert,
                package_name: package.inner.name,
                version: None,
                message: security_alert_message(vulnerability, versions),
                metadata: Some(metadata.to_string()),
                created_at: Utc::now(),
            },
        );
    }
}

/// Alert the subscribers of the package `lookalike` targets that `package`,
/// which has just arrived, imitates its name.
///
/// The event is filed under the imitated package, not the new one: its
/// subscribers depend on it, so they are the ones who might mistype it in a
/// manifest, and nobody is subscribed to a package that did not exist a
/// moment ago.
pub fn emit_lookalike_alert(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    package: &fossdb::Package,
    lookalike: &fossdb::typosquat::PackageLookalike,
) {
    tracing::info!(
        "New package {} resembles {} ({:?})",
        package.name,
        lookalike.target_name,
        lookalike.reason
    );
    let ecosystem = package
        .platform
        .as_deref()
        .map(|p| format!("{p} "))
        .unwrap_or_default();
    let metadata = serde_json::json!({
        "lookalike_package_id": package.id,
        "lookalike_name": package.name,
        "reason": lookalike.reason,
        "severity": lookalike.severity,
    });
    notify_subscribers(
        db,
        broadcaster,
        fossdb::TimelineEvent {
            id: 0,
            package_id: lookalike.target_id,
            user_id: None,
            event_type: EventType::SecurityAlert,
            package_name: lookalike.target_name.clone(),
            version: None,
            message: format!(
                "New {ecosystem}package {} closely resembles {} ({}). Check your manifests.",
                package.name,
                lookalike.target_name,
                lookalike.reason.describe()
            ),
            metadata: Some(metadata.to_string()),
            created_at: Utc::now(),
        },
    );
}

/// An install hook that a newly analysed version has and its baseline did not
/// have in the same form.
#[derive(Debug, PartialEq)]
pub struct HookChange<'a> {
    /// `false` when the baseline had a hook at the same location, but with a
    /// different description or severity (e.g. its script changed).
    pub added: bool,
    pub hook: &'a fossdb::AnalysisFinding,
}

/// The `InstallHook` findings of `current` that are new or different compared
/// with `baseline`, in `current`'s order. Removed hooks are not reported.
///
/// Hooks are matched by `location`, which the worker keeps stable across
/// versions (see [`fossdb::FindingKind::InstallHook`]).
pub fn install_hook_changes<'a>(
    baseline: &[fossdb::AnalysisFinding],
    current: &'a [fossdb::AnalysisFinding],
) -> Vec<HookChange<'a>> {
    fn hooks(
        findings: &[fossdb::AnalysisFinding],
    ) -> impl Iterator<Item = &fossdb::AnalysisFinding> {
        findings
            .iter()
            .filter(|f| f.kind == fossdb::FindingKind::InstallHook)
    }
    let before: std::collections::HashMap<Option<&str>, &fossdb::AnalysisFinding> = hooks(baseline)
        .map(|f| (f.location.as_deref(), f))
        .collect();

    hooks(current)
        .filter_map(|hook| match before.get(&hook.location.as_deref()) {
            None => Some(HookChange { added: true, hook }),
            Some(old) if old.description != hook.description || old.severity != hook.severity => {
                Some(HookChange { added: false, hook })
            }
            Some(_) => None,
        })
        .collect()
}

/// Tell the subscribers of a package when a newly stored analysis shows
/// install-time hooks that the package's previous analysis did not have.
///
/// The baseline is the analysis of the highest version below `analysis`'s.
/// The worker only analyses each package's latest version, so that is the
/// last version FossDB looked at, not necessarily the previous release; the
/// message names it. A package's first analysis has no baseline and raises
/// nothing.
///
/// A new or changed hook is a [`EventType::BehaviorChange`]: ordinary crates
/// gain a `build.rs` all the time. It becomes a [`EventType::SecurityAlert`]
/// when one of the hooks is High or Critical, i.e. its text matched one of the
/// worker's dropper patterns.
pub fn emit_install_hook_changes(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    analysis: &fossdb::WorkerAnalysis,
) -> Result<()> {
    let baseline = db
        .get_analyses_by_package(analysis.package_id)?
        .into_iter()
        .filter(|a| a.version_id < analysis.version_id)
        .max_by_key(|a| (a.version_id, a.id));
    let Some(baseline) = baseline else {
        return Ok(());
    };

    let changes = install_hook_changes(&baseline.findings, &analysis.findings);
    if changes.is_empty() {
        return Ok(());
    }

    let Some(package) = db.get_package(analysis.package_id)? else {
        return Ok(());
    };
    let version_name = |id: u64| -> Result<String> {
        Ok(db
            .get_version(id)?
            .map(|v| v.inner.version)
            .unwrap_or_else(|| format!("#{id}")))
    };
    let version = version_name(analysis.version_id)?;
    let baseline_version = version_name(baseline.version_id)?;

    let suspicious = changes.iter().any(|c| {
        matches!(
            c.hook.severity,
            fossdb::FindingSeverity::High | fossdb::FindingSeverity::Critical
        )
    });
    let event_type = if suspicious {
        EventType::SecurityAlert
    } else {
        EventType::BehaviorChange
    };

    tracing::info!(
        "{} {}: {} install hook change(s) since {}",
        package.name,
        version,
        changes.len(),
        baseline_version
    );
    let metadata = serde_json::json!({
        "analysis_id": analysis.id,
        "baseline_analysis_id": baseline.id,
        "baseline_version": baseline_version,
        "hooks": changes
            .iter()
            .map(|c| serde_json::json!({
                "change": if c.added { "added" } else { "changed" },
                "location": c.hook.location,
                "description": c.hook.description,
                "severity": c.hook.severity,
            }))
            .collect::<Vec<_>>(),
    });
    notify_subscribers(
        db,
        broadcaster,
        fossdb::TimelineEvent {
            id: 0,
            package_id: package.id,
            user_id: None,
            event_type,
            package_name: package.inner.name,
            message: install_hook_message(&version, &baseline_version, &changes),
            version: Some(version),
            metadata: Some(metadata.to_string()),
            created_at: Utc::now(),
        },
    );
    Ok(())
}

/// E.g. `1.3.1 runs new install-time code compared with 1.3.0: added npm
/// postinstall: node setup.js.`
fn install_hook_message(version: &str, baseline: &str, changes: &[HookChange]) -> String {
    let hooks = changes
        .iter()
        .map(|c| {
            let change = if c.added { "added" } else { "changed" };
            format!("{change} {}", c.hook.description.trim_end_matches('.'))
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("{version} runs new install-time code compared with {baseline}: {hooks}.")
}

/// E.g. `RUSTSEC-2016-0001 (High): SSL/TLS MitM vulnerability. Affects
/// 0.8.3, 0.9.0. Fixed in 0.9.0.`
fn security_alert_message(vulnerability: &fossdb::Vulnerability, versions: &[String]) -> String {
    let mut shown = versions
        .iter()
        .take(ALERT_VERSIONS_SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if versions.len() > ALERT_VERSIONS_SHOWN {
        shown.push_str(&format!(" and {} more", versions.len() - ALERT_VERSIONS_SHOWN));
    }

    let mut message = format!(
        "{} ({:?}): {}. Affects {}.",
        vulnerability.source_id,
        vulnerability.severity,
        vulnerability.title.trim_end_matches('.'),
        shown
    );
    if let Some(fixed) = &vulnerability.fixed_in {
        message.push_str(&format!(" Fixed in {fixed}."));
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use fossdb::{AnalysisFinding, FindingKind, FindingSeverity, VulnerabilitySeverity};

    fn vulnerability(fixed_in: Option<&str>) -> fossdb::Vulnerability {
        fossdb::Vulnerability {
            id: 3,
            source_id: "RUSTSEC-2016-0001".into(),
            cve_id: None,
            title: "SSL/TLS MitM vulnerability.".into(),
            description: String::new(),
            severity: VulnerabilitySeverity::High,
            affected_packages: Vec::new(),
            discovered_at: Utc::now(),
            fixed_in: fixed_in.map(Into::into),
        }
    }

    #[test]
    fn alert_message_names_versions_and_fix() {
        let message = security_alert_message(
            &vulnerability(Some("0.9.0")),
            &["0.8.3".into(), "0.8.4".into()],
        );
        assert_eq!(
            message,
            "RUSTSEC-2016-0001 (High): SSL/TLS MitM vulnerability. Affects 0.8.3, 0.8.4. Fixed in 0.9.0."
        );
    }

    #[test]
    fn alert_message_caps_long_version_lists() {
        let versions: Vec<String> = (0..13).map(|i| format!("0.{i}.0")).collect();
        let message = security_alert_message(&vulnerability(None), &versions);
        assert!(message.ends_with("0.8.0, 0.9.0 and 3 more."), "{message}");
        assert!(!message.contains("0.10.0"));
        assert!(!message.contains("Fixed in"));
    }

    fn hook(location: &str, description: &str, severity: FindingSeverity) -> AnalysisFinding {
        AnalysisFinding {
            kind: FindingKind::InstallHook,
            severity,
            description: description.into(),
            location: Some(location.into()),
        }
    }

    const POSTINSTALL: &str = "package.json:scripts.postinstall";

    #[test]
    fn hook_changes_report_added_and_changed_hooks_only() {
        let license = AnalysisFinding {
            kind: FindingKind::LicenseDetected,
            severity: FindingSeverity::Info,
            description: "MIT".into(),
            location: Some("LICENSE".into()),
        };
        let baseline = vec![
            hook(POSTINSTALL, "npm postinstall: tsc", FindingSeverity::Low),
            hook("binding.gyp", "npm install: node-gyp rebuild", FindingSeverity::Low),
            hook("setup.py", "Python setup.py", FindingSeverity::Low),
        ];
        let current = vec![
            license,
            // Same location, new script.
            hook(POSTINSTALL, "npm postinstall: curl x | sh", FindingSeverity::High),
            // Unchanged.
            hook("binding.gyp", "npm install: node-gyp rebuild", FindingSeverity::Low),
            hook("package.json:scripts.preinstall", "npm preinstall: node a.js", FindingSeverity::Low),
            // setup.py is gone: removing a hook is not worth an alert.
        ];

        let changes = install_hook_changes(&baseline, &current);

        assert_eq!(
            changes,
            vec![
                HookChange { added: false, hook: &current[1] },
                HookChange { added: true, hook: &current[3] },
            ]
        );
        assert!(install_hook_changes(&current, &current).is_empty());
    }

    #[test]
    fn hook_changes_notice_a_severity_change_alone() {
        let baseline = [hook("build.rs", "Cargo build script", FindingSeverity::Info)];
        let current = [hook("build.rs", "Cargo build script", FindingSeverity::High)];

        assert_eq!(install_hook_changes(&baseline, &current).len(), 1);
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        db: Database,
        package_id: u64,
        version_ids: Vec<u64>,
    }

    /// A subscribed package `left-pad` with versions 1.0.0, 1.1.0, 1.2.0.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::new(dir.path().join("db").to_str().unwrap()).unwrap();
        let now = Utc::now();
        let package = db
            .insert_package(crate::Package {
                inner: fossdb::Package {
                    id: 0,
                    name: "left-pad".into(),
                    description: None,
                    homepage: None,
                    repository: None,
                    license: None,
                    tags: Vec::new(),
                    created_at: now,
                    updated_at: now,
                    platform: Some("NPM".into()),
                    language: None,
                    status: None,
                    dependents_count: None,
                    rank: None,
                },
            })
            .unwrap();
        let version_ids = ["1.0.0", "1.1.0", "1.2.0"]
            .iter()
            .map(|v| {
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
                .unwrap()
                .id
            })
            .collect();
        db.insert_user(crate::User {
            inner: fossdb::User {
                user_id: "subscriber".into(),
                subscriptions: vec![fossdb::PackageSubscription {
                    package_name: "left-pad".into(),
                    notifications_enabled: true,
                }],
                created_at: now,
                notifications_enabled: true,
            },
        })
        .unwrap();
        Fixture { _dir: dir, db, package_id: package.id, version_ids }
    }

    impl Fixture {
        /// Store an analysis of the `index`th version and run the comparison
        /// the way `submit_analysis` does.
        fn analyse(&self, index: usize, findings: Vec<AnalysisFinding>) {
            let saved = self
                .db
                .insert_worker_analysis(crate::WorkerAnalysis {
                    inner: fossdb::WorkerAnalysis {
                        id: 0,
                        package_id: self.package_id,
                        version_id: self.version_ids[index],
                        analyzed_at: Utc::now(),
                        findings,
                        checksum_verified: None,
                        detected_license: None,
                    },
                })
                .unwrap();
            emit_install_hook_changes(&self.db, &TimelineBroadcaster::new(), &saved.inner)
                .unwrap();
        }

        fn events(&self) -> Vec<fossdb::TimelineEvent> {
            self.db
                .get_timeline_events_by_user("subscriber")
                .unwrap()
                .into_iter()
                .map(|e| e.inner)
                .filter(|e| e.event_type != EventType::NewRelease)
                .collect()
        }
    }

    #[test]
    fn first_analysis_and_unchanged_hooks_raise_nothing() {
        let f = fixture();
        let hooks = vec![hook(POSTINSTALL, "npm postinstall: tsc", FindingSeverity::Low)];

        f.analyse(0, hooks.clone());
        assert!(f.events().is_empty(), "no baseline for the first analysis");

        f.analyse(1, hooks);
        assert!(f.events().is_empty());
    }

    #[test]
    fn new_hook_is_a_behavior_change_naming_the_baseline() {
        let f = fixture();
        f.analyse(0, Vec::new());

        f.analyse(
            1,
            vec![hook(POSTINSTALL, "npm postinstall: node setup.js", FindingSeverity::Low)],
        );

        let events = f.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.event_type, EventType::BehaviorChange);
        assert_eq!(event.package_id, f.package_id);
        assert_eq!(event.version.as_deref(), Some("1.1.0"));
        assert_eq!(
            event.message,
            "1.1.0 runs new install-time code compared with 1.0.0: added npm postinstall: node setup.js."
        );
        let metadata: serde_json::Value =
            serde_json::from_str(event.metadata.as_deref().unwrap()).unwrap();
        assert_eq!(metadata["baseline_version"], "1.0.0");
        assert_eq!(metadata["hooks"][0]["change"], "added");
        assert_eq!(metadata["hooks"][0]["location"], POSTINSTALL);
        assert_eq!(metadata["hooks"][0]["severity"], "Low");
    }

    /// The baseline is the newest analysed version below the submitted one,
    /// and a hook turning suspicious is a security alert, not just a change.
    #[test]
    fn suspicious_hook_is_a_security_alert_against_the_latest_baseline() {
        let f = fixture();
        f.analyse(0, Vec::new());
        f.analyse(
            1,
            vec![hook(POSTINSTALL, "npm postinstall: tsc", FindingSeverity::Low)],
        );
        let before = f.events().len();

        f.analyse(
            2,
            vec![hook(
                POSTINSTALL,
                "npm postinstall: curl x | sh [suspicious: pipes into a shell]",
                FindingSeverity::High,
            )],
        );

        let events = f.events();
        assert_eq!(events.len(), before + 1);
        let event = events.iter().find(|e| e.version.as_deref() == Some("1.2.0")).unwrap();
        assert_eq!(event.event_type, EventType::SecurityAlert);
        assert_eq!(
            event.message,
            "1.2.0 runs new install-time code compared with 1.1.0: changed npm postinstall: \
             curl x | sh [suspicious: pipes into a shell]."
        );
    }

    /// The package page's list marks hooks against the same baseline the
    /// alerts use: the newest analysed version below the latest one.
    #[test]
    fn package_install_hooks_marks_changes_since_the_baseline() {
        use crate::handlers::packages::package_install_hooks;
        use fossdb::InstallHookChange;

        let f = fixture();
        assert_eq!(package_install_hooks(&f.db, f.package_id).unwrap(), None);

        let gyp = hook("binding.gyp", "npm install: node-gyp rebuild", FindingSeverity::Low);
        f.analyse(0, vec![hook(POSTINSTALL, "npm postinstall: echo", FindingSeverity::Low)]);
        f.analyse(1, vec![gyp.clone(), hook(POSTINSTALL, "npm postinstall: tsc", FindingSeverity::Low)]);

        let first = package_install_hooks(&f.db, f.package_id).unwrap().unwrap();
        assert_eq!(first.version, "1.1.0");
        assert_eq!(first.baseline_version.as_deref(), Some("1.0.0"));
        let changes: Vec<_> = first
            .hooks
            .iter()
            .map(|h| (h.location.as_deref().unwrap(), h.change))
            .collect();
        assert_eq!(
            changes,
            vec![
                ("binding.gyp", Some(InstallHookChange::Added)),
                (POSTINSTALL, Some(InstallHookChange::Changed)),
            ]
        );

        // Analysed out of order: the latest version still wins, and it is
        // compared with 1.1.0, not with the analysis stored just before it.
        let license = AnalysisFinding {
            kind: FindingKind::LicenseDetected,
            severity: FindingSeverity::Info,
            description: "MIT".into(),
            location: Some("LICENSE".into()),
        };
        f.analyse(2, vec![license, gyp]);
        f.analyse(0, Vec::new());

        let latest = package_install_hooks(&f.db, f.package_id).unwrap().unwrap();
        assert_eq!(latest.version, "1.2.0");
        assert_eq!(latest.baseline_version.as_deref(), Some("1.1.0"));
        assert_eq!(latest.hooks.len(), 1, "only InstallHook findings are listed");
        assert_eq!(latest.hooks[0].location.as_deref(), Some("binding.gyp"));
        assert_eq!(latest.hooks[0].change, None, "unchanged since 1.1.0");

        let json = serde_json::to_value(&first).unwrap();
        assert_eq!(json["hooks"][0]["change"], "added");
    }

    #[test]
    fn first_analysis_has_no_baseline_and_no_changes() {
        use crate::handlers::packages::package_install_hooks;

        let f = fixture();
        f.analyse(1, vec![hook("setup.py", "Python setup.py", FindingSeverity::Low)]);

        let hooks = package_install_hooks(&f.db, f.package_id).unwrap().unwrap();
        assert_eq!(hooks.version, "1.1.0");
        assert_eq!(hooks.baseline_version, None);
        assert_eq!(hooks.hooks[0].change, None);
    }
}
