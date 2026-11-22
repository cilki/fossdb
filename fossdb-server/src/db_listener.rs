use anyhow::Result;
use chrono::Utc;
use fossdb::InstallHookChange;
use native_db::watch::Event;
use std::sync::Arc;

use crate::db::Database;
use crate::{EventType, PackageVersion, TimelineEvent, WorkerAnalysis};
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

/// Tell the subscribers of `package` that stored `versions` have just been
/// yanked upstream: one event per package per ingest, however many versions
/// it names.
///
/// A [`EventType::BehaviorChange`], since most yanks are releases published
/// by mistake; but a yank is also often the first public sign of a bad or
/// compromised release, well before any advisory, so anyone who already
/// upgraded should know.
pub fn emit_yank_alert(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    package: &fossdb::Package,
    versions: &[String],
) {
    tracing::info!("{} yanked: {}", package.name, versions.join(", "));
    let from = package
        .platform
        .as_deref()
        .map(|p| format!(" from {p}"))
        .unwrap_or_default();
    let message = match versions {
        [one] => format!("{} {one} was yanked{from}", package.name),
        many => format!("{} {} were yanked{from}", package.name, many.join(", ")),
    };
    notify_subscribers(
        db,
        broadcaster,
        fossdb::TimelineEvent {
            id: 0,
            package_id: package.id,
            user_id: None,
            event_type: EventType::BehaviorChange,
            package_name: package.name.clone(),
            version: match versions {
                [one] => Some(one.clone()),
                _ => None,
            },
            message,
            metadata: Some(serde_json::json!({ "yanked_versions": versions }).to_string()),
            created_at: Utc::now(),
        },
    );
}

/// An install hook that a newly analysed version has and its baseline did not
/// have in the same form.
#[derive(Debug, PartialEq)]
pub struct HookChange<'a> {
    pub change: InstallHookChange,
    pub hook: &'a fossdb::AnalysisFinding,
}

/// The analysis `analysed` install hooks are compared with: the one of the
/// highest version below `version_id`, the newest if it was analysed twice.
pub fn baseline_analysis(
    analysed: impl IntoIterator<Item = WorkerAnalysis>,
    version_id: u64,
) -> Option<WorkerAnalysis> {
    analysed
        .into_iter()
        .filter(|a| a.version_id < version_id)
        .max_by_key(|a| (a.version_id, a.id))
}

/// The version string of `version_id`, or `#<id>` if it is gone.
pub fn version_name(db: &Database, version_id: u64) -> Result<String> {
    Ok(db
        .get_version(version_id)?
        .map(|v| v.inner.version)
        .unwrap_or_else(|| format!("#{version_id}")))
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
            None => Some(HookChange { change: InstallHookChange::Added, hook }),
            Some(old) if old.description != hook.description || old.severity != hook.severity => {
                Some(HookChange { change: InstallHookChange::Changed, hook })
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
    let analysed = db.get_analyses_by_package(analysis.package_id)?;
    let Some(baseline) = baseline_analysis(analysed, analysis.version_id) else {
        return Ok(());
    };

    let changes = install_hook_changes(&baseline.findings, &analysis.findings);
    if changes.is_empty() {
        return Ok(());
    }

    let Some(package) = db.get_package(analysis.package_id)? else {
        return Ok(());
    };
    let version = version_name(db, analysis.version_id)?;
    let baseline_version = version_name(db, baseline.version_id)?;

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
                "change": c.change,
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

/// Raise every alert a newly stored analysis calls for: install hook changes
/// (see [`emit_install_hook_changes`]) and the other notable findings (see
/// [`emit_finding_alerts`]). One failing does not stop the other.
pub fn emit_analysis_alerts(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    analysis: &fossdb::WorkerAnalysis,
) -> Result<()> {
    let hooks = emit_install_hook_changes(db, broadcaster, analysis);
    let findings = emit_finding_alerts(db, broadcaster, analysis);
    hooks.and(findings)
}

/// Whether a finding that is new since the baseline is worth telling
/// subscribers about, and if so how loudly. `ChecksumMismatch` and
/// `InstallHook` have their own rules and are not covered here.
///
/// Only Critical secrets alert: they are private keys and cloud credentials,
/// which let whoever finds them act as the maintainer. The High and Medium
/// patterns (credentials in URLs, hardcoded passwords) mostly match
/// placeholders in docs and tests. Binary findings count from Medium up; the
/// Low ones are symbol-name matches that most native code trips.
fn new_finding_event(finding: &fossdb::AnalysisFinding) -> Option<EventType> {
    use fossdb::{FindingKind, FindingSeverity};
    match (&finding.kind, &finding.severity) {
        (FindingKind::SecretDetected, FindingSeverity::Critical) => Some(EventType::SecurityAlert),
        (
            FindingKind::MaliciousPattern | FindingKind::SyscallReachable,
            FindingSeverity::Medium | FindingSeverity::High | FindingSeverity::Critical,
        ) => Some(EventType::BehaviorChange),
        _ => None,
    }
}

/// What identifies `finding` across versions of a package, so that the same
/// finding in the baseline does not alert again.
///
/// Source archives usually unpack into a versioned top-level directory
/// (`serde-1.0.200/src/lib.rs`), so a leading path component naming `version`
/// is dropped from the location. The description loses the parts that change
/// with every build: the address of a reachable syscall and the measured
/// entropy of a packed section.
fn finding_identity(
    finding: &fossdb::AnalysisFinding,
    version: &str,
) -> (String, Option<String>, String) {
    let location = finding.location.as_deref().map(|location| {
        match location.split_once('/') {
            Some((top, rest)) if !version.is_empty() && top.contains(version) => rest,
            _ => location,
        }
        .to_owned()
    });
    let description = [" at 0x", " (entropy="]
        .iter()
        .fold(finding.description.as_str(), |d, marker| {
            d.split_once(marker).map_or(d, |(stable, _)| stable)
        })
        .to_owned();
    (format!("{:?}", finding.kind), location, description)
}

/// The findings of `current` (analysis of `version`) that warrant an alert
/// because `baseline` (analysis of `baseline_version`) did not have them, with
/// the event each calls for, in `current`'s order. With no baseline nothing is
/// new: a package's first analysis would otherwise alert on everything it has
/// always shipped.
pub fn new_notable_findings<'a>(
    baseline: Option<(&[fossdb::AnalysisFinding], &str)>,
    current: &'a [fossdb::AnalysisFinding],
    version: &str,
) -> Vec<(&'a fossdb::AnalysisFinding, EventType)> {
    let Some((baseline, baseline_version)) = baseline else {
        return Vec::new();
    };
    let before: std::collections::HashSet<_> = baseline
        .iter()
        .map(|f| finding_identity(f, baseline_version))
        .collect();
    current
        .iter()
        .filter_map(|f| new_finding_event(f).map(|event| (f, event)))
        .filter(|(f, _)| !before.contains(&finding_identity(f, version)))
        .collect()
}

/// Tell the subscribers of a package when a newly stored analysis found
/// something they should know about, in one event per analysis:
///
/// - a `ChecksumMismatch`, always, even on the package's first analysis: the
///   archive the registry served is not the one that was published, which
///   does not depend on history. A [`EventType::SecurityAlert`].
/// - a Critical `SecretDetected` the baseline did not have: a
///   [`EventType::SecurityAlert`].
/// - a Medium or worse `MaliciousPattern` or `SyscallReachable` the baseline
///   did not have: a [`EventType::BehaviorChange`], unless one of the above
///   makes the event a security alert.
///
/// The baseline is the one [`emit_install_hook_changes`] uses.
pub fn emit_finding_alerts(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    analysis: &fossdb::WorkerAnalysis,
) -> Result<()> {
    let mismatch = analysis
        .findings
        .iter()
        .find(|f| f.kind == fossdb::FindingKind::ChecksumMismatch);

    let analysed = db.get_analyses_by_package(analysis.package_id)?;
    let baseline = baseline_analysis(analysed, analysis.version_id);
    let version = version_name(db, analysis.version_id)?;
    let baseline_version = baseline
        .as_ref()
        .map(|b| version_name(db, b.version_id))
        .transpose()?;

    let new = new_notable_findings(
        baseline
            .as_ref()
            .zip(baseline_version.as_deref())
            .map(|(b, v)| (b.findings.as_slice(), v)),
        &analysis.findings,
        &version,
    );
    if mismatch.is_none() && new.is_empty() {
        return Ok(());
    }

    let Some(package) = db.get_package(analysis.package_id)? else {
        return Ok(());
    };

    let event_type = if mismatch.is_some()
        || new.iter().any(|(_, e)| *e == EventType::SecurityAlert)
    {
        EventType::SecurityAlert
    } else {
        EventType::BehaviorChange
    };

    tracing::info!(
        "{} {}: checksum mismatch: {}, {} new notable finding(s)",
        package.name,
        version,
        mismatch.is_some(),
        new.len()
    );
    let finding_json = |f: &fossdb::AnalysisFinding| {
        serde_json::json!({
            "kind": f.kind,
            "severity": f.severity,
            "description": f.description,
            "location": f.location,
        })
    };
    let metadata = serde_json::json!({
        "analysis_id": analysis.id,
        "baseline_analysis_id": baseline.as_ref().map(|b| b.id),
        "baseline_version": baseline_version,
        "checksum_mismatch": mismatch.map(finding_json),
        "findings": new.iter().map(|(f, _)| finding_json(f)).collect::<Vec<_>>(),
    });
    let new_findings: Vec<_> = new.iter().map(|(f, _)| *f).collect();
    notify_subscribers(
        db,
        broadcaster,
        fossdb::TimelineEvent {
            id: 0,
            package_id: package.id,
            user_id: None,
            event_type,
            message: finding_alert_message(
                &version,
                package.platform.as_deref(),
                mismatch,
                baseline_version.as_deref(),
                &new_findings,
            ),
            package_name: package.inner.name,
            version: Some(version),
            metadata: Some(metadata.to_string()),
            created_at: Utc::now(),
        },
    );
    Ok(())
}

/// E.g. `1.4.3: the downloaded archive does not match the checksum crates.io
/// published (Expected checksum 3f…, got 9a…). New since 1.4.2: AWS access
/// key in src/config.rs.`
fn finding_alert_message(
    version: &str,
    platform: Option<&str>,
    mismatch: Option<&fossdb::AnalysisFinding>,
    baseline: Option<&str>,
    new: &[&fossdb::AnalysisFinding],
) -> String {
    let mut message = format!("{version}:");
    if let Some(mismatch) = mismatch {
        let publisher = platform.map(|p| format!("{p} ")).unwrap_or_default();
        message.push_str(&format!(
            " the downloaded archive does not match the checksum {publisher}published ({}).",
            mismatch.description.trim_end_matches('.')
        ));
    }
    if let (Some(baseline), false) = (baseline, new.is_empty()) {
        let findings = new
            .iter()
            .map(|f| {
                let description = f.description.trim_end_matches('.');
                match (&f.kind, &f.location) {
                    (fossdb::FindingKind::SecretDetected, Some(location)) => {
                        format!("{description} in {location}")
                    }
                    _ => description.to_owned(),
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        message.push_str(&format!(" New since {baseline}: {findings}."));
    }
    message
}

/// E.g. `1.3.1 runs new install-time code compared with 1.3.0: added npm
/// postinstall: node setup.js.`
fn install_hook_message(version: &str, baseline: &str, changes: &[HookChange]) -> String {
    let hooks = changes
        .iter()
        .map(|c| {
            let change = match c.change {
                InstallHookChange::Added => "added",
                InstallHookChange::Changed => "changed",
            };
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
                HookChange { change: InstallHookChange::Changed, hook: &current[1] },
                HookChange { change: InstallHookChange::Added, hook: &current[3] },
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
                        yanked_at: None,
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
            emit_analysis_alerts(&self.db, &TimelineBroadcaster::new(), &saved.inner)
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

    fn finding(
        kind: FindingKind,
        severity: FindingSeverity,
        description: &str,
        location: &str,
    ) -> AnalysisFinding {
        AnalysisFinding {
            kind,
            severity,
            description: description.into(),
            location: Some(location.into()),
        }
    }

    fn mismatch() -> AnalysisFinding {
        finding(
            FindingKind::ChecksumMismatch,
            FindingSeverity::High,
            "Expected checksum 3f00, got 9a11",
            "https://example.invalid/left-pad-1.0.0.tgz",
        )
    }

    fn aws_key(version: &str) -> AnalysisFinding {
        finding(
            FindingKind::SecretDetected,
            FindingSeverity::Critical,
            "AWS access key",
            &format!("left-pad-{version}/src/config.js"),
        )
    }

    fn execve(address: u64) -> AnalysisFinding {
        finding(
            FindingKind::SyscallReachable,
            FindingSeverity::Medium,
            &format!("Reachable syscall execve (#59) at 0x{address:x} args=[0x0, 0x0, 0x0, 0x0, 0x0, 0x0]"),
            "left-pad",
        )
    }

    #[test]
    fn checksum_mismatch_alerts_even_on_the_first_analysis() {
        let f = fixture();

        f.analyse(0, vec![mismatch(), aws_key("1.0.0")]);

        let events = f.events();
        assert_eq!(events.len(), 1, "{events:?}");
        let event = &events[0];
        assert_eq!(event.event_type, EventType::SecurityAlert);
        assert_eq!(event.version.as_deref(), Some("1.0.0"));
        assert_eq!(
            event.message,
            "1.0.0: the downloaded archive does not match the checksum NPM published \
             (Expected checksum 3f00, got 9a11).",
            "no baseline, so the secret is not new"
        );
        let metadata: serde_json::Value =
            serde_json::from_str(event.metadata.as_deref().unwrap()).unwrap();
        assert_eq!(metadata["checksum_mismatch"]["kind"], "ChecksumMismatch");
        assert_eq!(metadata["baseline_version"], serde_json::Value::Null);
        assert_eq!(metadata["findings"], serde_json::json!([]));
    }

    /// The same secret and syscall in a new version's versioned directory, at
    /// a new address, are not new findings.
    #[test]
    fn findings_already_in_the_baseline_raise_nothing() {
        let f = fixture();
        f.analyse(0, vec![aws_key("1.0.0"), execve(0x401000)]);

        f.analyse(1, vec![aws_key("1.1.0"), execve(0x402a10)]);

        assert!(f.events().is_empty(), "{:?}", f.events());
    }

    #[test]
    fn new_binary_behaviour_is_a_behavior_change() {
        let f = fixture();
        f.analyse(0, Vec::new());

        f.analyse(1, vec![execve(0x401000)]);

        let events = f.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::BehaviorChange);
        assert_eq!(
            events[0].message,
            "1.1.0: New since 1.0.0: Reachable syscall execve (#59) at 0x401000 \
             args=[0x0, 0x0, 0x0, 0x0, 0x0, 0x0]."
        );
        let metadata: serde_json::Value =
            serde_json::from_str(events[0].metadata.as_deref().unwrap()).unwrap();
        assert_eq!(metadata["baseline_version"], "1.0.0");
        assert_eq!(metadata["checksum_mismatch"], serde_json::Value::Null);
        assert_eq!(metadata["findings"][0]["kind"], "SyscallReachable");
    }

    /// A new Critical secret makes the whole event a security alert, and the
    /// message lists every new finding.
    #[test]
    fn new_critical_secret_is_a_security_alert() {
        let f = fixture();
        f.analyse(0, Vec::new());

        f.analyse(1, vec![execve(0x401000), aws_key("1.1.0")]);

        let events = f.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::SecurityAlert);
        assert!(
            events[0]
                .message
                .ends_with("; AWS access key in left-pad-1.1.0/src/config.js."),
            "{}",
            events[0].message
        );
    }

    #[test]
    fn minor_findings_raise_nothing() {
        let f = fixture();
        f.analyse(0, Vec::new());

        f.analyse(
            1,
            vec![
                finding(FindingKind::SecretDetected, FindingSeverity::High, "Credentials in URL", "README.md"),
                finding(FindingKind::SecretDetected, FindingSeverity::Medium, "Hardcoded password", "test.py"),
                finding(FindingKind::MaliciousPattern, FindingSeverity::Low, "Potentially sensitive symbols: popen", "left-pad"),
                finding(FindingKind::SyscallReachable, FindingSeverity::Info, "Reachable syscalls (1): read(0)", "left-pad"),
                finding(FindingKind::LicenseDetected, FindingSeverity::Info, "License file detected: MIT", "LICENSE"),
            ],
        );

        assert!(f.events().is_empty(), "{:?}", f.events());
    }

    #[test]
    fn finding_identity_ignores_build_specific_details() {
        let entropy = |section: &str, e: &str| {
            finding(
                FindingKind::MaliciousPattern,
                FindingSeverity::Medium,
                &format!("High-entropy section '{section}' (entropy={e}), possible packing or encryption"),
                "left-pad",
            )
        };
        assert_eq!(
            finding_identity(&entropy(".data", "7.61"), "1.0.0"),
            finding_identity(&entropy(".data", "7.93"), "1.1.0"),
        );
        assert_ne!(
            finding_identity(&entropy(".data", "7.61"), "1.0.0"),
            finding_identity(&entropy(".rodata", "7.61"), "1.0.0"),
        );
        // npm tarballs unpack into an unversioned `package/`, which is kept.
        let npm = finding(FindingKind::SecretDetected, FindingSeverity::Critical, "AWS access key", "package/a.js");
        assert_eq!(finding_identity(&npm, "1.0.0").1.as_deref(), Some("package/a.js"));
        assert_eq!(finding_identity(&aws_key("1.0.0"), "1.0.0").1.as_deref(), Some("src/config.js"));
    }
}
