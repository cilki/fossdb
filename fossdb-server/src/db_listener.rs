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

/// Alert the subscribers of `lookalike.target` that `package`, which has just
/// arrived, imitates its name.
///
/// The event is filed under the imitated package, not the new one: its
/// subscribers depend on it, so they are the ones who might mistype it in a
/// manifest, and nobody is subscribed to a package that did not exist a
/// moment ago.
pub fn emit_lookalike_alert(
    db: &Database,
    broadcaster: &TimelineBroadcaster,
    package: &fossdb::Package,
    lookalike: &crate::lookalike::Lookalike,
) {
    let target = &lookalike.target;
    tracing::info!(
        "New package {} resembles {} ({:?})",
        package.name,
        target.name,
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
        "severity": lookalike.reason.severity(),
    });
    notify_subscribers(
        db,
        broadcaster,
        fossdb::TimelineEvent {
            id: 0,
            package_id: target.id,
            user_id: None,
            event_type: EventType::SecurityAlert,
            package_name: target.name.clone(),
            version: None,
            message: format!(
                "New {ecosystem}package {} closely resembles {} ({}). Check your manifests.",
                package.name,
                target.name,
                lookalike.reason.describe()
            ),
            metadata: Some(metadata.to_string()),
            created_at: Utc::now(),
        },
    );
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
    use fossdb::VulnerabilitySeverity;

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
}
