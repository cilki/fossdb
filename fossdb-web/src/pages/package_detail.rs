use crate::api::{types::*, ApiClient};
use fossdb::url::percent_encode;
use fossdb::typosquat::PackageLookalike;
use crate::hooks::{use_auth, use_notifications};
use dioxus::prelude::*;
use std::collections::HashMap;

/// One advisory as shown next to a version it affects.
#[derive(Debug, Clone, PartialEq)]
struct AdvisoryBadge {
    source_id: String,
    title: String,
    severity: VulnerabilitySeverity,
}

fn severity_rank(severity: &VulnerabilitySeverity) -> u8 {
    match severity {
        VulnerabilitySeverity::Low => 0,
        VulnerabilitySeverity::Medium => 1,
        VulnerabilitySeverity::High => 2,
        VulnerabilitySeverity::Critical => 3,
    }
}

fn severity_classes(severity: &VulnerabilitySeverity) -> &'static str {
    match severity {
        VulnerabilitySeverity::Low => "bg-gray-600 text-gray-200",
        VulnerabilitySeverity::Medium => "bg-yellow-900 text-yellow-300",
        VulnerabilitySeverity::High => "bg-orange-900 text-orange-300",
        VulnerabilitySeverity::Critical => "bg-red-900 text-red-300",
    }
}

/// The advisories affecting each version, keyed by version string, most
/// severe first (ties keep the server's newest-first order).
fn advisories_by_version(
    advisories: &[PackageVulnerability],
) -> HashMap<String, Vec<AdvisoryBadge>> {
    let mut by_version: HashMap<String, Vec<AdvisoryBadge>> = HashMap::new();
    for advisory in advisories {
        let v = &advisory.vulnerability;
        for version in &advisory.affected_versions {
            by_version
                .entry(version.clone())
                .or_default()
                .push(AdvisoryBadge {
                    source_id: v.source_id.clone(),
                    title: v.title.clone(),
                    severity: v.severity.clone(),
                });
        }
    }
    for badges in by_version.values_mut() {
        // Stable, so equal severities stay newest first.
        badges.sort_by_key(|b| std::cmp::Reverse(severity_rank(&b.severity)));
    }
    by_version
}

/// Where to read the full advisory. Ids from OSV (RustSec, GHSA, ...) have a
/// page on osv.dev; rows imported before advisory ingestion carry a
/// `fossdb-<id>` placeholder that names nothing outside FossDB.
fn advisory_url(source_id: &str) -> Option<String> {
    if source_id.is_empty() || source_id.starts_with("fossdb-") {
        return None;
    }
    Some(format!(
        "https://osv.dev/vulnerability/{}",
        percent_encode(source_id)
    ))
}

fn finding_severity_classes(severity: &FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "bg-gray-700 text-gray-300",
        FindingSeverity::Low => "bg-gray-600 text-gray-200",
        FindingSeverity::Medium => "bg-yellow-900 text-yellow-300",
        FindingSeverity::High => "bg-orange-900 text-orange-300",
        FindingSeverity::Critical => "bg-red-900 text-red-300",
    }
}

/// E.g. `New since 1.3.0`, for a hook that differs from the baseline.
fn hook_change_label(change: Option<InstallHookChange>, baseline: Option<&str>) -> Option<String> {
    let baseline = baseline?;
    match change? {
        InstallHookChange::Added => Some(format!("New since {baseline}")),
        InstallHookChange::Changed => Some(format!("Changed since {baseline}")),
    }
}

/// Tooltip for a yanked version's badge, e.g. `Yanked upstream (noticed
/// 2026-11-21)`, or `None` while the version is live. The date is when FossDB
/// saw the yank, not when the registry recorded it, so it says "noticed".
fn yanked_tooltip(version: &PackageVersion) -> Option<String> {
    version
        .yanked_at
        .map(|at| format!("Yanked upstream (noticed {})", at.format("%Y-%m-%d")))
}

/// E.g. `This name resembles colorama (one character different), which has
/// 5000 dependents.`
/// Targets always have several dependents (`MIN_TARGET_POPULARITY` on the
/// server), so the count is never singular.
fn lookalike_warning(lookalike: &PackageLookalike) -> String {
    format!(
        "This name resembles {} ({}), which has {} dependents.",
        lookalike.target_name,
        lookalike.reason.describe(),
        lookalike.target_dependents
    )
}

#[component]
pub fn PackageDetail(id: String) -> Element {
    let auth = use_auth();
    let mut package = use_signal(|| None::<Package>);
    let mut versions = use_signal(|| Vec::<PackageVersion>::new());
    let mut displayed_versions = use_signal(|| Vec::<PackageVersion>::new());
    let mut subscribers = use_signal(|| 0usize);
    let mut advisories = use_signal(|| Vec::<PackageVulnerability>::new());
    let mut install_hooks = use_signal(|| None::<PackageInstallHooks>);
    let mut lookalike = use_signal(|| None::<PackageLookalike>);
    let mut loading = use_signal(|| true);
    let mut is_subscribed = use_signal(|| false);
    let mut notifications_enabled = use_signal(|| false);
    let mut page_size = use_signal(|| 10);
    let mut current_page = use_signal(|| 0);

    let credential = auth.user_id();

    // Name of the loaded package. The subscription endpoints key on package
    // *name*, while the route parameter is a numeric id, so the name has to be
    // resolved from the fetched package before subscribing.
    let mut package_name = use_signal(String::new);

    // Load package data.
    //
    // `id` and `auth.user_id()` are read inside the closure so the effect is
    // subscribed to them and re-runs when the route parameter changes or the
    // user logs in/out. Previously both were captured as plain clones, so
    // navigating from /packages/1 to /packages/2 left the first package's data
    // on screen.
    use_effect(move || {
        let pkg_id = id.clone();
        let credential = auth.user_id();
        let is_authenticated = auth.is_authenticated();

        loading.set(true);
        spawn(async move {
            let client = ApiClient::new().with_user_id(credential.clone());

            let loaded = client.get_package(&pkg_id).await.ok();
            if let Some(pkg) = &loaded {
                package_name.set(pkg.name.clone());
            }
            package.set(loaded.clone());

            match client.get_package_versions(&pkg_id).await {
                Ok(vers) => {
                    let end = (page_size() as usize).min(vers.len());
                    displayed_versions.set(vers[0..end].to_vec());
                    versions.set(vers);
                }
                Err(_) => {
                    versions.set(Vec::new());
                    displayed_versions.set(Vec::new());
                }
            }
            current_page.set(0);

            // Advisories are supplementary: if the request fails, the page
            // still renders, just without badges.
            advisories.set(
                client
                    .get_package_vulnerabilities(&pkg_id)
                    .await
                    .unwrap_or_default(),
            );

            // Likewise: without an analysis the section is simply not shown.
            install_hooks.set(
                client
                    .get_package_install_hooks(&pkg_id)
                    .await
                    .ok()
                    .flatten(),
            );

            // Likewise: no banner if the check fails.
            lookalike.set(
                client
                    .get_package_lookalike(&pkg_id)
                    .await
                    .ok()
                    .flatten(),
            );

            subscribers.set(client.get_package_subscribers(&pkg_id).await.unwrap_or(0));

            // Check if user is subscribed. Compare against the package we just
            // loaded rather than re-reading the `package` signal, which may not
            // have been observed yet.
            let mut subscribed = false;
            let mut notifications = false;
            if is_authenticated {
                if let (Ok(subs), Some(pkg)) = (client.get_subscriptions().await, &loaded) {
                    if let Some(sub) = subs.iter().find(|s| s.package_name == pkg.name) {
                        subscribed = true;
                        notifications = sub.notifications_enabled;
                    }
                }
            }
            is_subscribed.set(subscribed);
            notifications_enabled.set(notifications);

            loading.set(false);
        });
    });

    let mut update_pagination = move || {
        let page = current_page();
        let size = page_size();
        let all_vers = versions();
        let start = (page * size) as usize;
        let end = ((page + 1) * size) as usize;
        let end = end.min(all_vers.len());

        if start < all_vers.len() {
            displayed_versions.set(all_vers[start..end].to_vec());
        }
    };

    let mut change_page_size = move |new_size: i32| {
        page_size.set(new_size);
        current_page.set(0);
        update_pagination();
    };

    let next_page = move |_| {
        let total_pages = (versions().len() as f32 / page_size() as f32).ceil() as i32;
        if current_page() < total_pages - 1 {
            current_page.set(current_page() + 1);
            update_pagination();
        }
    };

    let prev_page = move |_| {
        if current_page() > 0 {
            current_page.set(current_page() - 1);
            update_pagination();
        }
    };

    let notif = use_notifications();

    let credential_for_subscribe = credential.clone();

    let handle_subscribe = move |_| {
        let mut notif_copy = notif;
        let credential = credential_for_subscribe.clone();
        // Subscription endpoints key on package name, not the numeric route id.
        let pkg_name = package_name();

        spawn(async move {
            if pkg_name.is_empty() {
                notif_copy.error("Package is still loading".to_string());
                return;
            }

            let client = ApiClient::new().with_user_id(credential);

            if is_subscribed() {
                match client.unsubscribe(&pkg_name).await {
                    Ok(_) => {
                        is_subscribed.set(false);
                        notifications_enabled.set(false);
                        notif_copy.success("Unsubscribed successfully".to_string());
                        subscribers.set(subscribers().saturating_sub(1));
                    }
                    Err(e) => notif_copy.error(format!("Failed to unsubscribe: {:?}", e)),
                }
            } else {
                match client.subscribe(pkg_name.clone()).await {
                    Ok(_) => {
                        is_subscribed.set(true);
                        notifications_enabled.set(true);
                        notif_copy.success("Subscribed successfully".to_string());
                        subscribers.set(subscribers() + 1);
                    }
                    Err(e) => notif_copy.error(format!("Failed to subscribe: {:?}", e)),
                }
            }
        });
    };

    let credential_for_toggle = credential.clone();

    let toggle_notifications = move |_| {
        let mut notif_copy = notif;
        let credential = credential_for_toggle.clone();
        let pkg_name = package_name();

        spawn(async move {
            if pkg_name.is_empty() {
                notif_copy.error("Package is still loading".to_string());
                return;
            }

            let client = ApiClient::new().with_user_id(credential);
            let new_state = !notifications_enabled();

            match client.toggle_notifications(&pkg_name, new_state).await {
                Ok(_) => {
                    notifications_enabled.set(new_state);
                    let msg = if new_state {
                        "Notifications enabled"
                    } else {
                        "Notifications disabled"
                    };
                    notif_copy.success(msg.to_string());
                }
                Err(e) => notif_copy.error(format!(
                    "Failed to update notification settings: {:?}",
                    e
                )),
            }
        });
    };

    let total_pages = (versions().len() as f32 / page_size() as f32).ceil() as i32;
    let badges = advisories_by_version(&advisories());

    rsx! {
        main { class: "min-h-screen bg-gray-900 py-12",
            div { class: "container mx-auto px-6",
                div { class: "max-w-5xl mx-auto",
                    // Back Button
                    div { class: "mb-6",
                        Link {
                            to: crate::Route::Packages {},
                            class: "flex items-center space-x-2 text-gray-400 hover:text-blue-400 transition-colors",
                            svg { class: "w-5 h-5", fill: "none", stroke: "currentColor", view_box: "0 0 24 24",
                                path { stroke_linecap: "round", stroke_linejoin: "round", stroke_width: "2", d: "M15 19l-7-7 7-7" }
                            }
                            span { "Back to Packages" }
                        }
                    }

                    if loading() {
                        div { class: "flex justify-center py-12",
                            div { class: "animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" }
                        }
                    } else if let Some(pkg) = package() {
                        // Package Header
                        div { class: "bg-gray-800 rounded-2xl shadow-xl p-8 mb-6 border border-gray-700",
                            div { class: "flex justify-between items-start mb-4",
                                h1 { class: "text-4xl font-bold text-gray-100", "{pkg.name}" }
                                if let Some(license) = &pkg.license {
                                    span { class: "px-4 py-2 bg-blue-900 text-blue-300 rounded-full text-sm font-medium",
                                        "{license}"
                                    }
                                }
                            }

                            if let Some(description) = &pkg.description {
                                p { class: "text-gray-300 text-lg mb-6", "{description}" }
                            }

                            div { class: "flex flex-wrap gap-4",
                                if let Some(homepage) = pkg.homepage.as_deref().and_then(crate::util::safe_external_url) {
                                    a {
                                        href: "{homepage}",
                                        target: "_blank",
                                        rel: "noopener noreferrer",
                                        class: "px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors",
                                        "Homepage"
                                    }
                                }
                                if let Some(repository) = pkg.repository.as_deref().and_then(crate::util::safe_external_url) {
                                    a {
                                        href: "{repository}",
                                        target: "_blank",
                                        rel: "noopener noreferrer",
                                        class: "px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors",
                                        "Repository"
                                    }
                                }
                            }
                        }

                        if let Some(lookalike) = lookalike() {
                            div { class: "bg-gray-800 rounded-2xl shadow-xl p-6 mb-6 border border-yellow-700",
                                div { class: "flex flex-wrap items-center gap-2 mb-2",
                                    span {
                                        class: "px-2 py-0.5 rounded text-xs font-medium {finding_severity_classes(&lookalike.severity)}",
                                        "{lookalike.severity:?}"
                                    }
                                    h3 { class: "text-lg font-bold text-yellow-300", "Possible lookalike name" }
                                }
                                p { class: "text-gray-300", "{lookalike_warning(&lookalike)}" }
                                p { class: "text-sm text-gray-400 mt-2",
                                    "If you meant "
                                    Link {
                                        to: crate::Route::PackageDetail { id: lookalike.target_id.to_string() },
                                        class: "font-mono text-blue-400 hover:text-blue-300",
                                        "{lookalike.target_name}"
                                    }
                                    ", check your manifests before installing this package."
                                }
                            }
                        }

                        // Package Details Grid
                        div { class: "grid grid-cols-1 lg:grid-cols-3 gap-6",
                            // Main Content - Versions with Pagination
                            div { class: "lg:col-span-2",
                                div { class: "bg-gray-800 rounded-2xl shadow-xl p-8 border border-gray-700",
                                    div { class: "flex justify-between items-center mb-6",
                                        h2 { class: "text-2xl font-bold text-gray-100", "Versions" }

                                        // Page size selector
                                        div { class: "flex items-center space-x-2",
                                            span { class: "text-sm text-gray-400", "Show:" }
                                            select {
                                                class: "p-2 bg-gray-700 border border-gray-600 rounded text-gray-100 text-sm",
                                                value: "{page_size()}",
                                                onchange: move |evt| {
                                                    if let Ok(size) = evt.value().parse::<i32>() {
                                                        change_page_size(size);
                                                    }
                                                },
                                                option { value: "5", "5" }
                                                option { value: "10", "10" }
                                                option { value: "25", "25" }
                                                option { value: "50", "50" }
                                                option { value: "100", "All" }
                                            }
                                        }
                                    }

                                    div { class: "space-y-2",
                                        for version in displayed_versions().iter() {
                                            div { key: "{version.id}", class: "flex justify-between items-center p-4 bg-gray-700 rounded-lg",
                                                div {
                                                    div { class: "flex items-center gap-2",
                                                        span {
                                                            class: if version.yanked_at.is_some() {
                                                                "font-semibold text-gray-400 line-through"
                                                            } else {
                                                                "font-semibold text-gray-100"
                                                            },
                                                            "{version.version}"
                                                        }
                                                        if let Some(tooltip) = yanked_tooltip(version) {
                                                            span {
                                                                class: "px-2 py-0.5 rounded text-xs font-medium bg-red-900 text-red-300",
                                                                title: "{tooltip}",
                                                                "Yanked"
                                                            }
                                                        }
                                                    }
                                                    div { class: "text-sm text-gray-400",
                                                        "Released: {version.release_date.format(\"%Y-%m-%d\")}"
                                                    }
                                                }
                                                if let Some(affecting) = badges.get(&version.version) {
                                                    div { class: "flex flex-wrap justify-end gap-2 ml-4",
                                                        for badge in affecting.iter() {
                                                            span {
                                                                key: "{badge.source_id}",
                                                                class: "px-2 py-1 rounded text-xs font-mono font-medium {severity_classes(&badge.severity)}",
                                                                title: "{badge.severity:?}: {badge.title}",
                                                                "{badge.source_id}"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if displayed_versions().is_empty() {
                                            div { class: "text-center py-8 text-gray-400",
                                                "No versions available"
                                            }
                                        }
                                    }

                                    // Pagination controls
                                    if total_pages > 1 {
                                        div { class: "flex justify-between items-center mt-6 pt-4 border-t border-gray-700",
                                            button {
                                                class: "px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded disabled:opacity-50 disabled:cursor-not-allowed",
                                                disabled: current_page() == 0,
                                                onclick: prev_page,
                                                "Previous"
                                            }

                                            span { class: "text-gray-400",
                                                "Page {current_page() + 1} of {total_pages}"
                                            }

                                            button {
                                                class: "px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded disabled:opacity-50 disabled:cursor-not-allowed",
                                                disabled: current_page() >= total_pages - 1,
                                                onclick: next_page,
                                                "Next"
                                            }
                                        }
                                    }
                                }

                                if !advisories().is_empty() {
                                    div { class: "bg-gray-800 rounded-2xl shadow-xl p-8 mt-6 border border-red-900",
                                        h2 { class: "text-2xl font-bold text-gray-100 mb-6",
                                            "Security Advisories ({advisories().len()})"
                                        }
                                        div { class: "space-y-4",
                                            for advisory in advisories().iter() {
                                                div {
                                                    key: "{advisory.vulnerability.id}",
                                                    class: "p-4 bg-gray-700 rounded-lg",
                                                    div { class: "flex flex-wrap items-center gap-2 mb-2",
                                                        span {
                                                            class: "px-2 py-1 rounded text-xs font-medium {severity_classes(&advisory.vulnerability.severity)}",
                                                            "{advisory.vulnerability.severity:?}"
                                                        }
                                                        if let Some(url) = advisory_url(&advisory.vulnerability.source_id) {
                                                            a {
                                                                href: "{url}",
                                                                target: "_blank",
                                                                rel: "noopener noreferrer",
                                                                class: "font-mono text-sm text-blue-400 hover:text-blue-300",
                                                                "{advisory.vulnerability.source_id}"
                                                            }
                                                        } else {
                                                            span { class: "font-mono text-sm text-gray-300",
                                                                "{advisory.vulnerability.source_id}"
                                                            }
                                                        }
                                                        if let Some(cve) = &advisory.vulnerability.cve_id {
                                                            span { class: "font-mono text-sm text-gray-400", "{cve}" }
                                                        }
                                                    }
                                                    div { class: "font-semibold text-gray-100", "{advisory.vulnerability.title}" }
                                                    div { class: "text-sm text-gray-400 mt-1",
                                                        if !advisory.version_range.is_empty() {
                                                            span { "Affected: {advisory.version_range}" }
                                                        }
                                                        if let Some(fixed) = &advisory.vulnerability.fixed_in {
                                                            span { class: "ml-3", "Fixed in {fixed}" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Sidebar
                            div { class: "space-y-6",
                                // Subscriber Count
                                div { class: "bg-gray-800 rounded-2xl shadow-xl p-6 border border-gray-700",
                                    h3 { class: "text-lg font-bold text-gray-100 mb-4", "Subscribers" }
                                    div { class: "text-center",
                                        div { class: "text-4xl font-bold text-blue-400", "{subscribers()}" }
                                    }
                                }

                                // Subscribe/Notification Actions
                                if auth.is_authenticated() {
                                    div { class: "bg-gray-800 rounded-2xl shadow-xl p-6 border border-gray-700",
                                        h3 { class: "text-lg font-bold text-gray-100 mb-4", "Actions" }
                                        div { class: "space-y-3",
                                            button {
                                                class: if is_subscribed() {
                                                    "w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
                                                } else {
                                                    "w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                                                },
                                                onclick: handle_subscribe,
                                                if is_subscribed() { "Unsubscribe" } else { "Subscribe" }
                                            }

                                            if is_subscribed() {
                                                button {
                                                    class: "w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors",
                                                    onclick: toggle_notifications,
                                                    if notifications_enabled() {
                                                        "Disable Notifications"
                                                    } else {
                                                        "Enable Notifications"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Some(analysis) = install_hooks() {
                                    div { class: "bg-gray-800 rounded-2xl shadow-xl p-6 border border-gray-700",
                                        h3 { class: "text-lg font-bold text-gray-100 mb-1", "Install hooks" }
                                        div { class: "text-xs text-gray-400 mb-4",
                                            "Code that runs when {analysis.version} is installed or built"
                                        }
                                        if analysis.hooks.is_empty() {
                                            div { class: "text-sm text-gray-400", "None found" }
                                        }
                                        div { class: "space-y-3",
                                            for hook in analysis.hooks.iter() {
                                                div {
                                                    key: "{hook.location.as_deref().unwrap_or_default()}",
                                                    class: "text-sm",
                                                    div { class: "flex flex-wrap items-center gap-2 mb-1",
                                                        span {
                                                            class: "px-2 py-0.5 rounded text-xs font-medium {finding_severity_classes(&hook.severity)}",
                                                            "{hook.severity:?}"
                                                        }
                                                        if let Some(label) = hook_change_label(hook.change, analysis.baseline_version.as_deref()) {
                                                            span { class: "px-2 py-0.5 rounded text-xs font-medium bg-purple-900 text-purple-300",
                                                                "{label}"
                                                            }
                                                        }
                                                    }
                                                    if let Some(location) = &hook.location {
                                                        div { class: "font-mono text-xs text-gray-300 break-all", "{location}" }
                                                    }
                                                    div { class: "text-gray-400 break-words", "{hook.description}" }
                                                }
                                            }
                                        }
                                    }
                                }

                                // Package Info
                                div { class: "bg-gray-800 rounded-2xl shadow-xl p-6 border border-gray-700",
                                    h3 { class: "text-lg font-bold text-gray-100 mb-4", "Information" }
                                    div { class: "space-y-3 text-sm",
                                        if let Some(language) = &pkg.language {
                                            div {
                                                div { class: "text-gray-400", "Language" }
                                                div { class: "text-gray-100 font-medium", "{language}" }
                                            }
                                        }
                                        if let Some(platform) = &pkg.platform {
                                            div {
                                                div { class: "text-gray-400", "Platform" }
                                                div { class: "text-gray-100 font-medium", "{platform}" }
                                            }
                                        }
                                        div {
                                            div { class: "text-gray-400", "Created" }
                                            div { class: "text-gray-100 font-medium", "{pkg.created_at.format(\"%Y-%m-%d\")}" }
                                        }
                                        div {
                                            div { class: "text-gray-400", "Updated" }
                                            div { class: "text-gray-100 font-medium", "{pkg.updated_at.format(\"%Y-%m-%d\")}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn advisory(
        source_id: &str,
        severity: VulnerabilitySeverity,
        versions: &[&str],
    ) -> PackageVulnerability {
        PackageVulnerability {
            vulnerability: Vulnerability {
                id: 1,
                source_id: source_id.into(),
                cve_id: None,
                title: format!("{source_id} title"),
                description: String::new(),
                severity,
                affected_packages: Vec::new(),
                discovered_at: Utc::now(),
                fixed_in: None,
            },
            version_range: String::new(),
            affected_versions: versions.iter().map(|v| v.to_string()).collect(),
        }
    }

    fn ids(badges: &[AdvisoryBadge]) -> Vec<&str> {
        badges.iter().map(|b| b.source_id.as_str()).collect()
    }

    #[test]
    fn badges_are_grouped_by_version_most_severe_first() {
        // Newest first, as the server returns them.
        let advisories = [
            advisory("RUSTSEC-2024-0003", VulnerabilitySeverity::Low, &["1.0.0"]),
            advisory("RUSTSEC-2024-0002", VulnerabilitySeverity::Critical, &["1.0.0", "1.1.0"]),
            advisory("RUSTSEC-2024-0001", VulnerabilitySeverity::Low, &["1.0.0"]),
        ];

        let by_version = advisories_by_version(&advisories);

        assert_eq!(
            ids(&by_version["1.0.0"]),
            vec!["RUSTSEC-2024-0002", "RUSTSEC-2024-0003", "RUSTSEC-2024-0001"]
        );
        assert_eq!(ids(&by_version["1.1.0"]), vec!["RUSTSEC-2024-0002"]);
        assert_eq!(by_version["1.1.0"][0].title, "RUSTSEC-2024-0002 title");
        assert!(!by_version.contains_key("1.2.0"));
    }

    #[test]
    fn only_published_ids_link_to_osv() {
        assert_eq!(
            advisory_url("RUSTSEC-2016-0001").as_deref(),
            Some("https://osv.dev/vulnerability/RUSTSEC-2016-0001")
        );
        assert_eq!(
            advisory_url("GHSA-34p9-f4q3-c4r7").as_deref(),
            Some("https://osv.dev/vulnerability/GHSA-34p9-f4q3-c4r7")
        );
        // Ids are encoded rather than trusted as a path segment.
        assert_eq!(
            advisory_url("a/../b?c").as_deref(),
            Some("https://osv.dev/vulnerability/a%2F..%2Fb%3Fc")
        );
        assert_eq!(advisory_url("fossdb-7"), None);
        assert_eq!(advisory_url(""), None);
    }

    #[test]
    fn hook_changes_name_the_baseline() {
        assert_eq!(
            hook_change_label(Some(InstallHookChange::Added), Some("1.3.0")).as_deref(),
            Some("New since 1.3.0")
        );
        assert_eq!(
            hook_change_label(Some(InstallHookChange::Changed), Some("1.3.0")).as_deref(),
            Some("Changed since 1.3.0")
        );
        assert_eq!(hook_change_label(None, Some("1.3.0")), None);
        // A first analysis has nothing to be new relative to.
        assert_eq!(hook_change_label(Some(InstallHookChange::Added), None), None);
    }

    #[test]
    fn only_yanked_versions_get_a_yanked_tooltip() {
        use chrono::TimeZone;
        let mut version = PackageVersion {
            id: 1,
            package_id: 1,
            version: "1.0.1".into(),
            release_date: Utc::now(),
            download_url: None,
            checksum: None,
            dependencies: Vec::new(),
            vulnerabilities: Vec::new(),
            changelog: None,
            created_at: Utc::now(),
            yanked_at: None,
        };
        assert_eq!(yanked_tooltip(&version), None);

        version.yanked_at = Some(Utc.with_ymd_and_hms(2026, 11, 21, 9, 30, 0).unwrap());
        assert_eq!(
            yanked_tooltip(&version).as_deref(),
            Some("Yanked upstream (noticed 2026-11-21)")
        );
    }

    #[test]
    fn lookalike_warning_names_the_target_and_reason() {
        let lookalike = PackageLookalike {
            target_id: 7,
            target_name: "colorama".into(),
            target_dependents: 5000,
            reason: fossdb::typosquat::SquatReason::Edit1,
            severity: FindingSeverity::Medium,
        };
        assert_eq!(
            lookalike_warning(&lookalike),
            "This name resembles colorama (one character different), which has 5000 dependents."
        );
    }
}
