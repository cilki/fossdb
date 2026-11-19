use anyhow::{Context, Result};
use async_trait::async_trait;
use fossdb::{CollectedPackage, CollectedVersion};
use serde::Deserialize;
use std::sync::Arc;
use tokio::process::Command;

use crate::client::{CollectorClient, aborts_run};
use crate::collectors::{Collector, helpers};

#[derive(Debug, Deserialize)]
struct NixSearchResult {
    #[serde(flatten)]
    packages: std::collections::HashMap<String, NixPackageInfo>,
}

#[derive(Debug, Deserialize)]
struct NixPackageInfo {
    pname: Option<String>,
    version: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NixPackageMeta {
    version: Option<String>,
    meta: NixMetaInfo,
}

#[derive(Debug, Deserialize)]
struct NixMetaInfo {
    description: Option<String>,
    homepage: Option<String>,
    license: Option<NixLicense>,
    changelog: Option<String>,
}

/// `meta.license` in nixpkgs may be an attrset, a bare string, or a list of
/// either.
///
/// The previous definition accepted only an attrset or a list of attrsets, so a
/// package declaring `meta.license = "GPL";` failed to deserialize - and because
/// the failure propagated out of `serde_json::from_str`, the *entire*
/// `NixPackageMeta` was discarded, losing description, homepage and version too.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NixLicense {
    Name(String),
    Single(NixLicenseInfo),
    Multiple(Vec<NixLicense>),
}

#[derive(Debug, Deserialize)]
struct NixLicenseInfo {
    #[serde(rename = "shortName")]
    short_name: Option<String>,
    #[serde(rename = "fullName")]
    full_name: Option<String>,
    #[serde(rename = "spdxId")]
    spdx_id: Option<String>,
}

impl NixLicenseInfo {
    fn id(&self) -> Option<String> {
        self.spdx_id
            .clone()
            .or_else(|| self.short_name.clone())
            .or_else(|| self.full_name.clone())
    }
}

impl NixLicense {
    /// Flatten into license identifiers, in declaration order.
    fn ids(&self) -> Vec<String> {
        match self {
            NixLicense::Name(name) => vec![name.clone()],
            NixLicense::Single(info) => info.id().into_iter().collect(),
            NixLicense::Multiple(licenses) => {
                licenses.iter().flat_map(|l| l.ids()).collect()
            }
        }
    }

    /// Combined SPDX-style expression, or `None` if nothing usable was found.
    fn expression(&self) -> Option<String> {
        let ids = self.ids();
        if ids.is_empty() {
            None
        } else {
            Some(ids.join(" OR "))
        }
    }
}

/// Escape a string for inclusion in a Nix double-quoted string literal.
fn escape_nix_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '$' => out.push_str("\\$"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Strip the `legacyPackages.<system>.` / `packages.<system>.` prefix that
/// `nix search` prepends.
///
/// The system component is matched generically instead of hardcoding
/// `x86_64-linux`: on any other host (aarch64 CI, Apple silicon, Graviton) the
/// hardcoded strip failed, leaving `legacyPackages.aarch64-linux.hello` to be
/// interpolated into the Nix expression, where `legacyPackages` is not in scope.
/// Every package then failed to evaluate and the collector submitted nothing.
fn strip_system_prefix(attr_path: &str) -> &str {
    for prefix in ["legacyPackages.", "packages."] {
        if let Some(rest) = attr_path.strip_prefix(prefix) {
            return match rest.split_once('.') {
                Some((_system, attr)) => attr,
                None => rest,
            };
        }
    }
    attr_path
}

/// Build a Nix list literal of attribute-path components.
///
/// Using `lib.getAttrFromPath` with quoted components means attribute names
/// that are not bare Nix identifiers (`nodePackages."@angular/cli"`,
/// `python3Packages."zope.interface"`) evaluate correctly instead of producing
/// a syntax error. It also removes the Nix-expression injection sink that raw
/// interpolation created.
fn attr_path_list(attr: &str) -> String {
    let components: Vec<String> = attr
        .split('.')
        .filter(|c| !c.is_empty())
        .map(|c| format!("\"{}\"", escape_nix_string(c)))
        .collect();
    format!("[ {} ]", components.join(" "))
}

pub struct NixpkgsCollector {}

impl NixpkgsCollector {
    async fn run_nix_command(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("nix")
            .args(args)
            .output()
            .await
            .context("Failed to execute nix command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nix command failed: {}", stderr);
        }

        Ok(String::from_utf8(output.stdout)?)
    }

    async fn search_packages(&self) -> Result<Vec<(String, NixPackageInfo)>> {
        tracing::info!("Searching nixpkgs for packages...");
        let output = self.run_nix_command(&["search", "nixpkgs", "^", "--json"]).await?;
        let search_result: NixSearchResult =
            serde_json::from_str(&output).context("Failed to parse nix search output")?;
        let mut packages: Vec<(String, NixPackageInfo)> =
            search_result.packages.into_iter().collect();
        packages.sort_by(|a, b| a.0.cmp(&b.0));
        tracing::info!("Found {} packages from nixpkgs", packages.len());
        Ok(packages)
    }

    async fn get_package_details(&self, attr_path: &str) -> Result<NixPackageMeta> {
        let expr = format!(
            r#"let
                 pkgs = import <nixpkgs> {{}};
                 pkg = pkgs.lib.getAttrFromPath {} pkgs;
               in {{
                 name = pkg.pname or pkg.name;
                 version = pkg.version or null;
                 meta = pkg.meta or {{}};
               }}"#,
            attr_path_list(strip_system_prefix(attr_path))
        );
        let output = self.run_nix_command(&["eval", "--impure", "--expr", &expr, "--json"]).await?;
        let package_meta: NixPackageMeta =
            serde_json::from_str(&output).context("Failed to parse package details")?;
        Ok(package_meta)
    }
}

#[async_trait]
impl Collector for NixpkgsCollector {
    fn name(&self) -> &str {
        "nixpkgs"
    }

    async fn collect(&self, client: Arc<CollectorClient>) -> Result<()> {
        use chrono::Utc;

        tracing::info!("Starting nixpkgs collection...");

        let mut packages_processed = 0;
        let max_packages = if cfg!(debug_assertions) { 5 } else { usize::MAX };

        let packages = self.search_packages().await?;

        for (attr_path, search_info) in packages {
            let package_name = search_info.pname.clone().unwrap_or_else(|| {
                attr_path.rsplit('.').next().unwrap_or(&attr_path).to_string()
            });

            // One transient lookup failure must not abort the whole run and
            // stall every remaining package for a full interval.
            let existing = match client.get_package(&package_name).await {
                Ok(existing) => existing,
                Err(e) if aborts_run(&e) => return Err(e),
                Err(e) => {
                    tracing::warn!("Lookup failed for {}: {:#}", package_name, e);
                    continue;
                }
            };

            let package_meta = match self.get_package_details(&attr_path).await {
                Ok(meta) => Some(meta),
                Err(e) => {
                    tracing::warn!("Failed to fetch details for {}: {:#}", package_name, e);
                    None
                }
            };

            let version_string = package_meta
                .as_ref()
                .and_then(|m| m.version.clone())
                .or_else(|| search_info.version.clone());

            // Unlike the previous code, an already-known package is not skipped
            // outright: nixpkgs version bumps were therefore never collected, so
            // after first discovery a package's releases became invisible
            // forever and no timeline event or notification ever fired again.
            if let Some(lookup) = &existing {
                let Some(ref version) = version_string else {
                    tracing::debug!("No version for existing package {}, skipping", package_name);
                    packages_processed += 1;
                    continue;
                };

                if lookup.version_strings.iter().any(|v| v == version) {
                    tracing::debug!(
                        "Package {} already has version {}, skipping",
                        package_name,
                        version
                    );
                    packages_processed += 1;
                    continue;
                }

                let pkg = CollectedPackage {
                    name: package_name.clone(),
                    description: None,
                    homepage: None,
                    repository: None,
                    license: None,
                    tags: Vec::new(),
                    versions: vec![CollectedVersion {
                        version: version.clone(),
                        // nixpkgs exposes no release date; this records when the
                        // version was first observed.
                        release_date: Utc::now(),
                        download_url: None,
                        checksum: None,
                        dependencies: Vec::new(),
                        changelog: package_meta
                            .as_ref()
                            .and_then(|m| m.meta.changelog.clone()),
                    }],
                    platform: None,
                    language: None,
                    status: None,
                    dependents_count: None,
                    rank: None,
                };

                match client.submit_package(pkg).await {
                    Ok(_) => tracing::info!(
                        "Submitted new version {} for {}",
                        version,
                        package_name
                    ),
                    Err(e) if aborts_run(&e) => return Err(e),
                    Err(e) => {
                        tracing::error!("Failed to submit version for {}: {:#}", package_name, e)
                    }
                }

                packages_processed += 1;
                if packages_processed >= max_packages {
                    break;
                }
                continue;
            }

            let license = package_meta
                .as_ref()
                .and_then(|m| m.meta.license.as_ref())
                .and_then(|lic| lic.expression());

            let Some(license) = license else {
                tracing::info!("Skipping {} with no license information", package_name);
                packages_processed += 1;
                continue;
            };

            if !helpers::is_free_license(&license) {
                tracing::info!(
                    "Skipping {} with non-free license: {}",
                    package_name,
                    license
                );
                packages_processed += 1;
                continue;
            }

            let description = package_meta
                .as_ref()
                .and_then(|m| m.meta.description.clone())
                .or_else(|| search_info.description.clone());
            let homepage = package_meta.as_ref().and_then(|m| m.meta.homepage.clone());

            let versions = if let Some(ver) = version_string {
                vec![CollectedVersion {
                    version: ver,
                    // See above: first-observed time, not a real release date.
                    release_date: Utc::now(),
                    download_url: None,
                    checksum: None,
                    dependencies: Vec::new(),
                    changelog: package_meta.as_ref().and_then(|m| m.meta.changelog.clone()),
                }]
            } else {
                Vec::new()
            };

            let pkg = CollectedPackage {
                name: package_name.clone(),
                description,
                homepage,
                repository: None,
                license: Some(license),
                tags: vec!["nix".to_string(), "nixpkgs".to_string()],
                versions,
                platform: Some("nixpkgs".to_string()),
                language: None,
                status: None,
                dependents_count: None,
                rank: None,
            };

            match client.submit_package(pkg).await {
                Ok(_) => tracing::info!("Submitted package: {}", package_name),
                Err(e) if aborts_run(&e) => return Err(e),
                Err(e) => tracing::error!("Failed to submit {}: {:#}", package_name, e),
            }

            packages_processed += 1;
            if packages_processed >= max_packages {
                if cfg!(debug_assertions) {
                    tracing::info!("Debug mode: reached limit of {} packages", max_packages);
                }
                break;
            }
        }

        tracing::info!("Nixpkgs collection completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The system component must be stripped on any host architecture, not just
    /// x86_64-linux.
    #[test]
    fn strips_prefix_for_any_system() {
        assert_eq!(
            strip_system_prefix("legacyPackages.x86_64-linux.hello"),
            "hello"
        );
        assert_eq!(
            strip_system_prefix("legacyPackages.aarch64-linux.hello"),
            "hello"
        );
        assert_eq!(
            strip_system_prefix("legacyPackages.aarch64-darwin.nodePackages.typescript"),
            "nodePackages.typescript"
        );
        assert_eq!(strip_system_prefix("packages.riscv64-linux.hello"), "hello");
        assert_eq!(strip_system_prefix("hello"), "hello");
    }

    #[test]
    fn builds_quoted_attr_path_lists() {
        assert_eq!(attr_path_list("hello"), r#"[ "hello" ]"#);
        assert_eq!(
            attr_path_list("nodePackages.typescript"),
            r#"[ "nodePackages" "typescript" ]"#
        );
        // Names that are not bare identifiers must still be valid Nix.
        assert_eq!(
            attr_path_list("nodePackages.@angular/cli"),
            r#"[ "nodePackages" "@angular/cli" ]"#
        );
    }

    #[test]
    fn escapes_nix_string_metacharacters() {
        assert_eq!(escape_nix_string(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_nix_string(r"a\b"), r"a\\b");
        assert_eq!(escape_nix_string("${evil}"), "\\${evil}");
    }

    /// nixpkgs allows `meta.license` to be a bare string; this used to discard
    /// the whole package record.
    #[test]
    fn accepts_string_license() {
        let meta: NixPackageMeta = serde_json::from_str(
            r#"{"version":"1.0","meta":{"description":"d","homepage":null,"license":"GPL","changelog":null}}"#,
        )
        .unwrap();
        assert_eq!(
            meta.meta.license.as_ref().unwrap().expression().as_deref(),
            Some("GPL")
        );
        assert_eq!(meta.meta.description.as_deref(), Some("d"));
    }

    #[test]
    fn accepts_attrset_license() {
        let meta: NixPackageMeta = serde_json::from_str(
            r#"{"version":"1.0","meta":{"description":null,"homepage":null,"license":{"spdxId":"MIT","shortName":"mit","fullName":"MIT License"},"changelog":null}}"#,
        )
        .unwrap();
        assert_eq!(
            meta.meta.license.unwrap().expression().as_deref(),
            Some("MIT")
        );
    }

    /// A list mixing strings and attrsets must work.
    #[test]
    fn accepts_mixed_license_list() {
        let meta: NixPackageMeta = serde_json::from_str(
            r#"{"version":"1.0","meta":{"description":null,"homepage":null,"license":[{"spdxId":"MIT"},"GPL-3.0"],"changelog":null}}"#,
        )
        .unwrap();
        assert_eq!(
            meta.meta.license.unwrap().expression().as_deref(),
            Some("MIT OR GPL-3.0")
        );
    }

    #[test]
    fn attrset_without_usable_ids_yields_none() {
        let meta: NixPackageMeta = serde_json::from_str(
            r#"{"version":"1.0","meta":{"description":null,"homepage":null,"license":{"free":true},"changelog":null}}"#,
        )
        .unwrap();
        assert!(meta.meta.license.unwrap().expression().is_none());
    }
}
