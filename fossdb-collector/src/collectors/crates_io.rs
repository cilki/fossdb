use anyhow::Result;
use async_trait::async_trait;
use crates_io_api::{AsyncClient, Sort};
use fossdb::{CollectedPackage, CollectedVersion};
use std::collections::HashSet;
use std::sync::Arc;

use crate::client::{CollectorClient, aborts_run};
use crate::collectors::{Collector, helpers};

/// Maximum versions submitted per crate in one pass.
const MAX_VERSIONS_PER_CRATE: usize = 10;

/// Minimum spacing between crates.io API calls, per their crawler policy.
const CRATES_IO_RATE_LIMIT: std::time::Duration = std::time::Duration::from_millis(1000);

pub struct CratesIoCollector {
    client: Arc<AsyncClient>,
}

impl CratesIoCollector {
    /// Takes no HTTP client: `crates_io_api` 0.12 is built against reqwest 0.12
    /// while this crate uses 0.13, so the two `reqwest::Client` types are not
    /// interchangeable and `with_http_client` cannot be handed ours. The
    /// previous signature accepted a `reqwest::Client` and silently discarded
    /// it, which just hid that fact.
    pub fn new() -> Self {
        Self {
            client: Arc::new(
                AsyncClient::new(
                    "fossdb (https://github.com/fossable/fossdb)",
                    CRATES_IO_RATE_LIMIT,
                )
                .expect("crates.io client construction cannot fail with a static user agent"),
            ),
        }
    }

    /// Map crates.io versions to collected versions, newest first, skipping
    /// yanked releases and anything already stored.
    fn to_collected_versions(
        versions: &[crates_io_api::Version],
        already_known: &HashSet<&str>,
    ) -> Vec<CollectedVersion> {
        let mut candidates: Vec<&crates_io_api::Version> = versions
            .iter()
            .filter(|v| !v.yanked && !already_known.contains(v.num.as_str()))
            .collect();

        // crates.io happens to return newest-first, but sort explicitly so the
        // "latest N" selection does not depend on that.
        candidates.sort_unstable_by(|a, b| b.created_at.cmp(&a.created_at));

        candidates
            .into_iter()
            .take(MAX_VERSIONS_PER_CRATE)
            .map(|v| CollectedVersion {
                version: v.num.clone(),
                release_date: v.created_at,
                download_url: Some(format!("https://crates.io{}", v.dl_path)),
                // crates.io publishes the hex sha256 of the .crate file, so the
                // worker can actually verify archive integrity.
                checksum: Some(v.checksum.clone()),
                dependencies: Vec::new(),
                changelog: None,
            })
            .collect()
    }

    /// Process a single crate.
    ///
    /// Errors are returned rather than propagated out of `collect`, so one bad
    /// crate cannot abort the whole run and stall every remaining crate for a
    /// full collection interval.
    async fn process_crate(
        &self,
        krate: &crates_io_api::Crate,
        client: &CollectorClient,
    ) -> Result<()> {
        let crate_name = krate.name.as_str();
        let existing = client.get_package(crate_name).await?;

        if let Some(lookup) = &existing {
            if krate.updated_at <= lookup.package.updated_at {
                tracing::debug!("Package {} hasn't been updated, skipping", crate_name);
                return Ok(());
            }
        }

        // `get_crate` returns every version in a single request. The previous
        // `full_crate(name, false)` returned only the newest version (so release
        // history was never collected) and indexed `versions[0]` without a
        // bounds check, panicking on a crate with no versions.
        let response = self.client.get_crate(crate_name).await?;

        if response.versions.is_empty() {
            tracing::warn!("Crate {} has no versions, skipping", crate_name);
            return Ok(());
        }

        match existing {
            Some(lookup) => {
                let already_known: HashSet<&str> =
                    lookup.version_strings.iter().map(String::as_str).collect();
                let new_versions =
                    Self::to_collected_versions(&response.versions, &already_known);

                if new_versions.is_empty() {
                    tracing::debug!("No new versions for {}", crate_name);
                } else {
                    let pkg = CollectedPackage {
                        name: crate_name.to_string(),
                        description: None,
                        homepage: None,
                        repository: None,
                        license: None,
                        tags: Vec::new(),
                        versions: new_versions,
                        platform: None,
                        language: None,
                        status: None,
                        dependents_count: None,
                        rank: None,
                    };

                    // The timestamp must only advance once the versions are
                    // durably submitted. Advancing it after a failed submit made
                    // the next run skip this crate on the `updated_at` check, so
                    // a single transient error lost those versions permanently.
                    client.submit_package(pkg).await?;
                    tracing::info!("Submitted new versions for {}", crate_name);
                }

                client
                    .update_package_timestamp(crate_name, krate.updated_at)
                    .await?;
            }
            None => {
                // Take the license from the newest version that declares one.
                let license = response
                    .versions
                    .iter()
                    .filter(|v| !v.yanked)
                    .max_by_key(|v| v.created_at)
                    .and_then(|v| v.license.clone())
                    .or_else(|| {
                        response
                            .versions
                            .iter()
                            .find_map(|v| v.license.clone())
                    });

                let Some(license) = license else {
                    tracing::info!("Skipping {} with no license information", crate_name);
                    return Ok(());
                };

                if !helpers::is_free_license(&license) {
                    tracing::info!(
                        "Skipping {} with non-free license: {}",
                        crate_name,
                        license
                    );
                    return Ok(());
                }

                let versions =
                    Self::to_collected_versions(&response.versions, &HashSet::new());

                if versions.is_empty() {
                    tracing::info!("Skipping {}: all versions are yanked", crate_name);
                    return Ok(());
                }

                let pkg = CollectedPackage {
                    name: response.crate_data.name.clone(),
                    description: response.crate_data.description.clone(),
                    homepage: response.crate_data.homepage.clone(),
                    repository: response.crate_data.repository.clone(),
                    license: Some(license),
                    tags: vec!["rust".to_string(), "crate".to_string()],
                    versions,
                    platform: Some("crates.io".to_string()),
                    language: Some("rust".to_string()),
                    status: None,
                    dependents_count: None,
                    rank: None,
                };

                client.submit_package(pkg).await?;
                tracing::info!("Submitted package: {}", crate_name);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Collector for CratesIoCollector {
    fn name(&self) -> &str {
        "crates.io"
    }

    async fn collect(&self, client: Arc<CollectorClient>) -> Result<()> {
        let mut packages_processed = 0;
        let max_packages = if cfg!(debug_assertions) { 5 } else { usize::MAX };

        for page in 1..=3 {
            let mut query = crates_io_api::CratesQuery::builder()
                .sort(Sort::RecentUpdates)
                .page(page)
                .build();
            query.set_page_size(100);

            let crates_page = self.client.crates(query).await?;
            tracing::info!(
                "Fetched {} crates from page {}",
                crates_page.crates.len(),
                page
            );

            for krate in &crates_page.crates {
                if let Err(e) = self.process_crate(krate, &client).await {
                    if aborts_run(&e) {
                        return Err(e);
                    }
                    tracing::warn!("Failed to process crate {}: {:#}", krate.name, e);
                }

                packages_processed += 1;
                if packages_processed >= max_packages {
                    if cfg!(debug_assertions) {
                        tracing::info!("Debug mode: reached limit of {} packages", max_packages);
                    }
                    return Ok(());
                }
            }

            if crates_page.crates.len() < 100 {
                break;
            }
        }

        Ok(())
    }
}

impl Default for CratesIoCollector {
    fn default() -> Self {
        Self::new()
    }
}
