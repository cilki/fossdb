use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use fossdb::url::percent_encode;
use fossdb::{CollectedPackage, CollectedVersion, Dependency};
use reqwest::{Client, Response};
use serde::{Deserialize, Deserializer, de::DeserializeOwned};
use std::sync::Arc;

use crate::client::{AdaptiveConfig, AdaptiveRateLimitedClient, CollectorClient, aborts_run};
use crate::collectors::{Collector, helpers};

/// Results requested per search page.
const PER_PAGE: u32 = 50;

/// Pages walked per platform per run. Without any pagination the collector
/// re-fetched the same rank-ordered first page every cycle, so it could never
/// ingest more than `PER_PAGE` packages per platform no matter how long it ran.
const MAX_PAGES_PER_PLATFORM: u32 = 5;

pub struct LibrariesIoCollector {
    client: AdaptiveRateLimitedClient,
    api_key: String,
}

/// Parse the handful of timestamp shapes libraries.io actually emits.
///
/// A plain `Option<DateTime<Utc>>` field requires strict RFC 3339 with an
/// offset; any other shape failed deserialization of the *entire* project
/// object, silently dropping the package. Returning `None` for an unparseable
/// timestamp keeps the rest of the record usable.
fn parse_datetime(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();

    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(raw, format) {
            return Some(naive.and_utc());
        }
    }
    if let Ok(date) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        return date.and_hms_opt(0, 0, 0).map(|naive| naive.and_utc());
    }

    tracing::debug!("Unparseable libraries.io timestamp: {:?}", raw);
    None
}

fn lenient_datetime<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(raw.as_deref().and_then(parse_datetime))
}

#[derive(Debug, Deserialize)]
struct LibrariesIoProject {
    name: String,
    platform: String,
    description: Option<String>,
    homepage: Option<String>,
    repository_url: Option<String>,
    licenses: Option<String>,
    latest_release_number: Option<String>,
    #[serde(default, deserialize_with = "lenient_datetime")]
    latest_release_published_at: Option<DateTime<Utc>>,
    language: Option<String>,
    status: Option<String>,
    dependents_count: Option<u32>,
    #[allow(dead_code)]
    dependent_repositories_count: Option<u32>,
    rank: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LibrariesIoVersion {
    number: String,
    #[serde(default, deserialize_with = "lenient_datetime")]
    published_at: Option<DateTime<Utc>>,
    spdx_expression: Option<String>,
    original_license: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LibrariesIoDependency {
    project_name: String,
    name: String,
    platform: String,
    requirements: String,
    /// Dependency kind: `runtime`, `development`, `test`, `optional`, ...
    ///
    /// Previously not deserialized at all, so every dev/test/optional
    /// dependency was stored as a mandatory runtime dependency.
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    optional: Option<bool>,
    latest_stable: Option<String>,
    latest: Option<String>,
    deprecated: Option<bool>,
    outdated: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LibrariesIoPlatform {
    name: String,
    project_count: u32,
    homepage: Option<String>,
    color: Option<String>,
    default_language: Option<String>,
}

/// Decode a JSON response, treating a non-success status as an error.
///
/// The previous code called `.json().await.unwrap_or_default()`, which turned a
/// 429/403/5xx HTML error body into an empty result set. That was reported as a
/// successful collection of zero packages, hiding rate limiting and bad API keys
/// entirely.
async fn decode<T: DeserializeOwned>(response: Response, context: &str) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let preview: String = body.chars().take(200).collect();
        bail!("libraries.io {} request failed with {}: {}", context, status, preview);
    }

    response
        .json::<T>()
        .await
        .with_context(|| format!("failed to parse libraries.io {} response", context))
}

impl LibrariesIoCollector {
    pub fn new(client: Client, api_key: String) -> Self {
        // Rates are requests per minute, matching libraries.io's quota.
        let config = AdaptiveConfig {
            initial_rate: 30,
            min_rate: 6,
            max_rate: 60,
        };
        Self {
            client: AdaptiveRateLimitedClient::new(client, config),
            api_key,
        }
    }

    async fn get_platforms(&self) -> Result<Vec<LibrariesIoPlatform>> {
        let url = format!(
            "https://libraries.io/api/platforms?api_key={}",
            percent_encode(&self.api_key)
        );
        let response = self.client.get(&url).await?;
        decode(response, "platforms").await
    }

    async fn get_project_dependencies(
        &self,
        platform: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Vec<Dependency>> {
        let version_param = version.unwrap_or("latest");
        // Path segments must be encoded: scoped npm names like `@babel/core`
        // contain `/` and `@`, which otherwise change the request path and 404.
        let url = format!(
            "https://libraries.io/api/{}/{}/{}/dependencies?api_key={}",
            percent_encode(platform),
            percent_encode(name),
            percent_encode(version_param),
            percent_encode(&self.api_key)
        );
        let response = self.client.get(&url).await?;
        let deps: Vec<LibrariesIoDependency> = decode(response, "dependencies").await?;

        Ok(deps
            .into_iter()
            .map(|dep| {
                let kind = dep
                    .kind
                    .unwrap_or_else(|| "runtime".to_string())
                    .to_lowercase();
                let optional = dep.optional.unwrap_or(kind == "optional");
                Dependency {
                    name: dep.name,
                    version_requirement: dep.requirements,
                    dependency_type: kind,
                    optional,
                }
            })
            .collect())
    }

    async fn get_project_details(
        &self,
        platform: &str,
        name: &str,
    ) -> Result<Option<LibrariesIoProject>> {
        let url = format!(
            "https://libraries.io/api/{}/{}?api_key={}",
            percent_encode(platform),
            percent_encode(name),
            percent_encode(&self.api_key)
        );
        let response = self.client.get(&url).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(decode(response, "project").await?))
    }

    /// Build a package record for one search hit, or `None` if it should be
    /// skipped.
    async fn build_package(
        &self,
        platform: &str,
        name: &str,
    ) -> Result<Option<CollectedPackage>> {
        let Some(details) = self.get_project_details(platform, name).await? else {
            return Ok(None);
        };

        let Some(license) = details.licenses.clone() else {
            tracing::info!("Skipping {} with no license information", details.name);
            return Ok(None);
        };
        if !helpers::is_free_license(&license) {
            tracing::info!(
                "Skipping {} with non-free license: {}",
                details.name,
                license
            );
            return Ok(None);
        }

        let mut versions = Vec::new();
        if let (Some(ver), Some(date)) = (
            &details.latest_release_number,
            &details.latest_release_published_at,
        ) {
            // Propagate a dependency-fetch failure rather than recording the
            // version with an empty dependency list, which is indistinguishable
            // from "genuinely has no dependencies" and corrupts the graph.
            let deps = self
                .get_project_dependencies(platform, name, Some(ver))
                .await
                .with_context(|| format!("dependencies for {}/{}@{}", platform, name, ver))?;

            versions.push(CollectedVersion {
                version: ver.clone(),
                release_date: *date,
                download_url: None,
                checksum: None,
                dependencies: deps,
                changelog: None,
            });
        }

        let mut tags = vec![details.platform.to_lowercase(), "libraries.io".to_string()];
        if let Some(lang) = &details.language {
            tags.push(lang.to_lowercase());
        }

        Ok(Some(CollectedPackage {
            name: details.name,
            description: details.description,
            homepage: details.homepage,
            repository: details.repository_url,
            license: details.licenses,
            tags,
            versions,
            platform: Some(details.platform),
            language: details.language,
            status: details.status,
            dependents_count: details.dependents_count,
            rank: details.rank,
        }))
    }

    async fn scrape_platform(
        &self,
        platform: &LibrariesIoPlatform,
    ) -> Result<Vec<CollectedPackage>> {
        let mut packages = Vec::new();

        for page in 1..=MAX_PAGES_PER_PLATFORM {
            let search_url = format!(
                "https://libraries.io/api/search?platforms={}&sort=rank&per_page={}&page={}&api_key={}",
                percent_encode(&platform.name.to_lowercase()),
                PER_PAGE,
                page,
                percent_encode(&self.api_key)
            );

            let response = self.client.get(&search_url).await?;
            let results: Vec<LibrariesIoProject> = decode(response, "search").await?;
            let returned = results.len();

            tracing::debug!(
                "libraries.io {} page {}: {} result(s)",
                platform.name,
                page,
                returned
            );

            for project in results {
                match self.build_package(&project.platform, &project.name).await {
                    Ok(Some(pkg)) => packages.push(pkg),
                    Ok(None) => {}
                    // One bad project must not abandon the rest of the page.
                    Err(e) => tracing::warn!(
                        "Skipping libraries.io project {}/{}: {}",
                        project.platform,
                        project.name,
                        e
                    ),
                }
            }

            if returned < PER_PAGE as usize {
                break;
            }
        }

        Ok(packages)
    }
}

#[async_trait]
impl Collector for LibrariesIoCollector {
    fn name(&self) -> &str {
        "libraries.io"
    }

    async fn collect(&self, client: Arc<CollectorClient>) -> Result<()> {
        let mut packages_processed = 0;
        let max_packages = if cfg!(debug_assertions) { 5 } else { usize::MAX };

        let platforms = self.get_platforms().await?;
        let priority_platforms = ["NPM", "Maven", "PyPI", "Packagist", "Go", "NuGet", "RubyGems"];

        'platform_loop: for platform in platforms {
            if !priority_platforms.contains(&platform.name.as_str()) {
                continue;
            }

            tracing::info!("Scraping libraries.io platform: {}", platform.name);

            match self.scrape_platform(&platform).await {
                Ok(packages) => {
                    tracing::info!(
                        "Collected {} package(s) from {}",
                        packages.len(),
                        platform.name
                    );
                    for pkg in packages {
                        match client.submit_package(pkg).await {
                            Ok(_) => {}
                            Err(e) if aborts_run(&e) => return Err(e),
                            Err(e) => tracing::error!("Failed to submit package: {:#}", e),
                        }

                        packages_processed += 1;
                        if packages_processed >= max_packages {
                            if cfg!(debug_assertions) {
                                tracing::info!("Debug mode: reached limit of {} packages", max_packages);
                            }
                            break 'platform_loop;
                        }
                    }
                }
                Err(e) => tracing::warn!("Failed to scrape platform {}: {:#}", platform.name, e),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_timestamps() {
        let parsed = parse_datetime("2024-05-01T12:30:00Z").unwrap();
        assert_eq!(parsed.to_rfc3339(), "2024-05-01T12:30:00+00:00");
    }

    /// libraries.io sometimes omits the offset; the whole project record used to
    /// be dropped in that case.
    #[test]
    fn parses_timestamps_without_offset() {
        assert!(parse_datetime("2024-05-01T12:30:00").is_some());
        assert!(parse_datetime("2024-05-01 12:30:00").is_some());
        assert!(parse_datetime("2024-05-01").is_some());
    }

    #[test]
    fn unparseable_timestamp_yields_none() {
        assert!(parse_datetime("not a date").is_none());
        assert!(parse_datetime("").is_none());
    }

    /// An unparseable date must not discard the surrounding project.
    #[test]
    fn project_survives_bad_timestamp() {
        let json = r#"{
            "name": "left-pad",
            "platform": "NPM",
            "description": null,
            "homepage": null,
            "repository_url": null,
            "licenses": "MIT",
            "latest_release_number": "1.3.0",
            "latest_release_published_at": "whenever",
            "language": "JavaScript",
            "status": null,
            "dependents_count": 1,
            "dependent_repositories_count": 2,
            "rank": 30
        }"#;

        let project: LibrariesIoProject = serde_json::from_str(json).unwrap();
        assert_eq!(project.name, "left-pad");
        assert!(project.latest_release_published_at.is_none());
    }

    #[test]
    fn dependency_kind_is_preserved() {
        let json = r#"[
            {"project_name":"a","name":"dev-dep","platform":"NPM","requirements":"^1","kind":"development"},
            {"project_name":"a","name":"opt-dep","platform":"NPM","requirements":"^2","kind":"optional"},
            {"project_name":"a","name":"run-dep","platform":"NPM","requirements":"^3"}
        ]"#;

        let deps: Vec<LibrariesIoDependency> = serde_json::from_str(json).unwrap();
        assert_eq!(deps[0].kind.as_deref(), Some("development"));
        assert_eq!(deps[1].kind.as_deref(), Some("optional"));
        assert_eq!(deps[2].kind, None);
    }
}
