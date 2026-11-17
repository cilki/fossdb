//! Security advisories from OSV (<https://osv.dev>).
//!
//! Each run downloads the bulk export (`all.zip`, one OSV JSON document per
//! advisory) of every configured ecosystem and submits every advisory that
//! names a package FossDB stores to `POST /advisories`. The server upserts by
//! advisory id, so resubmitting an unchanged advisory is a no-op and a revised
//! one replaces the stored copy.
//!
//! The ecosystems come from `OSV_ECOSYSTEMS` (comma-separated OSV ecosystem
//! names, default `crates.io`). Their names double as the `platform` the
//! server matches packages against, case-insensitively, so `npm` advisories
//! link to the `NPM` packages libraries.io stores.
//!
//! An advisory can span ecosystems (a GHSA record for both an npm package and
//! a gem, say) and then appears in each of their exports. Because the server
//! replaces the stored copy on every submission, the exports are merged first
//! and such an advisory is submitted once, with its entries for all
//! configured ecosystems; submitting it once per ecosystem would unlink
//! whatever the previous submission linked.
//!
//! Affected versions are those OSV lists in `versions[]`, plus those inside
//! a range. Ranges are only evaluated where the ordering is semver: SEMVER
//! ranges, and ECOSYSTEM ranges of the ecosystems in [`SEMVER_ECOSYSTEMS`].
//! Other ecosystems (PyPI's PEP 440, Maven, RubyGems, ...) have orderings of
//! their own and rely on `versions[]`, which OSV enumerates for them.

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fossdb::{CollectedAdvisory, CollectedAffected, PackageLookup, VulnerabilitySeverity};
use semver::Version;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use crate::client::CollectorClient;
use crate::collectors::Collector;

const OSV_BUCKET: &str = "https://osv-vulnerabilities.storage.googleapis.com";

/// Collected when `OSV_ECOSYSTEMS` is unset: the platform of the default
/// `collector-rust` feature.
const DEFAULT_ECOSYSTEM: &str = "crates.io";

/// OSV's spelling of the ecosystems FossDB's collectors store packages for.
/// `OSV_ECOSYSTEMS` is matched against these case-insensitively, since the
/// bucket paths are case-sensitive.
const KNOWN_ECOSYSTEMS: &[&str] = &[
    "crates.io",
    "npm",
    "PyPI",
    "Go",
    "Maven",
    "Packagist",
    "NuGet",
    "RubyGems",
];

/// Ecosystems whose versions are ordered as semver, so that their ECOSYSTEM
/// ranges can be evaluated with the `semver` crate.
const SEMVER_ECOSYSTEMS: &[&str] = &["crates.io", "npm", "Go"];

/// The ecosystems named by `OSV_ECOSYSTEMS`, or [`DEFAULT_ECOSYSTEM`].
pub fn ecosystems_from_env() -> Vec<String> {
    parse_ecosystems(std::env::var("OSV_ECOSYSTEMS").ok().as_deref())
}

fn parse_ecosystems(raw: Option<&str>) -> Vec<String> {
    let mut ecosystems: Vec<String> = Vec::new();
    for name in raw.unwrap_or(DEFAULT_ECOSYSTEM).split(',').map(str::trim) {
        if name.is_empty() {
            continue;
        }
        let name = KNOWN_ECOSYSTEMS
            .iter()
            .find(|known| known.eq_ignore_ascii_case(name))
            .map_or_else(|| name.to_string(), |known| known.to_string());
        if !ecosystems.contains(&name) {
            ecosystems.push(name);
        }
    }
    if ecosystems.is_empty() {
        ecosystems.push(DEFAULT_ECOSYSTEM.to_string());
    }
    ecosystems
}

pub struct OsvCollector {
    http: reqwest::Client,
    ecosystems: Vec<String>,
}

impl OsvCollector {
    pub fn new(http: reqwest::Client, ecosystems: Vec<String>) -> Self {
        Self { http, ecosystems }
    }

    async fn download(&self, ecosystem: &str) -> Result<Vec<OsvRecord>> {
        let url = format!("{OSV_BUCKET}/{ecosystem}/all.zip");
        let bytes = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        tokio::task::spawn_blocking(move || read_dump(&bytes)).await?
    }
}

#[async_trait]
impl Collector for OsvCollector {
    fn name(&self) -> &str {
        "osv"
    }

    async fn collect(&self, client: Arc<CollectorClient>) -> Result<()> {
        let mut exports = Vec::with_capacity(self.ecosystems.len());
        for ecosystem in &self.ecosystems {
            // Going on without one export would submit the advisories it
            // shares with the others without its entries, and the server
            // would unlink those.
            let records = self
                .download(ecosystem)
                .await
                .with_context(|| format!("OSV {ecosystem} export"))?;
            tracing::info!("OSV {}: {} advisories in export", ecosystem, records.len());
            exports.push(records);
        }
        let advisories = prepare(merge_exports(exports, &self.ecosystems));

        let mut lookups: HashMap<String, Option<PackageLookup>> = HashMap::new();
        let (mut submitted, mut created, mut failed) = (0usize, 0usize, 0usize);

        for prepared in advisories {
            let mut lookup_failed = false;
            for name in prepared.record.package_names() {
                if lookups.contains_key(name) {
                    continue;
                }
                match client.get_package(name).await {
                    Ok(lookup) => {
                        lookups.insert(name.to_string(), lookup);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to look up package {}: {}", name, e);
                        lookup_failed = true;
                        break;
                    }
                }
            }
            // A partial lookup would submit the advisory without that
            // package, and the server would unlink it.
            if lookup_failed {
                failed += 1;
                continue;
            }
            let packages: HashMap<&str, &PackageLookup> = prepared
                .record
                .package_names()
                .filter_map(|name| Some((name, lookups.get(name)?.as_ref()?)))
                .collect();

            let Some(advisory) = prepared.to_collected(&packages) else {
                continue;
            };
            let id = advisory.source_id.clone();
            match client.submit_advisory(&advisory).await {
                Ok(result) => {
                    submitted += 1;
                    if result.created {
                        created += 1;
                    }
                    if !result.skipped.is_empty() {
                        tracing::debug!("Advisory {} skipped {:?}", id, result.skipped);
                    }
                }
                Err(e) => {
                    failed += 1;
                    tracing::warn!("Failed to submit advisory {}: {}", id, e);
                }
            }
        }

        tracing::info!(
            "OSV {}: submitted {} advisories ({} new), {} failed",
            self.ecosystems.join(", "),
            submitted,
            created,
            failed
        );
        Ok(())
    }
}

/// Read every OSV document out of a bulk export zip.
///
/// An entry that fails to parse is logged and skipped rather than failing the
/// whole export.
fn read_dump(bytes: &[u8]) -> Result<Vec<OsvRecord>> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("OSV export is not a zip")?;
    let mut records = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name()?.into_owned();
        if !name.ends_with(".json") {
            continue;
        }
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        match serde_json::from_str::<OsvRecord>(&text) {
            Ok(record) => records.push(record),
            Err(e) => tracing::warn!("Skipping unparsable OSV entry {}: {}", name, e),
        }
    }
    Ok(records)
}

/// Combine the exports of the configured ecosystems into one record per
/// advisory, keeping only the `affected` entries for those ecosystems.
///
/// A record spanning several ecosystems is the same document in each export,
/// so the first copy is kept.
fn merge_exports(exports: Vec<Vec<OsvRecord>>, ecosystems: &[String]) -> Vec<OsvRecord> {
    let mut seen = HashSet::new();
    exports
        .into_iter()
        .flatten()
        .filter(|record| seen.insert(record.id.clone()))
        .map(|mut record| {
            if let Some(affected) = record.affected.as_mut() {
                affected.retain(|a| ecosystems.contains(&a.package.ecosystem));
            }
            record
        })
        .collect()
}

// --- OSV schema (the subset used here) --------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct OsvRecord {
    id: String,
    #[serde(default)]
    aliases: Option<Vec<String>>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    published: Option<DateTime<Utc>>,
    modified: DateTime<Utc>,
    #[serde(default)]
    withdrawn: Option<DateTime<Utc>>,
    #[serde(default)]
    severity: Option<Vec<OsvSeverity>>,
    #[serde(default)]
    affected: Option<Vec<OsvAffected>>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Option<Vec<OsvRange>>,
    #[serde(default)]
    versions: Option<Vec<String>>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OsvEvent {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    /// Only meaningful for GIT ranges, which are not evaluated.
    Limit(serde::de::IgnoredAny),
}

impl OsvRecord {
    fn aliases(&self) -> &[String] {
        self.aliases.as_deref().unwrap_or_default()
    }

    /// The `affected` entries, which [`merge_exports`] has narrowed to the
    /// configured ecosystems.
    fn affected(&self) -> impl Iterator<Item = &OsvAffected> {
        self.affected.iter().flatten()
    }

    fn package_names(&self) -> impl Iterator<Item = &str> {
        let mut seen = HashSet::new();
        self.affected()
            .map(|a| a.package.name.as_str())
            .filter(move |n| seen.insert(*n))
    }

    /// GitHub's rating (`database_specific.severity`), which GHSA records
    /// carry and RustSec records do not.
    fn github_severity(&self) -> Option<VulnerabilitySeverity> {
        let label = self.database_specific.as_ref()?.get("severity")?.as_str()?;
        match label.to_ascii_uppercase().as_str() {
            "LOW" => Some(VulnerabilitySeverity::Low),
            "MODERATE" | "MEDIUM" => Some(VulnerabilitySeverity::Medium),
            "HIGH" => Some(VulnerabilitySeverity::High),
            "CRITICAL" => Some(VulnerabilitySeverity::Critical),
            _ => None,
        }
    }

    fn cvss_v3_severity(&self) -> Option<VulnerabilitySeverity> {
        self.severity
            .iter()
            .flatten()
            .filter(|s| s.kind == "CVSS_V3")
            .find_map(|s| cvss_v3_base_score(&s.score))
            .map(bucket_score)
    }

    /// RustSec's `informational` kind for advisories that are not
    /// vulnerabilities as such: `unmaintained`, `unsound` or `notice`.
    fn informational(&self) -> Option<&str> {
        self.affected().find_map(|a| {
            a.database_specific
                .as_ref()?
                .get("informational")?
                .as_str()
        })
    }
}

/// An advisory to submit, with the severity resolved.
#[derive(Debug)]
struct Prepared {
    record: OsvRecord,
    severity: VulnerabilitySeverity,
}

/// Drop duplicates and resolve each advisory's severity.
///
/// The crates.io export carries most advisories twice: the RustSec record and
/// a GitHub (GHSA) record that lists it under `aliases`. Storing both would
/// show one vulnerability as two, so the GHSA copy is dropped whenever the
/// record it aliases is in the same export; its severity rating is kept as a
/// fallback for the RustSec record, which often has none.
fn prepare(records: Vec<OsvRecord>) -> Vec<Prepared> {
    let ids: HashSet<&str> = records.iter().map(|r| r.id.as_str()).collect();
    let mut duplicate = HashSet::new();
    let mut aliased_severity: HashMap<String, VulnerabilitySeverity> = HashMap::new();

    for record in &records {
        if !record.id.starts_with("GHSA-") {
            continue;
        }
        let Some(primary) = record
            .aliases()
            .iter()
            .find(|a| !a.starts_with("GHSA-") && ids.contains(a.as_str()))
        else {
            continue;
        };
        duplicate.insert(record.id.clone());
        if let Some(severity) = record.github_severity() {
            aliased_severity.insert(primary.clone(), severity);
        }
    }

    records
        .into_iter()
        .filter(|r| !duplicate.contains(&r.id))
        .map(|record| {
            let severity = resolve_severity(&record, aliased_severity.get(&record.id).cloned());
            Prepared { record, severity }
        })
        .collect()
}

/// In order: GitHub's rating, the CVSS v3 base score, the rating of a GHSA
/// duplicate, Low for `unmaintained`/`notice` advisories, and otherwise
/// Medium.
///
/// CVSS v4 vectors are not scored: their scoring is a lookup over macro
/// vectors rather than a formula, and almost every advisory that has one also
/// has a GitHub rating.
fn resolve_severity(
    record: &OsvRecord,
    aliased: Option<VulnerabilitySeverity>,
) -> VulnerabilitySeverity {
    record
        .github_severity()
        .or_else(|| record.cvss_v3_severity())
        .or(aliased)
        .or_else(|| match record.informational() {
            Some("unmaintained" | "notice") => Some(VulnerabilitySeverity::Low),
            _ => None,
        })
        .unwrap_or(VulnerabilitySeverity::Medium)
}

impl Prepared {
    /// Build the advisory to submit, given the stored packages it names
    /// (keyed by name).
    ///
    /// Returns `None` when it names no stored package, as the server would
    /// not store it anyway. A withdrawn advisory is still submitted, with no
    /// affected entries, so that a copy stored before it was withdrawn gets
    /// unlinked.
    fn to_collected(&self, packages: &HashMap<&str, &PackageLookup>) -> Option<CollectedAdvisory> {
        let record = &self.record;
        let affected: Vec<CollectedAffected> = record
            .affected()
            .filter_map(|a| {
                let lookup = packages.get(a.package.name.as_str())?;
                Some(collect_affected(a, &lookup.version_strings))
            })
            .collect();
        if affected.is_empty() {
            return None;
        }

        let title = record
            .summary
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                record
                    .details
                    .as_deref()
                    .and_then(|d| d.lines().find(|l| !l.trim().is_empty()))
                    .map(|l| l.trim().to_string())
            })
            .unwrap_or_else(|| record.id.clone());

        Some(CollectedAdvisory {
            source_id: record.id.clone(),
            aliases: record.aliases().to_vec(),
            title,
            description: record.details.clone().unwrap_or_default(),
            severity: self.severity.clone(),
            published: record.published.unwrap_or(record.modified),
            affected: if record.withdrawn.is_some() {
                Vec::new()
            } else {
                affected
            },
        })
    }
}

/// Map one `affected` entry to the wire type, keeping only the stored
/// versions it covers: those listed in `versions`, or inside one of its
/// ranges that can be evaluated as semver (see the module docs).
fn collect_affected(affected: &OsvAffected, stored_versions: &[String]) -> CollectedAffected {
    let ecosystem = affected.package.ecosystem.as_str();
    let semver_ordered = SEMVER_ECOSYSTEMS.contains(&ecosystem);
    let listed: HashSet<&str> = affected
        .versions
        .iter()
        .flatten()
        .map(|v| strip_go_prefix(ecosystem, v))
        .collect();
    // Shown to users whatever the ecosystem.
    let ranges: Vec<&OsvRange> = affected
        .ranges
        .iter()
        .flatten()
        .filter(|r| r.kind == "SEMVER" || r.kind == "ECOSYSTEM")
        .collect();
    let evaluated: Vec<&OsvRange> = ranges
        .iter()
        .copied()
        .filter(|r| r.kind == "SEMVER" || semver_ordered)
        .collect();

    let affected_versions = stored_versions
        .iter()
        .filter(|v| {
            let v = strip_go_prefix(ecosystem, v);
            listed.contains(v)
                || Version::parse(v).is_ok_and(|parsed| {
                    evaluated.iter().any(|r| range_contains(&r.events, &parsed))
                })
        })
        .cloned()
        .collect();

    let fixed_in = ranges
        .iter()
        .flat_map(|r| &r.events)
        .filter_map(|e| match e {
            OsvEvent::Fixed(v) => Some(v.clone()),
            _ => None,
        })
        .next_back();

    CollectedAffected {
        package_name: affected.package.name.clone(),
        platform: ecosystem.to_string(),
        affected_versions,
        ranges: ranges.iter().flat_map(|r| describe_range(&r.events)).collect(),
        fixed_in,
    }
}

/// Go module versions carry a `v` (`v1.2.3`) that OSV leaves out of its
/// ranges and version lists.
fn strip_go_prefix<'a>(ecosystem: &str, version: &'a str) -> &'a str {
    if ecosystem == "Go" {
        version.strip_prefix('v').unwrap_or(version)
    } else {
        version
    }
}

/// OSV writes the lower bound "all versions" as `0`, RustSec as `0.0.0-0`.
fn is_unbounded(introduced: &str) -> bool {
    introduced == "0" || introduced == "0.0.0-0"
}

fn parse_event_version(v: &str) -> Option<Version> {
    if is_unbounded(v) {
        // The lowest semver version: no pre-release sorts below `-0`.
        return Version::parse("0.0.0-0").ok();
    }
    Version::parse(v).ok().or_else(|| {
        // A few GHSA records shorten bounds to `0.65` or `1`; read those as
        // `0.65.0` and `1.0.0`.
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() < 3 && parts.iter().all(|p| p.parse::<u64>().is_ok()) {
            let mut padded = parts;
            padded.resize(3, "0");
            Version::parse(&padded.join(".")).ok()
        } else {
            None
        }
    })
}

/// Whether `version` falls inside a range, per the OSV evaluation rules:
/// walk the events in version order, entering the range at an `introduced`
/// at or below it and leaving at a `fixed` at or below it or a
/// `last_affected` below it.
///
/// A range with an event that does not parse as semver matches nothing,
/// rather than guessing.
fn range_contains(events: &[OsvEvent], version: &Version) -> bool {
    let mut parsed = Vec::with_capacity(events.len());
    for event in events {
        let (raw, kind) = match event {
            OsvEvent::Introduced(v) => (v, 0),
            OsvEvent::Fixed(v) => (v, 1),
            OsvEvent::LastAffected(v) => (v, 2),
            OsvEvent::Limit(_) => continue,
        };
        let Some(v) = parse_event_version(raw) else {
            return false;
        };
        parsed.push((v, kind));
    }
    parsed.sort_by(|a, b| a.0.cmp(&b.0));

    let mut affected = false;
    for (bound, kind) in &parsed {
        match kind {
            0 if version >= bound => affected = true,
            1 if version >= bound => affected = false,
            2 if version > bound => affected = false,
            _ => {}
        }
    }
    affected
}

/// Human-readable form of a range, one string per introduced..fixed span,
/// e.g. `<0.9.18` and `>=0.10.0, <0.10.2`.
fn describe_range(events: &[OsvEvent]) -> Vec<String> {
    fn lower(introduced: &str) -> Option<String> {
        (!is_unbounded(introduced)).then(|| format!(">={introduced}"))
    }
    fn open(introduced: &str) -> String {
        lower(introduced).unwrap_or_else(|| "*".to_string())
    }

    let mut spans = Vec::new();
    let mut start: Option<&str> = None;
    for event in events {
        let upper = match event {
            OsvEvent::Introduced(v) => {
                if let Some(prev) = start.replace(v) {
                    spans.push(open(prev));
                }
                continue;
            }
            OsvEvent::Fixed(v) => format!("<{v}"),
            OsvEvent::LastAffected(v) => format!("<={v}"),
            OsvEvent::Limit(_) => continue,
        };
        let span = start.take().and_then(lower);
        spans.push(span.into_iter().chain([upper]).collect::<Vec<_>>().join(", "));
    }
    if let Some(prev) = start {
        spans.push(open(prev));
    }
    spans
}

/// The bands from the issue that proposed this collector (#8), which match
/// the CVSS v3 qualitative ratings with "None" folded into Low.
fn bucket_score(score: f64) -> VulnerabilitySeverity {
    if score < 4.0 {
        VulnerabilitySeverity::Low
    } else if score < 7.0 {
        VulnerabilitySeverity::Medium
    } else if score < 9.0 {
        VulnerabilitySeverity::High
    } else {
        VulnerabilitySeverity::Critical
    }
}

/// CVSS v3.x base score of a vector such as
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, per section 7.1 of the
/// v3.1 specification. Returns `None` if any base metric is missing or
/// unknown.
fn cvss_v3_base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    if !parts.next()?.starts_with("CVSS:3") {
        return None;
    }
    let metrics: HashMap<&str, &str> = parts.filter_map(|p| p.split_once(':')).collect();
    let get = |k: &str| metrics.get(k).copied();

    let scope_changed = match get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k: &str| match get(k)? {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Some(round_up(raw.min(10.0)))
}

/// The v3.1 `Roundup`: smallest one-decimal number not below `x`, computed in
/// integers so that e.g. 4.000000000000001 does not become 4.1.
fn round_up(x: f64) -> f64 {
    let scaled = (x * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        (scaled / 10_000 + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const FIXTURES: &[(&str, &str)] = &[
        (
            "RUSTSEC-2016-0001.json",
            include_str!("../../testdata/osv/RUSTSEC-2016-0001.json"),
        ),
        (
            "GHSA-34p9-f4q3-c4r7.json",
            include_str!("../../testdata/osv/GHSA-34p9-f4q3-c4r7.json"),
        ),
        (
            "RUSTSEC-2016-0004.json",
            include_str!("../../testdata/osv/RUSTSEC-2016-0004.json"),
        ),
        (
            "RUSTSEC-2017-0002.json",
            include_str!("../../testdata/osv/RUSTSEC-2017-0002.json"),
        ),
        (
            "GHSA-262p-vjx5-45xh.json",
            include_str!("../../testdata/osv/GHSA-262p-vjx5-45xh.json"),
        ),
    ];

    /// The fixtures packed the way OSV ships them.
    fn fixture_zip() -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in FIXTURES {
            writer.start_file(*name, options).unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
        buf.into_inner()
    }

    fn prepared() -> HashMap<String, Prepared> {
        let records = read_dump(&fixture_zip()).unwrap();
        assert_eq!(records.len(), FIXTURES.len());
        by_id(prepare(merge_exports(vec![records], &ecosystems(&["crates.io"]))))
    }

    fn by_id(prepared: Vec<Prepared>) -> HashMap<String, Prepared> {
        prepared
            .into_iter()
            .map(|p| (p.record.id.clone(), p))
            .collect()
    }

    fn ecosystems(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn record(json: &str) -> OsvRecord {
        serde_json::from_str(json).unwrap()
    }

    /// lodash's GHSA record, which covers npm packages and a gem.
    fn lodash() -> OsvRecord {
        record(include_str!("../../testdata/osv/GHSA-35jh-r3h4-6jhm.json"))
    }

    /// The exports of npm, PyPI, Go and RubyGems, each holding the fixtures
    /// that have entries for it.
    fn other_exports() -> Vec<Vec<OsvRecord>> {
        let pysec = || record(include_str!("../../testdata/osv/PYSEC-2023-74.json"));
        let ghsa = || record(include_str!("../../testdata/osv/GHSA-j8r2-6x86-q33q.json"));
        let go = || record(include_str!("../../testdata/osv/GO-2022-0969.json"));
        vec![
            vec![lodash()],
            vec![pysec(), ghsa()],
            vec![go()],
            vec![lodash()],
        ]
    }

    fn platforms(advisory: &CollectedAdvisory) -> Vec<(&str, &str)> {
        advisory
            .affected
            .iter()
            .map(|a| (a.platform.as_str(), a.package_name.as_str()))
            .collect()
    }

    fn lookup(name: &str, versions: &[&str]) -> PackageLookup {
        PackageLookup {
            package: fossdb::Package {
                id: 1,
                name: name.to_string(),
                description: None,
                homepage: None,
                repository: None,
                license: None,
                tags: Vec::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                platform: Some(DEFAULT_ECOSYSTEM.to_string()),
                language: None,
                status: None,
                dependents_count: None,
                rank: None,
            },
            version_strings: versions.iter().map(|v| v.to_string()).collect(),
        }
    }

    fn collect(p: &Prepared, lookup: &PackageLookup) -> Option<CollectedAdvisory> {
        let packages = HashMap::from([(lookup.package.name.as_str(), lookup)]);
        p.to_collected(&packages)
    }

    #[test]
    fn ghsa_duplicate_of_a_rustsec_record_is_dropped() {
        let prepared = prepared();
        assert!(!prepared.contains_key("GHSA-34p9-f4q3-c4r7"));
        assert!(prepared.contains_key("RUSTSEC-2016-0001"));
        // A GHSA record with no counterpart in the export is kept.
        assert!(prepared.contains_key("GHSA-262p-vjx5-45xh"));
    }

    #[test]
    fn advisory_maps_to_the_wire_type() {
        let prepared = prepared();
        let openssl = lookup("openssl", &["0.8.3", "0.9.0", "0.10.40"]);
        let advisory = collect(&prepared["RUSTSEC-2016-0001"], &openssl).unwrap();

        assert_eq!(advisory.source_id, "RUSTSEC-2016-0001");
        assert_eq!(advisory.title, "SSL/TLS MitM vulnerability due to insecure defaults");
        assert!(advisory.aliases.contains(&"CVE-2016-10931".to_string()));
        assert!(advisory.description.starts_with("All versions of rust-openssl"));
        assert_eq!(advisory.published.to_rfc3339(), "2016-11-05T12:00:00+00:00");
        // CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H scores 8.1.
        assert_eq!(advisory.severity, VulnerabilitySeverity::High);

        assert_eq!(advisory.affected.len(), 1);
        let affected = &advisory.affected[0];
        assert_eq!(affected.package_name, "openssl");
        assert_eq!(affected.platform, "crates.io");
        assert_eq!(affected.affected_versions, vec!["0.8.3"]);
        assert_eq!(affected.ranges, vec!["<0.9.0"]);
        assert_eq!(affected.fixed_in.as_deref(), Some("0.9.0"));
    }

    #[test]
    fn multiple_spans_link_only_versions_inside_them() {
        let prepared = prepared();
        let hyper = lookup(
            "hyper",
            &["0.9.17", "0.9.18", "0.10.0", "0.10.1", "0.10.2", "1.0.0", "not-semver"],
        );
        let advisory = collect(&prepared["RUSTSEC-2017-0002"], &hyper).unwrap();
        let affected = &advisory.affected[0];
        assert_eq!(affected.affected_versions, vec!["0.9.17", "0.10.0", "0.10.1"]);
        assert_eq!(affected.ranges, vec!["<0.9.18", ">=0.10.0, <0.10.2"]);
        assert_eq!(affected.fixed_in.as_deref(), Some("0.10.2"));
        // AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N scores 5.3.
        assert_eq!(advisory.severity, VulnerabilitySeverity::Medium);
    }

    #[test]
    fn unmaintained_notice_is_low() {
        let prepared = prepared();
        assert_eq!(prepared["RUSTSEC-2016-0004"].severity, VulnerabilitySeverity::Low);
    }

    #[test]
    fn advisory_for_an_unknown_package_is_not_submitted() {
        let prepared = prepared();
        assert!(prepared["RUSTSEC-2016-0001"].to_collected(&HashMap::new()).is_none());
    }

    #[test]
    fn withdrawn_advisory_is_submitted_without_affected_entries() {
        let prepared = prepared();
        let pingora = lookup("pingora-core", &["0.7.0"]);
        let advisory = collect(&prepared["GHSA-262p-vjx5-45xh"], &pingora).unwrap();
        assert!(advisory.affected.is_empty());
    }

    #[test]
    fn other_ecosystems_are_ignored() {
        let merged = merge_exports(vec![vec![lodash()]], &ecosystems(&["npm"]));
        let prepared = by_id(prepare(merged));
        let rails = lookup("lodash-rails", &["4.17.4"]);
        assert!(collect(&prepared["GHSA-35jh-r3h4-6jhm"], &rails).is_none());

        let merged = merge_exports(vec![vec![lodash()]], &ecosystems(&["crates.io"]));
        let prepared = by_id(prepare(merged));
        let lodash = lookup("lodash", &["4.17.20"]);
        assert!(collect(&prepared["GHSA-35jh-r3h4-6jhm"], &lodash).is_none());
    }

    #[test]
    fn advisory_in_several_exports_is_submitted_once_with_every_ecosystem() {
        let merged = merge_exports(other_exports(), &ecosystems(&["npm", "RubyGems"]));
        assert_eq!(merged.iter().filter(|r| r.id == "GHSA-35jh-r3h4-6jhm").count(), 1);
        let prepared = by_id(prepare(merged));

        let lodash = lookup("lodash", &["4.17.20", "4.17.21"]);
        let rails = lookup("lodash-rails", &["4.17.4"]);
        let packages = HashMap::from([("lodash", &lodash), ("lodash-rails", &rails)]);
        let advisory = prepared["GHSA-35jh-r3h4-6jhm"].to_collected(&packages).unwrap();
        assert_eq!(
            platforms(&advisory),
            vec![("npm", "lodash"), ("RubyGems", "lodash-rails")]
        );
        assert_eq!(advisory.affected[0].affected_versions, vec!["4.17.20"]);
        assert_eq!(advisory.affected[1].affected_versions, vec!["4.17.4"]);
        assert_eq!(advisory.severity, VulnerabilitySeverity::High);
    }

    #[test]
    fn non_semver_ecosystems_link_only_listed_versions() {
        let merged = merge_exports(other_exports(), &ecosystems(&["RubyGems"]));
        let prepared = by_id(prepare(merged));
        // 4.17.20 is inside `>=0, <4.17.21` but not in OSV's list for the
        // gem, and RubyGems ordering is not semver, so it is not linked.
        let rails = lookup("lodash-rails", &["4.17.4", "4.17.20"]);
        let advisory = collect(&prepared["GHSA-35jh-r3h4-6jhm"], &rails).unwrap();
        let affected = &advisory.affected[0];
        assert_eq!(affected.affected_versions, vec!["4.17.4"]);
        // The range is still shown.
        assert_eq!(affected.ranges, vec!["<4.17.21"]);
        assert_eq!(affected.fixed_in.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn pypi_advisory_drops_its_ghsa_copy_and_keeps_its_rating() {
        let merged = merge_exports(other_exports(), &ecosystems(&["PyPI"]));
        let prepared = by_id(prepare(merged));
        assert!(!prepared.contains_key("GHSA-j8r2-6x86-q33q"));

        let requests = lookup("requests", &["2.2.1", "2.3.0", "2.30.0", "2.31.0"]);
        let advisory = collect(&prepared["PYSEC-2023-74"], &requests).unwrap();
        // GitHub rates it MODERATE; the PYSEC record has no rating.
        assert_eq!(advisory.severity, VulnerabilitySeverity::Medium);
        let affected = &advisory.affected[0];
        assert_eq!(affected.platform, "PyPI");
        assert_eq!(affected.affected_versions, vec!["2.3.0", "2.30.0"]);
        // The GIT range (commit hashes) is neither shown nor evaluated.
        assert_eq!(affected.ranges, vec![">=2.3.0, <2.31.0"]);
        assert_eq!(affected.fixed_in.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn go_versions_match_without_their_v_prefix() {
        let merged = merge_exports(other_exports(), &ecosystems(&["Go"]));
        let prepared = by_id(prepare(merged));
        let net = lookup(
            "golang.org/x/net",
            &[
                "v0.0.0-20220722155237-a158d28d115b",
                "v0.0.0-20220906165146-f3363e06e74c",
                "v0.1.0",
            ],
        );
        let advisory = collect(&prepared["GO-2022-0969"], &net).unwrap();
        assert_eq!(
            advisory.affected[0].affected_versions,
            vec!["v0.0.0-20220722155237-a158d28d115b"]
        );
    }

    #[test]
    fn ecosystems_are_read_case_insensitively() {
        assert_eq!(parse_ecosystems(None), vec!["crates.io"]);
        assert_eq!(parse_ecosystems(Some(" ,")), vec!["crates.io"]);
        assert_eq!(
            parse_ecosystems(Some("crates.io, NPM,pypi,npm,Hex")),
            vec!["crates.io", "npm", "PyPI", "Hex"]
        );
    }

    #[test]
    fn last_affected_is_inclusive() {
        let events = vec![
            OsvEvent::Introduced("0".into()),
            OsvEvent::LastAffected("0.3.24".into()),
        ];
        let v = |s| Version::parse(s).unwrap();
        assert!(range_contains(&events, &v("0.3.24")));
        assert!(!range_contains(&events, &v("0.3.25")));
        assert!(range_contains(&events, &v("0.1.0-alpha")));
        assert_eq!(describe_range(&events), vec!["<=0.3.24"]);
    }

    #[test]
    fn open_ended_range_covers_everything_after_introduced() {
        let events = vec![OsvEvent::Introduced("1.2.0".into())];
        let v = |s| Version::parse(s).unwrap();
        assert!(!range_contains(&events, &v("1.1.9")));
        assert!(range_contains(&events, &v("1.2.0")));
        assert!(range_contains(&events, &v("9.0.0")));
        assert_eq!(describe_range(&events), vec![">=1.2.0"]);
        assert_eq!(describe_range(&[OsvEvent::Introduced("0".into())]), vec!["*"]);
    }

    #[test]
    fn unparsable_range_matches_nothing() {
        let events = vec![
            OsvEvent::Introduced("0".into()),
            OsvEvent::Fixed("1.0-beta".into()),
        ];
        assert!(!range_contains(&events, &Version::parse("0.5.0").unwrap()));
    }

    #[test]
    fn shortened_bounds_are_padded() {
        let events = vec![
            OsvEvent::Introduced("0.60.0".into()),
            OsvEvent::Fixed("0.65".into()),
        ];
        let v = |s| Version::parse(s).unwrap();
        assert!(range_contains(&events, &v("0.64.9")));
        assert!(!range_contains(&events, &v("0.65.0")));
    }

    #[test]
    fn cvss_v3_base_scores_match_the_reference_calculator() {
        let cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N", 4.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ];
        for (vector, expected) in cases {
            assert_eq!(cvss_v3_base_score(vector), Some(expected), "{vector}");
        }
        assert_eq!(cvss_v3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"), None);
        assert_eq!(cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"), None);
    }

    #[test]
    fn scores_bucket_into_severities() {
        assert_eq!(bucket_score(0.0), VulnerabilitySeverity::Low);
        assert_eq!(bucket_score(3.9), VulnerabilitySeverity::Low);
        assert_eq!(bucket_score(4.0), VulnerabilitySeverity::Medium);
        assert_eq!(bucket_score(6.9), VulnerabilitySeverity::Medium);
        assert_eq!(bucket_score(7.0), VulnerabilitySeverity::High);
        assert_eq!(bucket_score(8.9), VulnerabilitySeverity::High);
        assert_eq!(bucket_score(9.0), VulnerabilitySeverity::Critical);
    }
}
