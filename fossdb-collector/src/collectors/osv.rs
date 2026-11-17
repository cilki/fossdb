//! Security advisories from OSV (<https://osv.dev>).
//!
//! Each run downloads the ecosystem's bulk export (`all.zip`, one OSV JSON
//! document per advisory) and submits every advisory that names a package
//! FossDB stores to `POST /advisories`. The server upserts by advisory id, so
//! resubmitting an unchanged advisory is a no-op and a revised one replaces
//! the stored copy.
//!
//! Only crates.io is collected for now. OSV's crates.io entries mostly give
//! affected versions as SEMVER ranges rather than enumerating them, so the
//! ranges are evaluated here against the versions the server already stores;
//! the server then links exactly those versions.

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

/// OSV's name for the ecosystem, which is also the `platform` the crates.io
/// collector stores packages under.
const ECOSYSTEM: &str = "crates.io";

pub struct OsvCollector {
    http: reqwest::Client,
}

impl OsvCollector {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }
}

#[async_trait]
impl Collector for OsvCollector {
    fn name(&self) -> &str {
        "osv"
    }

    async fn collect(&self, client: Arc<CollectorClient>) -> Result<()> {
        let url = format!("{OSV_BUCKET}/{ECOSYSTEM}/all.zip");
        let bytes = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let records = tokio::task::spawn_blocking(move || read_dump(&bytes)).await??;
        let advisories = prepare(records);
        tracing::info!("OSV {}: {} advisories in export", ECOSYSTEM, advisories.len());

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
            ECOSYSTEM,
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

    /// The `affected` entries for [`ECOSYSTEM`]. A GHSA advisory can span
    /// several ecosystems; the others are not ours to match.
    fn affected(&self) -> impl Iterator<Item = &OsvAffected> {
        self.affected
            .iter()
            .flatten()
            .filter(|a| a.package.ecosystem == ECOSYSTEM)
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
/// SEMVER/ECOSYSTEM ranges (crates.io versions are semver either way).
fn collect_affected(affected: &OsvAffected, stored_versions: &[String]) -> CollectedAffected {
    let listed: HashSet<&str> = affected
        .versions
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let ranges: Vec<&OsvRange> = affected
        .ranges
        .iter()
        .flatten()
        .filter(|r| r.kind == "SEMVER" || r.kind == "ECOSYSTEM")
        .collect();

    let affected_versions = stored_versions
        .iter()
        .filter(|v| {
            listed.contains(v.as_str())
                || Version::parse(v)
                    .is_ok_and(|parsed| ranges.iter().any(|r| range_contains(&r.events, &parsed)))
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
        platform: ECOSYSTEM.to_string(),
        affected_versions,
        ranges: ranges.iter().flat_map(|r| describe_range(&r.events)).collect(),
        fixed_in,
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
        prepare(records)
            .into_iter()
            .map(|p| (p.record.id.clone(), p))
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
                platform: Some(ECOSYSTEM.to_string()),
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
        let mut record: OsvRecord =
            serde_json::from_str(include_str!("../../testdata/osv/RUSTSEC-2016-0001.json")).unwrap();
        for a in record.affected.iter_mut().flatten() {
            a.package.ecosystem = "npm".to_string();
        }
        let p = Prepared {
            record,
            severity: VulnerabilitySeverity::High,
        };
        let openssl = lookup("openssl", &["0.8.3"]);
        assert!(collect(&p, &openssl).is_none());
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
