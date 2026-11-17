pub mod binary;
mod hooks;
pub mod source;
#[cfg(feature = "analysis-symbolic")]
pub mod symbolic;

use anyhow::Result;
use chrono::Utc;
use fossdb::{AnalysisFinding, FindingKind, FindingSeverity, WorkerAnalysis, WorkerTask};
use sha2::{Digest, Sha256};
use std::io::Write;

const MAX_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024; // 100 MB

pub async fn analyze(task: &WorkerTask, http: &reqwest::Client) -> Result<WorkerAnalysis> {
    let download_url = task
        .version
        .download_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No download URL for version"))?;

    tracing::info!(
        "Analyzing {}@{} from {}",
        task.package.name,
        task.version.version,
        download_url
    );

    let tmp = tempfile::NamedTempFile::new()?;
    let (actual_checksum, bytes_downloaded) = download(http, download_url, tmp.path()).await?;
    tracing::debug!("Downloaded {} bytes, sha256={}", bytes_downloaded, actual_checksum);

    let mut findings = Vec::new();

    // Verify checksum if available.
    //
    // Only hex SHA-256 can be compared against what `download` computes. Any
    // other digest (MD5, SHA-512, `sha512-<base64>` SRI, nix base32) would
    // never be equal, and reporting that as a High-severity mismatch would be
    // a false accusation of tampering - so it is surfaced as "unsupported"
    // with `checksum_verified = None` instead.
    let checksum_verified = match task.version.checksum.as_deref() {
        Some(expected) => {
            let expected_norm = expected
                .trim()
                .trim_start_matches("sha256:")
                .trim_start_matches("sha256-")
                .to_lowercase();

            if is_hex_sha256(&expected_norm) {
                let matches = actual_checksum.to_lowercase() == expected_norm;
                if !matches {
                    findings.push(AnalysisFinding {
                        kind: FindingKind::ChecksumMismatch,
                        severity: FindingSeverity::High,
                        description: format!(
                            "Expected checksum {}, got {}",
                            expected, actual_checksum
                        ),
                        location: Some(download_url.to_string()),
                    });
                }
                Some(matches)
            } else {
                tracing::warn!(
                    "Unsupported checksum format for {}@{}: {:?}",
                    task.package.name,
                    task.version.version,
                    expected
                );
                None
            }
        }
        None => None,
    };

    // Detect format from the file contents and dispatch to appropriate analyzer
    let mut detected_licenses: Vec<&'static str> = Vec::new();
    match source::detect_format(tmp.path())? {
        Some(format) => {
            tracing::debug!("Detected source archive format {:?}", format);
            match source::analyze_archive(tmp.path(), format) {
                Ok(mut analysis) => {
                    findings.append(&mut analysis.findings);
                    detected_licenses = analysis.detected_licenses;
                }
                Err(e) => tracing::warn!("Source analysis failed: {}", e),
            }
        }
        None => match binary::analyze(tmp.path(), &task.package.name) {
            Ok(mut binary_findings) => findings.append(&mut binary_findings),
            Err(e) => tracing::warn!("Binary analysis failed: {}", e),
        },
    }

    // Check the declared license against *every* detected license: a
    // dual-licensed project legitimately ships several license files, and
    // matching only the first one produced spurious mismatches.
    if let Some(declared) = &task.package.license {
        if !detected_licenses.is_empty() {
            let declared_upper = declared.to_uppercase();
            let any_match = detected_licenses.iter().any(|detected| {
                let detected_upper = detected.to_uppercase();
                declared_upper.contains(&detected_upper) || detected_upper.contains(&declared_upper)
            });

            if !any_match {
                findings.push(AnalysisFinding {
                    kind: FindingKind::LicenseMismatch,
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Declared license '{}' does not match detected '{}'",
                        declared,
                        detected_licenses.join(" OR ")
                    ),
                    location: None,
                });
            }
        }
    }

    let detected_license = if detected_licenses.is_empty() {
        None
    } else {
        Some(detected_licenses.join(" OR "))
    };

    Ok(WorkerAnalysis {
        id: 0,
        package_id: task.package.id,
        version_id: task.version.id,
        analyzed_at: Utc::now(),
        findings,
        checksum_verified,
        detected_license,
    })
}

/// True for a bare hex-encoded SHA-256 digest, the only format `download`
/// produces and therefore the only one that can be meaningfully compared.
fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn download(
    http: &reqwest::Client,
    url: &str,
    dest: &std::path::Path,
) -> Result<(String, u64)> {
    let mut response = http.get(url).send().await?.error_for_status()?;

    let mut file = std::fs::File::create(dest)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;

    while let Some(chunk) = response.chunk().await? {
        if total.saturating_add(chunk.len() as u64) > MAX_DOWNLOAD_BYTES {
            return Err(anyhow::anyhow!(
                "Download exceeds {} byte limit",
                MAX_DOWNLOAD_BYTES
            ));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)?;
        total += chunk.len() as u64;
    }

    let checksum = hex::encode(hasher.finalize());
    Ok((checksum, total))
}
