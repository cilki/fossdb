use anyhow::{Result, bail};
use fossdb::{AnalysisFinding, FindingKind, FindingSeverity};
use regex::Regex;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

/// Hard cap on total bytes written while unpacking an archive.
///
/// Neither `tar` nor `zip` limits decompressed size by default, so a ~100 MB
/// download (`MAX_DOWNLOAD_BYTES`) can expand to terabytes: DEFLATE reaches
/// ~1032:1 and bzip2 far more. The temp dir is frequently tmpfs, so an
/// unbounded unpack exhausts host memory, not just disk.
const MAX_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024; // 512 MB

/// Hard cap on archive entries, to bound inode usage and the per-file scanning
/// work that follows extraction.
const MAX_ARCHIVE_ENTRIES: usize = 50_000;

/// Largest file that will be read into memory for text scanning.
const MAX_SCANNED_FILE_BYTES: u64 = 1_000_000;

/// Source archive formats the worker knows how to unpack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    TarGz,
    TarBz2,
    Zip,
}

/// Result of analyzing a source archive.
#[derive(Debug, Default)]
pub struct SourceAnalysis {
    pub findings: Vec<AnalysisFinding>,
    /// SPDX ids of every recognized license file, deduplicated and sorted.
    ///
    /// Returned explicitly rather than recovered by string-parsing the finding
    /// descriptions, and covering *all* license files rather than whichever one
    /// the directory walk happened to yield first.
    pub detected_licenses: Vec<&'static str>,
}

/// Sniff the archive format from the file's leading bytes.
///
/// Download URLs are not a reliable signal: crates.io serves gzipped tarballs
/// from `/api/v1/crates/<name>/<version>/download` with no extension at all,
/// and the file is always written to an extension-less temp path anyway.
pub fn detect_format(path: &Path) -> Result<Option<ArchiveFormat>> {
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0u8; 4];
    // `read` may return a short count even when more data is available, so fill
    // the buffer in a loop before matching magic bytes.
    let mut filled = 0;
    while filled < magic.len() {
        match file.read(&mut magic[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(detect_format_from_magic(&magic[..filled]))
}

fn detect_format_from_magic(magic: &[u8]) -> Option<ArchiveFormat> {
    if magic.starts_with(&[0x1f, 0x8b]) {
        Some(ArchiveFormat::TarGz)
    } else if magic.starts_with(b"BZh") {
        Some(ArchiveFormat::TarBz2)
    } else if magic.starts_with(b"PK\x03\x04") || magic.starts_with(b"PK\x05\x06") {
        Some(ArchiveFormat::Zip)
    } else {
        None
    }
}

pub fn analyze_archive(path: &Path, format: ArchiveFormat) -> Result<SourceAnalysis> {
    match format {
        ArchiveFormat::TarGz => extract_and_analyze_targz(path),
        ArchiveFormat::TarBz2 => extract_and_analyze_tarbz2(path),
        ArchiveFormat::Zip => extract_and_analyze_zip(path),
    }
}

/// Unpack a tar stream with explicit size and entry-count limits.
///
/// Entries are iterated manually instead of calling `Archive::unpack`, which
/// has no limits at all. `unpack_in` is still used per entry, so the
/// path-traversal and symlink-escape protections in `tar` are preserved.
#[cfg(feature = "analysis-source")]
fn unpack_tar_limited<R: Read>(reader: R, dest: &Path) -> Result<()> {
    // Backstop against headers that understate their true size: the underlying
    // stream itself cannot yield more than the cap.
    let mut archive = tar::Archive::new(reader.take(MAX_UNCOMPRESSED_BYTES));

    let mut entries = 0usize;
    let mut declared_total = 0u64;

    for entry in archive.entries()? {
        let mut entry = entry?;

        entries += 1;
        if entries > MAX_ARCHIVE_ENTRIES {
            bail!("archive has more than {} entries", MAX_ARCHIVE_ENTRIES);
        }

        declared_total = declared_total.saturating_add(entry.size());
        if declared_total > MAX_UNCOMPRESSED_BYTES {
            bail!(
                "archive expands to more than {} bytes",
                MAX_UNCOMPRESSED_BYTES
            );
        }

        entry.unpack_in(dest)?;
    }

    Ok(())
}

#[cfg(feature = "analysis-source")]
fn extract_and_analyze_targz(path: &Path) -> Result<SourceAnalysis> {
    use flate2::read::GzDecoder;

    let file = std::fs::File::open(path)?;
    let tmp = tempfile::tempdir()?;
    unpack_tar_limited(GzDecoder::new(file), tmp.path())?;
    analyze_directory(tmp.path())
}

#[cfg(not(feature = "analysis-source"))]
fn extract_and_analyze_targz(_path: &Path) -> Result<SourceAnalysis> {
    Ok(SourceAnalysis::default())
}

#[cfg(feature = "analysis-source")]
fn extract_and_analyze_tarbz2(path: &Path) -> Result<SourceAnalysis> {
    use bzip2::read::BzDecoder;

    let file = std::fs::File::open(path)?;
    let tmp = tempfile::tempdir()?;
    unpack_tar_limited(BzDecoder::new(file), tmp.path())?;
    analyze_directory(tmp.path())
}

#[cfg(not(feature = "analysis-source"))]
fn extract_and_analyze_tarbz2(_path: &Path) -> Result<SourceAnalysis> {
    Ok(SourceAnalysis::default())
}

#[cfg(feature = "analysis-source")]
fn extract_and_analyze_zip(path: &Path) -> Result<SourceAnalysis> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    if archive.len() > MAX_ARCHIVE_ENTRIES {
        bail!(
            "archive has {} entries, more than the {} limit",
            archive.len(),
            MAX_ARCHIVE_ENTRIES
        );
    }

    let tmp = tempfile::tempdir()?;
    // `extract` defaults to `size_limit: None`, i.e. no bomb protection at all.
    // With a limit set, the total decompressed size is checked up front and an
    // archive that does not declare its sizes is rejected rather than trusted.
    archive.extract_with_options(
        tmp.path(),
        zip::read::ExtractOptions::default().with_size_limit(MAX_UNCOMPRESSED_BYTES),
    )?;
    analyze_directory(tmp.path())
}

#[cfg(not(feature = "analysis-source"))]
fn extract_and_analyze_zip(_path: &Path) -> Result<SourceAnalysis> {
    Ok(SourceAnalysis::default())
}

fn is_license_filename(filename: &str) -> bool {
    filename.starts_with("LICENSE") || filename.starts_with("COPYING") || filename.starts_with("LICENCE")
}

fn analyze_directory(dir: &Path) -> Result<SourceAnalysis> {
    let mut findings = Vec::new();
    let mut detected: BTreeSet<&'static str> = BTreeSet::new();
    let mut license_files_seen = 0usize;

    // `sort_by_file_name` keeps results deterministic; the default walk order is
    // whatever the OS returns, which made the reported license vary run to run
    // for dual-licensed projects (LICENSE-APACHE + LICENSE-MIT).
    let walk = walkdir::WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok());

    for entry in walk {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_uppercase();

        // Use the walk's own metadata (no extra stat, and no hard error if the
        // file vanished between listing and inspection).
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.len() > MAX_SCANNED_FILE_BYTES {
            continue;
        }

        let rel_path = || {
            path.strip_prefix(dir)
                .unwrap_or(path)
                .to_string_lossy()
                .into_owned()
        };

        if is_license_filename(&filename) {
            license_files_seen += 1;
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some(spdx) = detect_license(&content) {
                    if detected.insert(spdx) {
                        findings.push(AnalysisFinding {
                            kind: FindingKind::LicenseDetected,
                            severity: FindingSeverity::Info,
                            description: format!("License file detected: {}", spdx),
                            location: Some(rel_path()),
                        });
                    }
                }
            }
        }

        // Scan source files for secrets
        let ext = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if matches!(
            ext.as_str(),
            "rs" | "py" | "js" | "ts" | "go" | "java" | "c" | "cpp" | "h" | "rb" | "sh"
                | "yaml" | "yml" | "toml" | "json" | "env" | "cfg" | "conf" | "ini"
        ) {
            if let Ok(content) = std::fs::read_to_string(path) {
                findings.extend(scan_secrets(&content, &rel_path()));
            }
        }
    }

    findings.extend(super::hooks::detect_install_hooks(&super::hooks::package_root(dir)));

    // Distinguish "no license file at all" from "license file present but its
    // text is not one we recognize" - the previous code reported both as
    // "No license file found", which was simply untrue for the second case.
    if license_files_seen == 0 {
        findings.push(AnalysisFinding {
            kind: FindingKind::LicenseMismatch,
            severity: FindingSeverity::Low,
            description: "No license file found in source archive".to_string(),
            location: None,
        });
    } else if detected.is_empty() {
        findings.push(AnalysisFinding {
            kind: FindingKind::LicenseUnrecognized,
            severity: FindingSeverity::Low,
            description: format!(
                "{} license file(s) present but no recognized license text",
                license_files_seen
            ),
            location: None,
        });
    }

    Ok(SourceAnalysis {
        findings,
        detected_licenses: detected.into_iter().collect(),
    })
}

fn detect_license(content: &str) -> Option<&'static str> {
    let upper = content.to_uppercase();

    // Order matters. The Lesser and Affero variants both quote the plain "GNU
    // General Public License" in their own text, so the specific variants must
    // be tested before the generic GPL patterns or LGPL/AGPL would be reported
    // as GPL. Likewise "VERSION 2.1" is checked before "VERSION 2", since the
    // latter is a substring of the former.
    if upper.contains("MIT LICENSE")
        || upper.contains("PERMISSION IS HEREBY GRANTED, FREE OF CHARGE")
    {
        Some("MIT")
    } else if upper.contains("APACHE LICENSE") && upper.contains("VERSION 2.0") {
        Some("Apache-2.0")
    } else if upper.contains("GNU AFFERO GENERAL PUBLIC LICENSE") {
        if upper.contains("VERSION 3") {
            Some("AGPL-3.0")
        } else {
            Some("AGPL-1.0")
        }
    } else if upper.contains("GNU LESSER GENERAL PUBLIC LICENSE") {
        if upper.contains("VERSION 3") {
            Some("LGPL-3.0")
        } else if upper.contains("VERSION 2.1") {
            Some("LGPL-2.1")
        } else {
            Some("LGPL-2.0")
        }
    } else if upper.contains("GNU LIBRARY GENERAL PUBLIC LICENSE") {
        Some("LGPL-2.0")
    } else if upper.contains("GNU GENERAL PUBLIC LICENSE") {
        if upper.contains("VERSION 3") {
            Some("GPL-3.0")
        } else if upper.contains("VERSION 2") {
            Some("GPL-2.0")
        } else if upper.contains("VERSION 1") {
            Some("GPL-1.0")
        } else {
            None
        }
    } else if upper.contains("MOZILLA PUBLIC LICENSE") {
        Some("MPL-2.0")
    } else if upper.contains("ISC LICENSE")
        || (upper.contains("ISC") && upper.contains("PERMISSION TO USE, COPY, MODIFY"))
    {
        Some("ISC")
    } else if upper.contains("BSD 2-CLAUSE") || upper.contains("SIMPLIFIED BSD") {
        Some("BSD-2-Clause")
    } else if upper.contains("BSD 3-CLAUSE") || upper.contains("NEW BSD") {
        Some("BSD-3-Clause")
    } else if upper.contains("THIS IS FREE AND UNENCUMBERED SOFTWARE RELEASED INTO THE PUBLIC DOMAIN")
    {
        Some("Unlicense")
    } else if upper.contains("CREATIVE COMMONS") {
        Some("CC")
    } else if upper.contains("EUROPEAN UNION PUBLIC LICENCE") {
        Some("EUPL")
    } else {
        None
    }
}

/// Secret-scanning patterns, compiled once rather than per scanned file.
#[allow(clippy::type_complexity)]
static SECRET_PATTERNS: LazyLock<Vec<(Regex, &'static str, FindingSeverity)>> = LazyLock::new(|| {
    let specs: &[(&str, &str, FindingSeverity)] = &[
        (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "Private key material",
            FindingSeverity::Critical,
        ),
        (r"AKIA[0-9A-Z]{16}", "AWS access key", FindingSeverity::Critical),
        (
            r#"(?i)aws.{0,20}secret.{0,20}['"][A-Za-z0-9/+]{40}['"]"#,
            "AWS secret key",
            FindingSeverity::Critical,
        ),
        (
            r"ghp_[A-Za-z0-9]{36}",
            "GitHub personal access token",
            FindingSeverity::High,
        ),
        (
            r"github_pat_[A-Za-z0-9_]{82}",
            "GitHub fine-grained token",
            FindingSeverity::High,
        ),
        (
            r#"(?i)password\s*=\s*['"][^'"]{8,}['"]"#,
            "Hardcoded password",
            FindingSeverity::Medium,
        ),
        (
            r#"(?i)api[_-]?key\s*[=:]\s*['"][A-Za-z0-9\-_]{20,}['"]"#,
            "Hardcoded API key",
            FindingSeverity::Medium,
        ),
        (
            r"://[^:@/\s]+:[^@/\s]+@",
            "Credentials in URL",
            FindingSeverity::High,
        ),
    ];

    specs
        .iter()
        .filter_map(|(pattern, description, severity)| {
            match Regex::new(pattern) {
                Ok(re) => Some((re, *description, severity.clone())),
                Err(e) => {
                    // A literal in this table failed to compile; that is a bug
                    // in the table, so make it visible rather than silently
                    // dropping the detection.
                    tracing::error!("Invalid secret pattern {:?}: {}", pattern, e);
                    None
                }
            }
        })
        .collect()
});

fn scan_secrets(content: &str, location: &str) -> Vec<AnalysisFinding> {
    SECRET_PATTERNS
        .iter()
        .filter(|(re, _, _)| re.is_match(content))
        .map(|(_, description, severity)| AnalysisFinding {
            kind: FindingKind::SecretDetected,
            severity: severity.clone(),
            description: description.to_string(),
            location: Some(location.to_string()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_format_by_magic_bytes() {
        assert_eq!(detect_format_from_magic(&[0x1f, 0x8b, 0x08, 0x00]), Some(ArchiveFormat::TarGz));
        assert_eq!(detect_format_from_magic(b"BZh9"), Some(ArchiveFormat::TarBz2));
        assert_eq!(detect_format_from_magic(b"PK\x03\x04"), Some(ArchiveFormat::Zip));
        assert_eq!(detect_format_from_magic(b"\x7fELF"), None);
        assert_eq!(detect_format_from_magic(b"MZ"), None);
        assert_eq!(detect_format_from_magic(b""), None);
    }

    /// The Lesser/Affero variants quote the plain GPL name in their own text, so
    /// a naive generic-GPL-first ordering misreports them.
    #[test]
    fn lesser_and_affero_are_not_reported_as_gpl() {
        let lgpl3 = "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n\
            This version of the GNU Lesser General Public License incorporates the terms \
            and conditions of version 3 of the GNU General Public License.";
        assert_eq!(detect_license(lgpl3), Some("LGPL-3.0"));

        let lgpl21 = "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999\n\
            This license, the Lesser General Public License, applies to some specially \
            designated software packages. We sometimes refer to the ordinary GNU General \
            Public License.";
        assert_eq!(detect_license(lgpl21), Some("LGPL-2.1"));

        let agpl3 = "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n\
            13. Remote Network Interaction; Use with the GNU General Public License.";
        assert_eq!(detect_license(agpl3), Some("AGPL-3.0"));
    }

    #[test]
    fn plain_gpl_versions_still_detected() {
        let gpl3 = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007";
        assert_eq!(detect_license(gpl3), Some("GPL-3.0"));

        let gpl2 = "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991";
        assert_eq!(detect_license(gpl2), Some("GPL-2.0"));
    }

    #[test]
    fn unknown_license_text_is_not_detected() {
        assert_eq!(detect_license("All rights reserved. Internal use only."), None);
    }

    #[cfg(feature = "analysis-source")]
    fn targz_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};

        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *content).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[cfg(feature = "analysis-source")]
    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        tmp
    }

    /// A crates.io `.crate` file is a gzipped tarball served from a URL with no
    /// extension, and the worker always writes downloads to an extension-less
    /// temp file. Source analysis must still run on it.
    #[cfg(feature = "analysis-source")]
    #[test]
    fn analyzes_extensionless_targz() {
        let mit = "MIT License\n\nPermission is hereby granted, free of charge, to any person...";
        let src = "const TOKEN: &str = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\";\n";

        let bytes = targz_of(&[
            ("pkg-1.0.0/LICENSE", mit.as_bytes()),
            ("pkg-1.0.0/src/lib.rs", src.as_bytes()),
        ]);
        let tmp = write_temp(&bytes);
        assert!(tmp.path().extension().is_none());

        let format = detect_format(tmp.path()).unwrap().expect("gzip should be detected");
        assert_eq!(format, ArchiveFormat::TarGz);

        let analysis = analyze_archive(tmp.path(), format).unwrap();
        assert_eq!(analysis.detected_licenses, vec!["MIT"]);
        assert!(
            analysis.findings.iter().any(|f| f.kind == FindingKind::SecretDetected
                && f.location.as_deref() == Some("pkg-1.0.0/src/lib.rs")),
            "expected secret finding, got {:?}",
            analysis.findings
        );
        assert!(
            !analysis.findings.iter().any(|f| f.kind == FindingKind::LicenseMismatch),
            "license was present, got {:?}",
            analysis.findings
        );
    }

    /// Dual-licensed projects must report both licenses, not whichever file the
    /// directory walk happened to reach first.
    #[cfg(feature = "analysis-source")]
    #[test]
    fn reports_every_detected_license() {
        let mit = "MIT License\n\nPermission is hereby granted, free of charge, to any person...";
        let apache = "Apache License\nVersion 2.0, January 2004";

        let bytes = targz_of(&[
            ("pkg/LICENSE-MIT", mit.as_bytes()),
            ("pkg/LICENSE-APACHE", apache.as_bytes()),
        ]);
        let tmp = write_temp(&bytes);

        let analysis = analyze_archive(tmp.path(), ArchiveFormat::TarGz).unwrap();
        assert_eq!(analysis.detected_licenses, vec!["Apache-2.0", "MIT"]);
    }

    /// A license file whose text we do not recognize must not be reported as
    /// "no license file found".
    #[cfg(feature = "analysis-source")]
    #[test]
    fn unrecognized_license_is_distinct_from_missing() {
        let bytes = targz_of(&[("pkg/LICENSE", b"Totally bespoke terms, see lawyer.")]);
        let tmp = write_temp(&bytes);

        let analysis = analyze_archive(tmp.path(), ArchiveFormat::TarGz).unwrap();
        assert!(analysis.detected_licenses.is_empty());
        assert!(
            analysis
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::LicenseUnrecognized),
            "got {:?}",
            analysis.findings
        );
        assert!(
            !analysis
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::LicenseMismatch),
            "must not claim the license file is absent, got {:?}",
            analysis.findings
        );
    }

    #[cfg(feature = "analysis-source")]
    #[test]
    fn missing_license_is_reported() {
        let bytes = targz_of(&[("pkg/src/lib.rs", b"fn main() {}")]);
        let tmp = write_temp(&bytes);

        let analysis = analyze_archive(tmp.path(), ArchiveFormat::TarGz).unwrap();
        assert!(analysis.detected_licenses.is_empty());
        assert!(
            analysis
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::LicenseMismatch
                    && f.description.contains("No license file")),
            "got {:?}",
            analysis.findings
        );
    }

    /// Install hooks are keyed relative to the package root, so the same hook
    /// in two releases has the same location even though each tarball wraps
    /// its files in a differently named versioned directory.
    #[cfg(feature = "analysis-source")]
    #[test]
    fn install_hook_locations_are_stable_across_versions() {
        let hooks_of = |top: &str| {
            let package_json = br#"{"scripts":{"postinstall":"node install.js"}}"#;
            let bytes = targz_of(&[
                (&format!("{}/package.json", top), package_json.as_slice()),
                (&format!("{}/test/fixture/package.json", top), package_json.as_slice()),
            ]);
            let tmp = write_temp(&bytes);
            let analysis = analyze_archive(tmp.path(), ArchiveFormat::TarGz).unwrap();
            analysis
                .findings
                .into_iter()
                .filter(|f| f.kind == FindingKind::InstallHook)
                .map(|f| f.location.unwrap())
                .collect::<Vec<_>>()
        };

        assert_eq!(hooks_of("left-pad-1.3.0"), vec!["package.json:scripts.postinstall"]);
        assert_eq!(hooks_of("left-pad-1.3.1"), hooks_of("left-pad-1.3.0"));
    }

    /// A decompression bomb must be rejected rather than filling the disk. A
    /// highly compressible 600 MB member compresses to a few hundred KB.
    #[cfg(feature = "analysis-source")]
    #[test]
    fn rejects_decompression_bomb() {
        use flate2::{Compression, write::GzEncoder};

        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let chunk = vec![0u8; 1024 * 1024];
        let declared = MAX_UNCOMPRESSED_BYTES + 100 * 1024 * 1024;
        let mut header = tar::Header::new_gnu();
        header.set_size(declared);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append(&header, std::io::repeat(0).take(declared))
            .unwrap();
        drop(chunk);
        let bytes = builder.into_inner().unwrap().finish().unwrap();

        let tmp = write_temp(&bytes);
        let err = analyze_archive(tmp.path(), ArchiveFormat::TarGz)
            .expect_err("a 600 MB expansion must be refused");
        assert!(
            err.to_string().contains("expands to more than"),
            "unexpected error: {}",
            err
        );
    }

    /// Entry-count limits bound inode usage and post-extraction scanning work.
    #[cfg(feature = "analysis-source")]
    #[test]
    fn rejects_too_many_entries() {
        use flate2::{Compression, write::GzEncoder};

        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for i in 0..(MAX_ARCHIVE_ENTRIES + 1) {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("pkg/f{}", i), std::io::empty())
                .unwrap();
        }
        let bytes = builder.into_inner().unwrap().finish().unwrap();

        let tmp = write_temp(&bytes);
        let err = analyze_archive(tmp.path(), ArchiveFormat::TarGz)
            .expect_err("entry count over the cap must be refused");
        assert!(
            err.to_string().contains("more than"),
            "unexpected error: {}",
            err
        );
    }

    /// Build a raw tar archive with an arbitrary entry name.
    ///
    /// `tar::Builder` refuses to *write* a `..` path, so a malicious archive
    /// cannot be produced with the normal API and the header must be assembled
    /// by hand to exercise the extraction-side guard.
    #[cfg(feature = "analysis-source")]
    fn raw_tar(name: &str, content: &[u8]) -> Vec<u8> {
        let mut block = [0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..108].copy_from_slice(b"0000644\0");
        block[108..116].copy_from_slice(b"0000000\0");
        block[116..124].copy_from_slice(b"0000000\0");
        block[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
        block[136..148].copy_from_slice(b"00000000000\0");
        // Checksum is computed with this field filled with spaces.
        block[148..156].copy_from_slice(b"        ");
        block[156] = b'0'; // regular file
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");

        let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
        block[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());

        let mut out = block.to_vec();
        out.extend_from_slice(content);
        if content.len() % 512 != 0 {
            out.resize(out.len() + (512 - content.len() % 512), 0);
        }
        out.extend_from_slice(&[0u8; 1024]); // end-of-archive marker
        out
    }

    /// Path traversal is handled by `tar`, but assert it so a future switch to a
    /// manual write loop cannot silently regress it.
    #[cfg(feature = "analysis-source")]
    #[test]
    fn does_not_write_outside_destination() {
        let dest = tempfile::tempdir().unwrap();
        let escaped = dest.path().parent().unwrap().join("fossdb-escaped.txt");
        let _ = std::fs::remove_file(&escaped);

        let archive = raw_tar("../fossdb-escaped.txt", b"nope");
        // Either the entry is refused outright or it is skipped; both are fine,
        // what matters is that nothing lands outside `dest`.
        let _ = unpack_tar_limited(archive.as_slice(), dest.path());

        assert!(!escaped.exists(), "entry escaped the destination directory");
    }

    /// An absolute entry path must also stay inside the destination.
    #[cfg(feature = "analysis-source")]
    #[test]
    fn does_not_honour_absolute_entry_paths() {
        let dest = tempfile::tempdir().unwrap();
        let archive = raw_tar("/tmp/fossdb-absolute-escape.txt", b"nope");
        let _ = std::fs::remove_file("/tmp/fossdb-absolute-escape.txt");

        let _ = unpack_tar_limited(archive.as_slice(), dest.path());

        assert!(
            !Path::new("/tmp/fossdb-absolute-escape.txt").exists(),
            "absolute path escaped the destination directory"
        );
    }
}
