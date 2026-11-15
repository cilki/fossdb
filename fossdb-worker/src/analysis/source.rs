use anyhow::Result;
use fossdb::{AnalysisFinding, FindingKind, FindingSeverity};
use regex::Regex;
use std::io::Read;
use std::path::Path;

/// Source archive formats the worker knows how to unpack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    TarGz,
    TarBz2,
    Zip,
}

/// Sniff the archive format from the file's leading bytes.
///
/// Download URLs are not a reliable signal: crates.io serves gzipped tarballs
/// from `/api/v1/crates/<name>/<version>/download` with no extension at all,
/// and the file is always written to an extension-less temp path anyway.
pub fn detect_format(path: &Path) -> Result<Option<ArchiveFormat>> {
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0u8; 4];
    let n = file.read(&mut magic)?;
    Ok(detect_format_from_magic(&magic[..n]))
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

pub fn analyze_archive(path: &Path, format: ArchiveFormat) -> Result<Vec<AnalysisFinding>> {
    match format {
        ArchiveFormat::TarGz => extract_and_analyze_targz(path),
        ArchiveFormat::TarBz2 => extract_and_analyze_tarbz2(path),
        ArchiveFormat::Zip => extract_and_analyze_zip(path),
    }
}

#[cfg(feature = "analysis-source")]
fn extract_and_analyze_targz(path: &Path) -> Result<Vec<AnalysisFinding>> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let file = std::fs::File::open(path)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let tmp = tempfile::tempdir()?;
    archive.unpack(tmp.path())?;
    analyze_directory(tmp.path())
}

#[cfg(not(feature = "analysis-source"))]
fn extract_and_analyze_targz(_path: &Path) -> Result<Vec<AnalysisFinding>> {
    Ok(vec![])
}

#[cfg(feature = "analysis-source")]
fn extract_and_analyze_tarbz2(path: &Path) -> Result<Vec<AnalysisFinding>> {
    use bzip2::read::BzDecoder;
    use tar::Archive;

    let file = std::fs::File::open(path)?;
    let bz = BzDecoder::new(file);
    let mut archive = Archive::new(bz);

    let tmp = tempfile::tempdir()?;
    archive.unpack(tmp.path())?;
    analyze_directory(tmp.path())
}

#[cfg(not(feature = "analysis-source"))]
fn extract_and_analyze_tarbz2(_path: &Path) -> Result<Vec<AnalysisFinding>> {
    Ok(vec![])
}

#[cfg(feature = "analysis-source")]
fn extract_and_analyze_zip(path: &Path) -> Result<Vec<AnalysisFinding>> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let tmp = tempfile::tempdir()?;
    archive.extract(tmp.path())?;
    analyze_directory(tmp.path())
}

#[cfg(not(feature = "analysis-source"))]
fn extract_and_analyze_zip(_path: &Path) -> Result<Vec<AnalysisFinding>> {
    Ok(vec![])
}

fn analyze_directory(dir: &Path) -> Result<Vec<AnalysisFinding>> {
    let mut findings = Vec::new();
    let mut license_found = false;

    for entry in walkdir::WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let filename = path.file_name().unwrap_or_default().to_string_lossy().to_uppercase();

        // Only scan text-like files (skip large files)
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > 1_000_000 {
            continue;
        }

        if filename.starts_with("LICENSE")
            || filename.starts_with("COPYING")
            || filename.starts_with("LICENCE")
        {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some(spdx) = detect_license(&content) {
                    findings.push(AnalysisFinding {
                        kind: FindingKind::LicenseDetected,
                        severity: FindingSeverity::Info,
                        description: format!("License file detected: {}", spdx),
                        location: Some(
                            path.strip_prefix(dir)
                                .unwrap_or(path)
                                .to_string_lossy()
                                .into_owned(),
                        ),
                    });
                    license_found = true;
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
                let rel_path = path
                    .strip_prefix(dir)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .into_owned();
                findings.extend(scan_secrets(&content, &rel_path));
            }
        }
    }

    if !license_found {
        findings.push(AnalysisFinding {
            kind: FindingKind::LicenseMismatch,
            severity: FindingSeverity::Low,
            description: "No license file found in source archive".to_string(),
            location: None,
        });
    }

    Ok(findings)
}

fn detect_license(content: &str) -> Option<&'static str> {
    let upper = content.to_uppercase();

    if upper.contains("MIT LICENSE") || upper.contains("PERMISSION IS HEREBY GRANTED, FREE OF CHARGE") {
        Some("MIT")
    } else if upper.contains("APACHE LICENSE") && upper.contains("VERSION 2.0") {
        Some("Apache-2.0")
    } else if upper.contains("GNU GENERAL PUBLIC LICENSE") && upper.contains("VERSION 3") {
        Some("GPL-3.0")
    } else if upper.contains("GNU GENERAL PUBLIC LICENSE") && upper.contains("VERSION 2") {
        Some("GPL-2.0")
    } else if upper.contains("GNU LESSER GENERAL PUBLIC LICENSE") && upper.contains("VERSION 3") {
        Some("LGPL-3.0")
    } else if upper.contains("GNU LESSER GENERAL PUBLIC LICENSE") && upper.contains("VERSION 2") {
        Some("LGPL-2.0")
    } else if upper.contains("MOZILLA PUBLIC LICENSE") {
        Some("MPL-2.0")
    } else if upper.contains("ISC LICENSE") || (upper.contains("ISC") && upper.contains("PERMISSION TO USE, COPY, MODIFY")) {
        Some("ISC")
    } else if upper.contains("BSD 2-CLAUSE") || upper.contains("SIMPLIFIED BSD") {
        Some("BSD-2-Clause")
    } else if upper.contains("BSD 3-CLAUSE") || upper.contains("NEW BSD") {
        Some("BSD-3-Clause")
    } else if upper.contains("THIS IS FREE AND UNENCUMBERED SOFTWARE RELEASED INTO THE PUBLIC DOMAIN") {
        Some("Unlicense")
    } else if upper.contains("CREATIVE COMMONS") {
        Some("CC")
    } else if upper.contains("EUROPEAN UNION PUBLIC LICENCE") {
        Some("EUPL")
    } else {
        None
    }
}

fn scan_secrets(content: &str, location: &str) -> Vec<AnalysisFinding> {
    let patterns: &[(&str, &str, FindingSeverity)] = &[
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key material", FindingSeverity::Critical),
        (r"AKIA[0-9A-Z]{16}", "AWS access key", FindingSeverity::Critical),
        (r#"(?i)aws.{0,20}secret.{0,20}['"][A-Za-z0-9/+]{40}['"]"#, "AWS secret key", FindingSeverity::Critical),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token", FindingSeverity::High),
        (r"github_pat_[A-Za-z0-9_]{82}", "GitHub fine-grained token", FindingSeverity::High),
        (r#"(?i)password\s*=\s*['"][^'"]{8,}['"]"#, "Hardcoded password", FindingSeverity::Medium),
        (r#"(?i)api[_-]?key\s*[=:]\s*['"][A-Za-z0-9\-_]{20,}['"]"#, "Hardcoded API key", FindingSeverity::Medium),
        (r"://[^:@/\s]+:[^@/\s]+@", "Credentials in URL", FindingSeverity::High),
    ];

    let mut findings = Vec::new();
    for (pattern, description, severity) in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(content) {
                findings.push(AnalysisFinding {
                    kind: FindingKind::SecretDetected,
                    severity: severity.clone(),
                    description: description.to_string(),
                    location: Some(location.to_string()),
                });
            }
        }
    }
    findings
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

    /// A crates.io `.crate` file is a gzipped tarball served from a URL with no
    /// extension, and the worker always writes downloads to an extension-less
    /// temp file. Source analysis must still run on it.
    #[cfg(feature = "analysis-source")]
    #[test]
    fn analyzes_extensionless_targz() {
        use flate2::{Compression, write::GzEncoder};

        let mit = "MIT License\n\nPermission is hereby granted, free of charge, to any person...";
        let src = "const TOKEN: &str = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\";\n";

        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (name, content) in [("pkg-1.0.0/LICENSE", mit), ("pkg-1.0.0/src/lib.rs", src)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, content.as_bytes()).unwrap();
        }
        let bytes = builder.into_inner().unwrap().finish().unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &bytes).unwrap();
        assert!(tmp.path().extension().is_none());

        let format = detect_format(tmp.path()).unwrap().expect("gzip should be detected");
        assert_eq!(format, ArchiveFormat::TarGz);

        let findings = analyze_archive(tmp.path(), format).unwrap();
        assert!(
            findings.iter().any(|f| f.kind == FindingKind::LicenseDetected
                && f.description == "License file detected: MIT"),
            "expected MIT license finding, got {:?}",
            findings
        );
        assert!(
            findings.iter().any(|f| f.kind == FindingKind::SecretDetected
                && f.location.as_deref() == Some("pkg-1.0.0/src/lib.rs")),
            "expected secret finding, got {:?}",
            findings
        );
        assert!(
            !findings.iter().any(|f| f.kind == FindingKind::LicenseMismatch),
            "license was present, got {:?}",
            findings
        );
    }
}
