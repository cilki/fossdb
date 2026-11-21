//! On-disk credential storage.
//!
//! The account id is the whole credential, so the file holding it is as
//! sensitive as an SSH private key and is created with the same permissions.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Mode for the credential file: owner read/write only.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub user_id: String,
    /// Server the id belongs to. Stored so that pointing the CLI at a
    /// different deployment does not silently send one server's credential
    /// to another.
    pub server: String,
}

/// Canonical form of a server base URL: without trailing slashes.
///
/// `https://fossdb.example/` and `https://fossdb.example` are the same
/// deployment. Keeping the slash would both make the stored server differ from
/// the slash-less `--server` (so the credential is refused as another
/// deployment's) and put a `//` into every URL built from it, such as the feed
/// URLs, which the server then answers with 404.
pub fn normalize_server(server: &str) -> String {
    server.trim_end_matches('/').to_string()
}

/// Resolve the credential file path per the XDG Base Directory spec.
///
/// Hand-rolled rather than pulling in a crate: the rule is two lines, and
/// `$XDG_CONFIG_HOME` is only honoured when absolute, as the spec requires.
pub fn path() -> Result<PathBuf> {
    resolve_path(std::env::var_os("XDG_CONFIG_HOME"), std::env::var_os("HOME"))
}

/// [`path`] with the environment passed in, so tests need not mutate the
/// process-wide environment (which races with every other test thread).
fn resolve_path(xdg_config_home: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    if let Some(xdg) = xdg_config_home {
        let candidate = PathBuf::from(xdg);
        if candidate.is_absolute() {
            return Ok(candidate.join("fossdb").join("credentials.json"));
        }
    }

    let home = home
        .map(PathBuf::from)
        .context("neither XDG_CONFIG_HOME nor HOME is set; cannot locate a config directory")?;

    Ok(home.join(".config").join("fossdb").join("credentials.json"))
}

pub fn load() -> Result<Option<Credentials>> {
    let path = path()?;

    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };

    let mut credentials: Credentials = serde_json::from_str(&raw)
        .with_context(|| format!("{} is not valid credential JSON", path.display()))?;

    // Files written before the server was normalised may still carry a
    // trailing slash.
    credentials.server = normalize_server(&credentials.server);

    // Guard against a file that was hand-edited into an unusable state.
    if !fossdb::user_id::is_well_formed(&credentials.user_id) {
        bail!(
            "{} contains a malformed account id; run `fossdb login` again",
            path.display()
        );
    }

    Ok(Some(credentials))
}

/// Require a stored credential, with an actionable message when absent.
pub fn require() -> Result<Credentials> {
    load()?.context("not logged in - run `fossdb login <user-id>` first")
}

pub fn store(credentials: &Credentials) -> Result<()> {
    let path = path()?;

    let dir = path
        .parent()
        .context("credential path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let json = serde_json::to_string_pretty(credentials)?;

    // Create with restrictive permissions from the outset. Writing first and
    // chmod-ing after would leave the credential briefly world-readable.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;

        file.write_all(json.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;

        // An existing file keeps its old mode, so set it explicitly too.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(FILE_MODE))
            .with_context(|| format!("securing {}", path.display()))?;
    }

    #[cfg(not(unix))]
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

/// Remove the stored credential. Idempotent.
pub fn clear() -> Result<bool> {
    let path = path()?;

    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honours_absolute_xdg_config_home() {
        let resolved =
            resolve_path(Some("/tmp/xdg-test".into()), Some("/home/someone".into())).unwrap();

        assert_eq!(
            resolved,
            PathBuf::from("/tmp/xdg-test/fossdb/credentials.json")
        );
    }

    #[test]
    fn ignores_relative_xdg_config_home() {
        // The spec says a relative XDG_CONFIG_HOME must be treated as unset.
        let resolved =
            resolve_path(Some("relative/path".into()), Some("/home/someone".into())).unwrap();

        assert_eq!(
            resolved,
            PathBuf::from("/home/someone/.config/fossdb/credentials.json")
        );
    }

    #[test]
    fn falls_back_to_home_without_xdg_config_home() {
        let resolved = resolve_path(None, Some("/home/someone".into())).unwrap();

        assert_eq!(
            resolved,
            PathBuf::from("/home/someone/.config/fossdb/credentials.json")
        );
    }

    #[test]
    fn fails_without_xdg_config_home_or_home() {
        assert!(resolve_path(None, None).is_err());
    }

    #[test]
    fn server_trailing_slashes_are_dropped() {
        assert_eq!(normalize_server("https://fossdb.example/"), "https://fossdb.example");
        assert_eq!(normalize_server("https://fossdb.example//"), "https://fossdb.example");
        assert_eq!(normalize_server("https://fossdb.example"), "https://fossdb.example");
        assert_eq!(
            normalize_server("https://example.org/fossdb/"),
            "https://example.org/fossdb"
        );
    }

    #[test]
    fn credentials_round_trip() {
        let original = Credentials {
            user_id: "fdb_3k9x7m2qdv5r8ptw1ny6az4cbf".into(),
            server: "https://fossdb.example".into(),
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: Credentials = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.user_id, original.user_id);
        assert_eq!(parsed.server, original.server);
    }
}
