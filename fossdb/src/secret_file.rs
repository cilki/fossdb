//! Loading a secret from the environment or from a file.
//!
//! Service managers prefer to hand secrets to a process as a *file* rather
//! than an environment variable: an env var is visible to anything that can
//! read `/proc/<pid>/environ` and tends to leak into logs and crash
//! reports. systemd's `LoadCredential=` in particular exposes the secret as a
//! file under `$CREDENTIALS_DIRECTORY`.
//!
//! So every secret here is accepted two ways: `NAME` for the literal value,
//! or `NAME_FILE` for a path to read it from.

use std::fmt;

/// Why a secret could not be loaded.
#[derive(Debug)]
pub enum SecretError {
    /// Neither variable was set.
    Missing { var: String, file_var: String },
    /// The file named by `NAME_FILE` could not be read.
    Unreadable {
        file_var: String,
        path: String,
        source: std::io::Error,
    },
    /// The file was readable but held nothing usable.
    Empty { file_var: String, path: String },
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { var, file_var } => write!(
                f,
                "{var} is not set.\n\
                 Set {var} to the key itself, or {file_var} to a file containing it.\n\
                 Mint one on the server with:  fossdb admin api-key create --role <role>"
            ),
            Self::Unreadable {
                file_var,
                path,
                source,
            } => write!(f, "{file_var} points at {path}, which could not be read: {source}"),
            Self::Empty { file_var, path } => {
                write!(f, "{file_var} points at {path}, which is empty")
            }
        }
    }
}

impl std::error::Error for SecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Read a secret from `var`, or from the file named by `{var}_FILE`.
///
/// The file form wins when both are set, on the grounds that it is the more
/// deliberate configuration. Trailing whitespace is trimmed, because a file
/// written by `echo` or a text editor almost always ends in a newline and a
/// trailing `\n` in an API key is a maddening thing to debug.
pub fn from_env(var: &str) -> Result<String, SecretError> {
    let file_var = format!("{var}_FILE");

    if let Some(path) = std::env::var_os(&file_var) {
        let path = path.to_string_lossy().into_owned();

        let contents = std::fs::read_to_string(&path).map_err(|source| SecretError::Unreadable {
            file_var: file_var.clone(),
            path: path.clone(),
            source,
        })?;

        let trimmed = contents.trim().to_string();

        if trimmed.is_empty() {
            return Err(SecretError::Empty { file_var, path });
        }

        return Ok(trimmed);
    }

    match std::env::var(var) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => Err(SecretError::Missing {
            var: var.to_string(),
            file_var,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Unique variable names per test: `std::env` is process-global and the
    /// test harness runs these in parallel.
    fn unique(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        format!(
            "FOSSDB_TEST_{prefix}_{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn reads_a_plain_env_var() {
        let var = unique("PLAIN");
        unsafe { std::env::set_var(&var, "fdbk_abc") };

        assert_eq!(from_env(&var).unwrap(), "fdbk_abc");

        unsafe { std::env::remove_var(&var) };
    }

    #[test]
    fn missing_is_an_error_naming_both_variables() {
        let var = unique("ABSENT");
        let err = from_env(&var).unwrap_err().to_string();

        assert!(err.contains(&var));
        assert!(err.contains(&format!("{var}_FILE")));
    }

    #[test]
    fn reads_from_a_file() {
        let var = unique("FROMFILE");
        let path = std::env::temp_dir().join(format!("{var}.key"));
        std::fs::write(&path, "fdbk_fromfile").unwrap();

        unsafe { std::env::set_var(format!("{var}_FILE"), &path) };
        assert_eq!(from_env(&var).unwrap(), "fdbk_fromfile");

        unsafe { std::env::remove_var(format!("{var}_FILE")) };
        std::fs::remove_file(&path).ok();
    }

    /// The case this function exists for: a key file ending in a newline.
    #[test]
    fn trims_trailing_newline_from_a_file() {
        let var = unique("NEWLINE");
        let path = std::env::temp_dir().join(format!("{var}.key"));
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "fdbk_trimmed").unwrap();
        drop(file);

        unsafe { std::env::set_var(format!("{var}_FILE"), &path) };
        assert_eq!(from_env(&var).unwrap(), "fdbk_trimmed");

        unsafe { std::env::remove_var(format!("{var}_FILE")) };
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn file_wins_over_the_plain_variable() {
        let var = unique("BOTH");
        let path = std::env::temp_dir().join(format!("{var}.key"));
        std::fs::write(&path, "from_file").unwrap();

        unsafe { std::env::set_var(&var, "from_env") };
        unsafe { std::env::set_var(format!("{var}_FILE"), &path) };

        assert_eq!(from_env(&var).unwrap(), "from_file");

        unsafe { std::env::remove_var(&var) };
        unsafe { std::env::remove_var(format!("{var}_FILE")) };
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unreadable_file_names_the_path() {
        let var = unique("NOFILE");
        unsafe { std::env::set_var(format!("{var}_FILE"), "/nonexistent/fossdb.key") };

        let err = from_env(&var).unwrap_err().to_string();
        assert!(err.contains("/nonexistent/fossdb.key"));

        unsafe { std::env::remove_var(format!("{var}_FILE")) };
    }

    #[test]
    fn empty_file_is_an_error_not_an_empty_secret() {
        let var = unique("EMPTY");
        let path = std::env::temp_dir().join(format!("{var}.key"));
        std::fs::write(&path, "   \n").unwrap();

        unsafe { std::env::set_var(format!("{var}_FILE"), &path) };

        let err = from_env(&var).unwrap_err().to_string();
        assert!(err.contains("empty"));

        unsafe { std::env::remove_var(format!("{var}_FILE")) };
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn blank_env_var_is_treated_as_missing() {
        let var = unique("BLANK");
        unsafe { std::env::set_var(&var, "  ") };

        assert!(from_env(&var).is_err());

        unsafe { std::env::remove_var(&var) };
    }
}
