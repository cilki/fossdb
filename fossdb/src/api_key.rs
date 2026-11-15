//! Format rules for collector and worker API keys.
//!
//! Unlike an account id, a machine API key is split into two parts:
//!
//! ```text
//! fdbk_4m7k2xqa_3k9x7m2qdv5r8ptw1ny6az4cbf
//! ^^^^ ^------^ ^------------------------^
//! |    key id   secret (128 bits)
//! prefix
//! ```
//!
//! The split exists so the server can find the stored record by key id and
//! then verify the secret against a hash. A single opaque string would force
//! either storing the secret in the clear or scanning every key on every
//! request.
//!
//! The key id is not secret: it is what `fossdb admin api-key list` displays
//! and what `revoke` takes, so a key can be identified and withdrawn without
//! anyone ever having to handle the secret again.
//!
//! Generation and hashing live server-side; this module is pure so the CLI can
//! validate input without a crypto dependency.

use serde::{Deserialize, Serialize};

/// Marker prefix on every API key.
pub const PREFIX: &str = "fdbk_";

/// Length of the non-secret key id.
pub const ID_LEN: usize = 8;

/// Length of the secret component.
pub const SECRET_LEN: usize = 26;

/// Total length of a canonical key.
pub const TOTAL_LEN: usize = PREFIX.len() + ID_LEN + 1 + SECRET_LEN;

/// Crockford base32 digits, lowercase; shared with [`crate::user_id`].
pub const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Entropy backing the secret component.
pub const SECRET_ENTROPY_BYTES: usize = 16;

/// Which internal API a key grants access to.
///
/// A key is valid for exactly one role: a compromised worker key must not be
/// usable to write package data through the collector API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyRole {
    Collector,
    Worker,
}

impl ApiKeyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Collector => "collector",
            Self::Worker => "worker",
        }
    }
}

impl std::fmt::Display for ApiKeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ApiKeyRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "collector" => Ok(Self::Collector),
            "worker" => Ok(Self::Worker),
            other => Err(format!(
                "unknown role {other:?} (expected \"collector\" or \"worker\")"
            )),
        }
    }
}

/// Split a presented key into its id and secret components.
///
/// Returns `None` unless the whole key is well formed, so callers cannot
/// accidentally act on a partially valid key.
pub fn split(candidate: &str) -> Option<(&str, &str)> {
    let body = candidate.strip_prefix(PREFIX)?;
    let (id, secret) = body.split_once('_')?;

    let valid = id.len() == ID_LEN
        && secret.len() == SECRET_LEN
        && id.bytes().all(|b| ALPHABET.contains(&b))
        && secret.bytes().all(|b| ALPHABET.contains(&b));

    valid.then_some((id, secret))
}

/// True if `candidate` is a canonical API key.
pub fn is_well_formed(candidate: &str) -> bool {
    split(candidate).is_some()
}

/// True if `candidate` could be a key id, as accepted by `revoke`.
pub fn is_well_formed_id(candidate: &str) -> bool {
    candidate.len() == ID_LEN && candidate.bytes().all(|b| ALPHABET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "fdbk_4m7k2xqa_3k9x7m2qdv5r8ptw1ny6az4cbf";

    #[test]
    fn splits_a_canonical_key() {
        assert_eq!(VALID.len(), TOTAL_LEN);
        assert_eq!(
            split(VALID),
            Some(("4m7k2xqa", "3k9x7m2qdv5r8ptw1ny6az4cbf"))
        );
    }

    #[test]
    fn rejects_wrong_prefix_or_shape() {
        assert!(!is_well_formed("fdb_4m7k2xqa_3k9x7m2qdv5r8ptw1ny6az4cbf"));
        assert!(!is_well_formed("4m7k2xqa_3k9x7m2qdv5r8ptw1ny6az4cbf"));
        // Missing separator.
        assert!(!is_well_formed("fdbk_4m7k2xqa3k9x7m2qdv5r8ptw1ny6az4cbf"));
        assert!(!is_well_formed(""));
        assert!(!is_well_formed(PREFIX));
    }

    #[test]
    fn rejects_wrong_component_lengths() {
        assert!(!is_well_formed("fdbk_4m7k2xq_3k9x7m2qdv5r8ptw1ny6az4cbf"));
        assert!(!is_well_formed("fdbk_4m7k2xqaa_3k9x7m2qdv5r8ptw1ny6az4cbf"));
        assert!(!is_well_formed("fdbk_4m7k2xqa_3k9x7m2qdv5r8ptw1ny6az4cb"));
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // `i`, `l`, `o`, `u` are excluded from the alphabet.
        assert!(!is_well_formed("fdbk_4m7k2xqi_3k9x7m2qdv5r8ptw1ny6az4cbf"));
        assert!(!is_well_formed("fdbk_4m7k2xqa_3k9x7m2qdv5r8ptw1ny6az4cb!"));
        // Uppercase is not canonical.
        assert!(!is_well_formed(&VALID.to_uppercase()));
    }

    /// A key with extra trailing data must not be accepted by truncation.
    #[test]
    fn rejects_trailing_data() {
        assert!(!is_well_formed(&format!("{VALID}extra")));
        assert!(!is_well_formed(&format!("{VALID}_more")));
    }

    #[test]
    fn validates_bare_key_ids() {
        assert!(is_well_formed_id("4m7k2xqa"));
        assert!(!is_well_formed_id("4m7k2xq"));
        assert!(!is_well_formed_id("4m7k2xqa9"));
        assert!(!is_well_formed_id("4m7k2xqi"));
        assert!(!is_well_formed_id(""));
    }

    #[test]
    fn roles_round_trip_through_strings() {
        for role in [ApiKeyRole::Collector, ApiKeyRole::Worker] {
            assert_eq!(role.as_str().parse::<ApiKeyRole>().unwrap(), role);
        }
        assert!("Worker".parse::<ApiKeyRole>().is_ok());
        assert!(" collector ".parse::<ApiKeyRole>().is_ok());
        assert!("admin".parse::<ApiKeyRole>().is_err());
    }

    #[test]
    fn roles_serialize_lowercase() {
        let json = serde_json::to_string(&ApiKeyRole::Collector).unwrap();
        assert_eq!(json, "\"collector\"");
    }
}
