//! Format rules for the account identifier.
//!
//! A fossdb account has exactly one identifier, which doubles as its only
//! credential:
//!
//! ```text
//! fdb_3k9x7m2qdv5r8ptw1ny6az4cbf
//! ^^^^ ^------------------------^
//! |    26 chars of Crockford base32 (130 bits of entropy)
//! prefix
//! ```
//!
//! The alphabet is [Crockford base32], which omits `i`, `l`, `o` and `u`.
//! That buys two things: no visual ambiguity when a user copies the id off a
//! screen, and no accidental profanity. [`normalize`] additionally folds the
//! excluded letters onto the digits they resemble, so an id transcribed with
//! `l` for `1` or `O` for `0` still resolves.
//!
//! The literal `fdb_` prefix makes the id greppable, which lets secret
//! scanners recognise one if it is ever pasted somewhere public.
//!
//! Generation lives server-side (it needs a CSPRNG); this module is pure so
//! that the WASM frontend and the CLI can validate input without pulling in
//! `getrandom`.
//!
//! [Crockford base32]: https://www.crockford.com/base32.html

/// Marker prefix on every id.
pub const PREFIX: &str = "fdb_";

/// Number of alphabet characters following the prefix.
///
/// 26 chars x 5 bits = 130 bits of entropy.
pub const BODY_LEN: usize = 26;

/// Total length of a canonical id, prefix included.
pub const TOTAL_LEN: usize = PREFIX.len() + BODY_LEN;

/// Crockford base32 digits, lowercase. Note the absence of `i`, `l`, `o`, `u`.
pub const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Canonicalise user-supplied input.
///
/// Tolerates the mistakes people actually make when retyping an id: stray
/// whitespace, uppercase, decorative dashes, a missing prefix, and the four
/// letters Crockford excludes for being confusable with digits.
///
/// This does *not* validate - pair it with [`is_well_formed`].
pub fn normalize(input: &str) -> String {
    let trimmed = input.trim();

    // Accept a bare body, so a user who copied only the random part still
    // gets a usable id back.
    let body = trimmed
        .strip_prefix(PREFIX)
        .or_else(|| trimmed.strip_prefix(&PREFIX.to_uppercase()))
        .unwrap_or(trimmed);

    let mut out = String::with_capacity(TOTAL_LEN);
    out.push_str(PREFIX);

    for ch in body.chars() {
        // Separators people insert for readability.
        if ch.is_whitespace() || ch == '-' || ch == '_' {
            continue;
        }

        let lowered = ch.to_ascii_lowercase();
        out.push(match lowered {
            // Crockford's confusable folding.
            'i' | 'l' => '1',
            'o' => '0',
            other => other,
        });
    }

    out
}

/// True if `candidate` is exactly a canonical id.
///
/// Checked before any database lookup so that malformed bearer tokens are
/// rejected without touching storage.
pub fn is_well_formed(candidate: &str) -> bool {
    let Some(body) = candidate.strip_prefix(PREFIX) else {
        return false;
    };

    body.len() == BODY_LEN && body.bytes().all(|b| ALPHABET.contains(&b))
}

/// Render an id for display in logs or a terminal, keeping enough to identify
/// an account without disclosing enough to use it.
pub fn redact(user_id: &str) -> String {
    match user_id.strip_prefix(PREFIX) {
        Some(body) if body.len() == BODY_LEN => format!("{PREFIX}{}...", &body[..4]),
        _ => "<malformed>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "fdb_3k9x7m2qdv5r8ptw1ny6az4cbf";

    #[test]
    fn canonical_id_is_well_formed() {
        assert_eq!(VALID.len(), TOTAL_LEN);
        assert!(is_well_formed(VALID));
    }

    #[test]
    fn alphabet_excludes_confusable_letters() {
        for excluded in [b'i', b'l', b'o', b'u'] {
            assert!(
                !ALPHABET.contains(&excluded),
                "{} must not be generatable",
                excluded as char
            );
        }
        assert_eq!(ALPHABET.len(), 32);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(!is_well_formed("fdb_tooshort"));
        assert!(!is_well_formed(&format!("{VALID}extra")));
        assert!(!is_well_formed(PREFIX));
        assert!(!is_well_formed(""));
    }

    #[test]
    fn rejects_missing_or_wrong_prefix() {
        assert!(!is_well_formed("3k9x7m2qdv5r8ptw1ny6az4cbf"));
        assert!(!is_well_formed("usr_3k9x7m2qdv5r8ptw1ny6az4cbf"));
        // Canonical form is lowercase; uppercase must go through normalize.
        assert!(!is_well_formed(&VALID.to_uppercase()));
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // Right length, but contains excluded letters.
        assert!(!is_well_formed("fdb_ilou7m2qdv5r8ptw1ny6az4cb"));
        // Right length, but contains punctuation.
        assert!(!is_well_formed("fdb_3k9x7m2qdv5r8ptw1ny6az4c!"));
    }

    #[test]
    fn normalize_is_idempotent_on_canonical_input() {
        assert_eq!(normalize(VALID), VALID);
    }

    #[test]
    fn normalize_fixes_transcription_mistakes() {
        // Uppercase, surrounding whitespace, and readability dashes.
        assert_eq!(normalize("  FDB_3K9X7M2Q-DV5R8PTW-1NY6AZ4CBF "), VALID);
        // A bare body with no prefix.
        assert_eq!(normalize("3k9x7m2qdv5r8ptw1ny6az4cbf"), VALID);
    }

    #[test]
    fn normalize_folds_crockford_confusables() {
        // `l` and `I` both mean 1; `O` means 0.
        let typed = "fdb_3k9x7m2qdv5r8ptwlny6az4cbf";
        assert_eq!(normalize(typed), VALID);

        assert_eq!(normalize("fdb_O"), "fdb_0");
        assert_eq!(normalize("fdb_I"), "fdb_1");
    }

    #[test]
    fn normalized_garbage_still_fails_validation() {
        // normalize must not be mistaken for sanitisation.
        let hostile = normalize("'; DROP TABLE users; --");
        assert!(!is_well_formed(&hostile));
    }

    #[test]
    fn redact_keeps_only_a_prefix() {
        let shown = redact(VALID);
        assert_eq!(shown, "fdb_3k9x...");
        assert!(!VALID.contains(&shown));
        assert_eq!(redact("nonsense"), "<malformed>");
    }
}
