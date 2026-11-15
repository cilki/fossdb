/// SPDX identifiers (lowercased) that denote free/open-source licenses.
///
/// Matched as whole tokens, never as substrings. Substring matching is how the
/// previous implementation classified `"Limited Use License"` as free, since
/// "li-MIT-ed" contains "mit".
const FREE_LICENSE_IDS: &[&str] = &[
    "mit",
    "mit-0",
    "x11",
    "isc",
    "apache-1.0",
    "apache-1.1",
    "apache-2.0",
    "bsd-2-clause",
    "bsd-3-clause",
    "bsd-4-clause",
    "0bsd",
    "bsd-zero-clause",
    "bsl-1.0",
    "cc0-1.0",
    "unlicense",
    "wtfpl",
    "zlib",
    "ncsa",
    "gpl-1.0",
    "gpl-2.0",
    "gpl-3.0",
    "lgpl-2.0",
    "lgpl-2.1",
    "lgpl-3.0",
    "agpl-1.0",
    "agpl-3.0",
    "mpl-1.1",
    "mpl-2.0",
    "epl-1.0",
    "epl-2.0",
    "cpl-1.0",
    "cddl-1.0",
    "cddl-1.1",
    "eupl-1.1",
    "eupl-1.2",
    "osl-3.0",
    "afl-3.0",
    "artistic-2.0",
    "cc-by-3.0",
    "cc-by-4.0",
    "cc-by-sa-3.0",
    "cc-by-sa-4.0",
    "python-2.0",
    "postgresql",
    "openssl",
    "zpl-2.1",
    "ruby",
    "php-3.01",
];

/// Free-license family prefixes, used when a token carries a version suffix we
/// do not enumerate (e.g. `gpl-2.0-only`, `gpl-2.0-or-later`, `lgpl-3.0+`).
const FREE_LICENSE_PREFIXES: &[&str] = &[
    "mit-",
    "apache-",
    "bsd-2-clause",
    "bsd-3-clause",
    "gpl-",
    "lgpl-",
    "agpl-",
    "mpl-",
    "epl-",
    "cddl-",
    "eupl-",
    "osl-",
    "afl-",
    "artistic-",
    "cc-by-",
    "cc0-",
    "zpl-",
];

/// Tokens that unambiguously denote a non-free license.
///
/// `unlicensed` is npm's marker for "not licensed for use" - the opposite of
/// the `Unlicense` public-domain license - and must never be treated as free.
const NON_FREE_IDS: &[&str] = &[
    "unlicensed",
    "proprietary",
    "commercial",
    "private",
    "closed",
    "nonfree",
    "non-free",
    "see-license",
    "custom",
];

/// Non-free phrases that appear in free-text license fields rather than as
/// SPDX tokens, so they are matched against the whole normalized string.
const NON_FREE_PHRASES: &[&str] = &[
    "all rights reserved",
    "copyright only",
    "no license",
    "not licensed",
];

/// Non-free Creative Commons variants (NoDerivatives / NonCommercial).
const NON_FREE_PREFIXES: &[&str] = &["cc-by-nd", "cc-by-nc", "cc-nc", "cc-nd"];

/// Split an SPDX license expression into bare license tokens.
///
/// Handles the operators and punctuation that actually show up in registry
/// metadata: `OR`, `AND`, `WITH`, slashes, pipes, commas, and parentheses.
/// Trailing `+` ("or later") and `-only` / `-or-later` suffixes are preserved
/// for prefix matching but stripped for exact matching.
fn tokenize(expression: &str) -> Vec<String> {
    expression
        .to_lowercase()
        .replace(['(', ')', '[', ']'], " ")
        .split(|c: char| c == '/' || c == '|' || c == ',' || c.is_whitespace())
        .map(|token| token.trim().trim_end_matches('+').to_string())
        .filter(|token| {
            !token.is_empty() && !matches!(token.as_str(), "or" | "and" | "with" | "either")
        })
        .collect()
}

/// Strip SPDX disjunction suffixes so `gpl-2.0-only` matches `gpl-2.0`.
fn canonical(token: &str) -> &str {
    token
        .trim_end_matches("-or-later")
        .trim_end_matches("-only")
}

#[derive(Debug, PartialEq, Eq)]
enum TokenClass {
    Free,
    NonFree,
    Unknown,
}

/// Classify a single license token.
///
/// Non-free patterns are tested first because some overlap the free prefixes:
/// `cc-by-nc-4.0` starts with the free prefix `cc-by-` but is NonCommercial.
fn classify(token: &str) -> TokenClass {
    let token = canonical(token);

    if NON_FREE_IDS.contains(&token)
        || NON_FREE_PREFIXES
            .iter()
            .any(|prefix| token.starts_with(prefix))
    {
        return TokenClass::NonFree;
    }

    if FREE_LICENSE_IDS.contains(&token)
        || FREE_LICENSE_PREFIXES
            .iter()
            .any(|prefix| token.starts_with(prefix))
    {
        return TokenClass::Free;
    }

    TokenClass::Unknown
}

/// Check if a license string represents a free/open source license.
///
/// Unknown licenses are treated as non-free (fail closed). A disjunction is
/// free if *any* branch is free, since the user may choose that branch - so
/// `"MIT OR Commercial"` is free, which the previous keyword-precedence
/// implementation got backwards.
pub fn is_free_license(license: &str) -> bool {
    let normalized = license.to_lowercase();
    let trimmed = normalized.trim();

    if trimmed.is_empty() {
        return false;
    }

    if NON_FREE_PHRASES
        .iter()
        .any(|phrase| trimmed.contains(phrase))
    {
        return false;
    }

    let tokens = tokenize(trimmed);
    if tokens.is_empty() {
        tracing::warn!("Unparseable license, treating as non-free: {}", license);
        return false;
    }

    // A disjunction is free if any branch is free, and registry metadata rarely
    // distinguishes AND from OR reliably, so "any recognized free token" is the
    // rule. Unknown tokens fail closed.
    if tokens.iter().any(|token| classify(token) == TokenClass::Free) {
        return true;
    }

    if tokens
        .iter()
        .all(|token| classify(token) == TokenClass::Unknown)
    {
        tracing::warn!("Unknown license, treating as non-free: {}", license);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_free_licenses() {
        for license in [
            "MIT",
            "Apache-2.0",
            "BSD-3-Clause",
            "GPL-3.0",
            "GPL-2.0-only",
            "LGPL-2.1-or-later",
            "AGPL-3.0",
            "MPL-2.0",
            "ISC",
            "Unlicense",
            "CC0-1.0",
            "Zlib",
            "BSL-1.0",
            "GPL-2.0+",
        ] {
            assert!(is_free_license(license), "{} should be free", license);
        }
    }

    #[test]
    fn spdx_expressions() {
        assert!(is_free_license("MIT OR Apache-2.0"));
        assert!(is_free_license("MIT/Apache-2.0"));
        assert!(is_free_license("Apache-2.0 WITH LLVM-exception"));
        assert!(is_free_license("(MIT OR Apache-2.0)"));
        assert!(is_free_license("MIT AND BSD-3-Clause"));
    }

    /// npm's `UNLICENSED` means "not licensed for use". Treating it as free
    /// (because it contains the substring "unlicense") let proprietary packages
    /// through the collector's only license gate.
    #[test]
    fn npm_unlicensed_is_not_free() {
        assert!(!is_free_license("UNLICENSED"));
        assert!(!is_free_license("unlicensed"));
    }

    /// The old substring matcher classified this as free via "li-MIT-ed".
    #[test]
    fn substring_collisions_are_not_free() {
        assert!(!is_free_license("Limited Use License"));
        assert!(!is_free_license("Commits-Only License"));
    }

    #[test]
    fn explicitly_non_free() {
        for license in [
            "proprietary",
            "Proprietary",
            "CC-BY-NC-4.0",
            "CC-BY-ND-4.0",
            "All Rights Reserved",
            "SEE LICENSE IN LICENSE.txt",
            "",
            "   ",
        ] {
            assert!(!is_free_license(license), "{:?} should not be free", license);
        }
    }

    /// A dual license offering a free branch is free: the user can pick it.
    #[test]
    fn disjunction_with_a_free_branch_is_free() {
        assert!(is_free_license("MIT OR Commercial"));
        assert!(is_free_license("Apache-2.0 OR Proprietary"));
    }

    #[test]
    fn unknown_licenses_fail_closed() {
        assert!(!is_free_license("CustomLicense"));
        assert!(!is_free_license("Totally-Made-Up-1.0"));
    }

    #[test]
    fn unlicense_is_still_free() {
        assert!(is_free_license("Unlicense"));
        assert!(is_free_license("the unlicense"));
    }
}
