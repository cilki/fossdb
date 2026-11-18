//! Lookalike ("typosquat") package-name matching.
//!
//! Pure functions with no I/O. They live in the shared crate so the server
//! (which checks every new package against the popular ones) and the CLI
//! (which could warn on `fossdb subscribe <typo>`) agree on what counts as a
//! lookalike.

use serde::{Deserialize, Serialize};

use crate::FindingSeverity;

/// Edit-distance and affix checks are skipped for targets whose normalised
/// name is shorter than this. Short names (`rand`, `log`, `nom`) have too
/// many legitimate one-edit neighbours for a match to mean anything.
pub const MIN_FUZZY_TARGET_LEN: usize = 5;

/// Prefixes that turn a popular name into a plausible-looking port or
/// binding, applied to the normalised target (so `-` stands for any of
/// `-`, `_` and `.`).
const PREFIXES: &[&str] = &["py", "py-", "python-", "python3-", "node-"];
const SUFFIXES: &[&str] = &["js", "-js", "-rs", "-py", "2", "3", "-2", "-3"];

/// Why a name was judged to imitate another, strongest first.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SquatReason {
    /// The same name up to case and `-` / `_` / `.` (`serde-json` for
    /// `serde_json`).
    SeparatorOrCase,
    /// The same name once visually confusable characters are folded
    /// (`rnoment` for `moment`, `l0dash` for `lodash`).
    Homoglyph,
    /// Two adjacent characters swapped (`reqeusts` for `requests`).
    Transposition,
    /// One character inserted, deleted or substituted (`colourama` for
    /// `colorama`, `crossenv` for `cross-env`).
    Edit1,
    /// The popular name with a port-style prefix or suffix (`requests-js`,
    /// `pyleftpad`). Many of these are legitimate bindings, hence the lower
    /// severity.
    AffixOf,
}

impl SquatReason {
    pub fn severity(self) -> FindingSeverity {
        match self {
            SquatReason::AffixOf => FindingSeverity::Low,
            _ => FindingSeverity::Medium,
        }
    }

    /// Short human-readable description, e.g. for an alert message.
    pub fn describe(self) -> &'static str {
        match self {
            SquatReason::SeparatorOrCase => "separator or case swap",
            SquatReason::Homoglyph => "lookalike characters",
            SquatReason::Transposition => "swapped letters",
            SquatReason::Edit1 => "one character different",
            SquatReason::AffixOf => "added prefix or suffix",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SquatMatch {
    /// The imitated name, exactly as it appeared in `targets`.
    pub target: String,
    pub reason: SquatReason,
}

/// The popular package a stored package's name imitates. Served by
/// `GET /api/packages/{id}/lookalike`, which applies the same rules as the
/// alert raised when the package first arrived.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageLookalike {
    pub target_id: u64,
    pub target_name: String,
    /// The target's dependents, as used to rank it among its ecosystem's
    /// most popular packages.
    pub target_dependents: u32,
    pub reason: SquatReason,
    pub severity: FindingSeverity,
}

/// Lowercase, with `-`, `_` and `.` all mapped to `-` (PEP 503).
pub fn normalize(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '_' | '.' => '-',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// [`normalize`]d, then with visually confusable sequences folded together.
fn fold_homoglyphs(normalized: &str) -> String {
    normalized
        .replace("rn", "m")
        .replace("vv", "w")
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | 'i' | '|' => 'l',
            c => c,
        })
        .collect()
}

/// Whether `a` and `b` are exactly one edit apart, and if so which kind.
fn one_edit(a: &[char], b: &[char]) -> Option<SquatReason> {
    if a.len() == b.len() {
        let diffs: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        match diffs[..] {
            [_] => Some(SquatReason::Edit1),
            [i, j] if j == i + 1 && a[i] == b[j] && a[j] == b[i] => {
                Some(SquatReason::Transposition)
            }
            _ => None,
        }
    } else {
        let (long, short) = if a.len() > b.len() { (a, b) } else { (b, a) };
        if long.len() != short.len() + 1 {
            return None;
        }
        let split = short
            .iter()
            .zip(long)
            .position(|(s, l)| s != l)
            .unwrap_or(short.len());
        (short[split..] == long[split + 1..]).then_some(SquatReason::Edit1)
    }
}

fn is_affix_of(candidate: &str, target: &str) -> bool {
    PREFIXES
        .iter()
        .any(|p| candidate.strip_prefix(p) == Some(target))
        || SUFFIXES
            .iter()
            .any(|s| candidate.strip_suffix(s) == Some(target))
}

/// Why `candidate` looks like an imitation of `target`, if it does.
pub fn imitates(candidate: &str, target: &str) -> Option<SquatReason> {
    if candidate == target {
        return None;
    }
    let c = normalize(candidate);
    let t = normalize(target);
    if c == t {
        return Some(SquatReason::SeparatorOrCase);
    }
    if fold_homoglyphs(&c) == fold_homoglyphs(&t) {
        return Some(SquatReason::Homoglyph);
    }
    if t.chars().count() < MIN_FUZZY_TARGET_LEN {
        return None;
    }
    let cc: Vec<char> = c.chars().collect();
    let tc: Vec<char> = t.chars().collect();
    if let Some(reason) = one_edit(&cc, &tc) {
        return Some(reason);
    }
    is_affix_of(&c, &t).then_some(SquatReason::AffixOf)
}

/// The target `candidate` most plausibly imitates.
///
/// The strongest [`SquatReason`] wins; among equally strong matches, the
/// earliest target does, so callers should pass `targets` most popular
/// first. A candidate that is itself one of the targets matches nothing:
/// two established packages with similar names are not a new threat.
pub fn lookalike_of(candidate: &str, targets: &[&str]) -> Option<SquatMatch> {
    if targets.contains(&candidate) {
        return None;
    }
    targets
        .iter()
        .filter_map(|t| imitates(candidate, t).map(|reason| (reason, *t)))
        .min_by_key(|(reason, _)| *reason)
        .map(|(reason, target)| SquatMatch {
            target: target.to_string(),
            reason,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(candidate: &str, target: &str) -> Option<SquatReason> {
        imitates(candidate, target)
    }

    #[test]
    fn known_typosquats_match() {
        assert_eq!(reason("reqeusts", "requests"), Some(SquatReason::Transposition));
        assert_eq!(reason("rustdecimal", "rust_decimal"), Some(SquatReason::Edit1));
        assert_eq!(reason("crossenv", "cross-env"), Some(SquatReason::Edit1));
        assert_eq!(reason("colourama", "colorama"), Some(SquatReason::Edit1));
        assert_eq!(reason("rnoment", "moment"), Some(SquatReason::Homoglyph));
        assert_eq!(reason("l0dash", "lodash"), Some(SquatReason::Homoglyph));
        assert_eq!(reason("serde-json", "serde_json"), Some(SquatReason::SeparatorOrCase));
        assert_eq!(reason("Serde_Json", "serde_json"), Some(SquatReason::SeparatorOrCase));
        assert_eq!(
            reason("python3-dateutil", "python-dateutil"),
            Some(SquatReason::Edit1)
        );
        assert_eq!(reason("requests-js", "requests"), Some(SquatReason::AffixOf));
        assert_eq!(reason("pyrequests", "requests"), Some(SquatReason::AffixOf));
        assert_eq!(reason("node-lodash", "lodash"), Some(SquatReason::AffixOf));
    }

    #[test]
    fn exact_and_unrelated_names_do_not_match() {
        assert_eq!(reason("requests", "requests"), None);
        assert_eq!(reason("tokio", "serde"), None);
        assert_eq!(reason("requests", "urllib3"), None);
        // Two edits away.
        assert_eq!(reason("reqests2", "requests"), None);
        // Swapped, but not adjacently.
        assert_eq!(reason("sequertr", "requests"), None);
    }

    #[test]
    fn short_targets_only_match_exact_lookalikes() {
        // One edit from a short name is too common to mean anything.
        assert_eq!(reason("rang", "rand"), None);
        assert_eq!(reason("logs", "log"), None);
        assert_eq!(reason("nom2", "nom"), None);
        // But a separator or homoglyph swap still is.
        assert_eq!(reason("l0g", "log"), Some(SquatReason::Homoglyph));
        assert_eq!(reason("Rand", "rand"), Some(SquatReason::SeparatorOrCase));
    }

    #[test]
    fn one_edit_classifies() {
        let c = |s: &str| s.chars().collect::<Vec<_>>();
        assert_eq!(one_edit(&c("abcde"), &c("abxde")), Some(SquatReason::Edit1));
        assert_eq!(one_edit(&c("abcde"), &c("abde")), Some(SquatReason::Edit1));
        assert_eq!(one_edit(&c("abcde"), &c("abcdef")), Some(SquatReason::Edit1));
        assert_eq!(one_edit(&c("abcde"), &c("xabcde")), Some(SquatReason::Edit1));
        assert_eq!(one_edit(&c("abcde"), &c("bacde")), Some(SquatReason::Transposition));
        assert_eq!(one_edit(&c("abcde"), &c("abcde")), None);
        assert_eq!(one_edit(&c("abcde"), &c("axcxe")), None);
        assert_eq!(one_edit(&c("abcde"), &c("abc")), None);
    }

    #[test]
    fn strongest_reason_then_earliest_target_wins() {
        // `serde-jsom` is one edit from `serde-json` but a separator swap of
        // neither; `serde_json` is the closer imitation of `serde-json`.
        let m = lookalike_of("serde-json", &["serde-jsom", "serde_json"]).unwrap();
        assert_eq!(m.target, "serde_json");
        assert_eq!(m.reason, SquatReason::SeparatorOrCase);

        let m = lookalike_of("reqeust", &["request", "requests"]).unwrap();
        assert_eq!(m.target, "request");
        assert_eq!(m.reason, SquatReason::Transposition);

        let m = lookalike_of("colorana", &["colorama", "coloranb"]).unwrap();
        assert_eq!(m.target, "colorama", "ties go to the earlier target");
    }

    #[test]
    fn a_target_never_imitates_another() {
        assert_eq!(lookalike_of("colorama", &["colorama", "colourama"]), None);
        assert_eq!(lookalike_of("left-pad", &["requests"]), None);
        assert_eq!(lookalike_of("anything", &[]), None);
    }

    #[test]
    fn affix_matches_are_low_severity() {
        assert_eq!(SquatReason::AffixOf.severity(), FindingSeverity::Low);
        assert_eq!(SquatReason::Edit1.severity(), FindingSeverity::Medium);
    }
}
