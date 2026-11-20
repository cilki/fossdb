//! URL helpers shared by every client of the fossdb API.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// Every byte except the RFC 3986 unreserved set (`ALPHA / DIGIT / - . _ ~`).
const NOT_UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encode a value for use as one URL path segment or query value.
///
/// Everything outside the RFC 3986 unreserved set is escaped, byte by byte
/// of the UTF-8 encoding. Package names legitimately contain `/` (scoped npm
/// packages such as `@angular/cli`), `+` and `#`, and raw interpolation let
/// them hit a different route, arrive as spaces, truncate the URL or inject
/// extra query parameters.
pub fn percent_encode(value: &str) -> String {
    utf8_percent_encode(value, NOT_UNRESERVED).to_string()
}

#[cfg(test)]
mod tests {
    use super::percent_encode;

    #[test]
    fn leaves_unreserved_characters_alone() {
        assert_eq!(percent_encode("serde_json-1.0.x~test"), "serde_json-1.0.x~test");
    }

    #[test]
    fn encodes_utf8_as_bytes() {
        // One escape per UTF-8 byte, not one per scalar value.
        assert_eq!(percent_encode("é"), "%C3%A9");
        assert_eq!(percent_encode("中"), "%E4%B8%AD");
    }

    #[test]
    fn encodes_url_structural_characters() {
        assert_eq!(percent_encode("@angular/cli"), "%40angular%2Fcli");
        assert_eq!(percent_encode("../../etc"), "..%2F..%2Fetc");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("x&limit=1"), "x%26limit%3D1");
        assert_eq!(percent_encode("c++"), "c%2B%2B");
        assert_eq!(percent_encode("a#b?c"), "a%23b%3Fc");
    }
}
