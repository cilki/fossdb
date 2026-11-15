/// Return `url` only if it is safe to use as an `href`.
///
/// Package metadata (homepage, repository) is collected from third-party
/// registries, so it is untrusted. Rendering it directly into an `href` means a
/// stored `javascript:` URL executes when a user clicks the link - a stored XSS
/// with no `dangerous_inner_html` anywhere in sight.
///
/// Only `http` and `https` are allowed. Protocol-relative (`//host`) and
/// scheme-less values are rejected too, since they are ambiguous and no
/// registry needs them.
pub fn safe_external_url(url: &str) -> Option<&str> {
    let trimmed = url.trim();

    // Reject control characters and whitespace, which are used to smuggle
    // schemes past naive prefix checks (e.g. "java\0script:" or "java\tscript:").
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }

    let (scheme, rest) = trimmed.split_once(':')?;
    if rest.is_empty() {
        return None;
    }

    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        Some(trimmed)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_http_and_https() {
        assert_eq!(
            safe_external_url("https://example.com/x"),
            Some("https://example.com/x")
        );
        assert_eq!(
            safe_external_url("http://example.com"),
            Some("http://example.com")
        );
        // Scheme comparison is case-insensitive.
        assert_eq!(
            safe_external_url("HTTPS://example.com"),
            Some("HTTPS://example.com")
        );
        // Surrounding whitespace is trimmed, not rejected.
        assert_eq!(
            safe_external_url("  https://example.com  "),
            Some("https://example.com")
        );
    }

    #[test]
    fn rejects_script_and_data_urls() {
        assert_eq!(safe_external_url("javascript:alert(1)"), None);
        assert_eq!(safe_external_url("JaVaScRiPt:alert(1)"), None);
        assert_eq!(safe_external_url("data:text/html,<script>"), None);
        assert_eq!(safe_external_url("vbscript:msgbox"), None);
        assert_eq!(safe_external_url("file:///etc/passwd"), None);
    }

    #[test]
    fn rejects_obfuscated_schemes() {
        assert_eq!(safe_external_url("java\tscript:alert(1)"), None);
        assert_eq!(safe_external_url("java\nscript:alert(1)"), None);
        assert_eq!(safe_external_url("java\0script:alert(1)"), None);
    }

    #[test]
    fn rejects_relative_and_empty() {
        assert_eq!(safe_external_url(""), None);
        assert_eq!(safe_external_url("   "), None);
        assert_eq!(safe_external_url("example.com"), None);
        assert_eq!(safe_external_url("//example.com"), None);
        assert_eq!(safe_external_url("https:"), None);
    }
}
