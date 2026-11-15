//! Feed endpoints.
//!
//! These are the one place where the account credential travels in a URL
//! path rather than an `Authorization` header, because feed readers cannot
//! be configured with custom headers. The id in the path *is* the
//! authentication.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::AppState;
use crate::feed::{self, FeedContext};

/// Which serialisation a request wants.
enum Format {
    Atom,
    Rss,
}

pub async fn atom(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    serve(state, path, headers, Format::Atom).await
}

pub async fn rss(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    serve(state, path, headers, Format::Rss).await
}

async fn serve(
    State(state): State<AppState>,
    Path(raw_user_id): Path<String>,
    headers: HeaderMap,
    format: Format,
) -> Result<Response, StatusCode> {
    // Tolerate a `.xml` that a reader appended, and the usual transcription
    // noise, before validating.
    let user_id = fossdb::user_id::normalize(raw_user_id.trim_end_matches(".xml"));

    // Shape-check before touching storage so that feed-URL scanning cannot be
    // converted into database load.
    if !fossdb::user_id::is_well_formed(&user_id) {
        return Err(StatusCode::NOT_FOUND);
    }

    // A wrong id is indistinguishable from a deleted account: both 404. There
    // is deliberately no 401 here - it would confirm that an id is merely
    // unauthorised rather than nonexistent.
    let user = state
        .db
        .get_user(&user_id)
        .map_err(|e| {
            tracing::error!("feed account lookup failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Honour the account-wide switch: an opted-out account gets a valid but
    // empty feed rather than a 404, so the reader does not drop the
    // subscription outright.
    let events = if user.notifications_enabled {
        state
            .db
            .get_timeline_events_by_user(&user_id)
            .map_err(|e| {
                tracing::error!("feed timeline lookup failed: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    } else {
        Vec::new()
    };

    let ctx = FeedContext {
        user_id: &user_id,
        base_url: &state.public_base_url,
        events: &events,
    };

    let rendered = match format {
        Format::Atom => feed::render_atom(&ctx),
        Format::Rss => feed::render_rss(&ctx),
    };

    // Feed readers poll aggressively. Answering an unchanged feed with 304
    // avoids re-serialising and re-sending the whole document every few
    // minutes.
    if client_has_current_copy(&headers, &rendered) {
        return Ok(not_modified(&rendered));
    }

    Ok(ok(&rendered))
}

/// True when the client's validators show it already holds this exact feed.
///
/// `If-None-Match` takes precedence over `If-Modified-Since`, per RFC 9110.
fn client_has_current_copy(headers: &HeaderMap, rendered: &feed::Feed) -> bool {
    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        // A client may send several candidates, and `*` matches anything.
        return inm
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == "*" || candidate == rendered.etag);
    }

    let (Some(ims), Some(last_modified)) = (
        headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok()),
        rendered.last_modified,
    ) else {
        return false;
    };

    let Ok(since) = chrono::DateTime::parse_from_rfc2822(ims) else {
        return false;
    };

    // HTTP dates have one-second resolution, so compare truncated.
    last_modified.timestamp() <= since.timestamp()
}

/// Headers common to both 200 and 304 responses.
///
/// `Cache-Control: private` matters here: the URL embeds a credential, so a
/// shared cache must never retain the body.
fn validators(rendered: &feed::Feed) -> Vec<(header::HeaderName, HeaderValue)> {
    let mut out = vec![(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=300"),
    )];

    if let Ok(etag) = HeaderValue::from_str(&rendered.etag) {
        out.push((header::ETAG, etag));
    }

    if let Some(last_modified) = rendered.last_modified
        && let Ok(value) = HeaderValue::from_str(&last_modified.to_rfc2822())
    {
        out.push((header::LAST_MODIFIED, value));
    }

    out
}

fn ok(rendered: &feed::Feed) -> Response {
    let mut response = (StatusCode::OK, rendered.body.clone()).into_response();
    let headers = response.headers_mut();

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static_or_fallback(rendered.content_type),
    );
    for (name, value) in validators(rendered) {
        headers.insert(name, value);
    }

    response
}

fn not_modified(rendered: &feed::Feed) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    let headers = response.headers_mut();

    for (name, value) in validators(rendered) {
        headers.insert(name, value);
    }

    response
}

/// Small helper so a malformed content type cannot panic a request.
trait HeaderValueExt {
    fn from_static_or_fallback(s: &str) -> HeaderValue;
}

impl HeaderValueExt for HeaderValue {
    fn from_static_or_fallback(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static("application/xml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn rendered(etag: &str, last_modified: Option<chrono::DateTime<Utc>>) -> feed::Feed {
        feed::Feed {
            body: String::new(),
            content_type: "application/atom+xml; charset=utf-8",
            last_modified,
            etag: etag.to_string(),
        }
    }

    fn headers(name: header::HeaderName, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(name, HeaderValue::from_str(value).unwrap());
        map
    }

    #[test]
    fn matching_etag_is_a_hit() {
        let feed = rendered("W/\"3-100\"", None);
        let h = headers(header::IF_NONE_MATCH, "W/\"3-100\"");
        assert!(client_has_current_copy(&h, &feed));
    }

    #[test]
    fn differing_etag_is_a_miss() {
        let feed = rendered("W/\"4-200\"", None);
        let h = headers(header::IF_NONE_MATCH, "W/\"3-100\"");
        assert!(!client_has_current_copy(&h, &feed));
    }

    #[test]
    fn etag_list_and_wildcard_are_handled() {
        let feed = rendered("W/\"3-100\"", None);

        let list = headers(header::IF_NONE_MATCH, "W/\"1-1\", W/\"3-100\"");
        assert!(client_has_current_copy(&list, &feed));

        let wildcard = headers(header::IF_NONE_MATCH, "*");
        assert!(client_has_current_copy(&wildcard, &feed));
    }

    #[test]
    fn if_modified_since_is_honoured() {
        let now = Utc::now();
        let feed = rendered("W/\"1-1\"", Some(now - Duration::hours(2)));

        let fresh = headers(header::IF_MODIFIED_SINCE, &now.to_rfc2822());
        assert!(client_has_current_copy(&fresh, &feed));

        let stale = headers(
            header::IF_MODIFIED_SINCE,
            &(now - Duration::hours(5)).to_rfc2822(),
        );
        assert!(!client_has_current_copy(&stale, &feed));
    }

    #[test]
    fn etag_wins_over_if_modified_since() {
        let now = Utc::now();
        let feed = rendered("W/\"9-9\"", Some(now - Duration::hours(2)));

        // Date says "unchanged", ETag says otherwise. ETag is authoritative,
        // so this must be a miss.
        let mut h = headers(header::IF_NONE_MATCH, "W/\"1-1\"");
        h.insert(
            header::IF_MODIFIED_SINCE,
            HeaderValue::from_str(&now.to_rfc2822()).unwrap(),
        );
        assert!(!client_has_current_copy(&h, &feed));
    }

    #[test]
    fn garbage_validators_are_a_miss_not_a_panic() {
        let feed = rendered("W/\"1-1\"", Some(Utc::now()));
        let h = headers(header::IF_MODIFIED_SINCE, "not a date");
        assert!(!client_has_current_copy(&h, &feed));
    }

    #[test]
    fn no_validators_is_a_miss() {
        let feed = rendered("W/\"1-1\"", Some(Utc::now()));
        assert!(!client_has_current_copy(&HeaderMap::new(), &feed));
    }

    /// The URL embeds a credential, so a shared cache must not store it.
    #[test]
    fn responses_are_marked_private() {
        let feed = rendered("W/\"1-1\"", Some(Utc::now()));
        let cache_control = validators(&feed)
            .into_iter()
            .find(|(name, _)| name == header::CACHE_CONTROL)
            .map(|(_, value)| value)
            .expect("cache-control present");

        assert!(cache_control.to_str().unwrap().contains("private"));
    }
}
