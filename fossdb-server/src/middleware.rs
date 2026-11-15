use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};

use crate::AppState;

/// The authenticated account, injected into request extensions.
///
/// Handlers take this as `Extension<AuthedUser>` and read `user_id` directly.
/// Carrying the resolved account here (rather than a token the handler must
/// re-parse) is what removes the old `claims.sub.parse::<u64>()` dance that
/// was repeated in seven handlers, each with its own error arm.
#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub user_id: String,
}

/// Pull a bearer credential out of the `Authorization` header.
///
/// The scheme match is case-insensitive and tolerates extra spacing, per
/// RFC 7235; the previous `strip_prefix("Bearer ")` rejected the perfectly
/// legal `bearer <id>`.
fn bearer(req: &Request) -> Option<&str> {
    let header = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = header.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| value.trim_start())
}

/// Resolve a bearer credential to an account.
///
/// Malformed ids are rejected on shape alone, before any storage access, so
/// a flood of junk tokens cannot be turned into a flood of database reads.
async fn resolve(state: &AppState, candidate: &str) -> Option<AuthedUser> {
    if !fossdb::user_id::is_well_formed(candidate) {
        return None;
    }

    // The id is the primary key, so this is an index lookup rather than a
    // comparison; there is no string-compare timing signal to leak. 128 bits
    // of entropy makes online guessing infeasible regardless.
    let user = state.db.get_user(candidate).ok()??;

    Some(AuthedUser {
        user_id: user.user_id.clone(),
    })
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let candidate = bearer(&req).ok_or(StatusCode::UNAUTHORIZED)?.to_string();

    let authed = resolve(&state, &candidate)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    req.extensions_mut().insert(authed);

    Ok(next.run(req).await)
}

/// Auth for endpoints that serve both anonymous and signed-in callers.
///
/// A *missing* credential is fine and proceeds anonymously. A *present but
/// invalid* one is rejected: previously it was silently ignored, so a caller
/// whose account had been purged kept getting anonymous responses with no
/// indication that their credential had stopped working.
pub async fn optional_auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(candidate) = bearer(&req).map(str::to_string) {
        let authed = resolve(&state, &candidate)
            .await
            .ok_or(StatusCode::UNAUTHORIZED)?;
        req.extensions_mut().insert(authed);
    }

    Ok(next.run(req).await)
}

/// Authenticate a collector or worker API key for `required_role`.
///
/// Keys live in the database and are minted and revoked through the admin
/// socket; there is no environment-variable key, so a withdrawn key really
/// stops working.
async fn authenticate_api_key(
    state: &AppState,
    candidate: &str,
    required_role: fossdb::ApiKeyRole,
) -> Option<String> {
    // Shape-check before any storage access, so junk bearer values cannot be
    // turned into database load.
    let (key_id, secret) = fossdb::api_key::split(candidate)?;

    let stored = state.db.get_api_key(key_id).ok()??;

    // Revoked keys fail exactly like unknown ones.
    if stored.revoked_at.is_some() {
        tracing::warn!("rejected revoked API key {}", key_id);
        return None;
    }

    // Check the role before the secret so a worker key presented to the
    // collector API is rejected on authorisation grounds regardless.
    if stored.role != required_role {
        tracing::warn!(
            "API key {} has role {} but {} was required",
            key_id,
            stored.role,
            required_role
        );
        return None;
    }

    if !crate::api_key::verify_secret(secret, &stored.secret_hash) {
        tracing::warn!("rejected API key {} with a bad secret", key_id);
        return None;
    }

    // Record liveness for the admin reports. A poisoned lock must not fail
    // an otherwise valid request, so this is best-effort.
    if let Ok(mut activity) = state.key_activity.lock() {
        activity.record(key_id, chrono::Utc::now());
    }

    Some(key_id.to_string())
}

pub async fn collector_auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = bearer(&req).ok_or(StatusCode::UNAUTHORIZED)?.to_string();

    authenticate_api_key(&state, &token, fossdb::ApiKeyRole::Collector)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(next.run(req).await)
}

pub async fn worker_auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = bearer(&req).ok_or(StatusCode::UNAUTHORIZED)?.to_string();

    authenticate_api_key(&state, &token, fossdb::ApiKeyRole::Worker)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request_with(header_value: &str) -> Request {
        Request::builder()
            .header(header::AUTHORIZATION, header_value)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn extracts_a_bearer_credential() {
        let req = request_with("Bearer fdb_abc");
        assert_eq!(bearer(&req), Some("fdb_abc"));
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        assert_eq!(bearer(&request_with("bearer fdb_abc")), Some("fdb_abc"));
        assert_eq!(bearer(&request_with("BEARER fdb_abc")), Some("fdb_abc"));
    }

    #[test]
    fn tolerates_extra_space_after_the_scheme() {
        assert_eq!(bearer(&request_with("Bearer    fdb_abc")), Some("fdb_abc"));
    }

    #[test]
    fn rejects_other_schemes_and_bare_values() {
        assert_eq!(bearer(&request_with("Basic fdb_abc")), None);
        assert_eq!(bearer(&request_with("fdb_abc")), None);
        assert_eq!(bearer(&request_with("")), None);
    }

    #[test]
    fn rejects_an_api_key_with_the_wrong_shape() {
        // `authenticate_api_key` must bail before touching storage.
        assert!(fossdb::api_key::split("not-a-key").is_none());
        assert!(fossdb::api_key::split("fdbk_short_x").is_none());
    }
}
