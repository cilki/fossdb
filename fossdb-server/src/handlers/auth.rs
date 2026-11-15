use axum::{Json, extract::State, http::StatusCode};
use chrono::Utc;
use fossdb::{AuthResponse, LoginRequest, RegisterResponse};

use crate::AppState;
use crate::models::User;

/// How many times to retry a credential collision before giving up.
///
/// At 128 bits a collision will not happen; this exists so that if it somehow
/// does, registration retries instead of handing the caller someone else's
/// account or a 500.
const MINT_ATTEMPTS: usize = 4;

/// `POST /api/auth/register`
///
/// Takes no request body. The server mints the credential, because letting a
/// caller choose it would let them pick a guessable one or squat on an id
/// another user is about to be given.
///
/// The returned id is disclosed exactly once and is not recoverable: nothing
/// else about the account identifies its owner.
pub async fn register(
    State(state): State<AppState>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let created_at = Utc::now();

    for _ in 0..MINT_ATTEMPTS {
        let user_id = crate::user_id::generate().map_err(|e| {
            tracing::error!("failed to mint account id: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let user = User {
            inner: fossdb::User {
                user_id: user_id.clone(),
                subscriptions: Vec::new(),
                created_at,
                notifications_enabled: true,
            },
        };

        match state.db.insert_user(user) {
            // `None` means the id was taken; loop and draw fresh entropy.
            Ok(None) => continue,
            Ok(Some(user)) => {
                tracing::info!(
                    "registered account {}",
                    fossdb::user_id::redact(&user.user_id)
                );
                return Ok(Json(RegisterResponse {
                    user_id: user.user_id.clone(),
                    created_at: user.created_at,
                }));
            }
            Err(e) => {
                tracing::error!("failed to persist new account: {e}");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    tracing::error!("exhausted {MINT_ATTEMPTS} attempts minting a unique account id");
    Err(StatusCode::INTERNAL_SERVER_ERROR)
}

/// `POST /api/auth/login`
///
/// Confirms an id names a live account. No token is issued - the caller
/// already holds the only credential there is. This exists so a client can
/// validate input before storing it, and so the CLI can tell "wrong id" apart
/// from "server unreachable".
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Normalise first: accept an id as the user retyped it, with stray case,
    // spacing or dashes, rather than rejecting it for cosmetic reasons.
    let user_id = fossdb::user_id::normalize(&payload.user_id);

    if !fossdb::user_id::is_well_formed(&user_id) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user = state
        .db
        .get_user(&user_id)
        .map_err(|e| {
            tracing::error!("account lookup failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(Json(AuthResponse {
        user: user.inner.clone().into(),
    }))
}
