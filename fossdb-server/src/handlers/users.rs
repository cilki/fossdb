use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};

// `SubscriptionRequest`/`SubscriptionResponse` come from the shared `fossdb`
// crate so the client cannot drift out of sync with the wire format.
use fossdb::{SubscribeResponse, TimelineResponse};

use crate::db::Database;
use crate::lookalike::LookalikeTargets;
use crate::middleware::AuthedUser;
use crate::{AppState, PackageSubscription, SubscriptionRequest, SubscriptionResponse};

#[derive(Debug, Deserialize)]
pub struct UpdatePackageNotificationRequest {
    pub notifications_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct NotificationSettingsRequest {
    pub notifications_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct NotificationSettingsResponse {
    pub notifications_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Fetch the caller's account, mapping the two failure modes apart.
///
/// `NOT_FOUND` here means the credential authenticated but the account has
/// since been deleted - most likely reaped by the unsubscribed-account purge
/// between the middleware lookup and this one.
fn load_user(state: &AppState, authed: &AuthedUser) -> Result<crate::models::User, StatusCode> {
    state
        .db
        .get_user(&authed.user_id)
        .map_err(|e| {
            tracing::error!("account lookup failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)
}

/// The account's personal, persisted timeline, newest first and paginated.
pub async fn get_timeline(
    State(state): State<AppState>,
    Query(params): Query<TimelineQuery>,
    Extension(authed): Extension<AuthedUser>,
) -> Result<Json<TimelineResponse>, StatusCode> {
    let mut events = state
        .db
        .get_timeline_events_by_user(&authed.user_id)
        .map_err(|e| {
            tracing::error!("timeline lookup failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // The secondary-key scan returns insertion order, which is only
    // incidentally chronological.
    events.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let total = events.len();
    let limit = params.limit.unwrap_or(20).min(100);
    let offset = params.offset.unwrap_or(0);

    Ok(Json(TimelineResponse {
        events: events.into_iter().skip(offset).take(limit).map(|e| e.inner).collect(),
        total,
        limit,
        offset,
    }))
}

pub async fn get_subscriptions(
    State(state): State<AppState>,
    Extension(authed): Extension<AuthedUser>,
) -> Result<Json<SubscriptionResponse>, StatusCode> {
    let user = load_user(&state, &authed)?;

    Ok(Json(SubscriptionResponse {
        subscriptions: user.subscriptions.clone(),
    }))
}

pub async fn add_subscription(
    State(state): State<AppState>,
    Extension(authed): Extension<AuthedUser>,
    Json(payload): Json<SubscriptionRequest>,
) -> Result<Json<SubscribeResponse>, StatusCode> {
    let user = load_user(&state, &authed)?;

    match subscribe(&state.db, &state.lookalikes, user, &payload.package_name) {
        Ok(Some(response)) => Ok(Json(response)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("subscribing to {} failed: {e}", payload.package_name);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Subscribe `user` to `package_name`, and report the popular package that
/// name imitates so the client can warn about a likely typo. `None` when no
/// package has that name.
///
/// Subscribing to a lookalike is still allowed: it may be deliberate (to
/// watch a suspected squat), and a failed lookalike check never blocks it.
pub fn subscribe(
    db: &Database,
    lookalikes: &LookalikeTargets,
    mut user: crate::models::User,
    package_name: &str,
) -> anyhow::Result<Option<SubscribeResponse>> {
    let Some(package) = db.get_package_by_name(package_name)? else {
        return Ok(None);
    };

    if !user
        .subscriptions
        .iter()
        .any(|s| s.package_name == package_name)
    {
        user.subscriptions.push(PackageSubscription {
            package_name: package_name.to_string(),
            notifications_enabled: true,
        });
        db.update(user.clone())?;
    }

    let lookalike = match lookalikes.check(db, &package) {
        Ok(found) => found,
        Err(e) => {
            tracing::warn!("lookalike check of {package_name} failed: {e}");
            None
        }
    };

    Ok(Some(SubscribeResponse {
        subscriptions: user.subscriptions.clone(),
        lookalike,
    }))
}

pub async fn remove_subscription(
    State(state): State<AppState>,
    Extension(authed): Extension<AuthedUser>,
    Path(package_name): Path<String>,
) -> Result<Json<SubscriptionResponse>, StatusCode> {
    let mut user = load_user(&state, &authed)?;

    user.subscriptions
        .retain(|s| s.package_name != package_name);

    state
        .db
        .update(user.clone())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SubscriptionResponse {
        subscriptions: user.subscriptions.clone(),
    }))
}

pub async fn get_notification_settings(
    State(state): State<AppState>,
    Extension(authed): Extension<AuthedUser>,
) -> Result<Json<NotificationSettingsResponse>, StatusCode> {
    let user = load_user(&state, &authed)?;

    Ok(Json(NotificationSettingsResponse {
        notifications_enabled: user.notifications_enabled,
    }))
}

pub async fn update_notification_settings(
    State(state): State<AppState>,
    Extension(authed): Extension<AuthedUser>,
    Json(payload): Json<NotificationSettingsRequest>,
) -> Result<Json<NotificationSettingsResponse>, StatusCode> {
    let mut user = load_user(&state, &authed)?;

    user.notifications_enabled = payload.notifications_enabled;

    state
        .db
        .update(user)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(NotificationSettingsResponse {
        notifications_enabled: payload.notifications_enabled,
    }))
}

pub async fn update_package_notification(
    State(state): State<AppState>,
    Extension(authed): Extension<AuthedUser>,
    Path(package_name): Path<String>,
    Json(payload): Json<UpdatePackageNotificationRequest>,
) -> Result<Json<SubscriptionResponse>, StatusCode> {
    let mut user = load_user(&state, &authed)?;

    let Some(subscription) = user
        .subscriptions
        .iter_mut()
        .find(|s| s.package_name == package_name)
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    subscription.notifications_enabled = payload.notifications_enabled;

    state
        .db
        .update(user.clone())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SubscriptionResponse {
        subscriptions: user.subscriptions.clone(),
    }))
}
