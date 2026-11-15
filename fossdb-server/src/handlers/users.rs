use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// `SubscriptionRequest`/`SubscriptionResponse` come from the shared `fossdb`
// crate so the client cannot drift out of sync with the wire format.
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

pub async fn get_timeline(
    State(state): State<AppState>,
    Query(params): Query<TimelineQuery>,
    authed: Option<Extension<AuthedUser>>,
) -> Result<Json<Value>, StatusCode> {
    // Signed in: the account's personal, persisted timeline, paginated.
    // Anonymous: a global timeline synthesised from recent package versions.
    let is_authenticated = authed.is_some();

    let mut db_events = if let Some(Extension(authed)) = authed {
        let mut events = state
            .db
            .get_timeline_events_by_user(&authed.user_id)
            .map_err(|e| {
                tracing::error!("timeline lookup failed: {e}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Newest first. The secondary-key scan returns insertion order, which
        // is only incidentally chronological.
        events.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        events
    } else {
        use crate::{EventType, TimelineEvent};

        let mut versions = state
            .db
            .get_all_versions()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        versions.sort_by(|a, b| b.release_date.cmp(&a.release_date));

        versions
            .into_iter()
            .take(50)
            .filter_map(|version| {
                state
                    .db
                    .get_package(version.package_id)
                    .ok()?
                    .map(|package| {
                        let version_str = version.version.clone();
                        TimelineEvent {
                            inner: fossdb::TimelineEvent {
                                id: 0,
                                package_id: package.id,
                                user_id: None,
                                event_type: EventType::NewRelease,
                                package_name: package.name.clone(),
                                version: Some(version.version.clone()),
                                message: format!("New version {version_str} released"),
                                metadata: None,
                                created_at: version.release_date,
                            },
                        }
                    })
            })
            .collect()
    };

    let total = db_events.len();

    if is_authenticated {
        let limit = params.limit.unwrap_or(20).min(100);
        let offset = params.offset.unwrap_or(0);

        db_events = db_events.into_iter().skip(offset).take(limit).collect();

        Ok(Json(serde_json::json!({
            "events": db_events,
            "total": total,
            "limit": limit,
            "offset": offset
        })))
    } else {
        Ok(Json(serde_json::json!({ "events": db_events })))
    }
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
) -> Result<Json<SubscriptionResponse>, StatusCode> {
    let mut user = load_user(&state, &authed)?;

    if state
        .db
        .get_package_by_name(&payload.package_name)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_none()
    {
        return Err(StatusCode::NOT_FOUND);
    }

    if !user
        .subscriptions
        .iter()
        .any(|s| s.package_name == payload.package_name)
    {
        user.subscriptions.push(PackageSubscription {
            package_name: payload.package_name,
            notifications_enabled: true,
        });
        state
            .db
            .update_user(user.clone())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(Json(SubscriptionResponse {
        subscriptions: user.subscriptions.clone(),
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
        .update_user(user.clone())
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
        .update_user(user)
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
        .update_user(user.clone())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SubscriptionResponse {
        subscriptions: user.subscriptions.clone(),
    }))
}
