//! The public HTTP API's routing table.

use axum::{
    Router,
    response::Json,
    routing::{get, post, put},
};
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use crate::{AppState, handlers, middleware, websocket};

/// Router for the public API.
///
/// Bearer auth is attached with `route_layer`, not `layer`: `layer` also
/// wraps the router's fallback, so once merged every unknown path answered
/// 401 instead of 404, telling a caller with a typo or an outdated client that
/// their credential was the problem.
pub fn public_router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/packages", post(handlers::packages::create_package))
        .route("/api/users/subscriptions", get(handlers::users::get_subscriptions))
        .route("/api/users/subscriptions", post(handlers::users::add_subscription))
        .route(
            "/api/users/subscriptions/{package_name}",
            axum::routing::delete(handlers::users::remove_subscription),
        )
        .route(
            "/api/users/subscriptions/{package_name}/notifications",
            put(handlers::users::update_package_notification),
        )
        .route("/api/users/settings/notifications", get(handlers::users::get_notification_settings))
        .route("/api/users/settings/notifications", put(handlers::users::update_notification_settings))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ))
        .with_state(state.clone());

    let timeline_route = Router::new()
        .route("/api/users/timeline", get(handlers::users::get_timeline))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::optional_auth_middleware,
        ))
        .with_state(state.clone());

    Router::new()
        .route("/api/health", get(health_check))
        .route("/api/stats", get(handlers::analytics::get_db_stats))
        .route("/api/packages", get(handlers::packages::list_packages))
        .route("/api/packages/{id}", get(handlers::packages::get_package))
        .route("/api/packages/{id}/versions", get(handlers::packages::get_package_versions))
        .route("/api/packages/{id}/vulnerabilities", get(handlers::packages::get_package_vulnerabilities))
        .route("/api/packages/{id}/install-hooks", get(handlers::packages::get_package_install_hooks))
        .route("/api/packages/{id}/lookalike", get(handlers::packages::get_package_lookalike))
        .route("/api/packages/{id}/subscribers", get(handlers::packages::get_package_subscriber_count))
        .route("/api/auth/register", post(handlers::auth::register))
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/analytics", get(handlers::analytics::get_analytics))
        .route("/api/analytics/languages", get(handlers::analytics::get_language_trends))
        .route("/api/analytics/security", get(handlers::analytics::get_security_report))
        .route("/ws/timeline", get(websocket::timeline_websocket_handler))
        // Feeds authenticate by path: the id in the URL is the credential, so
        // these must stay off the bearer-auth router.
        .route("/feed/{user_id}/atom.xml", get(handlers::feed::atom))
        .route("/feed/{user_id}/rss.xml", get(handlers::feed::rss))
        .merge(timeline_route)
        .merge(protected)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "fossdb"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::new(dir.path().join("db").to_str().unwrap()).unwrap();
        let state = AppState {
            db: Arc::new(db),
            broadcaster: Arc::new(websocket::TimelineBroadcaster::new()),
            key_activity: Arc::new(Mutex::new(crate::key_activity::KeyActivity::new())),
            claimed_versions: Arc::new(Mutex::new(crate::claims::ClaimSet::new())),
            lookalikes: Arc::new(crate::lookalike::LookalikeTargets::new()),
            public_base_url: "http://localhost:3000".into(),
            started_at: chrono::Utc::now(),
        };
        (dir, state)
    }

    async fn status(method: Method, path: &str, bearer: Option<&str>) -> StatusCode {
        let (_dir, state) = state();
        let mut req = Request::builder().method(method).uri(path);
        if let Some(token) = bearer {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        public_router(state)
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn unknown_paths_are_not_found_not_unauthorized() {
        assert_eq!(status(Method::GET, "/", None).await, StatusCode::NOT_FOUND);
        assert_eq!(status(Method::GET, "/health", None).await, StatusCode::NOT_FOUND);
        assert_eq!(status(Method::GET, "/api/search", None).await, StatusCode::NOT_FOUND);
        // A credential the server rejects must not turn a 404 into a 401 either.
        assert_eq!(
            status(Method::GET, "/api/nope", Some("fdb_0123456789abcdefghjkmnpqrs")).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn protected_routes_still_require_a_credential() {
        assert_eq!(
            status(Method::GET, "/api/users/subscriptions", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(Method::DELETE, "/api/users/subscriptions/serde", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(Method::GET, "/api/users/timeline", Some("fdb_0123456789abcdefghjkmnpqrs")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(status(Method::GET, "/api/health", None).await, StatusCode::OK);
    }
}
