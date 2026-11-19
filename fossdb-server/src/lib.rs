pub use fossdb::{
    AffectedPackage, AnalysisFinding, AuthResponse, CreatePackageRequest, DatabaseStats,
    Dependency, EventType, FindingKind, FindingSeverity, LoginRequest, PackageSubscription,
    PackagesResponse, RegisterResponse, SubscriptionRequest, SubscriptionResponse,
    TimelineEventType, TimelineResponse, UserResponse, VulnerabilitySeverity, WebSocketMessage,
    WorkerTask,
};

#[cfg(feature = "db")]
pub mod db;
#[cfg(feature = "db")]
pub mod id_generator;
#[cfg(feature = "db")]
pub mod models;
#[cfg(feature = "db")]
pub use models::{
    ApiKey, Package, PackageVersion, TimelineEvent, User, Vulnerability, WorkerAnalysis,
};

#[cfg(all(feature = "api-server", unix))]
pub mod admin;
#[cfg(feature = "api-server")]
pub mod claims;
#[cfg(feature = "api-server")]
pub mod config;
#[cfg(feature = "api-server")]
pub mod db_listener;
#[cfg(feature = "api-server")]
pub mod feed;
#[cfg(feature = "api-server")]
pub mod key_activity;
#[cfg(feature = "api-server")]
pub mod lookalike;
#[cfg(feature = "api-server")]
pub mod handlers;
#[cfg(feature = "api-server")]
pub mod middleware;
#[cfg(feature = "api-server")]
pub mod api_key;
#[cfg(feature = "api-server")]
pub mod routes;
#[cfg(feature = "api-server")]
pub mod user_id;
#[cfg(feature = "api-server")]
pub mod websocket;

// Application state for API server
#[cfg(feature = "api-server")]
#[derive(Clone)]
pub struct AppState {
    pub db: std::sync::Arc<db::Database>,
    pub broadcaster: std::sync::Arc<websocket::TimelineBroadcaster>,
    /// Last-seen timestamps per API key, powering the admin reports.
    ///
    /// In memory only; see [`key_activity::KeyActivity`]. Collector and
    /// worker keys themselves live in the database and are managed through
    /// the admin socket, so there is no shared secret held here.
    pub key_activity: std::sync::Arc<std::sync::Mutex<key_activity::KeyActivity>>,
    /// Version IDs currently claimed by a worker, preventing double-assignment.
    /// Claims expire, so a worker that dies mid-task does not block its version
    /// forever. See [`claims::ClaimSet`].
    pub claimed_versions: std::sync::Arc<std::sync::Mutex<claims::ClaimSet>>,
    /// The popular package names each new package is checked against for
    /// typosquatting. See [`lookalike::LookalikeTargets`].
    pub lookalikes: std::sync::Arc<lookalike::LookalikeTargets>,
    /// Absolute origin this server is reachable at, used to build the
    /// self-referential links that feed readers require.
    pub public_base_url: String,
    /// Process start time, reported by the admin socket.
    pub started_at: chrono::DateTime<chrono::Utc>,
}

