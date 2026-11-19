use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod api_key;
pub mod secret_file;
pub mod typosquat;
pub mod url;
pub mod user_id;

pub use api_key::ApiKeyRole;

/// A collector or worker API key as stored by the server.
///
/// Holds only a hash of the secret, so this type is safe to keep in the
/// database but is still never returned to a client - the admin API returns
/// [`ApiKeyInfo`] instead. See the guard test in this crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Non-secret identifier, used for lookup and revocation.
    pub key_id: String,
    pub role: ApiKeyRole,
    /// Hex SHA-256 of the secret component.
    ///
    /// A plain hash rather than a password KDF: the secret carries 128 bits
    /// of entropy from a CSPRNG, so there is no dictionary to stretch
    /// against, and this is verified on every collector and worker request.
    pub secret_hash: String,
    /// Operator-supplied note, e.g. which host holds the key.
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Set when revoked. Revocation is a soft delete so that a withdrawn key
    /// remains visible in `api-key list --all` rather than silently vanishing.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Public view of an API key. Carries no secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub key_id: String,
    pub role: ApiKeyRole,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// When this key last authenticated a request.
    ///
    /// Tracked in memory only, so it resets when the server restarts. Keeping
    /// it out of the database avoids a write on every worker poll.
    pub last_used_at: Option<DateTime<Utc>>,
    pub seconds_since_use: Option<i64>,
}

impl From<ApiKey> for ApiKeyInfo {
    fn from(key: ApiKey) -> Self {
        Self {
            key_id: key.key_id,
            role: key.role,
            label: key.label,
            created_at: key.created_at,
            revoked_at: key.revoked_at,
            last_used_at: None,
            seconds_since_use: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub role: ApiKeyRole,
    pub label: Option<String>,
}

/// Response to key creation. The only time the secret is ever disclosed.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    /// The complete key, to be handed to a collector or worker.
    pub key: String,
    pub info: ApiKeyInfo,
}

impl std::fmt::Debug for CreateApiKeyResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateApiKeyResponse")
            .field("key", &"<redacted>")
            .field("info", &self.info)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Package {
    pub id: u64,
    pub name: String,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub platform: Option<String>,
    pub language: Option<String>,
    pub status: Option<String>,
    pub dependents_count: Option<u32>,
    pub rank: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVersion {
    pub id: u64,
    pub package_id: u64,
    pub version: String,
    pub release_date: DateTime<Utc>,
    pub download_url: Option<String>,
    pub checksum: Option<String>,
    pub dependencies: Vec<Dependency>,
    pub vulnerabilities: Vec<String>,
    pub changelog: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version_requirement: String,
    pub dependency_type: String,
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageSubscription {
    pub package_name: String,
    pub notifications_enabled: bool,
}

/// An account.
///
/// There is no password, no email and no username: the randomly generated
/// [`User::user_id`] is the account's sole identifier *and* its sole
/// credential. It is presented as a bearer token on the API and embedded in
/// the user's feed URLs, so it must be treated as a secret everywhere it
/// appears. See [`crate::user_id`] for the format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub user_id: String,
    pub subscriptions: Vec<PackageSubscription>,
    pub created_at: DateTime<Utc>,
    /// Global kill switch for this account's notifications. When false the
    /// account produces no live websocket events and an empty feed.
    pub notifications_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: u64,
    /// Identifier assigned by the advisory's publisher, e.g.
    /// `RUSTSEC-2024-0001` or `GHSA-xxxx-xxxx-xxxx`. Unique, and the key an
    /// advisory is upserted by, so ingesting the same advisory twice updates
    /// one row instead of creating two.
    ///
    /// Rows that predate advisory ingestion carry `fossdb-<id>`.
    #[serde(default)]
    pub source_id: String,
    pub cve_id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: VulnerabilitySeverity,
    pub affected_packages: Vec<AffectedPackage>,
    pub discovered_at: DateTime<Utc>,
    pub fixed_in: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilitySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedPackage {
    pub package_id: u64,
    pub version_range: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimelineEvent {
    pub id: u64,
    pub package_id: u64,
    /// Owning account, or `None` for a global (non-personal) event.
    pub user_id: Option<String>,
    pub event_type: EventType,
    pub package_name: String,
    pub version: Option<String>,
    pub message: String,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    NewRelease,
    SecurityAlert,
    PackageAdded,
    PackageUpdated,
    /// A release behaves differently from the last analysed one in a way
    /// subscribers should know about, without that being a vulnerability by
    /// itself, e.g. it newly runs code at install time.
    ///
    /// Kept last: stored events encode the variant by position.
    BehaviorChange,
}

pub type TimelineEventType = EventType;

/// Sent to `POST /api/auth/login`.
///
/// `Debug` deliberately redacts the id: it is a live credential, and this type
/// is the one most likely to end up in a log line or an error report.
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub user_id: String,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("user_id", &"<redacted>")
            .finish()
    }
}

/// Returned by `POST /api/auth/register`.
///
/// This is the only time the server ever discloses a freshly minted id. It is
/// not recoverable afterwards - the client must persist it.
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for RegisterResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterResponse")
            .field("user_id", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Returned by `POST /api/auth/login`. Carries no token: the id the caller
/// already holds *is* the credential, so there is nothing further to issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: UserResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_packages: u64,
    pub total_versions: u64,
    pub total_users: u64,
    pub total_vulnerabilities: u64,
    pub total_timeline_events: u64,
    pub collectors_running: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRequest {
    pub package_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Body returned by every `/users/subscriptions` endpoint.
///
/// This is the single definition of the wire format. The server previously
/// declared its own local `SubscriptionResponse { subscriptions }` that shadowed
/// this type, while this one described a completely different shape - so the
/// client could never deserialize what the server actually sent.
pub struct SubscriptionResponse {
    pub subscriptions: Vec<PackageSubscription>,
}

/// Body returned by `POST /users/subscriptions`: the account's subscriptions,
/// plus the popular package the newly followed one's name imitates, if any.
///
/// A superset of [`SubscriptionResponse`], so clients that read the reply as
/// one keep working.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResponse {
    pub subscriptions: Vec<PackageSubscription>,
    /// Lets a client warn that a subscription to e.g. `colourama` was meant
    /// for `colorama`. Judged by the same rules as the package page's warning.
    #[serde(default)]
    pub lookalike: Option<typosquat::PackageLookalike>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineResponse {
    pub events: Vec<TimelineEvent>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

/// Public view of an account.
///
/// Deliberately omits `user_id`: a caller who needs it already has it, and
/// keeping it out of general-purpose responses stops the credential from
/// being echoed into places it does not belong.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserResponse {
    pub created_at: String,
    pub subscription_count: usize,
    pub notifications_enabled: bool,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            created_at: user.created_at.to_rfc3339(),
            subscription_count: user.subscriptions.len(),
            notifications_enabled: user.notifications_enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackagesResponse {
    pub packages: Vec<Package>,
    pub total: usize,
    pub page: u32,
    pub limit: u32,
    /// For each package in `packages` whose name imitates a popular package,
    /// keyed by package id: what it imitates. Judged by the same rules as the
    /// package page's warning. Absent from servers that predate it.
    #[serde(default)]
    pub lookalikes: std::collections::HashMap<u64, typosquat::PackageLookalike>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedPackage {
    pub name: String,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
    pub tags: Vec<String>,
    pub versions: Vec<CollectedVersion>,
    pub platform: Option<String>,
    pub language: Option<String>,
    pub status: Option<String>,
    pub dependents_count: Option<u32>,
    pub rank: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedVersion {
    pub version: String,
    pub release_date: DateTime<Utc>,
    pub download_url: Option<String>,
    pub checksum: Option<String>,
    pub dependencies: Vec<Dependency>,
    pub changelog: Option<String>,
}

/// A published security advisory, as sent by a collector to
/// `POST /advisories`.
///
/// The shape follows OSV (<https://ossf.github.io/osv-schema/>), but nothing
/// here is OSV-specific: any source that can name the affected versions can
/// produce one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedAdvisory {
    /// The publisher's identifier (OSV `id`). The upsert key.
    pub source_id: String,
    /// Other identifiers for the same advisory (OSV `aliases`). The first
    /// `CVE-` entry becomes [`Vulnerability::cve_id`].
    pub aliases: Vec<String>,
    /// OSV `summary`.
    pub title: String,
    /// OSV `details`.
    pub description: String,
    pub severity: VulnerabilitySeverity,
    /// OSV `published`. Stored as [`Vulnerability::discovered_at`].
    pub published: DateTime<Utc>,
    pub affected: Vec<CollectedAffected>,
}

/// One package an advisory applies to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedAffected {
    pub package_name: String,
    /// Must equal the stored [`Package::platform`] (ignoring ASCII case) for
    /// the entry to be linked. Package names are only unique per ecosystem,
    /// so matching on the name alone could attach a crates.io advisory to an
    /// unrelated npm package that happens to share the name.
    pub platform: String,
    /// Every affected version, already enumerated by the source (OSV
    /// `versions`). The server matches these against stored versions
    /// verbatim, so it needs no ecosystem-specific version parser.
    pub affected_versions: Vec<String>,
    /// Human-readable affected ranges, e.g. `>=0, <1.2.3`. For display only.
    pub ranges: Vec<String>,
    pub fixed_in: Option<String>,
}

/// Response to `POST /advisories`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdvisoryIngestResult {
    /// The stored vulnerability, or `None` if the advisory named no package
    /// FossDB tracks and so was not stored.
    pub vulnerability_id: Option<u64>,
    /// True if this request created the vulnerability rather than updating it.
    pub created: bool,
    /// Packages the advisory was linked to.
    pub linked_packages: usize,
    /// Stored versions that now list this vulnerability.
    pub linked_versions: usize,
    /// `affected` entries that matched no stored package, as
    /// `platform/name`, so the collector can log the gap.
    pub skipped: Vec<String>,
}

/// One advisory as it applies to a single package, returned by
/// `GET /api/packages/{id}/vulnerabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVulnerability {
    #[serde(flatten)]
    pub vulnerability: Vulnerability,
    /// The advisory's affected range for this package, for display, e.g.
    /// `>=0.10.0, <0.10.2`.
    pub version_range: String,
    /// Stored versions of this package the advisory is linked to.
    pub affected_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageLookup {
    pub package: Package,
    pub version_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerTask {
    pub package: Package,
    pub version: PackageVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkerAnalysis {
    pub id: u64,
    pub package_id: u64,
    pub version_id: u64,
    pub analyzed_at: DateTime<Utc>,
    pub findings: Vec<AnalysisFinding>,
    pub checksum_verified: Option<bool>,
    pub detected_license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisFinding {
    pub kind: FindingKind,
    pub severity: FindingSeverity,
    pub description: String,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingKind {
    LicenseDetected,
    LicenseMismatch,
    /// A license file exists but its text matched none of the known licenses.
    /// Distinct from a missing license file and from a mismatch.
    LicenseUnrecognized,
    SecretDetected,
    ChecksumMismatch,
    BinaryMetadata,
    MaliciousPattern,
    SyscallReachable,
    /// Code the package runs when it is installed or built: npm lifecycle
    /// scripts, Cargo build scripts and proc-macros, Python `setup.py` and
    /// executable `.pth` files.
    ///
    /// `location` identifies the hook relative to the package root (without
    /// the versioned top-level directory that tarballs carry), so the same hook
    /// has the same location in every version of the package.
    InstallHook,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The install-time hooks of a package's most recently analysed version,
/// compared with the version analysed before it. Served by
/// `GET /api/packages/{id}/install-hooks`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageInstallHooks {
    /// The analysed version the hooks belong to.
    pub version: String,
    pub analyzed_at: DateTime<Utc>,
    /// The previously analysed version the hooks were compared with, or
    /// `None` when this is the package's first analysis. The worker only
    /// analyses each package's latest version, so this is not necessarily the
    /// preceding release.
    pub baseline_version: Option<String>,
    pub hooks: Vec<InstallHook>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstallHook {
    /// The hook relative to the package root, e.g.
    /// `package.json:scripts.postinstall` or `build.rs`.
    pub location: Option<String>,
    pub description: String,
    pub severity: FindingSeverity,
    /// How the hook differs from the baseline: `None` when it is unchanged, or
    /// when there is no baseline to compare with.
    pub change: Option<InstallHookChange>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InstallHookChange {
    /// The baseline had no hook at this location.
    Added,
    /// The baseline had a hook at this location with a different description
    /// or severity, e.g. its script changed.
    Changed,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    /// Sent by the client immediately after the socket opens to bind the
    /// connection to an account, so it receives that account's events rather
    /// than only global ones.
    Auth { user_id: String },
    Ping,
    Pong,
    TimelineEvent { event: TimelineEvent },
}

impl std::fmt::Debug for WebSocketMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Never render the credential, even in a trace log.
            Self::Auth { .. } => f.write_str("Auth { user_id: <redacted> }"),
            Self::Ping => f.write_str("Ping"),
            Self::Pong => f.write_str("Pong"),
            Self::TimelineEvent { event } => {
                f.debug_struct("TimelineEvent").field("event", event).finish()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_response_lookalikes_are_keyed_by_id_and_optional() {
        // Servers that predate search-result markers send no `lookalikes`.
        let response: PackagesResponse =
            serde_json::from_str(r#"{"packages":[],"total":0,"page":1,"limit":30}"#).unwrap();
        assert!(response.lookalikes.is_empty());

        // JSON object keys are strings; the id still has to come back a u64.
        let response: PackagesResponse = serde_json::from_str(
            r#"{"packages":[],"total":0,"page":1,"limit":30,"lookalikes":{"12":
                {"target_id":7,"target_name":"colorama","target_dependents":5000,
                 "reason":"Edit1","severity":"Medium"}}}"#,
        )
        .unwrap();
        assert_eq!(response.lookalikes[&12].target_name, "colorama");
        assert_eq!(response.lookalikes[&12].reason, typosquat::SquatReason::Edit1);
    }

    fn sample_user() -> User {
        User {
            user_id: "fdb_0123456789abcdefghjkmnpqrs".into(),
            subscriptions: vec![PackageSubscription {
                package_name: "serde".into(),
                notifications_enabled: true,
            }],
            created_at: Utc::now(),
            notifications_enabled: true,
        }
    }

    /// The id is a bearer credential. `UserResponse` is returned from general
    /// endpoints, so it must never carry it - this is the same class of bug as
    /// the `password_hash` leak this type previously guarded against.
    #[test]
    fn user_response_does_not_expose_the_credential() {
        let user = sample_user();
        let secret = user.user_id.clone();

        let response = AuthResponse { user: user.into() };

        let json = serde_json::to_value(&response).unwrap();
        assert!(json["user"].get("user_id").is_none());
        assert!(!json.to_string().contains(&secret));
        assert_eq!(json["user"]["subscription_count"], 1);
    }

    /// Credential-bearing types are the ones most likely to be logged, so
    /// their `Debug` impls are hand-written to redact. Guard that.
    #[test]
    fn debug_impls_redact_the_credential() {
        let secret = "fdb_0123456789abcdefghjkmnpqrs";

        let login = LoginRequest { user_id: secret.into() };
        assert!(!format!("{login:?}").contains(secret));

        let register = RegisterResponse {
            user_id: secret.into(),
            created_at: Utc::now(),
        };
        assert!(!format!("{register:?}").contains(secret));

        let auth = WebSocketMessage::Auth { user_id: secret.into() };
        assert!(!format!("{auth:?}").contains(secret));
    }

    /// `ApiKeyInfo` is what the admin API returns. It must not carry the
    /// secret hash, for the same reason `UserResponse` carries no id.
    #[test]
    fn api_key_info_does_not_expose_the_hash() {
        let key = ApiKey {
            key_id: "4m7k2xqa".into(),
            role: ApiKeyRole::Worker,
            secret_hash: "deadbeefcafe".into(),
            label: Some("worker-01".into()),
            created_at: Utc::now(),
            revoked_at: None,
        };

        let json = serde_json::to_value(ApiKeyInfo::from(key)).unwrap();

        assert!(json.get("secret_hash").is_none());
        assert!(!json.to_string().contains("deadbeefcafe"));
        assert_eq!(json["key_id"], "4m7k2xqa");
        assert_eq!(json["role"], "worker");
    }

    #[test]
    fn create_api_key_response_redacts_the_key_in_debug() {
        let secret = "fdbk_4m7k2xqa_3k9x7m2qdv5r8ptw1ny6az4cbf";
        let response = CreateApiKeyResponse {
            key: secret.into(),
            info: ApiKeyInfo {
                key_id: "4m7k2xqa".into(),
                role: ApiKeyRole::Collector,
                label: None,
                created_at: Utc::now(),
                revoked_at: None,
                last_used_at: None,
                seconds_since_use: None,
            },
        };

        assert!(!format!("{response:?}").contains(secret));
    }

    /// The wire format is what the CLI and the browser both parse; pin it.
    #[test]
    fn register_response_round_trips() {
        let original = RegisterResponse {
            user_id: "fdb_0123456789abcdefghjkmnpqrs".into(),
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: RegisterResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.user_id, original.user_id);
        assert_eq!(parsed.created_at, original.created_at);
    }
}
