use native_db::*;
use native_model::{Model, native_model};
use serde::{Deserialize, Serialize};

macro_rules! impl_deref {
    ($wrapper:ty, $inner:ty) => {
        impl std::ops::Deref for $wrapper {
            type Target = $inner;
            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }
        impl std::ops::DerefMut for $wrapper {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 1, version = 1)]
#[native_db(
    primary_key(id -> u64),
    secondary_key(name -> String, unique),
)]
pub struct Package {
    pub inner: fossdb::Package,
}

impl Package {
    fn id(&self) -> u64 {
        self.id
    }
    fn name(&self) -> String {
        self.name.clone()
    }
}

impl_deref!(Package, fossdb::Package);

/// The version 1 `PackageVersion` row, kept only so that
/// [`crate::db::Database::new`] can migrate it to version 2.
///
/// Field order must match what was encoded: rows are stored positionally.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[native_model(id = 2, version = 1)]
#[native_db(
    primary_key(id -> u64),
    secondary_key(package_id -> u64),
)]
pub struct PackageVersionV1 {
    pub id: u64,
    pub package_id: u64,
    pub version: String,
    pub release_date: chrono::DateTime<chrono::Utc>,
    pub download_url: Option<String>,
    pub checksum: Option<String>,
    pub dependencies: Vec<fossdb::Dependency>,
    pub vulnerabilities: Vec<String>,
    pub changelog: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl PackageVersionV1 {
    fn id(&self) -> u64 {
        self.id
    }
    fn package_id(&self) -> u64 {
        self.package_id
    }
}

/// Version 2 adds `yanked_at`. v1 rows migrate as live versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 2, version = 2, from = PackageVersionV1)]
#[native_db(
    primary_key(id -> u64),
    secondary_key(package_id -> u64),
)]
pub struct PackageVersion {
    pub inner: fossdb::PackageVersion,
}

impl PackageVersion {
    fn id(&self) -> u64 {
        self.id
    }
    fn package_id(&self) -> u64 {
        self.package_id
    }
}

impl From<PackageVersionV1> for PackageVersion {
    fn from(v: PackageVersionV1) -> Self {
        Self {
            inner: fossdb::PackageVersion {
                id: v.id,
                package_id: v.package_id,
                version: v.version,
                release_date: v.release_date,
                download_url: v.download_url,
                checksum: v.checksum,
                dependencies: v.dependencies,
                vulnerabilities: v.vulnerabilities,
                changelog: v.changelog,
                created_at: v.created_at,
                yanked_at: None,
            },
        }
    }
}

impl From<PackageVersion> for PackageVersionV1 {
    fn from(v: PackageVersion) -> Self {
        let v = v.inner;
        Self {
            id: v.id,
            package_id: v.package_id,
            version: v.version,
            release_date: v.release_date,
            download_url: v.download_url,
            checksum: v.checksum,
            dependencies: v.dependencies,
            vulnerabilities: v.vulnerabilities,
            changelog: v.changelog,
            created_at: v.created_at,
        }
    }
}

impl_deref!(PackageVersion, fossdb::PackageVersion);

/// Version 2 dropped password/email/username authentication in favour of a
/// single random credential, which is now the primary key. There is
/// deliberately no `from` migration: a v1 row has no credential to carry
/// forward, and inventing one would strand the account's owner. v1 rows must
/// be cleared - see [`crate::db::Database::preflight`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 3, version = 2)]
#[native_db(
    primary_key(user_id -> String),
)]
pub struct User {
    pub inner: fossdb::User,
}

impl User {
    fn user_id(&self) -> String {
        self.user_id.clone()
    }
}

impl_deref!(User, fossdb::User);

/// The version 1 `Vulnerability` row, kept only so that
/// [`crate::db::Database::new`] can migrate it to version 2.
///
/// Field order must match what was encoded: rows are stored positionally.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[native_model(id = 4, version = 1)]
#[native_db(
    primary_key(id -> u64),
)]
pub struct VulnerabilityV1 {
    pub id: u64,
    pub cve_id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: fossdb::VulnerabilitySeverity,
    pub affected_packages: Vec<fossdb::AffectedPackage>,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
    pub fixed_in: Option<String>,
}

impl VulnerabilityV1 {
    fn id(&self) -> u64 {
        self.id
    }
}

/// `source_id` stand-in for a vulnerability that has no publisher id: v1 rows
/// and imports from exports written before v2.
pub fn legacy_source_id(id: u64) -> String {
    format!("fossdb-{id}")
}

/// Version 2 adds the unique `source_id` key that advisories are upserted by.
/// v1 rows migrate with [`legacy_source_id`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 4, version = 2, from = VulnerabilityV1)]
#[native_db(
    primary_key(id -> u64),
    secondary_key(source_id -> String, unique),
)]
pub struct Vulnerability {
    pub inner: fossdb::Vulnerability,
}

impl Vulnerability {
    fn id(&self) -> u64 {
        self.id
    }
    fn source_id(&self) -> String {
        self.source_id.clone()
    }
}

impl From<VulnerabilityV1> for Vulnerability {
    fn from(v: VulnerabilityV1) -> Self {
        Self {
            inner: fossdb::Vulnerability {
                id: v.id,
                source_id: legacy_source_id(v.id),
                cve_id: v.cve_id,
                title: v.title,
                description: v.description,
                severity: v.severity,
                affected_packages: v.affected_packages,
                discovered_at: v.discovered_at,
                fixed_in: v.fixed_in,
            },
        }
    }
}

impl From<Vulnerability> for VulnerabilityV1 {
    fn from(v: Vulnerability) -> Self {
        let v = v.inner;
        Self {
            id: v.id,
            cve_id: v.cve_id,
            title: v.title,
            description: v.description,
            severity: v.severity,
            affected_packages: v.affected_packages,
            discovered_at: v.discovered_at,
            fixed_in: v.fixed_in,
        }
    }
}

impl_deref!(Vulnerability, fossdb::Vulnerability);

/// Version 2 follows `User` v2: the owning account is now identified by its
/// string credential rather than a numeric id, and the `notified_at` email
/// bookkeeping field is gone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 5, version = 2)]
#[native_db(
    primary_key(id -> u64),
    secondary_key(package_id -> u64),
    secondary_key(user_id -> Option<String>, optional),
)]
pub struct TimelineEvent {
    pub inner: fossdb::TimelineEvent,
}

impl TimelineEvent {
    fn id(&self) -> u64 {
        self.id
    }
    fn package_id(&self) -> u64 {
        self.package_id
    }
    fn user_id(&self) -> Option<String> {
        self.user_id.clone()
    }
}

impl_deref!(TimelineEvent, fossdb::TimelineEvent);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 6, version = 1)]
#[native_db(
    primary_key(id -> u64),
    secondary_key(package_id -> u64),
    secondary_key(version_id -> u64),
)]
pub struct WorkerAnalysis {
    pub inner: fossdb::WorkerAnalysis,
}

impl WorkerAnalysis {
    fn id(&self) -> u64 {
        self.id
    }
    fn package_id(&self) -> u64 {
        self.package_id
    }
    fn version_id(&self) -> u64 {
        self.version_id
    }
}

impl_deref!(WorkerAnalysis, fossdb::WorkerAnalysis);

/// Collector and worker API keys.
///
/// Keyed by the non-secret key id so that authentication is a single
/// primary-key lookup rather than a scan over every key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 7, version = 1)]
#[native_db(
    primary_key(key_id -> String),
)]
pub struct ApiKey {
    pub inner: fossdb::ApiKey,
}

impl ApiKey {
    fn key_id(&self) -> String {
        self.key_id.clone()
    }
}

impl_deref!(ApiKey, fossdb::ApiKey);
