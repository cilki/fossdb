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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 2, version = 1)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
#[native_model(id = 4, version = 1)]
#[native_db(
    primary_key(id -> u64),
)]
pub struct Vulnerability {
    pub inner: fossdb::Vulnerability,
}

impl Vulnerability {
    fn id(&self) -> u64 {
        self.id
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
