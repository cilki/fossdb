use anyhow::Result;
use native_db::*;
use once_cell::sync::Lazy;
use std::sync::Arc;

use crate::id_generator::IdGenerator;
use crate::models::{
    PackageKey, PackageVersionKey, TimelineEventKey, WorkerAnalysisKey,
};
use crate::models::{ApiKey, WorkerAnalysis};
use crate::*;

macro_rules! impl_insert {
    ($method:ident, $type:ty, $id_gen:ident) => {
        pub fn $method(&self, mut entity: $type) -> Result<$type> {
            if entity.id == 0 {
                entity.id = self.$id_gen.next();
            }
            let rw = self.db.rw_transaction()?;
            rw.insert(entity.clone())?;
            rw.commit()?;
            Ok(entity)
        }
    };
    (#[allow(dead_code)] $method:ident, $type:ty, $id_gen:ident) => {
        #[allow(dead_code)]
        pub fn $method(&self, mut entity: $type) -> Result<$type> {
            if entity.id == 0 {
                entity.id = self.$id_gen.next();
            }
            let rw = self.db.rw_transaction()?;
            rw.insert(entity.clone())?;
            rw.commit()?;
            Ok(entity)
        }
    };
}

macro_rules! impl_get {
    ($method:ident, $type:ty) => {
        pub fn $method(&self, id: u64) -> Result<Option<$type>> {
            let r = self.db.r_transaction()?;
            Ok(r.get().primary(id)?)
        }
    };
    (#[allow(dead_code)] $method:ident, $type:ty) => {
        #[allow(dead_code)]
        pub fn $method(&self, id: u64) -> Result<Option<$type>> {
            let r = self.db.r_transaction()?;
            Ok(r.get().primary(id)?)
        }
    };
}

macro_rules! impl_get_all {
    ($method:ident, $type:ty) => {
        pub fn $method(&self) -> Result<Vec<$type>> {
            let r = self.db.r_transaction()?;
            let all: Vec<$type> = r.scan().primary()?.all()?.collect::<Result<Vec<_>, _>>()?;
            Ok(all)
        }
    };
}

macro_rules! impl_update {
    ($method:ident, $type:ty) => {
        pub fn $method(&self, entity: $type) -> Result<()> {
            let rw = self.db.rw_transaction()?;
            if let Some(old) = rw.get().primary::<$type>(entity.id)? {
                rw.remove(old)?;
            }
            rw.insert(entity)?;
            rw.commit()?;
            Ok(())
        }
    };
}

macro_rules! find_max_id {
    ($tx:expr, $type:ty) => {
        $tx.scan()
            .primary::<$type>()?
            .all()?
            .map(|e| e.map(|item| item.id).unwrap_or(0))
            .max()
            .unwrap_or(0)
    };
}

static MODELS: Lazy<Models> = Lazy::new(|| {
    let mut models = Models::new();
    models.define::<Package>().unwrap();
    models.define::<PackageVersion>().unwrap();
    models.define::<User>().unwrap();
    models.define::<Vulnerability>().unwrap();
    models.define::<TimelineEvent>().unwrap();
    models.define::<WorkerAnalysis>().unwrap();
    models.define::<ApiKey>().unwrap();
    models
});

pub struct Database {
    pub db: native_db::Database<'static>,
    package_ids: Arc<IdGenerator>,
    version_ids: Arc<IdGenerator>,
    #[allow(dead_code)]
    vulnerability_ids: Arc<IdGenerator>,
    timeline_ids: Arc<IdGenerator>,
    analysis_ids: Arc<IdGenerator>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let db = Builder::new().create(&MODELS, path)?;

        let r = db.r_transaction()?;

        let max_package_id = find_max_id!(r, Package);
        let max_version_id = find_max_id!(r, PackageVersion);
        let max_vulnerability_id = find_max_id!(r, Vulnerability);
        let max_timeline_id = find_max_id!(r, TimelineEvent);
        let max_analysis_id = find_max_id!(r, WorkerAnalysis);

        drop(r);

        // `saturating_add` so a corrupt/hostile max id cannot overflow here;
        // `IdGenerator::next` then fails loudly rather than wrapping to 0.
        let package_ids = Arc::new(IdGenerator::new(max_package_id.saturating_add(1)));
        let version_ids = Arc::new(IdGenerator::new(max_version_id.saturating_add(1)));
        let vulnerability_ids = Arc::new(IdGenerator::new(max_vulnerability_id.saturating_add(1)));
        let timeline_ids = Arc::new(IdGenerator::new(max_timeline_id.saturating_add(1)));
        let analysis_ids = Arc::new(IdGenerator::new(max_analysis_id.saturating_add(1)));

        Ok(Self {
            db,
            package_ids,
            version_ids,
            vulnerability_ids,
            timeline_ids,
            analysis_ids,
        })
    }

    /// Fail fast, and legibly, on a database written before the auth rewrite.
    ///
    /// `User` and `TimelineEvent` moved to native_model version 2 with no
    /// backward migration, so v1 rows cannot be decoded. Without this check
    /// the first scan to touch one surfaces a raw native_model decode error
    /// from somewhere deep in a request handler, which tells an operator
    /// nothing useful.
    pub fn preflight(&self) -> Result<()> {
        let r = self.db.r_transaction()?;

        let users = r.scan().primary::<User>().and_then(|s| {
            s.all()
                .map(|iter| iter.collect::<Result<Vec<_>, _>>())
        });
        let events = r.scan().primary::<TimelineEvent>().and_then(|s| {
            s.all()
                .map(|iter| iter.collect::<Result<Vec<_>, _>>())
        });

        if users.is_err() || matches!(users, Ok(Err(_))) || events.is_err() || matches!(events, Ok(Err(_)))
        {
            anyhow::bail!(
                "this database predates the user-id authentication rewrite and cannot be \
                 opened.\n\n\
                 The `User` and `TimelineEvent` tables moved to native_model version 2. \
                 Version 1 rows stored a password hash, email and username, none of which \
                 exist any more, and they carry no user id to migrate forward - so there is \
                 no way to preserve a login.\n\n\
                 To proceed, remove the database file and let the server recreate it:\n\
                 \x20   rm -rf <DATABASE_PATH>\n\n\
                 Package, version, vulnerability and analysis data live in the same file and \
                 will be lost as well; export them first with `fossdb-server export` using \
                 the previous build if you need them."
            );
        }

        Ok(())
    }

    impl_insert!(insert_package, Package, package_ids);
    impl_get!(get_package, Package);

    /// Exact lookup by name. `name` is a `unique` secondary key, so this must
    /// use `get().secondary()` rather than a `start_with` prefix scan, which
    /// would match any package whose name merely begins with `name`.
    pub fn get_package_by_name(&self, name: &str) -> Result<Option<Package>> {
        let r = self.db.r_transaction()?;
        Ok(r.get().secondary(PackageKey::name, name)?)
    }

    impl_get_all!(get_all_packages, Package);
    impl_update!(update_package, Package);

    impl_insert!(insert_version, PackageVersion, version_ids);
    impl_get!(
        #[allow(dead_code)]
        get_version,
        PackageVersion
    );

    pub fn get_versions_by_package(&self, package_id: u64) -> Result<Vec<PackageVersion>> {
        let r = self.db.r_transaction()?;
        let versions: Vec<PackageVersion> = r
            .scan()
            .secondary(PackageVersionKey::package_id)?
            .start_with(package_id)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(versions)
    }

    impl_get_all!(get_all_versions, PackageVersion);

    /// Insert a user whose `user_id` has already been generated.
    ///
    /// Returns `Ok(None)` if that id is already taken, so the caller can
    /// retry with fresh entropy rather than surfacing a 500. A collision is
    /// vanishingly unlikely at 128 bits, but "unlikely" is not "impossible"
    /// and the failure would otherwise be silent corruption of someone
    /// else's account.
    pub fn insert_user(&self, user: User) -> Result<Option<User>> {
        let rw = self.db.rw_transaction()?;
        if rw.get().primary::<User>(user.user_id.clone())?.is_some() {
            return Ok(None);
        }
        rw.insert(user.clone())?;
        rw.commit()?;
        Ok(Some(user))
    }

    /// Exact primary-key lookup. This is the authentication hot path: every
    /// authenticated request resolves its bearer credential through here.
    pub fn get_user(&self, user_id: &str) -> Result<Option<User>> {
        let r = self.db.r_transaction()?;
        Ok(r.get().primary(user_id.to_string())?)
    }

    impl_get_all!(get_all_users, User);

    pub fn update_user(&self, user: User) -> Result<()> {
        let rw = self.db.rw_transaction()?;
        if let Some(old) = rw.get().primary::<User>(user.user_id.clone())? {
            rw.remove(old)?;
        }
        rw.insert(user)?;
        rw.commit()?;
        Ok(())
    }

    /// Delete an account and every timeline event belonging to it.
    ///
    /// Both happen in one transaction: a half-applied delete would leave
    /// orphaned events that no longer resolve to an account but still occupy
    /// the `user_id` index.
    pub fn delete_user(&self, user_id: &str) -> Result<bool> {
        let rw = self.db.rw_transaction()?;

        let Some(user) = rw.get().primary::<User>(user_id.to_string())? else {
            return Ok(false);
        };

        let events: Vec<TimelineEvent> = rw
            .scan()
            .secondary(TimelineEventKey::user_id)?
            .start_with(Some(user_id.to_string()))?
            .collect::<Result<Vec<_>, _>>()?;

        for event in events {
            rw.remove(event)?;
        }
        rw.remove(user)?;
        rw.commit()?;

        Ok(true)
    }

    impl_insert!(
        #[allow(dead_code)]
        insert_vulnerability,
        Vulnerability,
        vulnerability_ids
    );
    impl_get!(
        #[allow(dead_code)]
        get_vulnerability,
        Vulnerability
    );
    impl_get_all!(get_all_vulnerabilities, Vulnerability);

    impl_insert!(insert_timeline_event, TimelineEvent, timeline_ids);
    impl_get!(
        #[allow(dead_code)]
        get_timeline_event,
        TimelineEvent
    );
    impl_get_all!(get_all_timeline_events, TimelineEvent);

    #[allow(dead_code)]
    pub fn get_timeline_by_package(&self, package_id: u64) -> Result<Vec<TimelineEvent>> {
        let r = self.db.r_transaction()?;
        let events: Vec<TimelineEvent> = r
            .scan()
            .secondary(TimelineEventKey::package_id)?
            .start_with(package_id)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(events)
    }

    impl_update!(update_timeline_event, TimelineEvent);

    pub fn get_timeline_events_by_user(&self, user_id: &str) -> Result<Vec<TimelineEvent>> {
        let r = self.db.r_transaction()?;
        let events: Vec<TimelineEvent> = r
            .scan()
            .secondary(TimelineEventKey::user_id)?
            .start_with(Some(user_id.to_string()))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(events)
    }

    /// Accounts that should receive an event for `package_name`.
    ///
    /// Both notification switches are enforced here: the per-package one and
    /// the account-wide one. The account-wide flag used to be checked only at
    /// email-send time, so when the email subsystem was removed it would have
    /// silently become a no-op; centralising it here keeps it meaningful for
    /// websocket delivery and for feeds.
    pub fn get_users_subscribed_to(&self, package_name: &str) -> Result<Vec<String>> {
        let all_users = self.get_all_users()?;
        Ok(all_users
            .into_iter()
            .filter(|u| u.notifications_enabled)
            .filter(|u| {
                u.subscriptions
                    .iter()
                    .any(|s| s.package_name == package_name && s.notifications_enabled)
            })
            .map(|u| u.user_id.clone())
            .collect())
    }

    /// Delete accounts that never subscribed to anything.
    ///
    /// An account is reaped once it is older than `grace` and holds no
    /// subscriptions. Note this also reaps an established account that has
    /// since removed its last subscription - there is no "was once active"
    /// exemption, by design: an account with no subscriptions produces no
    /// events and no feed, so retaining it serves no purpose.
    pub fn purge_unsubscribed_users(&self, grace: chrono::Duration) -> Result<usize> {
        let cutoff = chrono::Utc::now() - grace;

        let stale: Vec<String> = self
            .get_all_users()?
            .into_iter()
            .filter(|u| u.created_at < cutoff && u.subscriptions.is_empty())
            .map(|u| u.user_id.clone())
            .collect();

        let mut purged = 0;
        for user_id in stale {
            if self.delete_user(&user_id)? {
                purged += 1;
            }
        }

        Ok(purged)
    }

    impl_insert!(insert_worker_analysis, WorkerAnalysis, analysis_ids);
    impl_get!(get_worker_analysis, WorkerAnalysis);
    impl_get_all!(get_all_analyses, WorkerAnalysis);

    pub fn get_analyses_by_package(&self, package_id: u64) -> Result<Vec<WorkerAnalysis>> {
        let r = self.db.r_transaction()?;
        let analyses: Vec<WorkerAnalysis> = r
            .scan()
            .secondary(WorkerAnalysisKey::package_id)?
            .start_with(package_id)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(analyses)
    }

    pub fn get_analyses_by_version(&self, version_id: u64) -> Result<Vec<WorkerAnalysis>> {
        let r = self.db.r_transaction()?;
        let analyses: Vec<WorkerAnalysis> = r
            .scan()
            .secondary(WorkerAnalysisKey::version_id)?
            .start_with(version_id)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(analyses)
    }

    /// Store a newly minted API key.
    pub fn insert_api_key(&self, key: ApiKey) -> Result<ApiKey> {
        let rw = self.db.rw_transaction()?;
        rw.insert(key.clone())?;
        rw.commit()?;
        Ok(key)
    }

    /// Look up a key by its non-secret id.
    ///
    /// This is the collector/worker authentication hot path.
    pub fn get_api_key(&self, key_id: &str) -> Result<Option<ApiKey>> {
        let r = self.db.r_transaction()?;
        Ok(r.get().primary(key_id.to_string())?)
    }

    pub fn get_all_api_keys(&self) -> Result<Vec<ApiKey>> {
        let r = self.db.r_transaction()?;
        let all: Vec<ApiKey> = r.scan().primary()?.all()?.collect::<Result<Vec<_>, _>>()?;
        Ok(all)
    }

    /// Mark a key revoked.
    ///
    /// A soft delete: the record stays so the key remains visible in an
    /// audit listing, and so a revoked id is never reissued. Returns
    /// `Ok(None)` if no such key exists, and the already-revoked key
    /// unchanged if it was revoked before, so revoking twice is harmless.
    pub fn revoke_api_key(&self, key_id: &str) -> Result<Option<ApiKey>> {
        let rw = self.db.rw_transaction()?;

        let Some(existing) = rw.get().primary::<ApiKey>(key_id.to_string())? else {
            return Ok(None);
        };

        if existing.revoked_at.is_some() {
            return Ok(Some(existing));
        }

        let mut revoked = existing.clone();
        revoked.inner.revoked_at = Some(chrono::Utc::now());

        rw.remove(existing)?;
        rw.insert(revoked.clone())?;
        rw.commit()?;

        Ok(Some(revoked))
    }

    pub fn purge_old_timeline_events(&self, older_than: chrono::Duration) -> Result<usize> {
        use chrono::Utc;

        let cutoff_time = Utc::now() - older_than;
        let r = self.db.r_transaction()?;

        let all_events: Vec<TimelineEvent> = r
            .scan()
            .primary()?
            .all()?
            .collect::<Result<Vec<_>, _>>()?;

        let events_to_delete: Vec<TimelineEvent> = all_events
            .into_iter()
            .filter(|event| event.created_at < cutoff_time)
            .collect();

        let delete_count = events_to_delete.len();

        if delete_count > 0 {
            drop(r);
            let rw = self.db.rw_transaction()?;
            for event in events_to_delete {
                rw.remove(event)?;
            }
            rw.commit()?;
        }

        Ok(delete_count)
    }
}
