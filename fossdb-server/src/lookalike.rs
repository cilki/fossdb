//! Typosquat detection for packages arriving from the collectors.
//!
//! Each new package is compared, within its ecosystem, against the most
//! depended-on packages already stored, using
//! [`fossdb::typosquat::lookalike_of`]. That set is computed from the whole
//! database, so it is cached and rebuilt at most once per
//! [`REFRESH_INTERVAL`].

use anyhow::Result;
use fossdb::typosquat::{lookalike_of, PackageLookalike, SquatReason};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::db::Database;
use crate::{Package, PackageVersion};

/// Most popular packages per ecosystem that new names are checked against.
pub const TARGETS_PER_PLATFORM: usize = 1000;

/// A package needs at least this many dependents to be worth imitating.
/// Without a floor, every obscure package in a small ecosystem would be a
/// target, and any new name one edit from it would raise an alert.
pub const MIN_TARGET_POPULARITY: u32 = 5;

/// How long a computed target set is reused. Packages that become popular
/// in the meantime are picked up on the next rebuild.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// A popular package a new name may be imitating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: u64,
    pub name: String,
    /// Dependents: the larger of what the collector reported and the number
    /// of stored packages whose versions depend on it.
    pub popularity: u32,
}

struct PlatformTargets {
    /// Most popular first, which is the order `lookalike_of` breaks ties in.
    targets: Vec<Target>,
    /// Popularity at which a candidate would itself be among `targets`.
    threshold: u32,
}

struct Cached {
    built_at: Instant,
    platforms: HashMap<String, PlatformTargets>,
}

/// The cached per-ecosystem target sets.
pub struct LookalikeTargets {
    cache: Mutex<Option<Cached>>,
}

impl Default for LookalikeTargets {
    fn default() -> Self {
        Self::new()
    }
}

impl LookalikeTargets {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(None),
        }
    }

    /// The popular package `candidate` most plausibly imitates, if any.
    ///
    /// A candidate popular enough to be a target itself is never reported:
    /// two established packages with similar names are not a new threat.
    pub fn check(
        &self,
        db: &Database,
        candidate: &fossdb::Package,
    ) -> Result<Option<PackageLookalike>> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache
            .as_ref()
            .is_none_or(|c| c.built_at.elapsed() >= REFRESH_INTERVAL)
        {
            *cache = Some(Cached {
                built_at: Instant::now(),
                platforms: build(db)?,
            });
        }
        let platforms = &cache.as_ref().expect("filled above").platforms;

        let platform = platform_key(candidate.platform.as_deref());
        let Some(entry) = platforms.get(&platform) else {
            return Ok(None);
        };
        if candidate.dependents_count.unwrap_or(0) >= entry.threshold {
            return Ok(None);
        }

        let names: Vec<&str> = entry.targets.iter().map(|t| t.name.as_str()).collect();
        let Some(found) = lookalike_of(&candidate.name, &names) else {
            return Ok(None);
        };
        // PyPI normalises names (PEP 503), so `foo_bar` and `Foo-Bar` are one
        // project there, not an imitation of each other.
        if found.reason == SquatReason::SeparatorOrCase && platform == "pypi" {
            return Ok(None);
        }
        let target = entry
            .targets
            .iter()
            .find(|t| t.name == found.target)
            .expect("lookalike_of returns one of the names it was given");
        Ok(Some(PackageLookalike {
            target_id: target.id,
            target_name: target.name.clone(),
            target_dependents: target.popularity,
            reason: found.reason,
            severity: found.reason.severity(),
        }))
    }
}

fn platform_key(platform: Option<&str>) -> String {
    platform.unwrap_or_default().to_ascii_lowercase()
}

/// Compute every ecosystem's target set from the database.
fn build(db: &Database) -> Result<HashMap<String, PlatformTargets>> {
    let r = db.db.r_transaction()?;

    // Dependency name -> distinct packages depending on it. Covers the
    // ecosystems whose collector reports no `dependents_count` (crates.io,
    // nixpkgs). Names are globally unique in this database, so a dependency
    // name identifies the package.
    let mut dependents: HashMap<String, HashSet<u64>> = HashMap::new();
    for version in r.scan().primary::<PackageVersion>()?.all()? {
        let version = version?;
        for dep in &version.dependencies {
            dependents
                .entry(dep.name.clone())
                .or_default()
                .insert(version.package_id);
        }
    }

    let mut by_platform: HashMap<String, Vec<Target>> = HashMap::new();
    for package in r.scan().primary::<Package>()?.all()? {
        let package = package?;
        let in_db = dependents.get(&package.name).map_or(0, |d| {
            d.iter().filter(|&&id| id != package.id).count() as u32
        });
        let popularity = package.dependents_count.unwrap_or(0).max(in_db);
        if popularity < MIN_TARGET_POPULARITY {
            continue;
        }
        by_platform
            .entry(platform_key(package.platform.as_deref()))
            .or_default()
            .push(Target {
                id: package.id,
                name: package.inner.name,
                popularity,
            });
    }

    Ok(by_platform
        .into_iter()
        .map(|(platform, mut targets)| {
            targets.sort_by(|a, b| b.popularity.cmp(&a.popularity).then(a.name.cmp(&b.name)));
            targets.truncate(TARGETS_PER_PLATFORM);
            let threshold = if targets.len() == TARGETS_PER_PLATFORM {
                targets.last().map_or(MIN_TARGET_POPULARITY, |t| t.popularity)
            } else {
                MIN_TARGET_POPULARITY
            };
            (platform, PlatformTargets { targets, threshold })
        })
        .collect())
}
