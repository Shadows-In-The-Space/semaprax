use super::super::Held;
use super::generation::{bootstrap, from_v1, load_chain, predecessor, prepare, Generation};
use super::*;
use crate::package_registry::trust::{stale, verify_root_rotation};

/// Non-cloneable live held authority. No serialized receipt restores this lock.
pub struct HeldTrustStore {
    held: Held,
    pin: String,
    active: String,
    generation: Generation,
}
impl HeldTrustStore {
    /// Copies exact selected subjects into the ordinary resolver cache. The
    /// destination gets data, not inherited signature/freshness authority.
    pub fn populate_resolver_cache(
        &self,
        path: &Path,
        request: &CacheFill<'_, '_>,
    ) -> std::result::Result<CacheFillReceipt, Vec<crate::diagnostic::Diagnostic>> {
        self.recheck().map_err(|error| vec![error])?;
        super::cache::populate(
            path,
            &self.generation,
            request,
            || self.recheck(),
            |read| self.read_artifact(read),
        )
    }
    /// One live explicit read, not a persistent bearer capability. All output
    /// bytes remain private until exact ACTIVE recheck under this held lock.
    pub fn read_artifact(&self, request: &ArtifactRead<'_, '_>) -> Result<VerifiedArtifact> {
        self.recheck()?;
        let artifact = super::read::verify(&self.generation, request)?;
        #[cfg(test)]
        super::read::before_release();
        self.recheck()?;
        Ok(artifact)
    }
    pub fn install(
        path: &Path,
        root: &str,
        independent_pin: &str,
        trusted_time: u64,
    ) -> Result<Self> {
        let held = Held::open(path)?;
        if !held.inventory()?.is_empty() {
            return Err(refused("bootstrap requires an empty store"));
        }
        let generation = bootstrap(root, independent_pin, trusted_time)?;
        let active = held.publish(None, &generation.bytes)?;
        let store = Self {
            held,
            pin: independent_pin.into(),
            active,
            generation,
        };
        store.recheck().map_err(|_| uncertain())?;
        Ok(store)
    }
    pub fn open(path: &Path, independent_pin: &str) -> Result<Self> {
        let held = Held::open(path)?;
        let active = held.read("ACTIVE", 66)?;
        let generation = load_chain(&held, &active, independent_pin, false)?;
        held.sync()?;
        Ok(Self {
            held,
            pin: independent_pin.into(),
            active,
            generation,
        })
    }
    fn recheck(&self) -> Result<()> {
        if self.held.read("ACTIVE", 66)? != self.active
            || load_chain(&self.held, &self.active, &self.pin, false)?.bytes
                != self.generation.bytes
        {
            return Err(refused("held store changed before commit"));
        }
        Ok(())
    }
    /// Evidence only, useful for independently retaining the exact retry predecessor.
    pub fn receipt(&self) -> CommitReceipt {
        CommitReceipt {
            generation_digest: hash(self.generation.bytes.as_bytes()),
            checkpoint_digest: hash(
                string(&self.generation.value["checkpoint"])
                    .expect("decoded")
                    .as_bytes(),
            ),
        }
    }
    pub fn commit_update(&mut self, update: &Update<'_, '_>) -> Result<CommitReceipt> {
        self.recheck()?;
        let generation = prepare(&self.generation, update, false)?;
        self.recheck()?;
        self.active = self.held.publish(Some(&self.active), &generation.bytes)?;
        self.generation = generation;
        self.recheck().map_err(|_| uncertain())?;
        Ok(self.receipt())
    }
    /// One-way same-store migration, never fallback from a v2 parse error. A
    /// signed v3 update with a complete lock/cache is mandatory for the pivot.
    pub fn migrate_v1(
        path: &Path,
        independent_pin: &str,
        expected_generation_digest: &str,
        update: &Update<'_, '_>,
    ) -> Result<Self> {
        let held = Held::open(path)?;
        let active = held.read("ACTIVE", 66)?;
        let old = super::super::load_chain(&held, &active, independent_pin, false)?;
        if hash(old.bytes.as_bytes()) != expected_generation_digest {
            return Err(refused("migration generation CAS disagrees"));
        }
        let previous = from_v1(old)?;
        let generation = prepare(&previous, update, true)?;
        // Recheck exact legacy state immediately before effects under the same lock.
        if held.read("ACTIVE", 66)? != active
            || super::super::load_chain(&held, &active, independent_pin, false)?.bytes
                != previous.bytes
        {
            return Err(refused("migration predecessor changed"));
        }
        let active = held.publish(Some(&active), &generation.bytes)?;
        let store = Self {
            held,
            pin: independent_pin.into(),
            active,
            generation,
        };
        store.recheck().map_err(|_| uncertain())?;
        Ok(store)
    }
    pub fn recover_update(
        path: &Path,
        independent_pin: &str,
        predecessor_digest: &str,
        update: &Update<'_, '_>,
        recovery_time: u64,
    ) -> Result<Self> {
        Self::recover(
            path,
            independent_pin,
            predecessor_digest,
            update,
            recovery_time,
            false,
        )
    }
    pub fn recover_migration_v1(
        path: &Path,
        independent_pin: &str,
        predecessor_digest: &str,
        update: &Update<'_, '_>,
        recovery_time: u64,
    ) -> Result<Self> {
        Self::recover(
            path,
            independent_pin,
            predecessor_digest,
            update,
            recovery_time,
            true,
        )
    }
    fn recover(
        path: &Path,
        pin: &str,
        previous_digest: &str,
        update: &Update<'_, '_>,
        now: u64,
        migration: bool,
    ) -> Result<Self> {
        let held = Held::open(path)?;
        let previous_name = format!(
            "g-{}",
            previous_digest
                .strip_prefix("sha256:")
                .ok_or_else(|| refused("invalid predecessor digest"))?
        );
        let previous = if migration {
            from_v1(super::super::load_chain(&held, &previous_name, pin, true)?)?
        } else {
            load_chain(&held, &previous_name, pin, true)?
        };
        if now < update.trusted_time {
            return Err(stale());
        }
        let rotated;
        let root = if let Some(rotation) = update.rotation {
            rotated = verify_root_rotation(&previous.root, rotation, now)?;
            rotated.root()
        } else {
            &previous.root
        };
        // Recovery must be fresh now as well as exact at original update time.
        proof::verify_update(root, &previous.checkpoint, now, &update.metadata)?;
        let generation = prepare(&previous, update, migration)?;
        let active = held.recover_profile(Some(&previous_name), &generation.bytes, predecessor)?;
        let store = Self {
            held,
            pin: pin.into(),
            active,
            generation,
        };
        store.recheck().map_err(|_| uncertain())?;
        Ok(store)
    }
    pub fn recover_install(
        path: &Path,
        root: &str,
        independent_pin: &str,
        original_time: u64,
        recovery_time: u64,
    ) -> Result<Self> {
        let held = Held::open(path)?;
        if recovery_time < original_time {
            return Err(stale());
        }
        bootstrap(root, independent_pin, recovery_time)?;
        let generation = bootstrap(root, independent_pin, original_time)?;
        let active = held.recover_profile(None, &generation.bytes, predecessor)?;
        let store = Self {
            held,
            pin: independent_pin.into(),
            active,
            generation,
        };
        store.recheck().map_err(|_| uncertain())?;
        Ok(store)
    }
}
