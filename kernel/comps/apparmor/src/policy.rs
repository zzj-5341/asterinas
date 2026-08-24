// SPDX-License-Identifier: MPL-2.0

use alloc::{string::String, sync::Arc, vec::Vec};

use aster_core::{Errno, Error, Result};
use spin::RwLock;

mod decoder;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileMode {
    Enforce,
    Complain,
}

pub(crate) struct Profile {
    pub(crate) attachment: String,
    pub(crate) mode: ProfileMode,
    pub(crate) allowed_capabilities: u64,
}

#[derive(Clone)]
pub(crate) enum TaskLabel {
    Unconfined,
    Confined(Arc<Profile>),
}

pub(crate) struct PolicySnapshot {
    pub(crate) profiles: Vec<Arc<Profile>>,
}

impl PolicySnapshot {
    pub(crate) fn profile_for_exec(&self, executable_path: &[u8]) -> Option<Arc<Profile>> {
        let path = core::str::from_utf8(executable_path).ok()?;
        self.profiles
            .binary_search_by(|profile| profile.attachment.as_str().cmp(path))
            .ok()
            .map(|index| self.profiles[index].clone())
    }
}

pub(crate) struct PolicyStore {
    snapshot: RwLock<Option<Arc<PolicySnapshot>>>,
}

impl PolicyStore {
    pub(crate) const fn new() -> Self {
        Self {
            snapshot: RwLock::new(None),
        }
    }

    pub(crate) fn load(&self, bytes: &[u8]) -> Result<()> {
        if self.snapshot.read().is_some() {
            return Err(Error::new(Errno::EEXIST));
        }

        let candidate = decoder::decode(bytes)?;
        let mut snapshot = self.snapshot.write();
        if snapshot.is_some() {
            return Err(Error::new(Errno::EEXIST));
        }
        *snapshot = Some(candidate);
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Option<Arc<PolicySnapshot>> {
        self.snapshot.read().clone()
    }
}
