// SPDX-License-Identifier: MPL-2.0

//! LSM hook points.

mod alien_access;
mod capability;
mod file;

pub use self::{
    alien_access::{AlienAccessContext, on_alien_access},
    capability::{CapableContext, on_capable},
    file::{FileOpenContext, on_file_open},
};
use crate::prelude::*;

pub(super) trait LsmAlienAccessHook: Sync {
    /// Handles an alien access attempt.
    fn on_alien_access(&self, _context: &AlienAccessContext) -> Result<()> {
        Ok(())
    }
}

pub(super) trait LsmCapabilityHook: Sync {
    /// Checks whether a thread holds a capability in a user namespace.
    fn on_capable(&self, _context: &CapableContext) -> Result<()> {
        Ok(())
    }
}

pub(super) trait LsmFileHook: Sync {
    /// Checks whether a new file handle may be opened.
    fn on_file_open(&self, _context: &FileOpenContext<'_>) -> Result<()> {
        Ok(())
    }
}
