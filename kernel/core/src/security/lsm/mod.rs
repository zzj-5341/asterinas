// SPDX-License-Identifier: MPL-2.0

//! The Linux Security Module (LSM) framework.
//!
//! LSM lets the kernel route security-sensitive operations through a stack of
//! built-in policy modules. Each module can implement shared hook traits and
//! inspect common hook contexts before allowing or rejecting an operation.
//!
//! This module defines the common LSM traits and hook contexts shared by
//! built-in modules such as `capability` and `yama`. Module selection follows
//! the `lsm=` and legacy `security=` kernel command-line parameters.

pub(crate) mod hooks;
mod modules;

pub(crate) mod yama {
    pub(crate) use super::modules::yama::{YamaScope, get_scope, set_scope};
}

use spin::Once;

pub use self::hooks::{AlienAccessContext, CapabilityContext};
use crate::prelude::*;

bitflags! {
    /// LSM module flags.
    pub struct LsmFlags: u32 {
        /// Marks a module as selectable through the legacy `security=` parameter.
        const LEGACY_MAJOR = 1 << 0;
        /// Marks a module as mutually exclusive with other exclusive modules.
        const EXCLUSIVE = 1 << 1;
    }
}

/// The common interface for LSM modules.
pub trait LsmModule: Send + Sync {
    /// Returns the module name.
    fn name(&self) -> &'static str;

    /// Returns the module flags.
    fn flags(&self) -> LsmFlags;

    /// Initializes an active module.
    fn init(&self) -> Result<()> {
        Ok(())
    }

    /// Checks whether a thread holds a capability in a user namespace.
    fn on_capable(&self, _context: &CapabilityContext<'_>) -> Result<()> {
        Ok(())
    }

    /// Handles an alien access attempt.
    fn on_alien_access(&self, _context: &AlienAccessContext<'_>) -> Result<()> {
        Ok(())
    }
}

/// An LSM module registration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    /// A built-in or extension module already uses the name.
    DuplicateName,
    /// Active-module selection has already started.
    SelectionClosed,
}

/// Registers an extension LSM before active-module selection.
pub fn register(module: &'static dyn LsmModule) -> core::result::Result<(), RegistrationError> {
    modules::register(module)
}

/// Returns whether the Yama LSM is enabled.
pub(crate) fn is_yama_enabled() -> bool {
    modules::active_modules()
        .iter()
        .any(|module| module.name() == "yama")
}

static INITIALIZED: Once<()> = Once::new();

pub(super) fn init() {
    INITIALIZED.call_once(|| {
        for module in modules::active_modules() {
            module.init().unwrap_or_else(|error| {
                panic!("failed to initialize LSM `{}`: {error:?}", module.name())
            });
            info!("[kernel] LSM module enabled: {}", module.name());
        }
    });
}
