// SPDX-License-Identifier: MPL-2.0

//! The Linux Security Module (LSM) framework.
//!
//! LSM lets the kernel route security-sensitive operations through a stack of
//! built-in policy modules. Each module can implement shared hook traits and
//! inspect common hook contexts before allowing or rejecting an operation.
//!
//! This module defines the common LSM traits, ptrace hook contexts, and
//! dispatch helpers shared by built-in modules such as `yama`. Module selection
//! follows the `lsm=` and legacy `security=` kernel command-line parameters.

mod checks;
mod modules;

pub use self::{
    checks::ptrace::{
        CredsSource, LsmPtraceCheck, PtraceAccessContext, PtraceAccessKind, PtraceAccessMode,
        ptrace_access_check,
    },
    modules::yama::{YamaScope, get_yama_scope, set_yama_scope},
};
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

/// Defines the common interface for built-in LSM modules.
pub trait LsmModule: LsmPtraceCheck + Sync {
    /// Returns the module name.
    fn name(&self) -> &'static str;

    /// Returns the module flags.
    fn flags(&self) -> LsmFlags;
}

/// Returns whether the Yama LSM is enabled.
pub fn is_yama_enabled() -> bool {
    modules::active_modules()
        .iter()
        .any(|module| module.name() == "yama")
}

pub(super) fn init() {
    modules::init();

    for module in modules::active_modules() {
        info!("[kernel] LSM module enabled: {}", module.name());
    }
}
