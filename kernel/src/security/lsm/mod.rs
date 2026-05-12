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

/// Distinguishes major and minor LSMs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmKind {
    Minor,
    #[expect(dead_code)]
    Major,
}

impl LsmKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }
}

bitflags! {
    /// LSM module flags.
    pub struct LsmFlags: u32 {
        /// Marks a module as mutually exclusive with other exclusive modules.
        const EXCLUSIVE = 1 << 0;
    }
}

/// Defines the common interface for built-in LSM modules.
pub trait LsmModule: LsmPtraceCheck + Sync {
    /// Returns the module name.
    fn name(&self) -> &'static str;

    /// Returns the module kind.
    fn kind(&self) -> LsmKind;

    /// Returns the module flags.
    fn flags(&self) -> LsmFlags;
}

pub(super) fn init() {
    modules::init();

    for module in modules::active_modules() {
        info!(
            "[kernel] LSM module enabled: {} ({})",
            module.name(),
            module.kind().as_str()
        );
    }
}
