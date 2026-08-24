// SPDX-License-Identifier: MPL-2.0

//! LSM hook points.

mod alien_access;
mod capability;

pub(crate) use self::{
    alien_access::on_alien_access,
    capability::{CapableContext, on_capable},
};
pub use self::{
    alien_access::{AlienAccessContext, AlienAccessKind},
    capability::CapabilityContext,
};
use super::TaskState;
use crate::prelude::*;

/// The stable inputs for an exec transition check.
pub struct ExecContext<'a> {
    task_state: Option<TaskState>,
    executable_path: &'a [u8],
}

impl<'a> ExecContext<'a> {
    pub(super) const fn new(task_state: Option<TaskState>, executable_path: &'a [u8]) -> Self {
        Self {
            task_state,
            executable_path,
        }
    }

    /// Returns this module's typed task state.
    pub fn task_state<T: Any>(&self) -> Option<&T> {
        self.raw_task_state()?.downcast_ref()
    }

    /// Returns the resolved absolute executable path.
    pub const fn executable_path(&self) -> &[u8] {
        self.executable_path
    }

    pub(super) const fn raw_task_state(&self) -> Option<&TaskState> {
        self.task_state.as_ref()
    }
}
