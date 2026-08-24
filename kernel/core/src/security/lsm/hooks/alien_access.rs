// SPDX-License-Identifier: MPL-2.0

//! Hooks for alien access checks.
//!
//! Linux names the corresponding LSM hook after `ptrace`, but Asterinas uses
//! `alien access` for permission checks against threads outside the caller's
//! thread group.

use super::super::{TaskState, modules};
use crate::{
    prelude::*,
    process::posix_thread::{
        PosixThread,
        alien_access::{AlienAccessKind as InternalAlienAccessKind, AlienAccessMode},
    },
};

/// Runs alien access hooks in module order.
pub(crate) fn on_alien_access(context: AlienAccessContext) -> Result<()> {
    for (index, module) in modules::active_modules().iter().enumerate() {
        let accessor_state = context.accessor.lsm_task_state(index);
        let target_state = context.target.lsm_task_state(index);
        let module_context = context.with_task_states(accessor_state, target_state);
        module.on_alien_access(&module_context)?;
    }

    Ok(())
}

/// The inputs for an alien access check through the LSM stack.
pub struct AlienAccessContext<'a> {
    accessor: &'a PosixThread,
    target: &'a PosixThread,
    mode: AlienAccessMode,
    accessor_state: Option<TaskState>,
    target_state: Option<TaskState>,
}

impl<'a> AlienAccessContext<'a> {
    /// Creates an alien access context.
    pub(crate) const fn new(
        accessor: &'a PosixThread,
        target: &'a PosixThread,
        mode: AlienAccessMode,
    ) -> Self {
        Self {
            accessor,
            target,
            mode,
            accessor_state: None,
            target_state: None,
        }
    }

    fn with_task_states(
        &self,
        accessor_state: Option<TaskState>,
        target_state: Option<TaskState>,
    ) -> Self {
        Self {
            accessor: self.accessor,
            target: self.target,
            mode: self.mode,
            accessor_state,
            target_state,
        }
    }

    /// Returns the accessor's task state owned by this module.
    pub fn accessor_state<T: Any>(&self) -> Option<&T> {
        self.accessor_state.as_ref()?.downcast_ref()
    }

    /// Returns the target's task state owned by this module.
    pub fn target_state<T: Any>(&self) -> Option<&T> {
        self.target_state.as_ref()?.downcast_ref()
    }

    /// Returns the accessor task ID.
    pub fn accessor_id(&self) -> u32 {
        self.accessor.tid()
    }

    /// Returns the target task ID.
    pub fn target_id(&self) -> u32 {
        self.target.tid()
    }

    /// Returns the stable class of alien access being checked.
    pub const fn kind(&self) -> AlienAccessKind {
        match self.mode.kind() {
            InternalAlienAccessKind::Attach => AlienAccessKind::PtraceAttach,
            InternalAlienAccessKind::Read => AlienAccessKind::Other,
        }
    }

    /// Returns the thread requesting access.
    pub(crate) const fn accessor(&self) -> &PosixThread {
        self.accessor
    }

    /// Returns the thread being accessed.
    pub(crate) const fn target(&self) -> &PosixThread {
        self.target
    }

    /// Returns the requested access mode.
    pub(crate) const fn mode(&self) -> AlienAccessMode {
        self.mode
    }
}

/// An alien-access operation exposed to extension LSMs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlienAccessKind {
    /// A ptrace-strength attachment check.
    PtraceAttach,
    /// Any alien access outside the M1 ptrace-attach surface.
    Other,
}
