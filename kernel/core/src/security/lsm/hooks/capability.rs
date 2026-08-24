// SPDX-License-Identifier: MPL-2.0

use super::super::{TaskState, modules};
use crate::{
    prelude::*,
    process::{
        UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::{AsPosixThread, PosixThread},
    },
};

/// Checks one Linux capability for the current POSIX thread in the initial user namespace.
pub fn require_current_capability(capability_number: u8) -> Result<()> {
    let required_cap = CapSet::from_capability_number(u64::from(capability_number))
        .ok_or_else(|| Error::new(Errno::EINVAL))?;
    let current = current_thread!();
    let posix_thread = current
        .as_posix_thread()
        .ok_or_else(|| Error::new(Errno::EINVAL))?;

    on_capable(CapabilityContext::new(
        UserNamespace::get_init_singleton().as_ref(),
        posix_thread,
        required_cap,
    ))
}

/// Runs capability hooks in module order.
pub(crate) fn on_capable(context: CapabilityContext) -> Result<()> {
    for (index, module) in modules::active_modules().iter().enumerate() {
        let task_state = context.posix_thread.lsm_task_state(index);
        let module_context = context.with_task_state(task_state);
        module.on_capable(&module_context)?;
    }

    Ok(())
}

/// The inputs for checking whether a thread has a capability.
pub struct CapabilityContext<'a> {
    target_user_ns: &'a UserNamespace,
    posix_thread: &'a PosixThread,
    required_cap: CapSet,
    task_state: Option<TaskState>,
}

impl<'a> CapabilityContext<'a> {
    /// Creates a capability check context.
    pub(crate) const fn new(
        target_user_ns: &'a UserNamespace,
        posix_thread: &'a PosixThread,
        required_cap: CapSet,
    ) -> Self {
        Self {
            target_user_ns,
            posix_thread,
            required_cap,
            task_state: None,
        }
    }

    fn with_task_state(&self, task_state: Option<TaskState>) -> Self {
        Self {
            target_user_ns: self.target_user_ns,
            posix_thread: self.posix_thread,
            required_cap: self.required_cap,
            task_state,
        }
    }

    /// Returns this module's typed task state.
    pub fn task_state<T: Any>(&self) -> Option<&T> {
        self.task_state.as_ref()?.downcast_ref()
    }

    /// Returns the checked task's ID.
    pub fn task_id(&self) -> u32 {
        self.posix_thread.tid()
    }

    /// Returns the one requested Linux capability number.
    pub fn required_capability(&self) -> Option<u8> {
        let bits = self.required_cap.bits();
        bits.is_power_of_two()
            .then_some(bits.trailing_zeros() as u8)
    }

    /// Returns the user namespace against which the capability is checked.
    #[expect(
        dead_code,
        reason = "Asterinas currently has only the initial user namespace"
    )]
    pub(crate) const fn target_user_ns(&self) -> &UserNamespace {
        self.target_user_ns
    }

    /// Returns the thread whose credentials are checked.
    pub(crate) const fn posix_thread(&self) -> &PosixThread {
        self.posix_thread
    }

    /// Returns the required capability.
    pub(crate) const fn required_cap(&self) -> CapSet {
        self.required_cap
    }
}

pub(crate) type CapableContext<'a> = CapabilityContext<'a>;
