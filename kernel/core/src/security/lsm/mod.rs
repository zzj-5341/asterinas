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

pub use self::hooks::{AlienAccessContext, AlienAccessKind, CapabilityContext, ExecContext};
use crate::{prelude::*, process::posix_thread::PosixThread};

/// Opaque task state owned by one LSM module.
pub type TaskState = Arc<dyn Any + Send + Sync>;

pub(crate) type TaskStates = Vec<Option<TaskState>>;

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

    /// Creates this module's state for a new task.
    fn init_task_state(&self) -> Result<Option<TaskState>> {
        Ok(None)
    }

    /// Derives this module's state for a cloned task.
    fn clone_task_state(&self, state: Option<&TaskState>) -> Result<Option<TaskState>> {
        Ok(state.cloned())
    }

    /// Prepares this module's state for a successful exec transition.
    fn prepare_exec(&self, context: &ExecContext<'_>) -> Result<Option<TaskState>> {
        Ok(context.raw_task_state().cloned())
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

fn task_states_with_capacity(capacity: usize) -> Result<TaskStates> {
    let mut states = Vec::new();
    states
        .try_reserve_exact(capacity)
        .map_err(|_| Error::new(Errno::ENOMEM))?;
    Ok(states)
}

fn initialize_task_states_for(modules: &[&'static dyn LsmModule]) -> Result<TaskStates> {
    let mut states = task_states_with_capacity(modules.len())?;
    for module in modules {
        states.push(module.init_task_state()?);
    }
    Ok(states)
}

#[cfg(ktest)]
fn clone_task_states_for(
    modules: &[&'static dyn LsmModule],
    current: &[Option<TaskState>],
) -> Result<TaskStates> {
    assert_eq!(modules.len(), current.len());
    let mut states = task_states_with_capacity(modules.len())?;
    for (module, state) in modules.iter().zip(current) {
        states.push(module.clone_task_state(state.as_ref())?);
    }
    Ok(states)
}

#[cfg(ktest)]
fn prepare_exec_states_for(
    modules: &[&'static dyn LsmModule],
    current: &[Option<TaskState>],
    executable_path: &[u8],
) -> Result<TaskStates> {
    assert_eq!(modules.len(), current.len());
    let mut states = task_states_with_capacity(modules.len())?;
    for (module, state) in modules.iter().zip(current) {
        let context = ExecContext::new(state.clone(), executable_path);
        states.push(module.prepare_exec(&context)?);
    }
    Ok(states)
}

pub(crate) fn initialize_task_states() -> Result<TaskStates> {
    initialize_task_states_for(modules::active_modules())
}

pub(crate) fn clone_task_states(posix_thread: &PosixThread) -> Result<TaskStates> {
    let modules = modules::active_modules();
    let mut states = task_states_with_capacity(modules.len())?;
    for (index, module) in modules.iter().enumerate() {
        let state = posix_thread.lsm_task_state(index);
        states.push(module.clone_task_state(state.as_ref())?);
    }
    Ok(states)
}

pub(crate) fn prepare_task_exec(
    posix_thread: &PosixThread,
    executable_path: &[u8],
) -> Result<TaskStates> {
    let modules = modules::active_modules();
    let mut states = task_states_with_capacity(modules.len())?;
    for (index, module) in modules.iter().enumerate() {
        let state = posix_thread.lsm_task_state(index);
        let context = ExecContext::new(state, executable_path);
        states.push(module.prepare_exec(&context)?);
    }
    Ok(states)
}

pub(crate) fn commit_task_exec(posix_thread: &PosixThread, states: TaskStates) {
    posix_thread.replace_lsm_task_states(states);
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
