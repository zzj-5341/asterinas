// SPDX-License-Identifier: MPL-2.0

//! Per-task state shared by Linux Security Modules.

use super::{modules, modules::apparmor::Label};
use crate::{prelude::*, process::posix_thread::PosixThread};

pub(crate) fn task_attrs_enabled() -> bool {
    modules::active_modules()
        .iter()
        .any(|module| module.task_attrs().is_some())
}

pub(crate) fn task_attr_current(posix_thread: &PosixThread) -> Result<String> {
    modules::active_modules()
        .iter()
        .find_map(|module| module.task_attrs())
        .ok_or_else(|| Error::with_message(Errno::ENOENT, "no LSM task attribute is available"))?
        .current(posix_thread)
}

pub(crate) fn set_task_attr_current(posix_thread: &PosixThread, value: &str) -> Result<()> {
    modules::active_modules()
        .iter()
        .find_map(|module| module.task_attrs())
        .ok_or_else(|| Error::with_message(Errno::ENOENT, "no LSM task attribute is available"))?
        .set_current(posix_thread, value)
}

/// Security state associated with a POSIX task.
pub struct TaskSecurity {
    apparmor_label: RwLock<Option<Arc<Label>>>,
}

impl TaskSecurity {
    /// Creates security state for an unconfined task.
    pub fn new() -> Self {
        Self {
            apparmor_label: RwLock::new(None),
        }
    }

    /// Creates security state inherited from a parent task.
    pub(crate) fn inherit(&self) -> Self {
        Self {
            apparmor_label: RwLock::new(self.apparmor_label()),
        }
    }

    /// Returns the current AppArmor label.
    pub(in crate::security::lsm) fn apparmor_label(&self) -> Option<Arc<Label>> {
        self.apparmor_label.read().clone()
    }

    /// Replaces the current AppArmor label.
    pub(in crate::security::lsm) fn set_apparmor_label(&self, label: Option<Arc<Label>>) {
        *self.apparmor_label.write() = label;
    }
}

impl Default for TaskSecurity {
    fn default() -> Self {
        Self::new()
    }
}
