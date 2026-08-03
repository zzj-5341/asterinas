// SPDX-License-Identifier: MPL-2.0

//! AppArmor task labels.

use super::{UNCONFINED_PROFILE_NAME, policy};
use crate::{
    prelude::*,
    process::posix_thread::{AsPosixThread, PosixThread},
    thread::Thread,
};

/// An AppArmor label attached to a task.
#[derive(Debug)]
pub(in crate::security::lsm) struct Label {
    // Keep the stable name instead of a parsed profile so replacing a loaded
    // profile also updates the policy applied to already-confined tasks.
    profile_name: Arc<str>,
}

impl Label {
    fn new(profile_name: Arc<str>) -> Self {
        Self { profile_name }
    }

    pub(super) fn profile_name(&self) -> &str {
        &self.profile_name
    }
}

/// Returns a task's AppArmor profile name.
pub(super) fn task_profile_name(posix_thread: &PosixThread) -> Option<Arc<str>> {
    posix_thread
        .security()
        .apparmor_label()
        .map(|label| label.profile_name.clone())
}

pub(super) fn set_task_profile(posix_thread: &PosixThread, name: &str) -> Result<()> {
    if posix_thread.security().apparmor_label().is_some() {
        return_errno_with_message!(
            Errno::EPERM,
            "a confined task cannot change its AppArmor profile"
        );
    }
    let name = name.trim();
    if name.is_empty() || (name != UNCONFINED_PROFILE_NAME && !policy::is_valid_profile_name(name))
    {
        return_errno_with_message!(Errno::EINVAL, "the AppArmor profile name is invalid");
    }
    if name == UNCONFINED_PROFILE_NAME {
        return Ok(());
    }

    let Some(profile_name) = policy::stored_profile_name(name) else {
        return_errno_with_message!(Errno::ENOENT, "the AppArmor profile is not loaded");
    };

    posix_thread
        .security()
        .set_apparmor_label(Some(Arc::new(Label::new(profile_name))));
    Ok(())
}

pub(super) fn current_label() -> Option<Arc<Label>> {
    let thread = Thread::current()?;
    let posix_thread = thread.as_posix_thread()?;

    posix_thread.security().apparmor_label()
}
