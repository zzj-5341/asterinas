// SPDX-License-Identifier: MPL-2.0

//! AppArmor major-LSM policy model.

mod capability;
mod dfa;
mod label;
mod namespace;
mod path;
mod policy;
mod policy_update;
mod profile;
mod state;

use self::{policy::AppArmorPolicy, policy_update::AppArmorPolicyUpdate};
pub use self::{
    profile::AppArmorProfileName,
    state::{AppArmorMode, AppArmorTaskState},
};
use super::super::{
    CapableContext, FileCreateContext, FileDeleteContext, FileGetattrContext, FileLinkContext,
    FileLockContext, FileMmapContext, FileOpenContext, FilePermissionContext, FileReceiveContext,
    FileRenameContext, FileSetattrContext, LsmFlags, LsmModule,
    hooks::{LsmAlienAccessHook, LsmBprmHook, LsmCapabilityHook, LsmFileHook, LsmSignalHook},
};
use crate::{prelude::*, process::posix_thread::AsPosixThread, thread::Thread};

pub(super) static APPARMOR_LSM: AppArmorLsm = AppArmorLsm;

static POLICY: AppArmorPolicy = AppArmorPolicy::new();

/// The AppArmor major LSM.
pub(super) struct AppArmorLsm;

impl LsmModule for AppArmorLsm {
    fn name(&self) -> &'static str {
        "apparmor"
    }

    fn flags(&self) -> LsmFlags {
        LsmFlags::LEGACY_MAJOR | LsmFlags::EXCLUSIVE
    }
}

impl LsmAlienAccessHook for AppArmorLsm {}
impl LsmBprmHook for AppArmorLsm {}
impl LsmSignalHook for AppArmorLsm {}

impl LsmCapabilityHook for AppArmorLsm {
    fn on_capable(&self, context: &CapableContext<'_>) -> Result<()> {
        let task_state = context.posix_thread().credentials().apparmor_task_state();
        POLICY.check_capability(&task_state, context.required_cap())
    }
}

impl LsmFileHook for AppArmorLsm {
    fn on_file_create(&self, context: &FileCreateContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_create(&task_state, context)
    }

    fn on_file_delete(&self, context: &FileDeleteContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_delete(
            &task_state,
            context.path_resolver(),
            context.parent(),
            context.name(),
            context.kind(),
        )
    }

    fn on_file_link(&self, context: &FileLinkContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_link(
            &task_state,
            context.path_resolver(),
            context.source(),
            context.target_parent(),
            context.target_name(),
        )
    }

    fn on_file_open(&self, context: &FileOpenContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_open(
            &task_state,
            context.path_resolver(),
            context.path(),
            context.access_mode(),
            context.status_flags(),
        )
    }

    fn on_file_rename(&self, context: &FileRenameContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_rename(&task_state, context)
    }

    fn on_file_setattr(&self, context: &FileSetattrContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_setattr(
            &task_state,
            context.path_resolver(),
            context.path(),
            context.kind(),
        )
    }

    fn on_file_permission(&self, context: &FilePermissionContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_permission(
            &task_state,
            context.path_resolver(),
            context.path(),
            context.permissions(),
        )
    }

    fn on_file_mmap(&self, context: &FileMmapContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_mmap(
            &task_state,
            context.path_resolver(),
            context.path(),
            context.permissions(),
        )
    }

    fn on_file_receive(&self, context: &FileReceiveContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_receive(
            &task_state,
            context.path_resolver(),
            context.path(),
            context.permissions(),
        )
    }

    fn on_file_lock(&self, context: &FileLockContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_lock(
            &task_state,
            context.path_resolver(),
            context.path(),
            context.permissions(),
        )
    }

    fn on_file_getattr(&self, context: &FileGetattrContext<'_>) -> Result<()> {
        let Some(task_state) = current_task_state() else {
            return Ok(());
        };
        POLICY.check_file_getattr(&task_state, context.path_resolver(), context.path())
    }
}

#[expect(dead_code, reason = "policy loaders are added with management ABIs")]
fn apply_policy_update(update: AppArmorPolicyUpdate) -> Result<()> {
    match update {
        AppArmorPolicyUpdate::Replace(profile) => {
            POLICY.replace_profile(*profile);
            Ok(())
        }
        AppArmorPolicyUpdate::ReplaceMany(profiles) => {
            for profile in profiles {
                POLICY.replace_profile(profile);
            }
            Ok(())
        }
        AppArmorPolicyUpdate::Remove(profile_name) => {
            if POLICY.remove_profile(&profile_name).is_none() {
                return_errno_with_message!(Errno::ENOENT, "the AppArmor profile is not loaded");
            }
            Ok(())
        }
    }
}

/// Returns summaries of the implicit and loaded AppArmor profiles.
pub fn profile_summaries() -> Vec<(AppArmorProfileName, AppArmorMode)> {
    POLICY.profile_summaries()
}

/// Returns the root AppArmor policy namespace name.
pub fn root_namespace_name() -> &'static str {
    POLICY.root_namespace_name()
}

fn current_task_state() -> Option<AppArmorTaskState> {
    Thread::current()?
        .as_posix_thread()
        .map(|thread| thread.credentials().apparmor_task_state())
}
