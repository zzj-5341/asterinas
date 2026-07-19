// SPDX-License-Identifier: MPL-2.0

use super::{
    namespace::AppArmorPolicyNamespace,
    path::{AppArmorFilePermission, AppArmorPathView},
    profile::{AppArmorProfile, AppArmorProfileName},
    state::{AppArmorMode, AppArmorTaskState},
};
use crate::{
    fs::{
        file::{AccessMode, InodeType, StatusFlags},
        vfs::{
            inode::RenameMode,
            path::{Path, PathResolver},
        },
    },
    prelude::*,
    process::credentials::capabilities::CapSet,
    security::{
        FileDeleteKind, FilePermission, FileSetattrKind,
        lsm::{FileCreateContext, FileRenameContext},
    },
};

/// The in-kernel AppArmor policy store.
pub struct AppArmorPolicy {
    root_namespace: AppArmorPolicyNamespace,
}

impl AppArmorPolicy {
    /// Creates an empty policy store with the implicit unconfined profile.
    pub const fn new() -> Self {
        Self {
            root_namespace: AppArmorPolicyNamespace::new_root(),
        }
    }

    /// Replaces or inserts a loaded profile.
    pub fn replace_profile(&self, profile: AppArmorProfile) {
        self.root_namespace.replace_profile(profile);
    }

    /// Removes a loaded profile.
    pub fn remove_profile(&self, name: &AppArmorProfileName) -> Option<AppArmorProfile> {
        self.root_namespace.remove_profile(name)
    }

    /// Returns summaries of the implicit and loaded profiles.
    pub fn profile_summaries(&self) -> Vec<(AppArmorProfileName, AppArmorMode)> {
        self.root_namespace.profile_summaries()
    }

    /// Returns the root policy namespace name.
    pub fn root_namespace_name(&self) -> &'static str {
        self.root_namespace.name()
    }

    /// Checks whether the task may open a file.
    pub fn check_file_open(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        path: &Path,
        access_mode: AccessMode,
        status_flags: StatusFlags,
    ) -> Result<()> {
        self.check_path_access(
            task_state,
            path_resolver,
            path,
            AppArmorFilePermission::from_open(access_mode, status_flags),
        )
    }

    /// Checks whether the task may create a filesystem object.
    pub fn check_file_create(
        &self,
        task_state: &AppArmorTaskState,
        context: &FileCreateContext<'_>,
    ) -> Result<()> {
        let permissions = AppArmorFilePermission::for_create(
            context.kind(),
            context.access_mode(),
            context.status_flags(),
        );
        if let Some(name) = context.name() {
            return self.check_child_path_access(
                task_state,
                context.path_resolver(),
                context.parent(),
                name,
                permissions,
            );
        }

        self.check_path_access(
            task_state,
            context.path_resolver(),
            context.parent(),
            permissions,
        )
    }

    /// Checks whether the task may delete a filesystem object.
    pub fn check_file_delete(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        parent: &Path,
        name: &str,
        kind: FileDeleteKind,
    ) -> Result<()> {
        self.check_child_path_access(
            task_state,
            path_resolver,
            parent,
            name,
            AppArmorFilePermission::for_delete(kind),
        )
    }

    /// Checks whether the task may create a hard link.
    pub fn check_file_link(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        source: &Path,
        target_parent: &Path,
        target_name: &str,
    ) -> Result<()> {
        self.check_path_access(
            task_state,
            path_resolver,
            source,
            AppArmorFilePermission::for_link_source(),
        )?;
        self.check_child_path_access(
            task_state,
            path_resolver,
            target_parent,
            target_name,
            AppArmorFilePermission::for_link_target(),
        )
    }

    /// Checks whether the task may rename a filesystem object.
    pub fn check_file_rename(
        &self,
        task_state: &AppArmorTaskState,
        context: &FileRenameContext<'_>,
    ) -> Result<()> {
        self.check_path_access(
            task_state,
            context.path_resolver(),
            context.source(),
            AppArmorFilePermission::for_rename_source(),
        )?;
        self.check_child_path_access(
            task_state,
            context.path_resolver(),
            context.new_parent(),
            context.new_name(),
            AppArmorFilePermission::for_rename_target(),
        )?;

        let Some(target) = context.target() else {
            return Ok(());
        };
        if target == context.source() {
            return Ok(());
        }
        let target_permissions = match context.mode() {
            RenameMode::Replace => {
                let kind = if target.type_() == InodeType::Dir {
                    FileDeleteKind::Directory
                } else {
                    FileDeleteKind::NonDirectory
                };
                AppArmorFilePermission::for_delete(kind)
            }
            RenameMode::NoReplace => AppArmorFilePermission::empty(),
            RenameMode::Exchange => AppArmorFilePermission::RENAME,
        };
        if target_permissions.is_empty() {
            return Ok(());
        }

        self.check_path_access(
            task_state,
            context.path_resolver(),
            target,
            target_permissions,
        )
    }

    /// Checks whether the task may change file attributes.
    pub fn check_file_setattr(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        path: &Path,
        kind: FileSetattrKind,
    ) -> Result<()> {
        self.check_path_access(
            task_state,
            path_resolver,
            path,
            AppArmorFilePermission::for_setattr(kind),
        )
    }

    /// Revalidates access through an existing opened file.
    pub fn check_file_permission(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        path: &Path,
        permissions: FilePermission,
    ) -> Result<()> {
        self.check_path_access(
            task_state,
            path_resolver,
            path,
            AppArmorFilePermission::from_file_permission(permissions),
        )
    }

    /// Checks whether the task may map a file.
    pub fn check_file_mmap(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        path: &Path,
        permissions: FilePermission,
    ) -> Result<()> {
        self.check_file_permission(task_state, path_resolver, path, permissions)
    }

    /// Checks whether the task may receive a file descriptor.
    pub fn check_file_receive(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        path: &Path,
        permissions: FilePermission,
    ) -> Result<()> {
        self.check_file_permission(task_state, path_resolver, path, permissions)
    }

    /// Checks whether the task may lock a file.
    pub fn check_file_lock(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        path: &Path,
        permissions: FilePermission,
    ) -> Result<()> {
        self.check_file_permission(task_state, path_resolver, path, permissions)
    }

    /// Checks whether the task may query file metadata.
    pub fn check_file_getattr(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        path: &Path,
    ) -> Result<()> {
        self.check_path_access(
            task_state,
            path_resolver,
            path,
            AppArmorFilePermission::READ,
        )
    }

    /// Checks whether the task may use a capability.
    pub fn check_capability(
        &self,
        task_state: &AppArmorTaskState,
        required_cap: CapSet,
    ) -> Result<()> {
        if task_state.is_unconfined() {
            return Ok(());
        }

        let Some(profile) = self.profile(task_state.current_profile()) else {
            return_errno_with_message!(Errno::EACCES, "the AppArmor profile is not loaded");
        };
        let outcome = profile.evaluate_capability_access(required_cap);
        if outcome.denied.is_empty() {
            return Ok(());
        }

        let mode = effective_mode(task_state.mode(), profile.mode());
        let message = if mode == AppArmorMode::Complain {
            "AppArmor would deny capability use"
        } else {
            "AppArmor denied capability use"
        };
        warn!(
            "{}: profile={} requested={:#x} denied={:#x}",
            message,
            profile.name().as_str(),
            required_cap.bits(),
            outcome.denied.bits()
        );
        if mode == AppArmorMode::Complain {
            return Ok(());
        }

        return_errno_with_message!(Errno::EACCES, "AppArmor policy denied capability use");
    }

    fn check_path_access(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        path: &Path,
        permissions: AppArmorFilePermission,
    ) -> Result<()> {
        if task_state.is_unconfined() {
            return Ok(());
        }

        let Some(profile) = self.profile(task_state.current_profile()) else {
            return_errno_with_message!(Errno::EACCES, "the AppArmor profile is not loaded");
        };
        let path_view = AppArmorPathView::from_path(path_resolver, path);
        self.check_profile_path_access(&profile, task_state.mode(), &path_view, permissions)
    }

    fn check_child_path_access(
        &self,
        task_state: &AppArmorTaskState,
        path_resolver: &PathResolver,
        parent: &Path,
        name: &str,
        permissions: AppArmorFilePermission,
    ) -> Result<()> {
        if task_state.is_unconfined() {
            return Ok(());
        }

        let Some(profile) = self.profile(task_state.current_profile()) else {
            return_errno_with_message!(Errno::EACCES, "the AppArmor profile is not loaded");
        };
        let path_view = AppArmorPathView::from_child_name(path_resolver, parent, name);
        self.check_profile_path_access(&profile, task_state.mode(), &path_view, permissions)
    }

    fn profile(&self, name: &AppArmorProfileName) -> Option<Arc<AppArmorProfile>> {
        self.root_namespace.profile(name)
    }

    fn check_profile_path_access(
        &self,
        profile: &AppArmorProfile,
        task_mode: AppArmorMode,
        path_view: &AppArmorPathView,
        permissions: AppArmorFilePermission,
    ) -> Result<()> {
        if permissions.is_empty() {
            return Ok(());
        }

        let mode = effective_mode(task_mode, profile.mode());
        if !path_view.is_reachable() {
            warn!(
                "AppArmor denied file access to unreachable path: profile={} path={} requested={:#x}",
                profile.name().as_str(),
                path_view.as_str(),
                permissions.bits()
            );
            if mode == AppArmorMode::Complain {
                return Ok(());
            }
            return_errno_with_message!(Errno::EACCES, "AppArmor path is unreachable");
        }

        let outcome = profile.evaluate_file_access(path_view, permissions)?;
        if outcome.denied.is_empty() {
            return Ok(());
        }

        let enforce_denial = mode != AppArmorMode::Complain || !outcome.explicit_denied.is_empty();
        let message = if enforce_denial {
            "AppArmor denied file access"
        } else {
            "AppArmor would deny file access"
        };
        warn!(
            "{}: profile={} path={} requested={:#x} denied={:#x}",
            message,
            profile.name().as_str(),
            path_view.as_str(),
            permissions.bits(),
            outcome.denied.bits()
        );
        if !enforce_denial {
            return Ok(());
        }

        return_errno_with_message!(Errno::EACCES, "AppArmor policy denied access");
    }
}

fn effective_mode(task_mode: AppArmorMode, profile_mode: AppArmorMode) -> AppArmorMode {
    if task_mode == AppArmorMode::Complain || profile_mode == AppArmorMode::Complain {
        AppArmorMode::Complain
    } else {
        AppArmorMode::Enforce
    }
}
