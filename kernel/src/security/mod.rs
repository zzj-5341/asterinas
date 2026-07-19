// SPDX-License-Identifier: MPL-2.0

pub mod lsm;

use aster_rights::ReadWriteOp;
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "x86_64", feature = "cvm_guest"))] {
        mod tsm;
        mod tsm_mr;
    }
}

pub use self::lsm::{FileCreateKind, FileDeleteKind, FilePermission, FileSetattrKind, YamaScope};
use crate::{
    fs::{
        file::{AccessMode, StatusFlags},
        vfs::{
            inode::RenameMode,
            path::{Path, PathResolver},
        },
    },
    prelude::*,
    process::{
        Credentials, UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::{AsPosixThread, PosixThread},
    },
    thread::Thread,
};

pub(super) fn init() {
    lsm::init();

    #[cfg(target_arch = "x86_64")]
    ostd::if_tdx_enabled!({
        tsm::init();
        tsm_mr::init();
    });
}

/// Runs the LSM stack for a capability check.
pub fn capable(
    user_namespace: &UserNamespace,
    capability: CapSet,
    posix_thread: &PosixThread,
) -> Result<()> {
    lsm::capable(lsm::CapableContext::new(
        user_namespace,
        posix_thread,
        capability,
    ))
}

/// Returns whether the Yama LSM is enabled.
pub fn is_yama_enabled() -> bool {
    lsm::is_yama_enabled()
}

/// Returns the Yama ptrace scope.
#[expect(dead_code, reason = "keeps the top-level security facade complete")]
pub fn get_yama_scope() -> YamaScope {
    lsm::yama::get_scope()
}

/// Sets the Yama ptrace scope.
#[expect(dead_code, reason = "keeps the top-level security facade complete")]
pub fn set_yama_scope(new_scope: YamaScope) -> Result<()> {
    lsm::yama::set_scope(new_scope)
}

/// Runs the LSM stack for an executable image check.
pub fn bprm_check_security(path: &Path, path_resolver: &PathResolver) -> Result<()> {
    lsm::bprm_check_security(&lsm::BprmCheckContext::new(path, path_resolver))
}

/// Updates security state after credentials are committed for a new executable.
pub fn bprm_committed_creds(
    path: &Path,
    path_resolver: &PathResolver,
    credentials: &Credentials<ReadWriteOp>,
) -> Result<()> {
    lsm::bprm_committed_creds(&lsm::BprmCommittedCredsContext::new(
        path,
        path_resolver,
        credentials,
    ))
}

/// Returns whether the executable should run in secure-execution mode.
pub fn bprm_secureexec(path: &Path, path_resolver: &PathResolver) -> Result<bool> {
    lsm::bprm_secureexec(&lsm::BprmCheckContext::new(path, path_resolver))
}

/// Runs the LSM stack for a file open check.
pub fn file_open(
    path: &Path,
    path_resolver: &PathResolver,
    access_mode: AccessMode,
    status_flags: StatusFlags,
) -> Result<()> {
    lsm::file_open(&lsm::FileOpenContext::new(
        path,
        path_resolver,
        access_mode,
        status_flags,
    ))
}

/// Runs the LSM stack before creating and opening a file.
pub fn file_create(
    parent: &Path,
    name: Option<&str>,
    path_resolver: &PathResolver,
    kind: FileCreateKind,
    access_mode: Option<AccessMode>,
    status_flags: StatusFlags,
) -> Result<()> {
    lsm::file_create(&lsm::FileCreateContext::new(
        parent,
        name,
        path_resolver,
        kind,
        access_mode,
        status_flags,
    ))
}

/// Runs the LSM stack before deleting a filesystem object.
pub fn file_delete(
    parent: &Path,
    name: &str,
    path_resolver: &PathResolver,
    kind: FileDeleteKind,
) -> Result<()> {
    lsm::file_delete(&lsm::FileDeleteContext::new(
        parent,
        name,
        path_resolver,
        kind,
    ))
}

/// Runs the LSM stack before creating a hard link.
pub fn file_link(
    source: &Path,
    target_parent: &Path,
    target_name: &str,
    path_resolver: &PathResolver,
) -> Result<()> {
    lsm::file_link(&lsm::FileLinkContext::new(
        source,
        target_parent,
        target_name,
        path_resolver,
    ))
}

/// Runs the LSM stack before renaming a filesystem object.
pub fn file_rename(
    source: &Path,
    new_parent: &Path,
    new_name: &str,
    target: Option<&Path>,
    path_resolver: &PathResolver,
    mode: RenameMode,
) -> Result<()> {
    lsm::file_rename(&lsm::FileRenameContext::new(
        source,
        new_parent,
        new_name,
        target,
        path_resolver,
        mode,
    ))
}

/// Runs the LSM stack before changing file attributes.
pub fn file_setattr(
    path: &Path,
    path_resolver: &PathResolver,
    kind: FileSetattrKind,
) -> Result<()> {
    lsm::file_setattr(&lsm::FileSetattrContext::new(path, path_resolver, kind))
}

/// Runs the LSM stack for access through an existing opened file.
pub fn file_permission(path: &Path, permissions: FilePermission) -> Result<()> {
    let Some(path_resolver) = current_path_resolver() else {
        return Ok(());
    };

    file_permission_at(path, &path_resolver, permissions)
}

/// Runs the LSM stack for path access through an existing file-like operation.
pub fn file_permission_at(
    path: &Path,
    path_resolver: &PathResolver,
    permissions: FilePermission,
) -> Result<()> {
    lsm::file_permission(&lsm::FilePermissionContext::new(
        path,
        path_resolver,
        permissions,
    ))
}

/// Runs the LSM stack for mapping a file.
pub fn file_mmap(path: &Path, permissions: FilePermission) -> Result<()> {
    let Some(path_resolver) = current_path_resolver() else {
        return Ok(());
    };

    lsm::file_mmap(&lsm::FileMmapContext::new(
        path,
        &path_resolver,
        permissions,
    ))
}

/// Runs the LSM stack for receiving a file descriptor.
pub fn file_receive(path: &Path, permissions: FilePermission) -> Result<()> {
    let Some(path_resolver) = current_path_resolver() else {
        return Ok(());
    };

    lsm::file_receive(&lsm::FileReceiveContext::new(
        path,
        &path_resolver,
        permissions,
    ))
}

/// Runs the LSM stack for locking a file.
pub fn file_lock(path: &Path, permissions: FilePermission) -> Result<()> {
    let Some(path_resolver) = current_path_resolver() else {
        return Ok(());
    };

    lsm::file_lock(&lsm::FileLockContext::new(
        path,
        &path_resolver,
        permissions,
    ))
}

/// Runs the LSM stack before querying file metadata.
pub fn file_getattr(path: &Path, path_resolver: &PathResolver) -> Result<()> {
    lsm::file_getattr(&lsm::FileGetattrContext::new(path, path_resolver))
}

/// Runs the LSM stack before querying metadata through an opened file.
pub fn file_getattr_current(path: &Path) -> Result<()> {
    let Some(path_resolver) = current_path_resolver() else {
        return Ok(());
    };

    file_getattr(path, &path_resolver)
}

fn current_path_resolver() -> Option<PathResolver> {
    let thread = Thread::current()?;
    let posix_thread = thread.as_posix_thread()?;
    let fs = posix_thread.read_fs();
    Some(fs.resolver().read().clone())
}
