// SPDX-License-Identifier: MPL-2.0

pub(crate) mod lsm;

#[cfg(all(target_arch = "x86_64", feature = "cvm_guest"))]
mod tsm;

pub(crate) use self::lsm::{
    BprmCheckContext, BprmCommittedCredsContext, CapabilityReason, FileOpenContext,
    InodePermissionContext, PtraceAccessContext, PtraceAccessCreds, PtraceAccessKind,
    PtraceAccessMode, YamaScope, get_yama_scope, set_yama_scope,
};
use crate::{
    fs::file::{InodeMode, Permission},
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::PosixThread},
};

pub(super) fn init() {
    lsm::init();

    #[cfg(all(target_arch = "x86_64", feature = "cvm_guest"))]
    tsm::init();
}

pub(crate) fn capable(
    user_namespace: &UserNamespace,
    capability: CapSet,
    posix_thread: &PosixThread,
    reason: CapabilityReason,
) -> Result<()> {
    lsm::capable(&lsm::CapableContext::new(
        user_namespace,
        posix_thread,
        capability,
        reason,
    ))
}

/// Runs the LSM stack for a ptrace-style access check.
pub(crate) fn ptrace_access_check(context: &PtraceAccessContext<'_>) -> Result<()> {
    lsm::ptrace_access_check(context)
}

/// Runs the LSM stack for an executable image check.
pub(crate) fn bprm_check_security(context: &BprmCheckContext<'_>) -> Result<()> {
    lsm::bprm_check_security(context)
}

/// Runs the LSM stack after executable credentials have been committed.
pub(crate) fn bprm_committed_creds(context: &BprmCommittedCredsContext<'_>) -> Result<()> {
    lsm::bprm_committed_creds(context)
}

/// Runs the LSM stack for an inode permission check.
pub(crate) fn inode_permission(context: &InodePermissionContext<'_>) -> Result<()> {
    lsm::inode_permission(context)
}

/// Runs the LSM stack for a file-open check.
pub(crate) fn file_open(context: &FileOpenContext<'_>) -> Result<()> {
    lsm::file_open(context)
}

/// Runs the LSM stack for a DAC override decision on an inode.
pub(crate) fn inode_dac_override(
    mode: InodeMode,
    permission: Permission,
    posix_thread: &PosixThread,
) -> Result<Permission> {
    lsm::inode_dac_override(&lsm::InodeDacOverrideContext::new(
        mode,
        permission,
        posix_thread,
    ))
}
