// SPDX-License-Identifier: MPL-2.0

pub(crate) mod lsm;

#[cfg(all(target_arch = "x86_64", feature = "cvm_guest"))]
mod tsm;

pub(crate) use self::lsm::{
    CapabilityReason, PtraceAccessContext, PtraceAccessCreds, PtraceAccessKind, PtraceAccessMode,
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
