// SPDX-License-Identifier: MPL-2.0

use super::super::{
    CapableContext, InodeDacOverrideContext, LsmKind, LsmModule, PtraceAccessContext,
    PtraceAccessCreds,
};
use crate::{prelude::*, process::credentials::capabilities::CapSet};

pub(crate) static CAPABILITY_LSM: CapabilityLsm = CapabilityLsm;

/// Implements capability-based authorization checks for built-in kernel operations.
pub(crate) struct CapabilityLsm;

impl LsmModule for CapabilityLsm {
    fn name(&self) -> &'static str {
        "capability"
    }

    fn kind(&self) -> LsmKind {
        LsmKind::Major
    }

    fn capable(&self, context: &CapableContext<'_>) -> Result<()> {
        let _ = (context.user_namespace(), context.reason());
        if context
            .posix_thread()
            .credentials()
            .effective_capset()
            .contains(context.capability())
        {
            return Ok(());
        }

        return_errno_with_message!(
            Errno::EPERM,
            "the thread does not have the required capability"
        );
    }

    fn ptrace_access_check(&self, context: &PtraceAccessContext<'_>) -> Result<()> {
        let accessor_cred = context.accessor().credentials();
        let (caller_uid, caller_gid) = match context.mode().creds() {
            PtraceAccessCreds::Fs => (accessor_cred.fsuid(), accessor_cred.fsgid()),
            PtraceAccessCreds::Real => (accessor_cred.ruid(), accessor_cred.rgid()),
        };

        let target_cred = context.target().credentials();
        let caller_is_same = caller_uid == target_cred.euid()
            && caller_uid == target_cred.suid()
            && caller_uid == target_cred.ruid()
            && caller_gid == target_cred.egid()
            && caller_gid == target_cred.sgid()
            && caller_gid == target_cred.rgid();
        if caller_is_same || context.accessor_has_sys_ptrace() {
            return Ok(());
        }

        return_errno_with_message!(
            Errno::EPERM,
            "the calling process does not have the required permissions"
        );
    }

    fn inode_dac_override(
        &self,
        context: &InodeDacOverrideContext<'_>,
    ) -> Result<crate::fs::file::Permission> {
        let credentials = context.posix_thread().credentials();
        if !credentials
            .effective_capset()
            .contains(CapSet::DAC_OVERRIDE)
        {
            return Ok(crate::fs::file::Permission::empty());
        }

        let mut overridden = crate::fs::file::Permission::empty();
        let permission = context.permission();

        if permission.may_read() {
            overridden |= crate::fs::file::Permission::MAY_READ;
        }
        if permission.may_write() {
            overridden |= crate::fs::file::Permission::MAY_WRITE;
        }
        if permission.may_exec() {
            let mode = context.mode();
            if mode.is_owner_executable()
                || mode.is_group_executable()
                || mode.is_other_executable()
            {
                overridden |= crate::fs::file::Permission::MAY_EXEC;
            } else {
                return_errno_with_message!(
                    Errno::EACCES,
                    "root execute permission denied: no execute bits set"
                );
            }
        }

        Ok(overridden)
    }
}
