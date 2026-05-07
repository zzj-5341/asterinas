// SPDX-License-Identifier: MPL-2.0

//! Alien access permission check for POSIX threads.
//!
//! An alien thread is one outside the current thread's thread group (the process).

use crate::{
    prelude::*,
    process::{credentials::capabilities::CapSet, posix_thread::PosixThread},
    security::{self, CredsSource, PtraceAccessContext, PtraceAccessMode},
};

impl PosixThread {
    /// Checks whether `accessor` may access resources of `self`.
    ///
    /// NOTE: In Linux, the corresponding check is named `ptrace_may_access`,
    /// but not every call to it is actually related to `ptrace`.
    // Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/ptrace.c#L276>.
    pub fn check_alien_access_from(
        &self,
        accessor: &PosixThread,
        mode: AlienAccessMode,
    ) -> Result<()> {
        if Weak::ptr_eq(accessor.weak_process(), self.weak_process()) {
            return Ok(());
        }

        let cred = accessor.credentials();
        let (caller_uid, caller_gid) = if mode.creds() == CredsSource::FsCreds {
            (cred.fsuid(), cred.fsgid())
        } else {
            (cred.ruid(), cred.rgid())
        };

        let self_cred = self.credentials();
        let caller_is_same = caller_uid == self_cred.euid()
            && caller_uid == self_cred.suid()
            && caller_uid == self_cred.ruid()
            && caller_gid == self_cred.egid()
            && caller_gid == self_cred.sgid()
            && caller_gid == self_cred.rgid();
        let caller_has_cap = self
            .process()
            .user_ns()
            .lock()
            .check_cap(CapSet::SYS_PTRACE, accessor)
            .is_ok();

        if !caller_is_same && !caller_has_cap {
            return_errno_with_message!(
                Errno::EPERM,
                "the calling process does not have the required permissions"
            );
        }

        security::ptrace_access_check(&PtraceAccessContext::new(
            accessor,
            self,
            mode,
            caller_has_cap,
        ))?;

        Ok(())
    }
}

/// The mode used by the alien access permission check.
pub type AlienAccessMode = PtraceAccessMode;
