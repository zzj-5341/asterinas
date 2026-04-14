// SPDX-License-Identifier: MPL-2.0

//! Alien access permission check for POSIX threads.
//!
//! An alien thread is one outside the current thread's thread group (the process).

use bitflags::bitflags;

use crate::{
    prelude::*,
    process::{credentials::capabilities::CapSet, posix_thread::PosixThread},
    security::{
        self, CapabilityReason, PtraceAccessContext, PtraceAccessCreds, PtraceAccessKind,
        PtraceAccessMode,
    },
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

        let caller_has_cap = self
            .process()
            .user_ns()
            .lock()
            .check_cap_with_reason(CapSet::SYS_PTRACE, accessor, CapabilityReason::Ptrace)
            .is_ok();

        security::ptrace_access_check(&PtraceAccessContext::new(
            accessor,
            self,
            mode.into_ptrace_access_mode(),
            caller_has_cap,
        ))
    }
}

/// The mode used by the alien access permission check.
pub struct AlienAccessMode(AlienAccessFlags, CredsSource);

impl AlienAccessMode {
    /// Read-only alien access check, using real credentials (`ruid`/`rgid`).
    #[expect(dead_code)]
    pub const READ_WITH_REAL_CREDS: Self = Self(AlienAccessFlags::READ, CredsSource::RealCreds);
    /// Attach-level alien access check, using real credentials (`ruid`/`rgid`).
    pub const ATTACH_WITH_REAL_CREDS: Self = Self(AlienAccessFlags::ATTACH, CredsSource::RealCreds);
    /// Read-only alien access check, using filesystem credentials (`fsuid`/`fsgid`).
    pub const READ_WITH_FS_CREDS: Self = Self(AlienAccessFlags::READ, CredsSource::FsCreds);
    /// Attach-level alien access check, using filesystem credentials (`fsuid`/`fsgid`).
    pub const ATTACH_WITH_FS_CREDS: Self = Self(AlienAccessFlags::ATTACH, CredsSource::FsCreds);
}

bitflags! {
    /// Access strength in the alien access permission check.
    struct AlienAccessFlags: u32 {
        const READ       = 0x01;
        const ATTACH     = 0x02;
    }
}

/// The credentials used in the alien access permission check.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CredsSource {
    FsCreds,
    RealCreds,
}

impl AlienAccessMode {
    fn into_ptrace_access_mode(self) -> PtraceAccessMode {
        let kind = if self.0.contains(AlienAccessFlags::ATTACH) {
            PtraceAccessKind::Attach
        } else {
            PtraceAccessKind::Read
        };
        let creds = match self.1 {
            CredsSource::FsCreds => PtraceAccessCreds::Fs,
            CredsSource::RealCreds => PtraceAccessCreds::Real,
        };
        PtraceAccessMode::new(kind, creds)
    }
}
