// SPDX-License-Identifier: MPL-2.0

use crate::{prelude::*, process::posix_thread::PosixThread};

/// Defines ptrace-style hooks supported by built-in LSM modules.
pub trait LsmPtraceCheck: Sync {
    /// Checks ptrace-style access between unrelated tasks.
    fn ptrace_access_check(&self, _context: &PtraceAccessContext<'_>) -> Result<()> {
        Ok(())
    }
}

/// Describes which credentials should be used by a ptrace-style access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredsSource {
    FsCreds,
    RealCreds,
}

/// Describes the strength of a ptrace-style access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtraceAccessKind {
    Read,
    Attach,
}

/// Describes a ptrace-style access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtraceAccessMode {
    kind: PtraceAccessKind,
    creds: CredsSource,
}

impl PtraceAccessMode {
    /// Read-only ptrace-style access check using real credentials.
    #[expect(dead_code)]
    pub const READ_WITH_REAL_CREDS: Self =
        Self::new(PtraceAccessKind::Read, CredsSource::RealCreds);
    /// Attach-level ptrace-style access check using real credentials.
    pub const ATTACH_WITH_REAL_CREDS: Self =
        Self::new(PtraceAccessKind::Attach, CredsSource::RealCreds);
    /// Read-only ptrace-style access check using filesystem credentials.
    pub const READ_WITH_FS_CREDS: Self = Self::new(PtraceAccessKind::Read, CredsSource::FsCreds);
    /// Attach-level ptrace-style access check using filesystem credentials.
    pub const ATTACH_WITH_FS_CREDS: Self =
        Self::new(PtraceAccessKind::Attach, CredsSource::FsCreds);

    pub const fn new(kind: PtraceAccessKind, creds: CredsSource) -> Self {
        Self { kind, creds }
    }

    pub const fn kind(self) -> PtraceAccessKind {
        self.kind
    }

    pub const fn creds(self) -> CredsSource {
        self.creds
    }
}

/// Carries the inputs for a ptrace-style access check through the LSM stack.
pub struct PtraceAccessContext<'a> {
    accessor: &'a PosixThread,
    target: &'a PosixThread,
    mode: PtraceAccessMode,
    accessor_has_sys_ptrace: bool,
}

impl<'a> PtraceAccessContext<'a> {
    pub const fn new(
        accessor: &'a PosixThread,
        target: &'a PosixThread,
        mode: PtraceAccessMode,
        accessor_has_sys_ptrace: bool,
    ) -> Self {
        Self {
            accessor,
            target,
            mode,
            accessor_has_sys_ptrace,
        }
    }

    pub const fn accessor(&self) -> &'a PosixThread {
        self.accessor
    }

    pub const fn target(&self) -> &'a PosixThread {
        self.target
    }

    pub const fn mode(&self) -> PtraceAccessMode {
        self.mode
    }

    pub const fn accessor_has_sys_ptrace(&self) -> bool {
        self.accessor_has_sys_ptrace
    }
}
