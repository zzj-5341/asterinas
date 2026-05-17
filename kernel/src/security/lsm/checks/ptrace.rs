// SPDX-License-Identifier: MPL-2.0

use super::super::modules;
use crate::{prelude::*, process::posix_thread::PosixThread};

/// Defines hooks for ptrace access checks.
pub trait LsmPtraceCheck: Sync {
    /// Checks whether the accessor may inspect or attach to the target.
    fn ptrace_access_check(&self, _context: &PtraceAccessContext) -> Result<()> {
        Ok(())
    }
}

/// The credentials used by a ptrace access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredsSource {
    FsCreds,
    RealCreds,
}

/// The strength of a ptrace access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtraceAccessKind {
    Read,
    Attach,
}

/// A ptrace access check mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtraceAccessMode {
    kind: PtraceAccessKind,
    creds: CredsSource,
}

impl PtraceAccessMode {
    /// Read-only ptrace access check using real credentials.
    #[expect(dead_code)]
    pub const READ_WITH_REAL_CREDS: Self =
        Self::new(PtraceAccessKind::Read, CredsSource::RealCreds);
    /// Attach-level ptrace access check using real credentials.
    pub const ATTACH_WITH_REAL_CREDS: Self =
        Self::new(PtraceAccessKind::Attach, CredsSource::RealCreds);
    /// Read-only ptrace access check using filesystem credentials.
    pub const READ_WITH_FS_CREDS: Self = Self::new(PtraceAccessKind::Read, CredsSource::FsCreds);
    /// Attach-level ptrace access check using filesystem credentials.
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

/// The inputs for a ptrace access check through the LSM stack.
pub struct PtraceAccessContext<'a> {
    accessor: &'a PosixThread,
    target: &'a PosixThread,
    mode: PtraceAccessMode,
    accessor_has_cap_sys_ptrace: bool,
}

impl<'a> PtraceAccessContext<'a> {
    pub const fn new(
        accessor: &'a PosixThread,
        target: &'a PosixThread,
        mode: PtraceAccessMode,
        accessor_has_cap_sys_ptrace: bool,
    ) -> Self {
        Self {
            accessor,
            target,
            mode,
            accessor_has_cap_sys_ptrace,
        }
    }

    pub const fn accessor(&self) -> &PosixThread {
        self.accessor
    }

    pub const fn target(&self) -> &PosixThread {
        self.target
    }

    pub const fn mode(&self) -> PtraceAccessMode {
        self.mode
    }

    pub const fn accessor_has_cap_sys_ptrace(&self) -> bool {
        self.accessor_has_cap_sys_ptrace
    }
}

/// Runs ptrace access hooks in module order.
pub fn ptrace_access_check(context: &PtraceAccessContext) -> Result<()> {
    for module in modules::active_modules() {
        module.ptrace_access_check(context)?;
    }

    Ok(())
}
