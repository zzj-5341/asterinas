// SPDX-License-Identifier: MPL-2.0

//! Linux Security Module framework for Asterinas.
//!
//! The first goal of this framework is to provide a stable place to host
//! minor LSMs such as Yama while keeping the hook surface small enough to
//! evolve with the kernel subsystems.

mod modules;

pub(crate) use self::modules::yama::{YamaScope, get_yama_scope, set_yama_scope};
use crate::{
    fs::file::{InodeMode, Permission},
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::PosixThread},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LsmKind {
    Minor,
    Major,
}

impl LsmKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }
}

/// Describes which credentials should be used by a ptrace-style access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PtraceAccessCreds {
    Fs,
    Real,
}

/// Describes the strength of a ptrace-style access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PtraceAccessKind {
    Read,
    Attach,
}

/// Describes a ptrace-style access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PtraceAccessMode {
    kind: PtraceAccessKind,
    creds: PtraceAccessCreds,
}

impl PtraceAccessMode {
    pub(crate) const fn new(kind: PtraceAccessKind, creds: PtraceAccessCreds) -> Self {
        Self { kind, creds }
    }

    pub(crate) const fn kind(self) -> PtraceAccessKind {
        self.kind
    }

    pub(crate) const fn creds(self) -> PtraceAccessCreds {
        self.creds
    }
}

/// Describes why a capability is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapabilityReason {
    CredentialsSetUid,
    CredentialsSetGid,
    CredentialsSetPcap,
    Namespace,
    Ptrace,
    ResourceLimit,
    Reboot,
    Signal,
    Socket,
    Xattr,
}

/// Carries the inputs for checking whether a thread has a capability.
pub(crate) struct CapableContext<'a> {
    user_namespace: &'a UserNamespace,
    posix_thread: &'a PosixThread,
    capability: CapSet,
    reason: CapabilityReason,
}

impl<'a> CapableContext<'a> {
    pub(crate) const fn new(
        user_namespace: &'a UserNamespace,
        posix_thread: &'a PosixThread,
        capability: CapSet,
        reason: CapabilityReason,
    ) -> Self {
        Self {
            user_namespace,
            posix_thread,
            capability,
            reason,
        }
    }

    pub(crate) const fn user_namespace(&self) -> &'a UserNamespace {
        self.user_namespace
    }

    pub(crate) const fn posix_thread(&self) -> &'a PosixThread {
        self.posix_thread
    }

    pub(crate) const fn capability(&self) -> CapSet {
        self.capability
    }

    pub(crate) const fn reason(&self) -> CapabilityReason {
        self.reason
    }
}

/// Carries the inputs for a ptrace-style access check through the LSM stack.
pub(crate) struct PtraceAccessContext<'a> {
    accessor: &'a PosixThread,
    target: &'a PosixThread,
    mode: PtraceAccessMode,
    accessor_has_sys_ptrace: bool,
}

impl<'a> PtraceAccessContext<'a> {
    pub(crate) const fn new(
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

    pub(crate) const fn accessor(&self) -> &'a PosixThread {
        self.accessor
    }

    pub(crate) const fn target(&self) -> &'a PosixThread {
        self.target
    }

    pub(crate) const fn mode(&self) -> PtraceAccessMode {
        self.mode
    }

    pub(crate) const fn accessor_has_sys_ptrace(&self) -> bool {
        self.accessor_has_sys_ptrace
    }
}

/// Carries the inputs for a DAC override decision on an inode.
pub(crate) struct InodeDacOverrideContext<'a> {
    mode: InodeMode,
    permission: Permission,
    posix_thread: &'a PosixThread,
}

impl<'a> InodeDacOverrideContext<'a> {
    pub(crate) const fn new(
        mode: InodeMode,
        permission: Permission,
        posix_thread: &'a PosixThread,
    ) -> Self {
        Self {
            mode,
            permission,
            posix_thread,
        }
    }

    pub(crate) const fn mode(&self) -> InodeMode {
        self.mode
    }

    pub(crate) const fn permission(&self) -> Permission {
        self.permission
    }

    pub(crate) const fn posix_thread(&self) -> &'a PosixThread {
        self.posix_thread
    }
}

/// Defines the hook surface supported by built-in LSM modules.
pub(crate) trait LsmModule: Sync {
    /// Returns the short module name.
    fn name(&self) -> &'static str;

    /// Returns whether the module is a major or minor LSM.
    fn kind(&self) -> LsmKind {
        LsmKind::Minor
    }

    /// Initializes the module during kernel startup.
    fn init(&self) {}

    /// Checks whether a thread holds a capability in a user namespace.
    fn capable(&self, context: &CapableContext<'_>) -> Result<()> {
        let _ = context;
        Ok(())
    }

    /// Checks ptrace-style access between unrelated tasks.
    fn ptrace_access_check(&self, context: &PtraceAccessContext<'_>) -> Result<()> {
        let _ = context;
        Ok(())
    }

    /// Returns which requested DAC permissions may be bypassed on an inode.
    fn inode_dac_override(&self, context: &InodeDacOverrideContext<'_>) -> Result<Permission> {
        let _ = context;
        Ok(Permission::empty())
    }
}

pub(super) fn init() {
    for module in modules::active_modules() {
        info!(
            "[kernel] LSM module enabled: {} ({})",
            module.name(),
            module.kind().as_str()
        );
        module.init();
    }
}

/// Runs capability hooks in module order.
pub(crate) fn capable(context: &CapableContext<'_>) -> Result<()> {
    for module in modules::active_modules() {
        module.capable(context)?;
    }

    Ok(())
}

/// Runs ptrace-style access hooks in module order.
pub(crate) fn ptrace_access_check(context: &PtraceAccessContext<'_>) -> Result<()> {
    for module in modules::active_modules() {
        module.ptrace_access_check(context)?;
    }

    Ok(())
}

/// Runs inode DAC override hooks in module order.
pub(crate) fn inode_dac_override(context: &InodeDacOverrideContext<'_>) -> Result<Permission> {
    let mut overridden = Permission::empty();

    for module in modules::active_modules() {
        overridden |= module.inode_dac_override(context)?;
    }

    Ok(overridden)
}
