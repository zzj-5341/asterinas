// SPDX-License-Identifier: MPL-2.0

//! AppArmor Linux Security Module.

#![no_std]
#![deny(unsafe_code)]
#![feature(allocator_api)]

extern crate alloc;

use alloc::sync::Arc;

use aster_core::{
    Errno, Error,
    security::lsm::{
        AlienAccessContext, AlienAccessKind, CapabilityContext, ExecContext, LsmFlags, LsmModule,
        TaskState,
    },
};
use component::{ComponentInitError, init_component};
use ostd::prelude::*;

macro_rules! __log_prefix {
    () => {
        "apparmor: "
    };
}

mod policy;
mod securityfs;

use self::policy::{Decision, PolicyStore, TaskLabel};

static POLICY_STORE: PolicyStore = PolicyStore::new();

static APPARMOR_LSM: AppArmorLsm = AppArmorLsm;

struct AppArmorLsm;

impl LsmModule for AppArmorLsm {
    fn name(&self) -> &'static str {
        "apparmor"
    }

    fn flags(&self) -> LsmFlags {
        LsmFlags::LEGACY_MAJOR
    }

    fn init(&self) -> aster_core::Result<()> {
        securityfs::register()
    }

    fn init_task_state(&self) -> aster_core::Result<Option<TaskState>> {
        new_task_state(TaskLabel::Unconfined)
    }

    fn prepare_exec(&self, context: &ExecContext<'_>) -> aster_core::Result<Option<TaskState>> {
        let current = context
            .task_state::<TaskLabel>()
            .ok_or_else(|| Error::new(Errno::EINVAL))?;
        let snapshot = POLICY_STORE.snapshot();
        new_task_state(policy::label_for_exec(
            current,
            snapshot.as_deref(),
            context.executable_path(),
        ))
    }

    fn on_capable(&self, context: &CapabilityContext<'_>) -> aster_core::Result<()> {
        let label = context
            .task_state::<TaskLabel>()
            .ok_or_else(|| Error::new(Errno::EINVAL))?;
        let capability = context
            .required_capability()
            .ok_or_else(|| Error::new(Errno::EINVAL))?;

        match policy::decide_capability(label, capability) {
            Decision::Allow => Ok(()),
            Decision::Deny => {
                log_capability_denial(label, context.task_id(), capability, "enforced");
                Err(Error::new(Errno::EPERM))
            }
            Decision::Complain => {
                log_capability_denial(label, context.task_id(), capability, "report-only");
                Ok(())
            }
        }
    }

    fn on_alien_access(&self, context: &AlienAccessContext<'_>) -> aster_core::Result<()> {
        if context.kind() != AlienAccessKind::PtraceAttach {
            return Ok(());
        }

        let accessor = context
            .accessor_state::<TaskLabel>()
            .ok_or_else(|| Error::new(Errno::EINVAL))?;
        let target = context
            .target_state::<TaskLabel>()
            .ok_or_else(|| Error::new(Errno::EINVAL))?;
        if policy::ptrace_allowed(accessor, target) {
            return Ok(());
        }

        let (profile, mode) = accessor.audit_identity();
        warn!(
            r#"apparmor="DENIED" operation="ptrace" profile="{}" task_id="{}" target_id="{}" mode="{}" result="enforced""#,
            profile,
            context.accessor_id(),
            context.target_id(),
            mode.as_str()
        );
        Err(Error::new(Errno::EPERM))
    }
}

fn new_task_state(label: TaskLabel) -> aster_core::Result<Option<TaskState>> {
    let label: Arc<TaskLabel> = Arc::try_new(label).map_err(|_| Error::new(Errno::ENOMEM))?;
    Ok(Some(label))
}

fn log_capability_denial(label: &TaskLabel, task_id: u32, capability: u8, result: &str) {
    let (profile, mode) = label.audit_identity();
    warn!(
        r#"apparmor="DENIED" operation="capability" profile="{}" task_id="{}" capability="{}" mode="{}" result="{}""#,
        profile,
        task_id,
        capability,
        mode.as_str(),
        result
    );
}

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    aster_core::security::lsm::register(&APPARMOR_LSM).map_err(|_| ComponentInitError::Unknown)
}
