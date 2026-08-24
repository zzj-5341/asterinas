// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec::Vec};

use ostd::prelude::*;

use super::{ModuleSelection, Registry};
use crate::security::lsm::{
    ExecContext, LsmFlags, LsmModule, RegistrationError, TaskState, clone_task_states_for,
    initialize_task_states_for, prepare_exec_states_for,
};

struct FakeModule {
    name: &'static str,
    flags: LsmFlags,
}

impl LsmModule for FakeModule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn flags(&self) -> LsmFlags {
        self.flags
    }
}

static APPARMOR: FakeModule = FakeModule {
    name: "apparmor",
    flags: LsmFlags::LEGACY_MAJOR,
};

static OTHER: FakeModule = FakeModule {
    name: "other",
    flags: LsmFlags::empty(),
};

struct LifecycleModule;

impl LsmModule for LifecycleModule {
    fn name(&self) -> &'static str {
        "lifecycle"
    }

    fn flags(&self) -> LsmFlags {
        LsmFlags::empty()
    }

    fn init_task_state(&self) -> crate::Result<Option<TaskState>> {
        Ok(Some(Arc::new(1_u32)))
    }

    fn clone_task_state(&self, state: Option<&TaskState>) -> crate::Result<Option<TaskState>> {
        Ok(Some(Arc::new(state_value(state) + 1)))
    }

    fn prepare_exec(&self, context: &ExecContext<'_>) -> crate::Result<Option<TaskState>> {
        Ok(Some(Arc::new(
            context.task_state::<u32>().copied().unwrap() + 1,
        )))
    }
}

static LIFECYCLE: LifecycleModule = LifecycleModule;

fn state_value(state: Option<&TaskState>) -> u32 {
    *state.unwrap().downcast_ref::<u32>().unwrap()
}

fn module_names(selection: ModuleSelection) -> Vec<&'static str> {
    selection
        .into_modules()
        .iter()
        .map(|module| module.name())
        .collect()
}

#[ktest]
fn default_stack_is_capability_then_yama() {
    let modules = super::modules_by_name(&[]);
    let selection = ModuleSelection::select(None, None, &modules);

    assert_eq!(module_names(selection), ["capability", "yama"]);
}

#[ktest]
fn lsm_parameter_selects_registered_apparmor_in_order() {
    let modules = super::modules_by_name(&[&APPARMOR]);
    let selection = ModuleSelection::select(Some("apparmor,yama,apparmor"), None, &modules);

    assert_eq!(module_names(selection), ["capability", "apparmor", "yama"]);
}

#[ktest]
fn legacy_security_selects_registered_legacy_major() {
    let modules = super::modules_by_name(&[&APPARMOR]);
    let selection = ModuleSelection::select(None, Some("apparmor"), &modules);

    assert_eq!(module_names(selection), ["capability", "yama", "apparmor"]);
}

#[ktest]
fn duplicate_registration_is_rejected() {
    let mut registry = Registry::default();

    assert_eq!(registry.register(&APPARMOR), Ok(()));
    assert_eq!(
        registry.register(&APPARMOR),
        Err(RegistrationError::DuplicateName)
    );
}

#[ktest]
fn registration_after_selection_is_rejected() {
    let mut registry = Registry::default();
    let _ = registry.close();

    assert_eq!(
        registry.register(&OTHER),
        Err(RegistrationError::SelectionClosed)
    );
}

#[ktest]
fn initial_state_matches_active_module_order() {
    let modules: [&'static dyn LsmModule; 2] = [&OTHER, &LIFECYCLE];
    let states = initialize_task_states_for(&modules).unwrap();

    assert!(states[0].is_none());
    assert_eq!(state_value(states[1].as_ref()), 1);
}

#[ktest]
fn cloned_state_is_derived_before_task_publication() {
    let modules: [&'static dyn LsmModule; 1] = [&LIFECYCLE];
    let current = initialize_task_states_for(&modules).unwrap();
    let cloned = clone_task_states_for(&modules, &current).unwrap();

    assert_eq!(state_value(current[0].as_ref()), 1);
    assert_eq!(state_value(cloned[0].as_ref()), 2);
}

#[ktest]
fn prepared_exec_does_not_mutate_the_current_state() {
    let modules: [&'static dyn LsmModule; 1] = [&LIFECYCLE];
    let current = initialize_task_states_for(&modules).unwrap();
    let prepared = prepare_exec_states_for(&modules, &current, b"/bin/test").unwrap();

    assert_eq!(state_value(current[0].as_ref()), 1);
    assert_eq!(state_value(prepared[0].as_ref()), 2);
}
