// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

use ostd::prelude::*;

use super::{ModuleSelection, Registry};
use crate::security::lsm::{LsmFlags, LsmModule, RegistrationError};

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
