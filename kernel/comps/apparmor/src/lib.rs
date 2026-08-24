// SPDX-License-Identifier: MPL-2.0

//! AppArmor Linux Security Module.

#![no_std]
#![deny(unsafe_code)]

use aster_core::security::lsm::{LsmFlags, LsmModule};
use component::{ComponentInitError, init_component};

static APPARMOR_LSM: AppArmorLsm = AppArmorLsm;

struct AppArmorLsm;

impl LsmModule for AppArmorLsm {
    fn name(&self) -> &'static str {
        "apparmor"
    }

    fn flags(&self) -> LsmFlags {
        LsmFlags::LEGACY_MAJOR
    }
}

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    aster_core::security::lsm::register(&APPARMOR_LSM).map_err(|_| ComponentInitError::Unknown)
}
