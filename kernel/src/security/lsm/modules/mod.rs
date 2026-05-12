// SPDX-License-Identifier: MPL-2.0

//! Built-in LSM module registration and boot-time selection.
//!
//! The `lsm=` kernel parameter explicitly lists enabled modules in stack order.
//! The legacy `security=` parameter selects one module by name on top of the
//! default stack. If the selected module is exclusive, it replaces the currently
//! selected exclusive module. If neither parameter is specified, the default
//! module stack is used. Unknown module names are ignored with a warning, and
//! duplicate names are ignored after their first selection.

pub mod yama;

use spin::Once;

use super::{LsmFlags, LsmModule};
use crate::prelude::*;

static LSM_PARAM: Once<String> = Once::new();
static LEGACY_SECURITY_PARAM: Once<String> = Once::new();

aster_cmdline::define_kv_param!("lsm", LSM_PARAM);
aster_cmdline::define_kv_param!("security", LEGACY_SECURITY_PARAM);

/// All LSM modules compiled into the kernel.
static ALL_MODULES: [&'static dyn LsmModule; 1] = [&yama::YAMA_LSM];

/// The fallback LSM stack used when no boot-time selector is specified.
pub(super) static DEFAULT_MODULES: [&'static dyn LsmModule; 1] = [&yama::YAMA_LSM];

static ALL_MODULES_BY_NAME: Once<BTreeMap<&'static str, &'static dyn LsmModule>> = Once::new();
static ACTIVE_MODULES: Once<Vec<&'static dyn LsmModule>> = Once::new();

pub(super) fn init() {
    active_modules();
}

pub(super) fn active_modules() -> &'static [&'static dyn LsmModule] {
    ACTIVE_MODULES.call_once(select_active_modules).as_slice()
}

pub(super) fn is_module_enabled(name: &str) -> bool {
    active_modules().iter().any(|module| module.name() == name)
}

fn all_modules_by_name() -> &'static BTreeMap<&'static str, &'static dyn LsmModule> {
    ALL_MODULES_BY_NAME.call_once(build_all_modules_by_name)
}

fn build_all_modules_by_name() -> BTreeMap<&'static str, &'static dyn LsmModule> {
    let mut modules_by_name = BTreeMap::new();

    for module in ALL_MODULES.iter().copied() {
        if modules_by_name.contains_key(module.name()) {
            warn!(
                "duplicate built-in LSM module `{}` is ignored",
                module.name()
            );
            continue;
        }

        modules_by_name.insert(module.name(), module);
    }

    modules_by_name
}

fn select_active_modules() -> Vec<&'static dyn LsmModule> {
    let mut selection = ModuleSelection::new();

    if let Some(lsm_param) = LSM_PARAM.get() {
        if LEGACY_SECURITY_PARAM.get().is_some() {
            warn!("`security=` is ignored because `lsm=` is specified");
        }

        selection.select_from_lsm_param(lsm_param);
        return selection.into_modules();
    }

    for module in DEFAULT_MODULES.iter().copied() {
        selection.push(module);
    }

    if let Some(security_param) = LEGACY_SECURITY_PARAM.get() {
        selection.select_from_security_param(security_param);
    }

    selection.into_modules()
}

struct ModuleSelection {
    modules: Vec<&'static dyn LsmModule>,
    selected_names: BTreeSet<&'static str>,
    exclusive_module_name: Option<&'static str>,
}

impl ModuleSelection {
    fn new() -> Self {
        Self {
            modules: Vec::new(),
            selected_names: BTreeSet::new(),
            exclusive_module_name: None,
        }
    }

    fn into_modules(self) -> Vec<&'static dyn LsmModule> {
        self.modules
    }

    fn select_from_lsm_param(&mut self, param: &str) {
        for name in param
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            self.push_by_name(name, "lsm=");
        }
    }

    fn select_from_security_param(&mut self, param: &str) {
        let name = param.trim();

        if name.is_empty() {
            warn!("`security=` requires an LSM module name");
            return;
        }

        let Some(module) = find_module_by_name(name, "security=") else {
            return;
        };

        if module.flags().contains(LsmFlags::EXCLUSIVE) {
            self.remove_current_exclusive_module();
        }

        self.push(module);
    }

    fn push_by_name(&mut self, name: &str, param_name: &str) {
        let Some(module) = find_module_by_name(name, param_name) else {
            return;
        };

        self.push(module);
    }

    fn push(&mut self, module: &'static dyn LsmModule) {
        let module_name = module.name();

        if self.selected_names.contains(module_name) {
            warn!("duplicate LSM module `{}` is ignored", module_name);
            return;
        }

        if module.flags().contains(LsmFlags::EXCLUSIVE) {
            if let Some(selected_name) = self.exclusive_module_name {
                warn!(
                    "LSM module `{}` is ignored because exclusive module `{}` is already enabled",
                    module_name, selected_name
                );
                return;
            }

            self.exclusive_module_name = Some(module_name);
        }

        self.selected_names.insert(module_name);
        self.modules.push(module);
    }

    fn remove_current_exclusive_module(&mut self) {
        let Some(module_name) = self.exclusive_module_name.take() else {
            return;
        };

        self.modules.retain(|module| module.name() != module_name);
        self.selected_names.remove(module_name);
    }
}

fn find_module_by_name(name: &str, param_name: &str) -> Option<&'static dyn LsmModule> {
    let module = all_modules_by_name().get(name).copied();

    if module.is_none() {
        warn!("unknown LSM module `{}` in `{}`", name, param_name);
    }

    module
}
