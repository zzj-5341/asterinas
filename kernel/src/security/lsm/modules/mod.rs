// SPDX-License-Identifier: MPL-2.0

pub mod yama;

use spin::Once;

use super::{LsmFlags, LsmModule};
use crate::prelude::*;

static LSM_PARAM: Once<String> = Once::new();
static LEGACY_SECURITY_PARAM: Once<String> = Once::new();

aster_cmdline::define_kv_param!("lsm", LSM_PARAM);
aster_cmdline::define_kv_param!("security", LEGACY_SECURITY_PARAM);

static BUILTIN_MODULES: [&'static dyn LsmModule; 1] = [&yama::YAMA_LSM];
pub(super) static DEFAULT_MODULES: [&'static dyn LsmModule; 1] = [&yama::YAMA_LSM];

static ACTIVE_MODULES: Once<Vec<&'static dyn LsmModule>> = Once::new();

pub(super) fn init() {
    ACTIVE_MODULES.call_once(select_active_modules);
}

pub(super) fn active_modules() -> &'static [&'static dyn LsmModule] {
    ACTIVE_MODULES
        .get()
        .map(Vec::as_slice)
        .unwrap_or(DEFAULT_MODULES.as_slice())
}

fn select_active_modules() -> Vec<&'static dyn LsmModule> {
    if let Some(lsm_param) = LSM_PARAM.get() {
        if LEGACY_SECURITY_PARAM.get().is_some() {
            warn!("`security=` is ignored because `lsm=` is specified");
        }

        return select_modules_from_lsm_param(lsm_param);
    }

    if let Some(security_param) = LEGACY_SECURITY_PARAM.get() {
        return select_modules_from_security_param(security_param);
    }

    select_default_modules()
}

fn select_default_modules() -> Vec<&'static dyn LsmModule> {
    let mut modules = Vec::new();

    for module in DEFAULT_MODULES.iter().copied() {
        push_selected_module(&mut modules, module);
    }

    modules
}

fn select_modules_from_lsm_param(param: &str) -> Vec<&'static dyn LsmModule> {
    let mut modules = Vec::new();

    for name in param
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        select_module_by_name(&mut modules, name);
    }

    modules
}

fn select_modules_from_security_param(param: &str) -> Vec<&'static dyn LsmModule> {
    let mut modules = select_default_modules();
    let name = param.trim();

    if name.is_empty() {
        warn!("`security=` requires an LSM module name");
        return modules;
    }

    let Some(module) = find_builtin_module(name) else {
        warn!("unknown LSM module `{}` in `security=`", name);
        return modules;
    };

    if module.flags().contains(LsmFlags::EXCLUSIVE) {
        modules.retain(|selected| !selected.flags().contains(LsmFlags::EXCLUSIVE));
    }

    push_selected_module(&mut modules, module);
    modules
}

fn select_module_by_name(modules: &mut Vec<&'static dyn LsmModule>, name: &str) {
    let Some(module) = find_builtin_module(name) else {
        warn!("unknown LSM module `{}` in `lsm=`", name);
        return;
    };

    push_selected_module(modules, module);
}

fn find_builtin_module(name: &str) -> Option<&'static dyn LsmModule> {
    BUILTIN_MODULES
        .iter()
        .copied()
        .find(|module| module.name() == name)
}

fn push_selected_module(modules: &mut Vec<&'static dyn LsmModule>, module: &'static dyn LsmModule) {
    if modules
        .iter()
        .any(|selected| selected.name() == module.name())
    {
        warn!("duplicate LSM module `{}` is ignored", module.name());
        return;
    }

    if module.flags().contains(LsmFlags::EXCLUSIVE)
        && let Some(selected) = modules
            .iter()
            .find(|selected| selected.flags().contains(LsmFlags::EXCLUSIVE))
    {
        warn!(
            "LSM module `{}` is ignored because exclusive module `{}` is already enabled",
            module.name(),
            selected.name()
        );
        return;
    }

    modules.push(module);
}
