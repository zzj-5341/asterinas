// SPDX-License-Identifier: MPL-2.0

//! AppArmor major-LSM policy model.

mod capability;
mod label;
mod namespace;
mod path;
mod policy;
mod policy_update;
mod profile;
mod state;

use self::{policy::AppArmorPolicy, policy_update::AppArmorPolicyUpdate};
pub use self::{
    profile::AppArmorProfileName,
    state::{AppArmorMode, AppArmorTaskState},
};
use super::super::{
    LsmFlags, LsmModule,
    hooks::{LsmAlienAccessHook, LsmBprmHook, LsmCapabilityHook, LsmFileHook, LsmSignalHook},
};
use crate::prelude::*;

pub(super) static APPARMOR_LSM: AppArmorLsm = AppArmorLsm;

static POLICY: AppArmorPolicy = AppArmorPolicy::new();

/// The AppArmor major LSM.
pub(super) struct AppArmorLsm;

impl LsmModule for AppArmorLsm {
    fn name(&self) -> &'static str {
        "apparmor"
    }

    fn flags(&self) -> LsmFlags {
        LsmFlags::LEGACY_MAJOR | LsmFlags::EXCLUSIVE
    }
}

impl LsmAlienAccessHook for AppArmorLsm {}
impl LsmBprmHook for AppArmorLsm {}
impl LsmCapabilityHook for AppArmorLsm {}
impl LsmFileHook for AppArmorLsm {}
impl LsmSignalHook for AppArmorLsm {}

#[expect(dead_code, reason = "policy loaders are added with management ABIs")]
fn apply_policy_update(update: AppArmorPolicyUpdate) -> Result<()> {
    match update {
        AppArmorPolicyUpdate::Replace(profile) => {
            POLICY.replace_profile(*profile);
            Ok(())
        }
        AppArmorPolicyUpdate::ReplaceMany(profiles) => {
            for profile in profiles {
                POLICY.replace_profile(profile);
            }
            Ok(())
        }
        AppArmorPolicyUpdate::Remove(profile_name) => {
            if POLICY.remove_profile(&profile_name).is_none() {
                return_errno_with_message!(Errno::ENOENT, "the AppArmor profile is not loaded");
            }
            Ok(())
        }
    }
}

/// Returns summaries of the implicit and loaded AppArmor profiles.
pub fn profile_summaries() -> Vec<(AppArmorProfileName, AppArmorMode)> {
    POLICY.profile_summaries()
}

/// Returns the root AppArmor policy namespace name.
pub fn root_namespace_name() -> &'static str {
    POLICY.root_namespace_name()
}
