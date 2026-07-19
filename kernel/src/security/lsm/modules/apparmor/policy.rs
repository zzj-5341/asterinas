// SPDX-License-Identifier: MPL-2.0

use super::{
    namespace::AppArmorPolicyNamespace,
    profile::{AppArmorProfile, AppArmorProfileName},
    state::AppArmorMode,
};
use crate::prelude::*;

/// The AppArmor policy store rooted at the initial namespace.
pub(super) struct AppArmorPolicy {
    root_namespace: AppArmorPolicyNamespace,
}

impl AppArmorPolicy {
    /// Creates an empty policy with an implicit unconfined profile.
    pub const fn new() -> Self {
        Self {
            root_namespace: AppArmorPolicyNamespace::new_root(),
        }
    }

    /// Replaces or inserts a profile in the root namespace.
    pub fn replace_profile(&self, profile: AppArmorProfile) {
        self.root_namespace.replace_profile(profile);
    }

    /// Removes a profile from the root namespace.
    pub fn remove_profile(&self, name: &AppArmorProfileName) -> Option<AppArmorProfile> {
        self.root_namespace.remove_profile(name)
    }

    /// Looks up a profile by name.
    pub fn profile(&self, name: &AppArmorProfileName) -> Option<Arc<AppArmorProfile>> {
        self.root_namespace.profile(name)
    }

    /// Returns summaries of the implicit and loaded profiles.
    pub fn profile_summaries(&self) -> Vec<(AppArmorProfileName, AppArmorMode)> {
        self.root_namespace.profile_summaries()
    }

    /// Returns the root policy namespace name.
    pub const fn root_namespace_name(&self) -> &'static str {
        self.root_namespace.name()
    }
}
