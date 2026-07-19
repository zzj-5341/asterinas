// SPDX-License-Identifier: MPL-2.0

use super::{
    profile::{AppArmorProfile, AppArmorProfileName},
    state::AppArmorMode,
};
use crate::prelude::*;

/// An AppArmor policy namespace.
pub struct AppArmorPolicyNamespace {
    name: &'static str,
    profiles: RwLock<BTreeMap<AppArmorProfileName, Arc<AppArmorProfile>>>,
}

impl AppArmorPolicyNamespace {
    /// Creates the root AppArmor policy namespace.
    pub const fn new_root() -> Self {
        Self {
            name: "root",
            profiles: RwLock::new(BTreeMap::new()),
        }
    }

    /// Returns the namespace name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Replaces or inserts a loaded profile.
    pub fn replace_profile(&self, profile: AppArmorProfile) {
        let name = profile.name().clone();
        self.profiles.write().insert(name, Arc::new(profile));
    }

    /// Removes a loaded profile.
    pub fn remove_profile(&self, name: &AppArmorProfileName) -> Option<AppArmorProfile> {
        self.profiles
            .write()
            .remove(name)
            .and_then(|profile| Arc::try_unwrap(profile).ok())
    }

    /// Looks up a profile by name.
    pub fn profile(&self, name: &AppArmorProfileName) -> Option<Arc<AppArmorProfile>> {
        if name.is_unconfined() {
            return Some(Arc::new(AppArmorProfile::new_unconfined()));
        }
        self.profiles.read().get(name).cloned()
    }

    /// Returns summaries of the implicit and loaded profiles.
    pub fn profile_summaries(&self) -> Vec<(AppArmorProfileName, AppArmorMode)> {
        let profiles = self.profiles.read();
        let mut summaries = Vec::with_capacity(profiles.len() + 1);
        summaries.push((AppArmorProfileName::new_unconfined(), AppArmorMode::Enforce));
        summaries.extend(
            profiles
                .values()
                .map(|profile| (profile.name().clone(), profile.mode())),
        );
        summaries
    }
}
