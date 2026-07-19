// SPDX-License-Identifier: MPL-2.0

use super::{capability::AppArmorCapabilityPolicy, path::AppArmorPathRule, state::AppArmorMode};
use crate::prelude::*;

/// The name of an AppArmor profile.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AppArmorProfileName(String);

impl AppArmorProfileName {
    /// The default profile before policy-driven transitions exist.
    pub const UNCONFINED: &'static str = "unconfined";

    /// Creates a profile name.
    pub fn new(name: String) -> Result<Self> {
        if name.is_empty() {
            return_errno_with_message!(Errno::EINVAL, "the AppArmor profile name is empty");
        }
        Ok(Self(name))
    }

    /// Creates the default unconfined profile name.
    pub fn new_unconfined() -> Self {
        Self(String::from(Self::UNCONFINED))
    }

    /// Returns whether this is the default unconfined profile.
    pub fn is_unconfined(&self) -> bool {
        self.as_str() == Self::UNCONFINED
    }

    /// Returns the profile name text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Default for AppArmorProfileName {
    fn default() -> Self {
        Self::new_unconfined()
    }
}

/// An AppArmor profile and its policy data.
#[derive(Clone, Debug)]
pub struct AppArmorProfile {
    name: AppArmorProfileName,
    mode: AppArmorMode,
    file_rules: Vec<AppArmorPathRule>,
    capability_policy: AppArmorCapabilityPolicy,
}

impl AppArmorProfile {
    /// Creates a profile with pathname rules.
    pub fn new(
        name: AppArmorProfileName,
        mode: AppArmorMode,
        file_rules: Vec<AppArmorPathRule>,
    ) -> Self {
        Self::new_with_policies(name, mode, file_rules, AppArmorCapabilityPolicy::default())
    }

    /// Creates a profile with file and capability policies.
    pub(super) fn new_with_policies(
        name: AppArmorProfileName,
        mode: AppArmorMode,
        file_rules: Vec<AppArmorPathRule>,
        capability_policy: AppArmorCapabilityPolicy,
    ) -> Self {
        Self {
            name,
            mode,
            file_rules,
            capability_policy,
        }
    }

    /// Creates the default unconfined profile.
    pub fn new_unconfined() -> Self {
        Self::new(
            AppArmorProfileName::new_unconfined(),
            AppArmorMode::Enforce,
            Vec::new(),
        )
    }

    /// Returns the profile name.
    pub fn name(&self) -> &AppArmorProfileName {
        &self.name
    }

    /// Returns the profile mode.
    pub fn mode(&self) -> AppArmorMode {
        self.mode
    }

    /// Returns the pathname rules.
    pub(super) fn file_rules(&self) -> &[AppArmorPathRule] {
        &self.file_rules
    }

    /// Returns the capability policy.
    pub(super) fn capability_policy(&self) -> AppArmorCapabilityPolicy {
        self.capability_policy
    }
}
