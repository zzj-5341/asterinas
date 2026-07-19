// SPDX-License-Identifier: MPL-2.0

use super::{
    capability::AppArmorCapabilityPolicy,
    dfa::{AppArmorDfaAccessOutcome, AppArmorDfaFilePolicy},
    path::{AppArmorFilePermission, AppArmorPathRule, AppArmorPathView},
    state::AppArmorMode,
};
use crate::{prelude::*, process::credentials::capabilities::CapSet};

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

/// An AppArmor profile and its enforcement policies.
#[derive(Clone, Debug)]
pub struct AppArmorProfile {
    name: AppArmorProfileName,
    mode: AppArmorMode,
    file_policy: AppArmorFilePolicy,
    capability_policy: AppArmorCapabilityPolicy,
}

impl AppArmorProfile {
    /// Creates a profile backed by pathname rules.
    pub fn new(
        name: AppArmorProfileName,
        mode: AppArmorMode,
        file_rules: Vec<AppArmorPathRule>,
    ) -> Self {
        Self::new_with_file_policy(name, mode, AppArmorFilePolicy::PathRules(file_rules))
    }

    /// Creates a profile with an explicit file-policy backend.
    pub(super) fn new_with_file_policy(
        name: AppArmorProfileName,
        mode: AppArmorMode,
        file_policy: AppArmorFilePolicy,
    ) -> Self {
        Self::new_with_policies(name, mode, file_policy, AppArmorCapabilityPolicy::default())
    }

    /// Creates a profile with file and capability policies.
    pub(super) fn new_with_policies(
        name: AppArmorProfileName,
        mode: AppArmorMode,
        file_policy: AppArmorFilePolicy,
        capability_policy: AppArmorCapabilityPolicy,
    ) -> Self {
        Self {
            name,
            mode,
            file_policy,
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

    /// Evaluates file access for this profile.
    pub fn evaluate_file_access(
        &self,
        path_view: &AppArmorPathView,
        permissions: AppArmorFilePermission,
    ) -> Result<AppArmorFileAccessOutcome> {
        match &self.file_policy {
            AppArmorFilePolicy::PathRules(rules) => {
                Ok(evaluate_path_rules(rules, path_view, permissions))
            }
            AppArmorFilePolicy::Dfa(policy) => policy
                .evaluate_path_access(path_view, permissions)
                .map(AppArmorFileAccessOutcome::from),
        }
    }

    /// Evaluates capability access for this profile.
    pub fn evaluate_capability_access(&self, capabilities: CapSet) -> AppArmorCapabilityOutcome {
        let denied = if self.capability_policy.allows(capabilities) {
            CapSet::empty()
        } else {
            capabilities
        };
        AppArmorCapabilityOutcome { denied }
    }
}

/// The file-policy backend used by an AppArmor profile.
#[derive(Clone, Debug)]
pub(super) enum AppArmorFilePolicy {
    /// Path rules constructed by an in-kernel caller.
    PathRules(Vec<AppArmorPathRule>),
    /// A Linux AppArmor DFA policy.
    Dfa(Box<AppArmorDfaFilePolicy>),
}

/// A file-access decision from a profile.
pub struct AppArmorFileAccessOutcome {
    /// Permissions denied by the policy.
    pub denied: AppArmorFilePermission,
    /// Permissions denied by an explicit `deny` rule.
    pub explicit_denied: AppArmorFilePermission,
}

/// A capability-access decision from a profile.
pub struct AppArmorCapabilityOutcome {
    /// Capabilities denied by the policy.
    pub denied: CapSet,
}

impl From<AppArmorDfaAccessOutcome> for AppArmorFileAccessOutcome {
    fn from(outcome: AppArmorDfaAccessOutcome) -> Self {
        Self {
            denied: outcome.denied,
            explicit_denied: outcome.explicit_denied,
        }
    }
}

fn evaluate_path_rules(
    rules: &[AppArmorPathRule],
    path_view: &AppArmorPathView,
    permissions: AppArmorFilePermission,
) -> AppArmorFileAccessOutcome {
    let mut allowed = AppArmorFilePermission::empty();
    let mut explicit_denied = AppArmorFilePermission::empty();

    for rule in rules {
        if !rule.matches(path_view) {
            continue;
        }

        let matched_permissions = rule.permissions() & permissions;
        if matched_permissions.is_empty() {
            continue;
        }

        if rule.deny() {
            explicit_denied |= matched_permissions;
        } else {
            allowed |= matched_permissions;
        }
    }

    AppArmorFileAccessOutcome {
        denied: explicit_denied | (permissions - allowed),
        explicit_denied,
    }
}
