// SPDX-License-Identifier: MPL-2.0

use crate::process::credentials::capabilities::CapSet;

/// AppArmor capability policy attached to a profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AppArmorCapabilityPolicy {
    allowed: CapSet,
}

impl AppArmorCapabilityPolicy {
    /// Creates a capability policy from an allowed capability mask.
    pub const fn new(allowed: CapSet) -> Self {
        Self { allowed }
    }

    /// Returns whether all requested capabilities are allowed.
    pub fn allows(self, capabilities: CapSet) -> bool {
        self.allowed.contains(capabilities)
    }
}

impl Default for AppArmorCapabilityPolicy {
    fn default() -> Self {
        Self::new(CapSet::empty())
    }
}
