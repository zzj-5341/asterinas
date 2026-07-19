// SPDX-License-Identifier: MPL-2.0

use super::{label::AppArmorLabel, profile::AppArmorProfileName};
use crate::prelude::*;

/// AppArmor state attached to a task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppArmorTaskState {
    label: AppArmorLabel,
    mode: AppArmorMode,
}

impl AppArmorTaskState {
    /// Creates the default unconfined AppArmor task state.
    pub fn new_unconfined() -> Self {
        Self {
            label: AppArmorLabel::new_unconfined(),
            mode: AppArmorMode::Enforce,
        }
    }

    /// Creates task state for a single profile.
    pub(super) fn new_single(profile_name: AppArmorProfileName, mode: AppArmorMode) -> Self {
        Self {
            label: AppArmorLabel::new_single(profile_name),
            mode,
        }
    }

    /// Returns the current profile.
    pub fn current_profile(&self) -> &AppArmorProfileName {
        self.label.primary_profile()
    }

    /// Returns whether the current task label is unconfined.
    pub fn is_unconfined(&self) -> bool {
        self.label.is_unconfined()
    }

    /// Returns the current profile mode.
    pub fn mode(&self) -> AppArmorMode {
        self.mode
    }
}

impl Default for AppArmorTaskState {
    fn default() -> Self {
        Self::new_unconfined()
    }
}

/// The enforcement mode of an AppArmor profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppArmorMode {
    /// Denied operations fail.
    Enforce,
    /// Denied operations are logged but allowed.
    Complain,
}

impl AppArmorMode {
    /// Parses an AppArmor enforcement mode.
    pub fn parse(mode: &str) -> Result<Self> {
        match mode {
            "enforce" => Ok(Self::Enforce),
            "complain" => Ok(Self::Complain),
            _ => return_errno_with_message!(Errno::EINVAL, "the AppArmor mode is invalid"),
        }
    }

    /// Returns the mode text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Complain => "complain",
        }
    }
}
