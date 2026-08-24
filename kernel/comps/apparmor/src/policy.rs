// SPDX-License-Identifier: MPL-2.0

//! Loaded profiles, task labels, and AppArmor access decisions.

use alloc::{string::String, sync::Arc, vec::Vec};

use aster_core::{Errno, Error, Result};
use spin::RwLock;

mod decoder;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileMode {
    Enforce,
    Complain,
}

impl ProfileMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Complain => "complain",
        }
    }
}

pub(crate) struct Profile {
    pub(crate) attachment: String,
    pub(crate) mode: ProfileMode,
    pub(crate) allowed_capabilities: u64,
}

#[derive(Clone)]
pub(crate) enum TaskLabel {
    Unconfined,
    Confined(Arc<Profile>),
}

impl TaskLabel {
    pub(crate) fn audit_identity(&self) -> (&str, ProfileMode) {
        match self {
            Self::Unconfined => ("unconfined", ProfileMode::Enforce),
            Self::Confined(profile) => (&profile.attachment, profile.mode),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Decision {
    Allow,
    Deny,
    Complain,
}

pub(crate) struct PolicySnapshot {
    pub(crate) profiles: Vec<Arc<Profile>>,
}

impl PolicySnapshot {
    pub(crate) fn profile_for_exec(&self, executable_path: &[u8]) -> Option<Arc<Profile>> {
        let path = core::str::from_utf8(executable_path).ok()?;
        self.profiles
            .binary_search_by(|profile| profile.attachment.as_str().cmp(path))
            .ok()
            .map(|index| self.profiles[index].clone())
    }
}

pub(crate) fn label_for_exec(
    current: &TaskLabel,
    snapshot: Option<&PolicySnapshot>,
    executable_path: &[u8],
) -> TaskLabel {
    snapshot
        .and_then(|snapshot| snapshot.profile_for_exec(executable_path))
        .map_or_else(|| current.clone(), TaskLabel::Confined)
}

pub(crate) fn decide_capability(label: &TaskLabel, capability: u8) -> Decision {
    let TaskLabel::Confined(profile) = label else {
        return Decision::Allow;
    };
    let allowed = capability < 64 && profile.allowed_capabilities & (1_u64 << capability) != 0;
    if allowed {
        Decision::Allow
    } else if profile.mode == ProfileMode::Complain {
        Decision::Complain
    } else {
        Decision::Deny
    }
}

pub(crate) fn ptrace_allowed(accessor: &TaskLabel, target: &TaskLabel) -> bool {
    match (accessor, target) {
        (TaskLabel::Unconfined, TaskLabel::Unconfined) => true,
        (TaskLabel::Confined(accessor), TaskLabel::Confined(target)) => {
            Arc::ptr_eq(accessor, target)
        }
        _ => false,
    }
}

pub(crate) struct PolicyStore {
    snapshot: RwLock<Option<Arc<PolicySnapshot>>>,
}

impl PolicyStore {
    pub(crate) const fn new() -> Self {
        Self {
            snapshot: RwLock::new(None),
        }
    }

    pub(crate) fn load(&self, bytes: &[u8]) -> Result<()> {
        if self.snapshot.read().is_some() {
            return Err(Error::new(Errno::EEXIST));
        }

        let candidate = decoder::decode(bytes)?;
        let mut snapshot = self.snapshot.write();
        if snapshot.is_some() {
            return Err(Error::new(Errno::EEXIST));
        }
        *snapshot = Some(candidate);
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Option<Arc<PolicySnapshot>> {
        self.snapshot.read().clone()
    }
}

#[cfg(ktest)]
mod test {
    use alloc::{sync::Arc, vec};

    use ostd::prelude::ktest;

    use super::{Decision, PolicySnapshot, Profile, ProfileMode, TaskLabel};

    fn profile(attachment: &str, mode: ProfileMode, allowed: u64) -> Arc<Profile> {
        Arc::new(Profile {
            attachment: attachment.into(),
            mode,
            allowed_capabilities: allowed,
        })
    }

    #[ktest]
    fn exact_exec_match_confines_and_nonmatch_preserves_current_label() {
        let profile = profile("/test/enforce", ProfileMode::Enforce, 0);
        let snapshot = PolicySnapshot {
            profiles: vec![profile.clone()],
        };
        let unconfined = TaskLabel::Unconfined;
        let confined = TaskLabel::Confined(profile.clone());

        assert!(matches!(
            super::label_for_exec(&unconfined, Some(&snapshot), b"/test/enforce"),
            TaskLabel::Confined(candidate) if Arc::ptr_eq(&candidate, &profile)
        ));
        assert!(matches!(
            super::label_for_exec(&confined, Some(&snapshot), b"/test/other"),
            TaskLabel::Confined(candidate) if Arc::ptr_eq(&candidate, &profile)
        ));
        assert!(matches!(
            super::label_for_exec(&unconfined, None, b"/test/enforce"),
            TaskLabel::Unconfined
        ));
    }

    #[ktest]
    fn allowed_enforce_and_complain_capabilities_differ() {
        let enforce = TaskLabel::Confined(profile("/enforce", ProfileMode::Enforce, 1));
        let complain = TaskLabel::Confined(profile("/complain", ProfileMode::Complain, 1));

        assert_eq!(super::decide_capability(&enforce, 0), Decision::Allow);
        assert_eq!(super::decide_capability(&enforce, 1), Decision::Deny);
        assert_eq!(super::decide_capability(&enforce, 64), Decision::Deny);
        assert_eq!(super::decide_capability(&complain, 1), Decision::Complain);
        assert_eq!(
            super::decide_capability(&TaskLabel::Unconfined, 63),
            Decision::Allow
        );
    }

    #[ktest]
    fn equal_labels_allow_ptrace_and_cross_labels_deny() {
        let shared_profile = profile("/enforce", ProfileMode::Enforce, 0);
        let same = TaskLabel::Confined(shared_profile.clone());
        let inherited = same.clone();
        let other = TaskLabel::Confined(profile("/other", ProfileMode::Complain, 0));

        assert!(super::ptrace_allowed(
            &TaskLabel::Unconfined,
            &TaskLabel::Unconfined
        ));
        assert!(super::ptrace_allowed(&same, &inherited));
        assert!(!super::ptrace_allowed(&same, &other));
        assert!(!super::ptrace_allowed(&TaskLabel::Unconfined, &same));
    }
}
