// SPDX-License-Identifier: MPL-2.0

//! Decoding and validation of AppArmor policies.

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::cmp::Ordering;

use aster_core::prelude::*;
use ostd::sync::Mutex;

mod abi;
mod dfa;

pub(super) const MAX_POLICY_BLOB_SIZE: usize = 1024 * 1024;
const MAX_LOADED_PROFILES: usize = 1024;
const MAX_POLICY_STORE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROFILE_NAME_LEN: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileMode {
    Enforce,
    Complain,
}

impl ProfileMode {
    fn decode(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::Enforce),
            1 => Ok(Self::Complain),
            2..=4 => Err(Error::new(Errno::EOPNOTSUPP)),
            _ => Err(Error::new(Errno::EPROTO)),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Complain => "complain",
        }
    }
}

#[cfg_attr(
    not(ktest),
    expect(
        dead_code,
        reason = "M1 retains attachment matchers but does not execute them"
    )
)]
#[derive(Debug)]
pub(crate) struct AttachmentMatcher {
    encoded_dfa: Box<[u8]>,
    xmatch_len: u32,
}

#[cfg_attr(
    not(ktest),
    expect(
        dead_code,
        reason = "M1 retains attachment matchers but does not execute them"
    )
)]
impl AttachmentMatcher {
    pub(crate) fn encoded_dfa(&self) -> &[u8] {
        &self.encoded_dfa
    }

    pub(crate) fn xmatch_len(&self) -> u32 {
        self.xmatch_len
    }
}

#[derive(Debug)]
pub(crate) struct Profile {
    name: String,
    mode: ProfileMode,
    #[cfg_attr(
        not(ktest),
        expect(
            dead_code,
            reason = "M1 retains attachment matchers but does not execute them"
        )
    )]
    attachment: Option<AttachmentMatcher>,
}

impl Profile {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn mode(&self) -> ProfileMode {
        self.mode
    }

    #[cfg_attr(
        not(ktest),
        expect(
            dead_code,
            reason = "M1 retains attachment matchers but does not execute them"
        )
    )]
    pub(crate) fn attachment(&self) -> Option<&AttachmentMatcher> {
        self.attachment.as_ref()
    }
}

#[derive(Debug)]
struct DecodedPolicy {
    profiles: Vec<Profile>,
    charge: usize,
}

#[derive(Debug)]
pub(crate) struct PolicySet {
    profiles: Vec<Arc<Profile>>,
    charged_bytes: usize,
}

impl PolicySet {
    fn try_insert_all(current: Option<&Self>, mut decoded: DecodedPolicy) -> Result<Self> {
        let current_len = current.map_or(0, |set| set.profiles.len());
        let total_len = current_len
            .checked_add(decoded.profiles.len())
            .filter(|total| *total <= MAX_LOADED_PROFILES)
            .ok_or_else(capacity_error)?;

        let current_charge = current.map_or(0, |set| set.charged_bytes);
        let charged_bytes = current_charge
            .checked_add(decoded.charge)
            .filter(|total| *total <= MAX_POLICY_STORE_BYTES)
            .ok_or_else(capacity_error)?;

        decoded
            .profiles
            .sort_unstable_by(|left, right| left.name().cmp(right.name()));
        if decoded
            .profiles
            .windows(2)
            .any(|pair| pair[0].name() == pair[1].name())
        {
            return Err(Error::new(Errno::EEXIST));
        }

        let mut profiles = Vec::new();
        profiles
            .try_reserve_exact(total_len)
            .map_err(|_| Error::new(Errno::ENOMEM))?;

        let current_profiles = current.map_or(&[][..], |set| set.profiles.as_slice());
        let mut current_index = 0;
        let mut incoming = decoded.profiles.into_iter();
        let mut next_incoming = incoming.next();
        while current_index < current_profiles.len() || next_incoming.is_some() {
            match (current_profiles.get(current_index), next_incoming.as_ref()) {
                (Some(current), Some(next)) => match current.name().cmp(next.name()) {
                    Ordering::Less => {
                        profiles.push(current.clone());
                        current_index += 1;
                    }
                    Ordering::Equal => return Err(Error::new(Errno::EEXIST)),
                    Ordering::Greater => {
                        if let Some(profile) = next_incoming.take() {
                            profiles.push(
                                Arc::try_new(profile).map_err(|_| Error::new(Errno::ENOMEM))?,
                            );
                        }
                        next_incoming = incoming.next();
                    }
                },
                (Some(current), None) => {
                    profiles.push(current.clone());
                    current_index += 1;
                }
                (None, Some(_)) => {
                    if let Some(profile) = next_incoming.take() {
                        profiles
                            .push(Arc::try_new(profile).map_err(|_| Error::new(Errno::ENOMEM))?);
                    }
                    next_incoming = incoming.next();
                }
                (None, None) => break,
            }
        }

        Ok(Self {
            profiles,
            charged_bytes,
        })
    }

    pub(crate) fn profiles(&self) -> &[Arc<Profile>] {
        &self.profiles
    }
}

pub(crate) struct PolicyStore {
    current: Mutex<Option<Arc<PolicySet>>>,
}

impl PolicyStore {
    const fn new() -> Self {
        Self {
            current: Mutex::new(None),
        }
    }

    pub(crate) fn load(&self, blob: &[u8]) -> Result<()> {
        if blob.is_empty() {
            return Err(Error::new(Errno::EINVAL));
        }
        if blob.len() > MAX_POLICY_BLOB_SIZE {
            return Err(Error::new(Errno::E2BIG));
        }

        let decoded = abi::decode(blob)?;
        let mut guard = self.current.lock();
        let next = PolicySet::try_insert_all(guard.as_deref(), decoded)?;
        *guard = Some(Arc::try_new(next).map_err(|_| Error::new(Errno::ENOMEM))?);
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Option<Arc<PolicySet>> {
        self.current.lock().clone()
    }
}

pub(super) static POLICY_STORE: PolicyStore = PolicyStore::new();

fn capacity_error() -> Error {
    Error::new(Errno::ENOSPC)
}

#[cfg(ktest)]
mod tests {
    use alloc::format;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use ostd::{
        prelude::ktest,
        task::{Task, TaskOptions},
    };

    use super::*;

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.push(2);
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn push_chunk(output: &mut Vec<u8>, code: u8, value: &[u8]) {
        output.push(code);
        output.extend_from_slice(&((value.len() + 1) as u16).to_le_bytes());
        output.extend_from_slice(value);
        output.push(0);
    }

    fn push_name(output: &mut Vec<u8>, name: &str) {
        push_chunk(output, 4, name.as_bytes());
    }

    fn push_named_struct(output: &mut Vec<u8>, name: &str) {
        push_name(output, name);
        output.push(7);
    }

    fn policy_unit(name: &str) -> Vec<u8> {
        let mut output = Vec::new();
        push_name(&mut output, "version");
        push_u32(&mut output, 5);
        push_named_struct(&mut output, "profile");
        push_chunk(&mut output, 5, name.as_bytes());
        push_named_struct(&mut output, "flags");
        push_u32(&mut output, 0);
        push_u32(&mut output, 0);
        push_u32(&mut output, 0);
        output.push(8);
        for _ in 0..4 {
            push_u32(&mut output, 0);
        }
        push_named_struct(&mut output, "caps64");
        for _ in 0..4 {
            push_u32(&mut output, 0);
        }
        output.push(8);
        output.push(8);
        output
    }

    fn profile(name: &str) -> Profile {
        Profile {
            name: name.into(),
            mode: ProfileMode::Enforce,
            attachment: None,
        }
    }

    fn assert_errno<T>(result: Result<T>, expected: Errno) {
        assert_eq!(result.err().unwrap().error(), expected);
    }

    fn assert_names(set: &PolicySet, expected: &[&str]) {
        let actual: Vec<&str> = set
            .profiles()
            .iter()
            .map(|profile| profile.name())
            .collect();
        assert_eq!(actual, expected);
    }

    #[ktest]
    fn loads_one_or_multiple_profiles_in_sorted_snapshots() {
        let one = PolicyStore::new();
        assert!(one.snapshot().is_none());
        one.load(&policy_unit("demo")).unwrap();
        assert_names(&one.snapshot().unwrap(), &["demo"]);

        let multiple = PolicyStore::new();
        assert!(multiple.snapshot().is_none());
        let mut blob = policy_unit("z-last");
        blob.extend_from_slice(&policy_unit("a-first"));
        multiple.load(&blob).unwrap();
        assert_names(&multiple.snapshot().unwrap(), &["a-first", "z-last"]);
    }

    #[ktest]
    fn sequential_loads_preserve_existing_profiles() {
        let store = PolicyStore::new();
        assert!(store.snapshot().is_none());
        store.load(&policy_unit("second")).unwrap();
        store.load(&policy_unit("first")).unwrap();
        assert_names(&store.snapshot().unwrap(), &["first", "second"]);
    }

    #[ktest]
    fn duplicate_or_decoder_failure_preserves_snapshot() {
        let store = PolicyStore::new();
        assert!(store.snapshot().is_none());

        let mut duplicate = policy_unit("same");
        duplicate.extend_from_slice(&policy_unit("same"));
        assert_errno(store.load(&duplicate), Errno::EEXIST);
        assert!(store.snapshot().is_none());

        store.load(&policy_unit("same")).unwrap();
        let before = store.snapshot().unwrap();
        assert_errno(store.load(&policy_unit("same")), Errno::EEXIST);
        let after_conflict = store.snapshot().unwrap();
        assert!(Arc::ptr_eq(&before, &after_conflict));

        assert_errno(store.load(&[0]), Errno::EPROTO);
        let after_decode = store.snapshot().unwrap();
        assert!(Arc::ptr_eq(&before, &after_decode));
        assert_names(&after_decode, &["same"]);
    }

    #[ktest]
    fn partial_conflict_does_not_publish_new_profile() {
        let store = PolicyStore::new();
        store.load(&policy_unit("existing")).unwrap();
        let before = store.snapshot().unwrap();

        let mut batch = policy_unit("existing");
        batch.extend_from_slice(&policy_unit("new"));
        assert_errno(store.load(&batch), Errno::EEXIST);

        let after = store.snapshot().unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        assert_names(&after, &["existing"]);
    }

    #[ktest]
    fn rejects_input_profile_and_charge_limits() {
        let store = PolicyStore::new();
        assert!(store.snapshot().is_none());
        assert_errno(store.load(&[]), Errno::EINVAL);
        assert_errno(
            store.load(&alloc::vec![0; MAX_POLICY_BLOB_SIZE + 1]),
            Errno::E2BIG,
        );

        let mut profiles = Vec::new();
        for index in 0..=MAX_LOADED_PROFILES {
            profiles.push(profile(&format!("profile-{index}")));
        }
        assert_errno(
            PolicySet::try_insert_all(
                None,
                DecodedPolicy {
                    profiles,
                    charge: 1,
                },
            ),
            Errno::ENOSPC,
        );

        assert_errno(
            PolicySet::try_insert_all(
                None,
                DecodedPolicy {
                    profiles: alloc::vec![profile("large")],
                    charge: MAX_POLICY_STORE_BYTES + 1,
                },
            ),
            Errno::ENOSPC,
        );
    }

    #[ktest]
    fn concurrent_writers_do_not_lose_profiles() {
        let store = Arc::new(PolicyStore::new());
        assert!(store.snapshot().is_none());
        let done = Arc::new(AtomicUsize::new(0));

        for name in ["first", "second"] {
            let store = store.clone();
            let done = done.clone();
            TaskOptions::new(move || {
                store.load(&policy_unit(name)).unwrap();
                done.fetch_add(1, Ordering::Release);
            })
            .spawn()
            .unwrap();
        }

        while done.load(Ordering::Acquire) != 2 {
            Task::yield_now();
        }
        assert_names(&store.snapshot().unwrap(), &["first", "second"]);
    }

    #[ktest]
    fn reader_observes_only_complete_snapshots() {
        let store = Arc::new(PolicyStore::new());
        assert!(store.snapshot().is_none());
        store.load(&policy_unit("old")).unwrap();
        assert_names(&store.snapshot().unwrap(), &["old"]);

        let done = Arc::new(AtomicBool::new(false));
        let writer_store = store.clone();
        let writer_done = done.clone();
        TaskOptions::new(move || {
            writer_store.load(&policy_unit("new")).unwrap();
            writer_done.store(true, Ordering::Release);
        })
        .spawn()
        .unwrap();

        loop {
            let snapshot = store.snapshot().unwrap();
            match snapshot.profiles().len() {
                1 => assert_names(&snapshot, &["old"]),
                2 => assert_names(&snapshot, &["new", "old"]),
                _ => panic!("partial snapshot"),
            }
            if done.load(Ordering::Acquire) {
                break;
            }
            Task::yield_now();
        }
        assert_names(&store.snapshot().unwrap(), &["new", "old"]);
    }
}
