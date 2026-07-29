// SPDX-License-Identifier: MPL-2.0

//! AppArmor policy representation and storage.
//!
//! The initial policy language contains one profile header followed by exact
//! absolute-path rules with read (`r`) and write (`w`) permissions.

use super::UNCONFINED_PROFILE_NAME;
use crate::prelude::*;

const MAX_PROFILE_NAME_LEN_BYTES: usize = 128;
const MAX_RULE_PATH_LEN_BYTES: usize = 4096;

bitflags! {
    pub(super) struct FilePermissions: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
    }
}

#[derive(Debug)]
struct Profile {
    name: String,
    file_rules: BTreeMap<String, FilePermissions>,
}

impl Profile {
    fn parse(policy: &str) -> Result<Self> {
        let mut lines = policy
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'));

        let Some(header) = lines.next() else {
            return_errno_with_message!(Errno::EINVAL, "the AppArmor policy is empty");
        };
        let mut header_fields = header.split_ascii_whitespace();
        if header_fields.next() != Some("profile") {
            return_errno_with_message!(
                Errno::EINVAL,
                "the AppArmor policy must start with `profile <name>`"
            );
        }
        let Some(name) = header_fields.next() else {
            return_errno_with_message!(Errno::EINVAL, "the AppArmor profile name is missing");
        };
        if header_fields.next().is_some()
            || name == UNCONFINED_PROFILE_NAME
            || !is_valid_profile_name(name)
        {
            return_errno_with_message!(Errno::EINVAL, "the AppArmor profile name is invalid");
        }

        let mut file_rules = BTreeMap::<String, FilePermissions>::new();
        for line in lines {
            let mut fields = line.split_ascii_whitespace();
            let Some(path) = fields.next() else {
                continue;
            };
            let Some(permissions) = fields.next() else {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "an AppArmor file rule is missing permissions"
                );
            };
            if fields.next().is_some() || !is_canonical_absolute_path(path) {
                return_errno_with_message!(Errno::EINVAL, "an AppArmor file rule is invalid");
            }

            let permissions = parse_file_permissions(permissions)?;
            file_rules
                .entry(path.to_string())
                .and_modify(|current| current.insert(permissions))
                .or_insert(permissions);
        }

        Ok(Self {
            name: name.to_string(),
            file_rules,
        })
    }

    fn allows(&self, path: &str, requested: FilePermissions) -> bool {
        self.file_rules
            .get(path)
            .is_some_and(|allowed| allowed.contains(requested))
    }
}

#[derive(Default)]
struct PolicyStore {
    profiles: BTreeMap<String, Arc<Profile>>,
}

fn policy_store() -> &'static RwLock<PolicyStore> {
    static POLICY_STORE: spin::Once<RwLock<PolicyStore>> = spin::Once::new();

    POLICY_STORE.call_once(|| RwLock::new(PolicyStore::default()))
}

/// Loads or atomically replaces one AppArmor profile.
///
/// The first meaningful line must be `profile <name>`. Each remaining line has
/// the form `<absolute-path> <permissions>`, where permissions are a combination
/// of `r` and `w`.
pub(super) fn load_profile(policy: &str) -> Result<()> {
    let profile = Profile::parse(policy)?;
    let profile_name = profile.name.clone();

    policy_store()
        .write()
        .profiles
        .insert(profile_name, Arc::new(profile));
    Ok(())
}

/// Returns a stable snapshot of loaded profile names.
pub(super) fn loaded_profile_names() -> Vec<String> {
    policy_store().read().profiles.keys().cloned().collect()
}

pub(super) fn stored_profile_name(name: &str) -> Option<Arc<str>> {
    let store = policy_store().read();
    let (stored_name, _) = store.profiles.get_key_value(name)?;
    Some(Arc::from(stored_name.as_str()))
}

pub(super) fn allows_file(profile_name: &str, path: &str, requested: FilePermissions) -> bool {
    policy_store()
        .read()
        .profiles
        .get(profile_name)
        .is_some_and(|profile| profile.allows(path, requested))
}

pub(super) fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PROFILE_NAME_LEN_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn is_canonical_absolute_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_RULE_PATH_LEN_BYTES || !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }
    if path.ends_with('/') {
        return false;
    }

    path.split('/')
        .skip(1)
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn parse_file_permissions(permissions: &str) -> Result<FilePermissions> {
    if permissions.is_empty() {
        return_errno_with_message!(Errno::EINVAL, "AppArmor file permissions are empty");
    }

    let mut parsed = FilePermissions::empty();
    for permission in permissions.bytes() {
        match permission {
            b'r' => parsed.insert(FilePermissions::READ),
            b'w' => parsed.insert(FilePermissions::WRITE),
            _ => {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "AppArmor file permissions contain an unsupported value"
                );
            }
        }
    }

    Ok(parsed)
}
