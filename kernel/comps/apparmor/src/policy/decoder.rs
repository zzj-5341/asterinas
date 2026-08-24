// SPDX-License-Identifier: MPL-2.0

//! Decoder for the capability-only AppArmor policy ABI used by M1.
//!
//! The outer stream follows AppArmor 5.0.2's
//! [`sd_serialize_profile`](https://gitlab.com/apparmor/apparmor/-/blob/v5.0.2/parser/parser_interface.c).

use alloc::{string::String, sync::Arc, vec::Vec};

use aster_core::{Errno, Error, Result};

use super::{PolicySnapshot, Profile, ProfileMode};

mod dfa;

const U32: u8 = 2;
const NAME: u8 = 4;
const STRING: u8 = 5;
const BLOB: u8 = 6;
const STRUCT: u8 = 7;
const STRUCT_END: u8 = 8;
const VERSION: u32 = 5;

pub(super) fn decode(bytes: &[u8]) -> Result<Arc<PolicySnapshot>> {
    let mut cursor = Cursor::new(bytes);
    let mut profiles = Vec::new();

    while !cursor.is_empty() {
        profiles
            .try_reserve_exact(1)
            .map_err(|_| Error::new(Errno::ENOMEM))?;
        profiles.push(decode_profile(&mut cursor)?);
    }
    if profiles.is_empty() {
        return Err(Error::new(Errno::EPROTO));
    }

    profiles.sort_unstable_by(|left, right| left.attachment.cmp(&right.attachment));
    if profiles
        .windows(2)
        .any(|profiles| profiles[0].attachment == profiles[1].attachment)
    {
        return Err(Error::new(Errno::EEXIST));
    }

    Arc::try_new(PolicySnapshot { profiles }).map_err(|_| Error::new(Errno::ENOMEM))
}

fn decode_profile(cursor: &mut Cursor<'_>) -> Result<Arc<Profile>> {
    if cursor.named_u32("version")? != VERSION {
        return Err(Error::new(Errno::EPROTO));
    }
    cursor.named_struct("profile")?;
    let attachment = cursor.string()?;
    if attachment.len() <= 1
        || !attachment.starts_with('/')
        || !attachment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(Error::new(Errno::EPROTO));
    }
    dfa::validate_literal(cursor.named_blob("aadfa")?, attachment.as_bytes())?;
    if cursor.u32()? as usize != attachment.len() {
        return Err(Error::new(Errno::EPROTO));
    }

    cursor.named_struct("flags")?;
    if cursor.u32()? != 0 {
        return Err(Error::new(Errno::EPROTO));
    }
    let mode = match cursor.u32()? {
        0 => ProfileMode::Enforce,
        1 => ProfileMode::Complain,
        _ => return Err(Error::new(Errno::EPROTO)),
    };
    if cursor.u32()? != 0 {
        return Err(Error::new(Errno::EPROTO));
    }
    cursor.struct_end()?;

    let low_allow = cursor.u32()?;
    let _low_audit = cursor.u32()?;
    let _low_quiet = cursor.u32()?;
    if cursor.u32()? != 0 {
        return Err(Error::new(Errno::EPROTO));
    }

    cursor.named_struct("caps64")?;
    let high_allow = cursor.u32()?;
    let _high_audit = cursor.u32()?;
    let _high_quiet = cursor.u32()?;
    if cursor.u32()? != 0 {
        return Err(Error::new(Errno::EPROTO));
    }
    cursor.struct_end()?;

    cursor.struct_end()?;

    Arc::try_new(Profile {
        attachment,
        mode,
        allowed_capabilities: u64::from(low_allow) | (u64::from(high_allow) << 32),
    })
    .map_err(|_| Error::new(Errno::ENOMEM))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| Error::new(Errno::EPROTO))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| Error::new(Errno::EPROTO))?;
        self.position = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or_else(|| Error::new(Errno::EPROTO))?)
    }

    fn expect(&mut self, code: u8) -> Result<()> {
        if self.byte()? != code {
            return Err(Error::new(Errno::EPROTO));
        }
        Ok(())
    }

    fn raw_u16(&mut self) -> Result<u16> {
        let bytes = self
            .take(2)?
            .try_into()
            .map_err(|_| Error::new(Errno::EPROTO))?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn raw_u32(&mut self) -> Result<u32> {
        let bytes = self
            .take(4)?
            .try_into()
            .map_err(|_| Error::new(Errno::EPROTO))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn nul_terminated_bytes(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.raw_u16()?);
        let bytes = self.take(length)?;
        let (terminator, value) = bytes
            .split_last()
            .ok_or_else(|| Error::new(Errno::EPROTO))?;
        if *terminator != 0 || value.contains(&0) {
            return Err(Error::new(Errno::EPROTO));
        }
        Ok(value)
    }

    fn name(&mut self, expected: &str) -> Result<()> {
        self.expect(NAME)?;
        if self.nul_terminated_bytes()? != expected.as_bytes() {
            return Err(Error::new(Errno::EPROTO));
        }
        Ok(())
    }

    fn named_u32(&mut self, name: &str) -> Result<u32> {
        self.name(name)?;
        self.u32()
    }

    fn u32(&mut self) -> Result<u32> {
        self.expect(U32)?;
        self.raw_u32()
    }

    fn named_struct(&mut self, name: &str) -> Result<()> {
        self.name(name)?;
        self.expect(STRUCT)
    }

    fn string(&mut self) -> Result<String> {
        self.expect(STRING)?;
        let bytes = self.nul_terminated_bytes()?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::new(Errno::ENOMEM))?;
        owned.extend_from_slice(bytes);
        String::from_utf8(owned).map_err(|_| Error::new(Errno::EPROTO))
    }

    fn named_blob(&mut self, name: &str) -> Result<&'a [u8]> {
        self.name(name)?;
        self.expect(BLOB)?;
        let length = usize::try_from(self.raw_u32()?).map_err(|_| Error::new(Errno::EPROTO))?;
        self.take(length)
    }

    fn struct_end(&mut self) -> Result<()> {
        self.expect(STRUCT_END)
    }
}

#[cfg(ktest)]
mod test {
    use alloc::{vec, vec::Vec};

    use aster_core::Errno;
    use ostd::prelude::ktest;

    use super::{
        super::{PolicyStore, ProfileMode},
        decode,
    };

    const U32: u8 = 2;
    const NAME: u8 = 4;
    const STRING: u8 = 5;
    const BLOB: u8 = 6;
    const STRUCT: u8 = 7;
    const STRUCT_END: u8 = 8;
    const VERSION: u32 = 5;
    const DFA_MAGIC: u32 = 0x1b5e_783d;
    const DFA_HEADER_SIZE: usize = 24;

    struct Serializer(Vec<u8>);

    impl Serializer {
        fn new() -> Self {
            Self(Vec::new())
        }

        fn name(&mut self, name: &str) {
            self.0.push(NAME);
            self.string_body(name);
        }

        fn string_body(&mut self, value: &str) {
            let length = u16::try_from(value.len() + 1).unwrap();
            self.0.extend_from_slice(&length.to_le_bytes());
            self.0.extend_from_slice(value.as_bytes());
            self.0.push(0);
        }

        fn named_u32(&mut self, name: &str, value: u32) {
            self.name(name);
            self.u32(value);
        }

        fn u32(&mut self, value: u32) {
            self.0.push(U32);
            self.0.extend_from_slice(&value.to_le_bytes());
        }

        fn named_struct(&mut self, name: &str) {
            self.name(name);
            self.0.push(STRUCT);
        }

        fn string(&mut self, value: &str) {
            self.0.push(STRING);
            self.string_body(value);
        }

        fn named_blob(&mut self, name: &str, value: &[u8]) {
            self.name(name);
            self.0.push(BLOB);
            self.0
                .extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
            self.0.extend_from_slice(value);
        }

        fn attachment_dfa(&mut self, attachment: &str) {
            self.name("aadfa");
            self.0.push(BLOB);
            let length_offset = self.0.len();
            self.0.extend_from_slice(&0_u32.to_le_bytes());
            let value_offset = self.0.len();
            while !self.0.len().is_multiple_of(8) {
                self.0.push(0);
            }
            self.0
                .extend_from_slice(&literal_dfa(attachment.as_bytes()));
            let length = u32::try_from(self.0.len() - value_offset).unwrap();
            self.0[length_offset..length_offset + 4].copy_from_slice(&length.to_le_bytes());
        }

        fn profile(&mut self, attachment: &str, mode: u32, low_allow: u32, high_allow: u32) {
            self.profile_with_fields(attachment, 0, mode, 0, low_allow, high_allow, 0, 0, false);
        }

        #[expect(clippy::too_many_arguments)]
        fn profile_with_fields(
            &mut self,
            attachment: &str,
            profile_flags: u32,
            mode: u32,
            audit_flags: u32,
            low_allow: u32,
            high_allow: u32,
            low_reserved: u32,
            high_reserved: u32,
            include_policydb: bool,
        ) {
            self.named_u32("version", VERSION);
            self.named_struct("profile");
            self.string(attachment);
            self.attachment_dfa(attachment);
            self.u32(u32::try_from(attachment.len()).unwrap());
            self.named_struct("flags");
            self.u32(profile_flags);
            self.u32(mode);
            self.u32(audit_flags);
            self.0.push(STRUCT_END);
            self.u32(low_allow);
            self.u32(0);
            self.u32(0);
            self.u32(low_reserved);
            self.named_struct("caps64");
            self.u32(high_allow);
            self.u32(0);
            self.u32(0);
            self.u32(high_reserved);
            self.0.push(STRUCT_END);
            if include_policydb {
                self.named_struct("policydb");
                self.named_blob("aadfa", b"policydb");
                self.0.push(STRUCT_END);
            }
            self.0.push(STRUCT_END);
        }

        fn finish(self) -> Vec<u8> {
            self.0
        }
    }

    fn literal_dfa(attachment: &[u8]) -> Vec<u8> {
        let state_count = attachment.len() + 2;
        let mut accept = vec![0; state_count];
        let accept2 = vec![0; state_count];
        let mut base = vec![0; state_count];
        let default = vec![0; state_count];
        let mut positions = Vec::new();
        let mut used = vec![false; 256 + attachment.len()];
        let mut max_base = 0;

        accept[state_count - 1] = 1;
        for (index, byte) in attachment.iter().copied().enumerate() {
            let table_base = (0..=attachment.len())
                .find(|base| !used[base + usize::from(byte)])
                .unwrap();
            let position = table_base + usize::from(byte);
            used[position] = true;
            base[index + 1] = u32::try_from(table_base).unwrap();
            max_base = max_base.max(table_base);
            positions.push((position, index + 1));
        }

        let transition_count = 256 + max_base;
        let mut next = vec![0; transition_count];
        let mut check = vec![0; transition_count];
        for (position, state) in positions {
            next[position] = u32::try_from(state + 1).unwrap();
            check[position] = u32::try_from(state).unwrap();
        }

        let mut dfa = Vec::new();
        dfa.extend_from_slice(&DFA_MAGIC.to_be_bytes());
        dfa.extend_from_slice(&u32::try_from(DFA_HEADER_SIZE).unwrap().to_be_bytes());
        dfa.extend_from_slice(&0_u32.to_be_bytes());
        dfa.extend_from_slice(&0_u16.to_be_bytes());
        dfa.extend_from_slice(b"notflex\0");
        dfa.extend_from_slice(&[0, 0]);
        dfa_table(&mut dfa, 1, 4, &accept);
        dfa_table(&mut dfa, 7, 4, &accept2);
        dfa_table(&mut dfa, 2, 4, &base);
        dfa_table(&mut dfa, 4, 2, &default);
        dfa_table(&mut dfa, 8, 2, &next);
        dfa_table(&mut dfa, 3, 2, &check);
        let size = u32::try_from(dfa.len()).unwrap().to_be_bytes();
        dfa[8..12].copy_from_slice(&size);
        dfa
    }

    fn dfa_table(bytes: &mut Vec<u8>, id: u16, width: u16, values: &[u32]) {
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(values.len()).unwrap().to_be_bytes());
        for value in values {
            match width {
                2 => bytes.extend_from_slice(&u16::try_from(*value).unwrap().to_be_bytes()),
                4 => bytes.extend_from_slice(&value.to_be_bytes()),
                _ => unreachable!(),
            }
        }
        while !bytes.len().is_multiple_of(8) {
            bytes.push(0);
        }
    }

    fn valid_blob() -> Vec<u8> {
        let mut serializer = Serializer::new();
        serializer.profile("/test/complain", 1, 0x0000_0002, 0x8000_0000);
        serializer.profile("/test/enforce", 0, 0x0000_0001, 0x4000_0000);
        serializer.finish()
    }

    fn assert_eproto(blob: &[u8]) {
        assert_eq!(decode(blob).err().unwrap().error(), Errno::EPROTO);
    }

    #[ktest]
    fn decodes_multiple_enforce_and_complain_profiles() {
        let snapshot = decode(&valid_blob()).unwrap();

        assert_eq!(snapshot.profiles.len(), 2);
        assert_eq!(snapshot.profiles[0].attachment, "/test/complain");
        assert_eq!(snapshot.profiles[0].mode, ProfileMode::Complain);
        assert_eq!(
            snapshot.profiles[0].allowed_capabilities,
            0x8000_0000_0000_0002
        );
        assert_eq!(snapshot.profiles[1].attachment, "/test/enforce");
        assert_eq!(snapshot.profiles[1].mode, ProfileMode::Enforce);
        assert_eq!(
            snapshot.profiles[1].allowed_capabilities,
            0x4000_0000_0000_0001
        );
        assert!(snapshot.profile_for_exec(b"/test/enforce").is_some());
        assert!(snapshot.profile_for_exec(&[0xff]).is_none());
    }

    #[ktest]
    fn rejects_every_truncation_of_a_valid_stream() {
        let mut serializer = Serializer::new();
        serializer.profile("/test/enforce", 0, 1, 0);
        let blob = serializer.finish();

        for length in 0..blob.len() {
            assert_eproto(&blob[..length]);
        }
    }

    #[ktest]
    fn rejects_unknown_types_names_modes_and_trailing_bytes() {
        let mut unknown_type = valid_blob();
        unknown_type[0] = 0xff;
        assert_eproto(&unknown_type);

        let mut unknown_name = valid_blob();
        let version = unknown_name
            .windows(b"version\0".len())
            .position(|bytes| bytes == b"version\0")
            .unwrap();
        unknown_name[version] = b'V';
        assert_eproto(&unknown_name);

        let mut invalid_mode = Serializer::new();
        invalid_mode.profile("/test/enforce", 2, 0, 0);
        assert_eproto(&invalid_mode.finish());

        let mut invalid_version = valid_blob();
        let version_value = invalid_version
            .windows(b"version\0".len())
            .position(|bytes| bytes == b"version\0")
            .unwrap()
            + b"version\0".len()
            + 1;
        invalid_version[version_value] ^= 1;
        assert_eproto(&invalid_version);

        let mut malformed_string = valid_blob();
        let terminator = malformed_string
            .windows(b"/test/complain\0".len())
            .position(|bytes| bytes == b"/test/complain\0")
            .unwrap()
            + b"/test/complain".len();
        malformed_string[terminator] = b'x';
        assert_eproto(&malformed_string);

        for fields in [(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)] {
            let mut reserved = Serializer::new();
            reserved.profile_with_fields(
                "/test/enforce",
                fields.0,
                0,
                fields.1,
                0,
                0,
                fields.2,
                fields.3,
                false,
            );
            assert_eproto(&reserved.finish());
        }

        let mut trailing = valid_blob();
        trailing.push(0);
        assert_eproto(&trailing);
    }

    #[ktest]
    fn rejects_policydb_outside_the_m1_subset() {
        let mut serializer = Serializer::new();
        serializer.profile_with_fields("/test/enforce", 0, 0, 0, 0, 0, 0, 0, true);

        assert_eproto(&serializer.finish());
    }

    #[ktest]
    fn rejects_malformed_attachment_dfa() {
        let mut malformed = valid_blob();
        let version = malformed
            .windows(b"notflex".len())
            .position(|bytes| bytes == b"notflex")
            .unwrap();
        malformed[version] ^= 1;

        assert_eproto(&malformed);
    }

    #[ktest]
    fn rejects_relative_and_duplicate_attachments() {
        let mut relative = Serializer::new();
        relative.profile("test/enforce", 0, 0, 0);
        assert_eproto(&relative.finish());

        let mut pattern = Serializer::new();
        pattern.profile("/test/*", 0, 0, 0);
        assert_eproto(&pattern.finish());

        let mut duplicate = Serializer::new();
        duplicate.profile("/test/enforce", 0, 0, 0);
        duplicate.profile("/test/enforce", 1, 0, 0);
        assert_eq!(
            decode(&duplicate.finish()).err().unwrap().error(),
            Errno::EEXIST
        );
    }

    #[ktest]
    fn failed_load_does_not_publish_a_snapshot() {
        let store = PolicyStore::new();

        assert_eq!(store.load(&[0]).unwrap_err().error(), Errno::EPROTO);
        assert!(store.snapshot().is_none());
        store.load(&valid_blob()).unwrap();
        assert!(store.snapshot().is_some());
    }

    #[ktest]
    fn second_successful_load_returns_eexist() {
        let store = PolicyStore::new();
        store.load(&valid_blob()).unwrap();

        assert_eq!(
            store.load(&valid_blob()).unwrap_err().error(),
            Errno::EEXIST
        );
    }
}
