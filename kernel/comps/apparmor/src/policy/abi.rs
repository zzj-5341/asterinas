// SPDX-License-Identifier: MPL-2.0

//! Decoder for the frozen AppArmor policy ABI v5 subset.

use alloc::{string::String, vec::Vec};
use core::str;

use aster_core::prelude::*;

use super::{AttachmentMatcher, DecodedPolicy, Profile, ProfileMode, dfa};

pub(super) fn decode(blob: &[u8]) -> Result<DecodedPolicy> {
    if blob.is_empty() {
        return Err(Error::new(Errno::EINVAL));
    }

    let mut cursor = Cursor::new(blob);
    let mut profiles = Vec::new();
    while !cursor.is_eof() {
        decode_header(&mut cursor)?;
        let profile = decode_profile(&mut cursor)?;
        if profiles.len() >= super::MAX_LOADED_PROFILES {
            return Err(Error::new(Errno::ENOSPC));
        }
        profiles
            .try_reserve(1)
            .map_err(|_| Error::new(Errno::ENOMEM))?;
        profiles.push(profile);
    }

    // Charge the serialized input plus derived literal storage and attachment
    // index slots. The input charge conservatively remains after DFA discard.
    let derived = profiles
        .iter()
        .map(|p| {
            p.attachment().map_or(0, |a| a.literal.capacity())
                + size_of::<alloc::sync::Arc<Profile>>()
        })
        .sum::<usize>();
    Ok(DecodedPolicy {
        profiles,
        charge: blob.len().checked_add(derived).ok_or_else(protocol_error)?,
    })
}

fn decode_header(cursor: &mut Cursor<'_>) -> Result<()> {
    if cursor.named_u32(b"version")? != 5 {
        return Err(Error::new(Errno::EPROTONOSUPPORT));
    }
    if cursor.peek_name()? == Some(b"namespace") {
        return Err(unsupported_error());
    }
    Ok(())
}

fn decode_profile(cursor: &mut Cursor<'_>) -> Result<Profile> {
    cursor.named_struct(b"profile")?;
    let name = validate_profile_name(cursor.string()?)?;
    let attachment = decode_attachment(cursor)?;
    let mode = decode_flags(cursor)?;
    if cursor.peek_name()? == Some(b"path_flags") {
        return Err(unsupported_error());
    }
    decode_zero_capabilities(cursor)?;
    decode_zero_caps64(cursor)?;
    if cursor.peek_name()?.is_some() {
        return Err(unsupported_error());
    }
    cursor.expect_code(Code::StructEnd)?;

    Ok(Profile {
        name,
        mode,
        attachment,
    })
}

fn validate_profile_name(raw: &[u8]) -> Result<String> {
    let name = str::from_utf8(raw).map_err(|_| Error::new(Errno::EILSEQ))?;
    if name.starts_with(':') || name.contains("//") {
        return Err(unsupported_error());
    }
    if raw.is_empty()
        || raw.len() > super::MAX_PROFILE_NAME_LEN
        || name.chars().any(char::is_control)
    {
        return Err(Error::new(Errno::EINVAL));
    }

    let mut owned = String::new();
    owned
        .try_reserve_exact(name.len())
        .map_err(|_| Error::new(Errno::ENOMEM))?;
    owned.push_str(name);
    Ok(owned)
}

fn decode_attachment(cursor: &mut Cursor<'_>) -> Result<Option<AttachmentMatcher>> {
    match cursor.peek_name()? {
        Some(b"flags") => Ok(None),
        Some(b"aadfa") => {
            let encoded = cursor.aligned_blob(b"aadfa")?;
            let xmatch_len = cursor.u32()?;
            let literal = dfa::literal_path(encoded, xmatch_len)?;
            Ok(Some(AttachmentMatcher { literal }))
        }
        Some(_) => Err(unsupported_error()),
        None => Err(protocol_error()),
    }
}

fn decode_flags(cursor: &mut Cursor<'_>) -> Result<ProfileMode> {
    cursor.expect_no_named_field_before(b"flags")?;
    cursor.named_struct(b"flags")?;
    let flags = cursor.u32()?;
    let mode = cursor.u32()?;
    let audit = cursor.u32()?;
    cursor.expect_code(Code::StructEnd)?;
    if flags != 0 || audit != 0 {
        return Err(unsupported_error());
    }
    ProfileMode::decode(mode)
}

fn decode_zero_capabilities(cursor: &mut Cursor<'_>) -> Result<()> {
    let mut any = 0;
    for _ in 0..4 {
        any |= cursor.u32()?;
    }
    if any == 0 {
        Ok(())
    } else {
        Err(unsupported_error())
    }
}

fn decode_zero_caps64(cursor: &mut Cursor<'_>) -> Result<()> {
    cursor.expect_no_named_field_before(b"caps64")?;
    cursor.named_struct(b"caps64")?;
    decode_zero_capabilities(cursor)?;
    cursor.expect_code(Code::StructEnd)
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Code {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    U64 = 3,
    Name = 4,
    String = 5,
    Blob = 6,
    Struct = 7,
    StructEnd = 8,
    List = 9,
    ListEnd = 10,
    Array = 11,
    ArrayEnd = 12,
}

impl TryFrom<u8> for Code {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::U8),
            1 => Ok(Self::U16),
            2 => Ok(Self::U32),
            3 => Ok(Self::U64),
            4 => Ok(Self::Name),
            5 => Ok(Self::String),
            6 => Ok(Self::Blob),
            7 => Ok(Self::Struct),
            8 => Ok(Self::StructEnd),
            9 => Ok(Self::List),
            10 => Ok(Self::ListEnd),
            11 => Ok(Self::Array),
            12 => Ok(Self::ArrayEnd),
            _ => Err(protocol_error()),
        }
    }
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or_else(protocol_error)?;
        let bytes = self.bytes.get(self.pos..end).ok_or_else(protocol_error)?;
        self.pos = end;
        Ok(bytes)
    }

    fn code(&mut self) -> Result<Code> {
        Code::try_from(self.take(1)?[0])
    }

    fn u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| protocol_error())?,
        ))
    }

    fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| protocol_error())?,
        ))
    }

    fn chunk16(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16_le()?);
        self.take(len)
    }

    fn name(&mut self) -> Result<&'a [u8]> {
        self.nul_terminated_chunk(Code::Name)
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        self.nul_terminated_chunk(Code::String)
    }

    fn nul_terminated_chunk(&mut self, expected: Code) -> Result<&'a [u8]> {
        self.expect_code(expected)?;
        let chunk = self.chunk16()?;
        let Some((&0, value)) = chunk.split_last() else {
            return Err(protocol_error());
        };
        if value.is_empty() || value.contains(&0) {
            return Err(protocol_error());
        }
        Ok(value)
    }

    fn aligned_blob(&mut self, name: &[u8]) -> Result<&'a [u8]> {
        self.expect_name(name)?;
        self.expect_code(Code::Blob)?;
        let total_len = self.u32_le()? as usize;
        let data_start = self.pos;
        let data_end = data_start
            .checked_add(total_len)
            .ok_or_else(protocol_error)?;
        if data_end > self.bytes.len() {
            return Err(protocol_error());
        }

        // The parser serializes each profile in its own buffer before concatenation,
        // so later profile units may not start at a globally aligned offset. Recover
        // the parser-local padding from `data_end`, matching Linux
        // `security/apparmor/policy_unpack.c::unpack_dfa`; aligning `data_start`
        // directly would reject valid multi-profile streams.
        let rem = data_end & 7;
        let size_before_pad = data_start.checked_sub(rem).ok_or_else(protocol_error)?;
        let pad = (8 - (size_before_pad & 7)) & 7;
        if pad > total_len {
            return Err(protocol_error());
        }

        let data = self.take(total_len)?;
        if data[..pad].iter().any(|byte| *byte != 0) {
            return Err(protocol_error());
        }
        Ok(&data[pad..])
    }

    fn expect_name(&mut self, expected: &[u8]) -> Result<()> {
        if self.name()? == expected {
            Ok(())
        } else {
            Err(unsupported_error())
        }
    }

    fn expect_code(&mut self, expected: Code) -> Result<()> {
        if self.code()? == expected {
            Ok(())
        } else {
            Err(protocol_error())
        }
    }

    fn u32(&mut self) -> Result<u32> {
        self.expect_code(Code::U32)?;
        self.u32_le()
    }

    fn named_u32(&mut self, name: &[u8]) -> Result<u32> {
        self.expect_name(name)?;
        self.u32()
    }

    fn named_struct(&mut self, name: &[u8]) -> Result<()> {
        self.expect_name(name)?;
        self.expect_code(Code::Struct)
    }

    fn peek_name(&self) -> Result<Option<&'a [u8]>> {
        if self.bytes.get(self.pos) != Some(&(Code::Name as u8)) {
            return Ok(None);
        }
        let mut cursor = *self;
        cursor.name().map(Some)
    }

    fn expect_no_named_field_before(&self, expected: &[u8]) -> Result<()> {
        if self.peek_name()?.is_some_and(|actual| actual != expected) {
            Err(unsupported_error())
        } else {
            Ok(())
        }
    }
}

fn protocol_error() -> Error {
    Error::new(Errno::EPROTO)
}

fn unsupported_error() -> Error {
    Error::new(Errno::EOPNOTSUPP)
}

#[cfg(ktest)]
mod tests {
    use alloc::{vec, vec::Vec};

    use aster_core::prelude::{Errno, Result};
    use ostd::prelude::ktest;

    use super::{Profile, decode};

    const MAGIC: u32 = 0x1b5e_783d;

    #[derive(Clone)]
    struct UnitOptions<'a> {
        version: u32,
        mode: u32,
        flags: u32,
        audit: u32,
        low_caps: [u32; 4],
        high_caps: [u32; 4],
        attachment: Option<(&'a [u8], u32)>,
        namespace: bool,
        before_flags: Option<&'a str>,
        path_flags: Option<u32>,
        before_end: Option<&'a str>,
    }

    impl Default for UnitOptions<'_> {
        fn default() -> Self {
            Self {
                version: 5,
                mode: 0,
                flags: 0,
                audit: 0,
                low_caps: [0; 4],
                high_caps: [0; 4],
                attachment: None,
                namespace: false,
                before_flags: None,
                path_flags: None,
                before_end: None,
            }
        }
    }

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

    fn push_named_u32(output: &mut Vec<u8>, name: &str, value: u32) {
        push_name(output, name);
        push_u32(output, value);
    }

    fn push_named_struct(output: &mut Vec<u8>, name: &str) {
        push_name(output, name);
        output.push(7);
    }

    fn minimal_dfa() -> Vec<u8> {
        let blob = include_bytes!(
            "../../../../../test/initramfs/src/regression/security/lsm/apparmor-fixtures/demo.bin"
        );
        let start = find(blob, &MAGIC.to_be_bytes());
        let len = u32::from_be_bytes(blob[start + 8..start + 12].try_into().unwrap()) as usize;
        blob[start..start + len].to_vec()
    }

    fn policy_unit(name: &[u8], options: &UnitOptions<'_>) -> Vec<u8> {
        let mut output = Vec::new();
        push_named_u32(&mut output, "version", options.version);
        if options.namespace {
            push_name(&mut output, "namespace");
            push_chunk(&mut output, 5, b"m1-test");
        }
        push_named_struct(&mut output, "profile");
        push_chunk(&mut output, 5, name);

        if let Some((dfa, xmatch_len)) = options.attachment {
            push_name(&mut output, "aadfa");
            output.push(6);
            let length_offset = output.len();
            output.extend_from_slice(&[0; 4]);
            let padding = (8 - (output.len() & 7)) & 7;
            let total_len = padding + dfa.len();
            output[length_offset..length_offset + 4]
                .copy_from_slice(&(total_len as u32).to_le_bytes());
            output.resize(output.len() + padding, 0);
            output.extend_from_slice(dfa);
            push_u32(&mut output, xmatch_len);
        }

        if let Some(name) = options.before_flags {
            push_named_u32(&mut output, name, 0);
        }
        push_named_struct(&mut output, "flags");
        push_u32(&mut output, options.flags);
        push_u32(&mut output, options.mode);
        push_u32(&mut output, options.audit);
        output.push(8);
        if let Some(path_flags) = options.path_flags {
            push_named_u32(&mut output, "path_flags", path_flags);
        }
        for value in options.low_caps {
            push_u32(&mut output, value);
        }
        push_named_struct(&mut output, "caps64");
        for value in options.high_caps {
            push_u32(&mut output, value);
        }
        output.push(8);
        if let Some(name) = options.before_end {
            push_named_u32(&mut output, name, 0);
        }
        output.push(8);
        output
    }

    fn find(bytes: &[u8], needle: &[u8]) -> usize {
        bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap()
    }

    fn assert_errno<T>(result: Result<T>, expected: Errno) {
        assert_eq!(result.err().unwrap().error(), expected);
    }

    #[ktest]
    fn decodes_minimal_modes_attachment_and_multiple_units() {
        let enforce = policy_unit(b"demo", &UnitOptions::default());
        let decoded = decode(&enforce).unwrap();
        assert_eq!(
            decoded.charge,
            enforce.len() + size_of::<alloc::sync::Arc<Profile>>()
        );
        assert_eq!(decoded.profiles.len(), 1);
        assert_eq!(decoded.profiles[0].name(), "demo");
        assert_eq!(decoded.profiles[0].mode().as_str(), "enforce");
        assert!(decoded.profiles[0].attachment().is_none());

        let complain_options = UnitOptions {
            mode: 1,
            ..Default::default()
        };
        let complain = decode(&policy_unit(b"observe", &complain_options)).unwrap();
        assert_eq!(complain.profiles[0].mode().as_str(), "complain");

        let dfa = minimal_dfa();
        let attachment_options = UnitOptions {
            attachment: Some((&dfa, 13)),
            ..Default::default()
        };
        let attached_blob = policy_unit(b"attached", &attachment_options);
        let attached = decode(&attached_blob).unwrap();
        let matcher = attached.profiles[0].attachment().unwrap();
        assert_eq!(matcher.literal_path(), "/usr/bin/demo");
        assert_eq!(
            attached.charge,
            attached_blob.len() + "/usr/bin/demo".len() + size_of::<alloc::sync::Arc<Profile>>()
        );

        let mut stream = enforce;
        stream.extend_from_slice(&policy_unit(b"observe", &complain_options));
        let decoded = decode(&stream).unwrap();
        assert_eq!(decoded.profiles.len(), 2);
        assert_eq!(decoded.profiles[0].name(), "demo");
        assert_eq!(decoded.profiles[1].name(), "observe");
    }

    #[ktest]
    fn truncation_is_strict_but_complete_unit_boundaries_are_valid() {
        assert_errno(decode(&[]), Errno::EINVAL);

        let first = policy_unit(b"first", &UnitOptions::default());
        for end in 1..first.len() {
            assert_errno(decode(&first[..end]), Errno::EPROTO);
        }

        let second = policy_unit(b"second", &UnitOptions::default());
        let first_len = first.len();
        let mut stream = first;
        stream.extend_from_slice(&second);
        decode(&stream[..first_len]).unwrap();
        for end in first_len + 1..stream.len() {
            assert_errno(decode(&stream[..end]), Errno::EPROTO);
        }
        assert_eq!(decode(&stream).unwrap().profiles.len(), 2);
    }

    #[ktest]
    fn rejects_bad_codes_lengths_nuls_and_trailing_bytes() {
        let valid = policy_unit(b"demo", &UnitOptions::default());

        let mut bytes = valid.clone();
        bytes[0] = 0xff;
        assert_errno(decode(&bytes), Errno::EPROTO);

        let mut bytes = valid.clone();
        bytes[1..3].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_errno(decode(&bytes), Errno::EPROTO);

        let mut bytes = valid.clone();
        bytes[10] = b'x';
        assert_errno(decode(&bytes), Errno::EPROTO);

        let mut bytes = valid.clone();
        bytes[3] = 0;
        assert_errno(decode(&bytes), Errno::EPROTO);

        let mut bytes = valid;
        bytes.push(0);
        assert_errno(decode(&bytes), Errno::EPROTO);
    }

    #[ktest]
    fn distinguishes_unsupported_and_invalid_policy_values() {
        let v7 = UnitOptions {
            version: 7,
            ..Default::default()
        };
        assert_errno(decode(&policy_unit(b"demo", &v7)), Errno::EPROTONOSUPPORT);

        let namespace = UnitOptions {
            namespace: true,
            ..Default::default()
        };
        assert_errno(decode(&policy_unit(b"demo", &namespace)), Errno::EOPNOTSUPP);

        for mode in 2..=4 {
            let options = UnitOptions {
                mode,
                ..Default::default()
            };
            assert_errno(decode(&policy_unit(b"demo", &options)), Errno::EOPNOTSUPP);
        }
        let invalid_mode = UnitOptions {
            mode: 5,
            ..Default::default()
        };
        assert_errno(decode(&policy_unit(b"demo", &invalid_mode)), Errno::EPROTO);

        for options in [
            UnitOptions {
                flags: 1,
                ..Default::default()
            },
            UnitOptions {
                audit: 1,
                ..Default::default()
            },
            UnitOptions {
                low_caps: [1, 0, 0, 0],
                ..Default::default()
            },
            UnitOptions {
                high_caps: [0, 0, 0, 1],
                ..Default::default()
            },
            UnitOptions {
                before_flags: Some("attach"),
                ..Default::default()
            },
            UnitOptions {
                path_flags: Some(1),
                ..Default::default()
            },
            UnitOptions {
                before_end: Some("policydb"),
                ..Default::default()
            },
        ] {
            assert_errno(decode(&policy_unit(b"demo", &options)), Errno::EOPNOTSUPP);
        }
    }

    #[ktest]
    fn validates_profile_names() {
        let max_name = vec![b'a'; 255];
        let decoded = decode(&policy_unit(&max_name, &UnitOptions::default())).unwrap();
        assert_eq!(decoded.profiles[0].name().as_bytes(), max_name.as_slice());

        assert_errno(
            decode(&policy_unit(&[0xff], &UnitOptions::default())),
            Errno::EILSEQ,
        );
        for name in [b":namespace//demo".as_slice(), b"parent//child"] {
            assert_errno(
                decode(&policy_unit(name, &UnitOptions::default())),
                Errno::EOPNOTSUPP,
            );
        }
        assert_errno(
            decode(&policy_unit(b"line\nbreak", &UnitOptions::default())),
            Errno::EINVAL,
        );
        assert_errno(
            decode(&policy_unit(&vec![b'a'; 256], &UnitOptions::default())),
            Errno::EINVAL,
        );
    }

    #[ktest]
    fn enforces_the_per_write_profile_limit() {
        let unit = policy_unit(b"same", &UnitOptions::default());
        let mut stream = Vec::new();
        for _ in 0..super::super::MAX_LOADED_PROFILES {
            stream.extend_from_slice(&unit);
        }

        assert_eq!(
            decode(&stream).unwrap().profiles.len(),
            super::super::MAX_LOADED_PROFILES
        );
        stream.extend_from_slice(&unit);

        assert_errno(decode(&stream), Errno::ENOSPC);
    }

    #[ktest]
    fn decodes_second_attachment_with_unit_relative_alignment() {
        let dfa = minimal_dfa();
        let options = UnitOptions {
            attachment: Some((&dfa, 13)),
            ..Default::default()
        };
        let first = policy_unit(b"first", &options);
        assert_ne!(first.len() & 7, 0);
        let mut stream = first;
        stream.extend_from_slice(&policy_unit(b"second", &options));

        let decoded = decode(&stream).unwrap();
        assert_eq!(decoded.profiles.len(), 2);
        assert_eq!(
            decoded.profiles[1].attachment().unwrap().literal_path(),
            "/usr/bin/demo"
        );
    }

    #[ktest]
    fn rejects_bad_attachment_padding_length_and_dfa() {
        let dfa = minimal_dfa();
        let options = UnitOptions {
            attachment: Some((&dfa, 13)),
            ..Default::default()
        };
        let valid = policy_unit(b"attached", &options);

        let mut bytes = valid.clone();
        let magic = find(&bytes, &MAGIC.to_be_bytes());
        assert!(magic > 0 && bytes[magic - 1] == 0);
        bytes[magic - 1] = 1;
        assert_errno(decode(&bytes), Errno::EPROTO);

        let mut zero_xmatch = UnitOptions {
            attachment: Some((&dfa, 0)),
            ..Default::default()
        };
        assert_errno(
            decode(&policy_unit(b"attached", &zero_xmatch)),
            Errno::EPROTO,
        );

        let mut corrupt_dfa = dfa.clone();
        corrupt_dfa[0] = 0;
        zero_xmatch.attachment = Some((&corrupt_dfa, 4));
        assert_errno(
            decode(&policy_unit(b"attached", &zero_xmatch)),
            Errno::EPROTO,
        );

        let unsupported_perms = UnitOptions {
            attachment: Some((&minimal_dfa(), 13)),
            before_flags: Some("perms"),
            ..Default::default()
        };
        assert_errno(
            decode(&policy_unit(b"attached", &unsupported_perms)),
            Errno::EOPNOTSUPP,
        );
    }
}
