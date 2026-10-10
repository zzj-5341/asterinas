// SPDX-License-Identifier: MPL-2.0

//! Decoding and validation of AppArmor policies.

use alloc::{boxed::Box, string::String, vec::Vec};

use aster_core::prelude::*;

mod abi;
mod dfa;

pub(super) const MAX_LOADED_PROFILES: usize = 1024;
pub(super) const MAX_PROFILE_NAME_LEN: usize = 255;

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

#[derive(Debug)]
pub(crate) struct AttachmentMatcher {
    encoded_dfa: Box<[u8]>,
    xmatch_len: u32,
}

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
    attachment: Option<AttachmentMatcher>,
}

impl Profile {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn mode(&self) -> ProfileMode {
        self.mode
    }

    pub(crate) fn attachment(&self) -> Option<&AttachmentMatcher> {
        self.attachment.as_ref()
    }
}

#[derive(Debug)]
pub(super) struct DecodedPolicy {
    profiles: Vec<Profile>,
    charge: usize,
}
