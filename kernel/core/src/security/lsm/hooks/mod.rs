// SPDX-License-Identifier: MPL-2.0

//! LSM hook points.

mod alien_access;
mod capability;

pub use self::{alien_access::AlienAccessContext, capability::CapabilityContext};
pub(crate) use self::{
    alien_access::on_alien_access,
    capability::{CapableContext, on_capable},
};
