// SPDX-License-Identifier: MPL-2.0

//! AppArmor policy loading through `securityfs`.

use alloc::vec::Vec;

use aster_core::{
    Errno, Error, Result,
    security::{self, securityfs::SysPerms},
};
use ostd::mm::{FallibleVmRead, VmReader, VmWriter};

use super::POLICY_STORE;

// ponytail: 1 MiB single-write ceiling; raise it or add streamed buffering when real policies require it.
const MAX_POLICY_SIZE: usize = 1024 * 1024;
const CAP_MAC_ADMIN: u8 = 33;

pub(super) fn register() -> Result<()> {
    security::securityfs::register_control_file("apparmor", ".load", SysPerms::OWNER_W, load)
}

fn load(offset: usize, reader: &mut VmReader) -> Result<usize> {
    security::require_current_capability(CAP_MAC_ADMIN)?;

    let size = reader.remain();
    validate_load(offset, size)?;

    let mut blob = Vec::new();
    blob.try_reserve_exact(size)
        .map_err(|_| Error::new(Errno::ENOMEM))?;
    blob.resize(size, 0);
    reader.read_fallible(&mut VmWriter::from(blob.as_mut_slice()))?;

    POLICY_STORE.load(&blob)?;
    Ok(size)
}

fn validate_load(offset: usize, size: usize) -> Result<()> {
    if offset != 0 || size == 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    if size > MAX_POLICY_SIZE {
        return Err(Error::new(Errno::E2BIG));
    }
    Ok(())
}

#[cfg(ktest)]
mod test {
    use aster_core::Errno;
    use ostd::prelude::ktest;

    use super::{MAX_POLICY_SIZE, validate_load};

    #[ktest]
    fn load_rejects_offset_empty_and_oversized_input() {
        assert_eq!(validate_load(1, 1).unwrap_err().error(), Errno::EINVAL);
        assert_eq!(validate_load(0, 0).unwrap_err().error(), Errno::EINVAL);
        assert_eq!(
            validate_load(0, MAX_POLICY_SIZE + 1).unwrap_err().error(),
            Errno::E2BIG
        );
        assert!(validate_load(0, MAX_POLICY_SIZE).is_ok());
    }
}
