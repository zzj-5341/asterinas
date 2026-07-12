// SPDX-License-Identifier: MPL-2.0

//! File privilege invalidation after inode mutations.
//!
//! The rules mirror Linux `file_remove_privs()` and `cap_inode_killpriv()`:
//! <https://github.com/torvalds/linux/blob/master/fs/inode.c> and
//! <https://github.com/torvalds/linux/blob/master/security/commoncap.c>.

use crate::{
    fs::{
        file::{InodeMode, InodeType},
        vfs::{
            inode::Inode,
            xattr::{SECURITY_CAPABILITY_XATTR_NAME, XattrName},
        },
    },
    prelude::*,
    process::{credentials::capabilities::CapSet, posix_thread::AsPosixThread},
};

/// Clears file privileges invalidated by a content modification.
///
/// Linux conditionally clears `S_ISGID` only for group-executable files;
/// see `file_remove_privs()` in the source cited by this module.
pub fn invalidate_for_content_change(inode: &dyn Inode) -> Result<()> {
    if inode.type_() != InodeType::File {
        return Ok(());
    }

    remove_file_capabilities(inode)?;

    let current_thread = current_thread!();
    if current_thread
        .as_posix_thread()
        .is_some_and(|posix_thread| {
            posix_thread
                .credentials()
                .effective_capset()
                .contains(CapSet::FSETID)
        })
    {
        return Ok(());
    }

    let mode = inode.mode()?;
    let mut bits_to_clear = mode & InodeMode::S_ISUID;
    if mode.contains(InodeMode::S_IXGRP) {
        bits_to_clear |= mode & InodeMode::S_ISGID;
    }
    clear_mode_bits(inode, mode, bits_to_clear)
}

/// Clears file privileges invalidated by an ownership change.
///
/// This follows the `chown(2)` ownership-change rules for set-ID bits and
/// removes `security.capability` through the same capability hook as Linux.
pub fn invalidate_for_ownership_change(inode: &dyn Inode) -> Result<()> {
    if inode.type_() != InodeType::File {
        return Ok(());
    }

    remove_file_capabilities(inode)?;

    let mode = inode.mode()?;
    let mut bits_to_clear = mode & InodeMode::S_ISUID;
    if mode.contains(InodeMode::S_IXGRP) {
        bits_to_clear |= mode & InodeMode::S_ISGID;
    }
    clear_mode_bits(inode, mode, bits_to_clear)
}

fn remove_file_capabilities(inode: &dyn Inode) -> Result<()> {
    let xattr_name = XattrName::try_from_full_name(SECURITY_CAPABILITY_XATTR_NAME)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "invalid file capability xattr name"))?;

    match inode.remove_xattr(xattr_name) {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.error(), Errno::ENODATA | Errno::EOPNOTSUPP) => Ok(()),
        Err(error) => Err(error),
    }
}

fn clear_mode_bits(inode: &dyn Inode, mut mode: InodeMode, bits_to_clear: InodeMode) -> Result<()> {
    if bits_to_clear.is_empty() {
        return Ok(());
    }

    mode.remove(bits_to_clear);
    inode.set_mode(mode)
}
