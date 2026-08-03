// SPDX-License-Identifier: MPL-2.0

//! AppArmor file mediation.

use super::{
    label,
    policy::{self, FilePermissions},
};
use crate::{
    fs::{
        file::{CreationFlags, StatusFlags},
        vfs::path::AbsPathResult,
    },
    prelude::*,
    security::lsm::hooks::FileOpenContext,
};

pub(super) fn open(context: &FileOpenContext<'_>) -> Result<()> {
    if context.status_flags().contains(StatusFlags::O_PATH) {
        return Ok(());
    }

    let mut requested = FilePermissions::empty();
    if context.access_mode().is_readable() {
        requested.insert(FilePermissions::READ);
    }
    if context.access_mode().is_writable() {
        requested.insert(FilePermissions::WRITE);
    }
    if context.creation_flags().contains(CreationFlags::O_TRUNC) {
        requested.insert(FilePermissions::WRITE);
    }
    if context.creates_file() {
        requested.insert(FilePermissions::WRITE);
    }

    check_access(context, requested)
}

fn check_access(context: &FileOpenContext<'_>, requested: FilePermissions) -> Result<()> {
    let Some(label) = label::current_label() else {
        return Ok(());
    };
    if requested.is_empty() {
        return Ok(());
    }

    let path_name = match context.resolve_path_name() {
        AbsPathResult::Reachable(path_name) => path_name,
        AbsPathResult::Unreachable(_) => {
            return Err(Error::with_message(
                Errno::EACCES,
                "AppArmor denied file open",
            ));
        }
    };

    if !policy::allows_file(label.profile_name(), &path_name, requested) {
        return Err(Error::with_message(
            Errno::EACCES,
            "AppArmor denied file open",
        ));
    }

    Ok(())
}
