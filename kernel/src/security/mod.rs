// SPDX-License-Identifier: MPL-2.0

pub mod lsm;

use cfg_if::cfg_if;

use crate::{
    fs::{
        file::{AccessMode, CreationFlags, StatusFlags},
        vfs::path::{Path, PathResolver},
    },
    prelude::*,
};

cfg_if! {
    if #[cfg(all(target_arch = "x86_64", feature = "cvm_guest"))] {
        mod tsm;
        mod tsm_mr;
    }
}

pub(super) fn init() {
    lsm::init();

    #[cfg(target_arch = "x86_64")]
    ostd::if_tdx_enabled!({
        tsm::init();
        tsm_mr::init();
    });
}

/// Runs the LSM stack for a file open check.
pub(crate) fn file_open(
    path: &Path,
    path_resolver: &PathResolver,
    access_mode: AccessMode,
    creation_flags: CreationFlags,
    status_flags: StatusFlags,
) -> Result<()> {
    lsm::hooks::on_file_open(&lsm::hooks::FileOpenContext::new(
        path,
        path_resolver,
        access_mode,
        creation_flags,
        status_flags,
    ))
}

/// Runs the LSM stack before opening a child that will be created.
pub(crate) fn file_open_child(
    parent: &Path,
    name: &str,
    path_resolver: &PathResolver,
    access_mode: AccessMode,
    creation_flags: CreationFlags,
    status_flags: StatusFlags,
) -> Result<()> {
    lsm::hooks::on_file_open(&lsm::hooks::FileOpenContext::new_child(
        parent,
        name,
        path_resolver,
        access_mode,
        creation_flags,
        status_flags,
    ))
}

/// Runs the LSM stack before opening an unnamed temporary file.
pub(crate) fn file_open_tmpfile(
    parent: &Path,
    path_resolver: &PathResolver,
    access_mode: AccessMode,
    creation_flags: CreationFlags,
    status_flags: StatusFlags,
) -> Result<()> {
    lsm::hooks::on_file_open(&lsm::hooks::FileOpenContext::new_anonymous_child(
        parent,
        path_resolver,
        access_mode,
        creation_flags,
        status_flags,
    ))
}
