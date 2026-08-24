// SPDX-License-Identifier: MPL-2.0

//! Public registration interface for `securityfs` control files.

pub use aster_systree::SysPerms;
use ostd::mm::VmReader;

/// A securityfs control-file write callback.
pub type WriteCallback = fn(offset: usize, reader: &mut VmReader) -> crate::Result<usize>;

/// Registers one named securityfs directory containing one control file.
pub fn register_control_file(
    directory: &'static str,
    file: &'static str,
    perms: SysPerms,
    write: WriteCallback,
) -> crate::Result<()> {
    crate::fs::securityfs::register_control_file(directory, file, perms, write)
}
