// SPDX-License-Identifier: MPL-2.0

//! AppArmor securityfs control plane.

use aster_systree::{
    BranchNodeFields, Error as SysTreeError, MAX_ATTR_SIZE, Result as SysTreeResult,
    SysAttrSetBuilder, SysObj, SysPerms, SysStr, inherit_sys_branch_node,
};
use aster_util::printer::VmPrinter;

use crate::{
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet, posix_thread::AsPosixThread},
    security::lsm::hooks as lsm_hooks,
    thread::Thread,
};

#[derive(Debug)]
struct AppArmorNode {
    fields: BranchNodeFields<dyn SysObj, Self>,
}

pub(super) fn new_node() -> Arc<dyn SysObj> {
    let mut attrs = SysAttrSetBuilder::new();
    attrs.add(SysStr::from(".load"), SysPerms::from_bits_retain(0o0200));
    attrs.add(SysStr::from("profiles"), SysPerms::DEFAULT_RO_ATTR_PERMS);
    let attrs = attrs.build().unwrap();

    Arc::new_cyclic(|weak_self| AppArmorNode {
        fields: BranchNodeFields::new(SysStr::from("apparmor"), attrs, weak_self.clone()),
    })
}

inherit_sys_branch_node!(AppArmorNode, fields, {
    fn read_attr_at(
        &self,
        name: &str,
        offset: usize,
        writer: &mut VmWriter,
    ) -> SysTreeResult<usize> {
        if name != "profiles" {
            return Err(SysTreeError::PermissionDenied);
        }

        let profile_names = super::policy::loaded_profile_names();
        let mut printer = VmPrinter::new_skip(writer, offset);
        for profile_name in profile_names {
            writeln!(printer, "{} (enforce)", profile_name)?;
        }

        Ok(printer.bytes_written())
    }

    fn write_attr(&self, name: &str, reader: &mut VmReader) -> SysTreeResult<usize> {
        if name != ".load" {
            return Err(SysTreeError::PermissionDenied);
        }
        ensure_current_task_can_manage_policy()?;

        let (policy_text, read_len) = read_text(reader, MAX_ATTR_SIZE)?;
        super::policy::load_profile(&policy_text).map_err(|_| SysTreeError::InvalidOperation)?;

        Ok(read_len)
    }

    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RO_PERMS
    }
});

fn ensure_current_task_can_manage_policy() -> SysTreeResult<()> {
    let thread = Thread::current().ok_or(SysTreeError::PermissionDenied)?;
    let posix_thread = thread
        .as_posix_thread()
        .ok_or(SysTreeError::PermissionDenied)?;

    // Asterinas cannot create user namespaces yet, so the initial namespace is
    // also the only namespace in which policy-management capability can exist.
    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        UserNamespace::get_init_singleton().as_ref(),
        posix_thread,
        CapSet::MAC_ADMIN,
    ))
    .map_err(|_| SysTreeError::PermissionDenied)
}

fn read_text(reader: &mut VmReader, max_len: usize) -> SysTreeResult<(String, usize)> {
    let read_len = reader.remain();
    if read_len == 0 || read_len > max_len {
        return Err(SysTreeError::InvalidOperation);
    }

    let mut bytes = vec![0u8; read_len];
    let mut writer = VmWriter::from(bytes.as_mut_slice());
    let copied = reader
        .read_fallible(&mut writer)
        .map_err(|_| SysTreeError::PageFault)?;
    if copied != read_len || bytes.contains(&0) {
        return Err(SysTreeError::InvalidOperation);
    }

    let text = core::str::from_utf8(&bytes).map_err(|_| SysTreeError::InvalidOperation)?;
    Ok((text.to_string(), read_len))
}
