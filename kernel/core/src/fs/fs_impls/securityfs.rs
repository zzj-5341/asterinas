// SPDX-License-Identifier: MPL-2.0

//! The `securityfs` pseudo file system implementation.

use aster_systree::{
    BranchNodeFields, Error as SysTreeError, NormalNodeFields, Result as SysTreeResult,
    SysAttrSetBuilder, SysNode, SysObj, SysPerms, SysStr, inherit_sys_branch_node,
    inherit_sys_leaf_node,
};
use spin::Once;

use crate::{
    fs::{
        file::{InodeMode, InodeType, StatusFlags},
        pseudofs::AnonDeviceId,
        sysfs,
        utils::systree_inode::{SysTreeInodeTy, SysTreeNodeKind},
        vfs::{
            file_system::{FileSystem, FsEventSubscriberStats, SuperBlock},
            inode::{Extension, FileOps, Inode, Metadata},
            registry::{self, FsCreationCtx, FsProperties, FsType},
        },
    },
    prelude::*,
    security::securityfs::WriteCallback,
};

const MAGIC_NUMBER: u64 = 0x7363_6673;
const BLOCK_SIZE: usize = 4096;
const NAME_MAX: usize = 255;

pub(crate) fn register_control_file(
    directory: &'static str,
    file: &'static str,
    perms: SysPerms,
    write: WriteCallback,
) -> crate::Result<()> {
    validate_name(directory)?;
    validate_name(file)?;

    securityfs_root()
        .add_control_directory(ControlDirectory::new(directory, file, perms, write))?;

    *FILESYSTEM_REGISTRATION.call_once(|| {
        registry::register(&SECURITY_FS_TYPE)?;
        sysfs::register_kernel_sysnode(SecurityMountPoint::new())
    })
}

fn validate_name(name: &str) -> crate::Result<()> {
    if name.len() > NAME_MAX {
        return Err(Error::new(Errno::ENAMETOOLONG));
    }
    if name.is_empty() || name.as_bytes().iter().any(|byte| matches!(byte, b'/' | 0)) {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

static FILESYSTEM_REGISTRATION: Once<crate::Result<()>> = Once::new();

fn securityfs_root() -> &'static Arc<SecurityFsRoot> {
    static ROOT: Once<Arc<SecurityFsRoot>> = Once::new();
    ROOT.call_once(SecurityFsRoot::new)
}

#[derive(Debug)]
struct SecurityFsRoot {
    fields: BranchNodeFields<ControlDirectory, Self>,
}

impl SecurityFsRoot {
    fn new() -> Arc<Self> {
        let attrs = SysAttrSetBuilder::new().build().unwrap();
        Arc::new_cyclic(|weak_self| Self {
            fields: BranchNodeFields::new(SysStr::from(""), attrs, weak_self.clone()),
        })
    }

    fn add_control_directory(&self, directory: Arc<ControlDirectory>) -> crate::Result<()> {
        self.fields.add_child(directory)?;
        Ok(())
    }
}

inherit_sys_branch_node!(SecurityFsRoot, fields, {
    fn is_root(&self) -> bool {
        true
    }

    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RO_PERMS
    }
});

#[derive(Debug)]
struct ControlDirectory {
    fields: NormalNodeFields<Self>,
    file: &'static str,
    write: WriteCallback,
}

impl ControlDirectory {
    fn new(
        directory: &'static str,
        file: &'static str,
        perms: SysPerms,
        write: WriteCallback,
    ) -> Arc<Self> {
        let mut builder = SysAttrSetBuilder::new();
        builder.add(SysStr::from(file), perms);
        let attrs = builder.build().unwrap();
        Arc::new_cyclic(|weak_self| Self {
            fields: NormalNodeFields::new(SysStr::from(directory), attrs, weak_self.clone()),
            file,
            write,
        })
    }

    fn write_control(
        &self,
        file: &str,
        offset: usize,
        reader: &mut VmReader,
    ) -> crate::Result<usize> {
        if file != self.file {
            return Err(Error::new(Errno::ENOENT));
        }
        (self.write)(offset, reader)
    }
}

inherit_sys_leaf_node!(ControlDirectory, fields, {
    fn write_attr(&self, name: &str, reader: &mut VmReader) -> SysTreeResult<usize> {
        self.write_control(name, 0, reader)
            .map_err(|_| SysTreeError::AttributeError)
    }

    fn write_attr_at(
        &self,
        name: &str,
        offset: usize,
        reader: &mut VmReader,
    ) -> SysTreeResult<usize> {
        self.write_control(name, offset, reader)
            .map_err(|_| SysTreeError::AttributeError)
    }

    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RO_PERMS
    }
});

#[derive(Debug)]
struct SecurityMountPoint {
    fields: BranchNodeFields<dyn SysNode, Self>,
}

impl SecurityMountPoint {
    fn new() -> Arc<Self> {
        let attrs = SysAttrSetBuilder::new().build().unwrap();
        Arc::new_cyclic(|weak_self| Self {
            fields: BranchNodeFields::new(SysStr::from("security"), attrs, weak_self.clone()),
        })
    }
}

inherit_sys_branch_node!(SecurityMountPoint, fields, {
    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RO_PERMS
    }
});

#[derive(Debug)]
struct SecurityFs {
    _anon_device_id: AnonDeviceId,
    sb: SuperBlock,
    root: Arc<dyn Inode>,
    fs_event_subscriber_stats: FsEventSubscriberStats,
}

impl SecurityFs {
    fn singleton() -> &'static Arc<Self> {
        static SINGLETON: Once<Arc<SecurityFs>> = Once::new();
        SINGLETON.call_once(|| Self::new(securityfs_root().clone()))
    }

    fn new(root: Arc<SecurityFsRoot>) -> Arc<Self> {
        let anon_device_id =
            AnonDeviceId::acquire().expect("no device ID is available for securityfs");
        let sb = SuperBlock::new(MAGIC_NUMBER, BLOCK_SIZE, NAME_MAX, anon_device_id.id());
        let root_inode = SecurityFsInode::new_root(root, &sb);

        Arc::new(Self {
            _anon_device_id: anon_device_id,
            sb,
            root: root_inode,
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
        })
    }
}

impl FileSystem for SecurityFs {
    fn name(&self) -> &'static str {
        "securityfs"
    }

    fn sync(&self) -> crate::Result<()> {
        Ok(())
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn sb(&self) -> SuperBlock {
        self.sb.clone()
    }

    fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        &self.fs_event_subscriber_stats
    }
}

struct SecurityFsType;
static SECURITY_FS_TYPE: SecurityFsType = SecurityFsType;

impl FsType for SecurityFsType {
    type Key = ();

    fn name(&self) -> &'static str {
        "securityfs"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::empty()
    }

    fn create(&self, _fs_creation_ctx: &mut FsCreationCtx) -> crate::Result<Arc<dyn FileSystem>> {
        Ok(SecurityFs::singleton().clone())
    }

    fn sysnode(&self) -> Option<Arc<dyn SysNode>> {
        None
    }
}

struct SecurityFsInode {
    node_kind: SysTreeNodeKind,
    metadata: Metadata,
    extension: Extension,
    mode: RwLock<InodeMode>,
    parent: Weak<SecurityFsInode>,
    this: Weak<SecurityFsInode>,
}

impl SysTreeInodeTy for SecurityFsInode {
    fn new_arc(
        node_kind: SysTreeNodeKind,
        metadata: Metadata,
        mode: InodeMode,
        parent: Weak<Self>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            node_kind,
            metadata,
            extension: Extension::new(),
            mode: RwLock::new(mode),
            parent,
            this: this.clone(),
        })
    }

    fn node_kind(&self) -> &SysTreeNodeKind {
        &self.node_kind
    }

    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn mode(&self) -> crate::Result<InodeMode> {
        Ok(*self.mode.read())
    }

    fn set_mode(&self, mode: InodeMode) -> crate::Result<()> {
        *self.mode.write() = mode;
        Ok(())
    }

    fn extension(&self) -> &Extension {
        &self.extension
    }

    fn parent(&self) -> &Weak<Self> {
        &self.parent
    }

    fn this(&self) -> Arc<Self> {
        self.this.upgrade().expect("invalid weak self reference")
    }
}

impl FileOps for SecurityFsInode {
    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> crate::Result<usize> {
        let SysTreeNodeKind::Attr(attr, node) = self.node_kind() else {
            return Err(Error::new(Errno::EINVAL));
        };

        if let Some(directory) = node.as_any().downcast_ref::<ControlDirectory>() {
            return directory.write_control(attr.name(), offset, reader);
        }

        if offset == 0 {
            Ok(node.write_attr(attr.name(), reader)?)
        } else {
            Ok(node.write_attr_at(attr.name(), offset, reader)?)
        }
    }
}

impl Inode for SecurityFsInode {
    fn fs(&self) -> Arc<dyn FileSystem> {
        SecurityFs::singleton().clone()
    }

    fn create(
        &self,
        _name: &str,
        _type_: InodeType,
        _mode: InodeMode,
    ) -> crate::Result<Arc<dyn Inode>> {
        Err(Error::new(Errno::EPERM))
    }
}

#[cfg(ktest)]
mod test {
    use aster_systree::{SysNode, SysPerms};
    use ostd::prelude::*;

    use super::{ControlDirectory, MAGIC_NUMBER, NAME_MAX, SecurityFsInode, SecurityFsRoot};
    use crate::{
        fs::{
            file::StatusFlags,
            pseudofs::AnonDeviceId,
            utils::systree_inode::SysTreeInodeTy,
            vfs::{file_system::SuperBlock, inode::FileOps},
        },
        prelude::*,
        time::clocks::init_for_ktest as time_init_for_ktest,
    };

    fn fail_write(_offset: usize, _reader: &mut VmReader) -> crate::Result<usize> {
        Err(Error::new(Errno::EPROTO))
    }

    #[ktest]
    fn control_write_preserves_callback_errno() {
        time_init_for_ktest();
        let directory = ControlDirectory::new("apparmor", ".load", SysPerms::OWNER_W, fail_write);
        let attr = directory.node_attrs().get(".load").unwrap().clone();
        let device_id = AnonDeviceId::acquire().unwrap();
        let sb = SuperBlock::new(MAGIC_NUMBER, 4096, NAME_MAX, device_id.id());
        let inode = SecurityFsInode::new_attr(attr, directory, Weak::new(), &sb);
        let mut reader = VmReader::from(b"blob".as_slice()).to_fallible();

        let error =
            FileOps::write_at(inode.as_ref(), 0, &mut reader, StatusFlags::empty()).unwrap_err();

        assert_eq!(error.error(), Errno::EPROTO);
    }

    #[ktest]
    fn duplicate_control_directory_is_rejected() {
        let root = SecurityFsRoot::new();
        root.add_control_directory(ControlDirectory::new(
            "apparmor",
            ".load",
            SysPerms::OWNER_W,
            fail_write,
        ))
        .unwrap();

        let error = root
            .add_control_directory(ControlDirectory::new(
                "apparmor",
                ".load",
                SysPerms::OWNER_W,
                fail_write,
            ))
            .unwrap_err();

        assert_eq!(error.error(), Errno::EEXIST);
    }
}
