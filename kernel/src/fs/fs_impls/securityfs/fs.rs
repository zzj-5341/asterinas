// SPDX-License-Identifier: MPL-2.0

use aster_systree::SysNode;
use spin::Once;

use super::{inode::SecurityFsInode, systree_node::SecurityRootNode};
use crate::{
    fs::{
        pseudofs::AnonDeviceId,
        utils::{NAME_MAX, systree_inode::SysTreeInodeTy},
        vfs::{
            file_system::{FileSystem, FsEventSubscriberStats, SuperBlock},
            inode::Inode,
            registry::{FsCreationCtx, FsProperties, FsType},
        },
    },
    prelude::*,
};

/// A file system that exposes security subsystem control interfaces.
pub(super) struct SecurityFs {
    _anon_device_id: AnonDeviceId,
    sb: SuperBlock,
    root: Arc<dyn Inode>,
    fs_event_subscriber_stats: FsEventSubscriberStats,
}

// Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/include/uapi/linux/magic.h>
const SECURITYFS_MAGIC: u64 = 0x7363_6673;
const BLOCK_SIZE: usize = 1024;
static SECURITY_FS: Once<Arc<SecurityFs>> = Once::new();

impl SecurityFs {
    pub(super) fn mount_singleton() -> Result<&'static Arc<Self>> {
        SECURITY_FS.try_call_once(Self::new)
    }

    pub(super) fn singleton() -> &'static Arc<Self> {
        SECURITY_FS
            .get()
            .expect("a securityfs inode exists before its file system")
    }

    fn new() -> Result<Arc<Self>> {
        let anon_device_id = AnonDeviceId::acquire().ok_or_else(|| {
            Error::with_message(Errno::ENOSPC, "no anonymous device ID available")
        })?;
        let sb = SuperBlock::new(SECURITYFS_MAGIC, BLOCK_SIZE, NAME_MAX, anon_device_id.id());
        let root = SecurityFsInode::new_root(SecurityRootNode::new(), &sb);

        Ok(Arc::new(Self {
            _anon_device_id: anon_device_id,
            sb,
            root,
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
        }))
    }
}

impl FileSystem for SecurityFs {
    fn name(&self) -> &'static str {
        "securityfs"
    }

    fn sync(&self) -> Result<()> {
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

pub(super) struct SecurityFsType;

impl FsType for SecurityFsType {
    fn name(&self) -> &'static str {
        "securityfs"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::empty()
    }

    fn create(&self, _fs_creation_ctx: &FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        Ok(SecurityFs::mount_singleton()?.clone())
    }

    fn sysnode(&self) -> Option<Arc<dyn SysNode>> {
        None
    }
}
