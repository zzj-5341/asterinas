// SPDX-License-Identifier: MPL-2.0

use super::fs::SecurityFs;
use crate::{
    fs::{
        file::InodeMode,
        utils::systree_inode::{SysTreeInodeTy, SysTreeNodeKind},
        vfs::{
            file_system::FileSystem,
            inode::{Extension, Inode, Metadata},
        },
    },
    prelude::*,
};

/// An inode backed by a security subsystem `SysTree` node.
pub(super) struct SecurityFsInode {
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

    fn mode(&self) -> Result<InodeMode> {
        Ok(*self.mode.read())
    }

    fn set_mode(&self, mode: InodeMode) -> Result<()> {
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
        self.this
            .upgrade()
            .expect("invalid weak reference to `self`")
    }
}

impl Inode for SecurityFsInode {
    fn fs(&self) -> Arc<dyn FileSystem> {
        SecurityFs::singleton().clone()
    }
}
