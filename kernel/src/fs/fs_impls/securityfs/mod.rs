// SPDX-License-Identifier: MPL-2.0

//! Securityfs for Linux Security Module control interfaces.
//!
//! [`fs::SecurityFs`] adapts a systree to the VFS, while
//! [`systree_node::SecurityRootNode`] populates its root from the control nodes
//! registered by active LSMs.

use aster_systree::EmptyNode;
use fs::SecurityFsType;

mod fs;
mod inode;
mod systree_node;

pub(super) fn init() {
    super::sysfs::register_kernel_sysnode(EmptyNode::new("security".into())).unwrap();
    crate::fs::vfs::registry::register(&SecurityFsType).unwrap();
}
