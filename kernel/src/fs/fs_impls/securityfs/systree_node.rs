// SPDX-License-Identifier: MPL-2.0

use aster_systree::{
    BranchNodeFields, SysAttrSetBuilder, SysBranchNode, SysObj, SysPerms, SysStr,
    inherit_sys_branch_node,
};

use crate::{prelude::*, security::lsm};

#[derive(Debug)]
pub(super) struct SecurityRootNode {
    fields: BranchNodeFields<dyn SysObj, Self>,
}

impl SecurityRootNode {
    pub(super) fn new() -> Arc<Self> {
        let root = Arc::new_cyclic(|weak_self| Self {
            fields: BranchNodeFields::new(
                SysStr::from("security"),
                SysAttrSetBuilder::new().build().unwrap(),
                weak_self.clone(),
            ),
        });

        for node in lsm::securityfs_nodes() {
            root.fields.add_child(node).unwrap();
        }

        root
    }
}

inherit_sys_branch_node!(SecurityRootNode, fields, {
    fn is_root(&self) -> bool {
        true
    }

    fn init_parent(&self, _parent: Weak<dyn SysBranchNode>) {}

    fn perms(&self) -> SysPerms {
        SysPerms::DEFAULT_RO_PERMS
    }
});
