// SPDX-License-Identifier: MPL-2.0

use aster_util::slot_vec::SlotVec;
use ostd::sync::RwMutexUpgradeableGuard;

use crate::{
    fs::{
        file::mkmod,
        procfs::{
            ProcDir,
            sys::kernel::{
                cap_last_cap::CapLastCapFileOps, pid_max::PidMaxFileOps, yama::YamaDirOps,
            },
            template::{
                DirOps, ProcDirBuilder, lookup_child_from_table, populate_children_from_table,
            },
        },
        vfs::inode::Inode,
    },
    prelude::*,
    security::lsm::is_yama_enabled,
};

mod cap_last_cap;
mod pid_max;
mod yama;

type StaticEntry = (&'static str, fn(Weak<dyn Inode>) -> Arc<dyn Inode>);

/// Represents the inode at `/proc/sys/kernel`.
pub struct KernelDirOps;

impl KernelDirOps {
    pub fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Reference:
        // <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/sysctl.c#L1765>
        // <https://elixir.bootlin.com/linux/v6.16.5/source/fs/proc/proc_sysctl.c#L978>
        ProcDirBuilder::new(Self, mkmod!(a+rx))
            .parent(parent)
            .build()
            .unwrap()
    }

    const STATIC_ENTRIES: &'static [StaticEntry] = &[
        ("cap_last_cap", CapLastCapFileOps::new_inode),
        ("pid_max", PidMaxFileOps::new_inode),
    ];

    const STATIC_ENTRIES_WITH_YAMA: &'static [StaticEntry] = &[
        ("cap_last_cap", CapLastCapFileOps::new_inode),
        ("pid_max", PidMaxFileOps::new_inode),
        ("yama", YamaDirOps::new_inode),
    ];

    fn static_entries() -> &'static [StaticEntry] {
        if is_yama_enabled() {
            Self::STATIC_ENTRIES_WITH_YAMA
        } else {
            Self::STATIC_ENTRIES
        }
    }
}

impl DirOps for KernelDirOps {
    fn lookup_child(&self, dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        let mut cached_children = dir.cached_children().write();

        if let Some(child) =
            lookup_child_from_table(name, &mut cached_children, Self::static_entries(), |f| {
                (f)(dir.this_weak().clone())
            })
        {
            return Ok(child);
        }

        return_errno_with_message!(Errno::ENOENT, "the file does not exist");
    }

    fn populate_children<'a>(
        &self,
        dir: &'a ProcDir<Self>,
    ) -> RwMutexUpgradeableGuard<'a, SlotVec<(String, Arc<dyn Inode>)>> {
        let mut cached_children = dir.cached_children().write();

        populate_children_from_table(&mut cached_children, Self::static_entries(), |f| {
            (f)(dir.this_weak().clone())
        });

        cached_children.downgrade()
    }
}
