// SPDX-License-Identifier: MPL-2.0

//! LSM task attributes exposed under `/proc/<pid>/attr`.

use aster_util::printer::VmPrinter;

use super::TidDirOps;
use crate::{
    fs::{
        file::{InodeType, mkmod},
        procfs::{
            StaticEntryWithOps,
            template::{
                ProcDir, ProcDirOps, ProcFile, ProcFileOps, ReaddirEntry,
                listed_entries_from_table, lookup_child_from_table, visit_listed_entries,
            },
        },
        vfs::inode::Inode,
    },
    prelude::*,
    process::{pid_table::PidEntry, posix_thread::AsPosixThread},
    security::lsm,
    thread::Thread,
};

const MAX_TASK_ATTR_SIZE_BYTES: usize = 256;

/// Operations for `/proc/<pid>/attr`.
pub(super) struct AttrDirOps {
    pid_entry: Arc<PidEntry>,
}

impl AttrDirOps {
    pub(super) fn new_inode(dir: &TidDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcDir::new(
            Self {
                pid_entry: dir.pid_entry().clone(),
            },
            parent,
            mkmod!(a+rx),
        )
    }

    fn thread(&self) -> Option<Arc<Thread>> {
        self.pid_entry.thread()
    }

    const STATIC_ENTRIES: &'static [StaticEntryWithOps<Self>] =
        &[("current", InodeType::File, CurrentFileOps::new_inode)];
}

impl ProcDirOps for AttrDirOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.thread()
    }

    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        if self.pid_entry.type_().is_none() {
            return_errno_with_message!(Errno::ENOENT, "the thread does not exist");
        }

        if let Some(child) = lookup_child_from_table(name, Self::STATIC_ENTRIES, |constructor_fn| {
            constructor_fn(self, this_dir.this_weak().clone())
        }) {
            return Ok(child);
        }

        return_errno_with_message!(Errno::ENOENT, "the task attribute does not exist");
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        visit_listed_entries(
            offset,
            listed_entries_from_table(Self::STATIC_ENTRIES),
            visit_fn,
        )
    }
}

/// Operations for `/proc/<pid>/attr/current`.
struct CurrentFileOps {
    pid_entry: Arc<PidEntry>,
}

impl CurrentFileOps {
    fn new_inode(dir: &AttrDirOps, parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(
            Self {
                pid_entry: dir.pid_entry.clone(),
            },
            parent,
            mkmod!(a+r, u+w),
        )
    }

    fn thread(&self) -> Option<Arc<Thread>> {
        self.pid_entry.thread()
    }
}

impl ProcFileOps for CurrentFileOps {
    fn owner_thread(&self) -> Option<Arc<Thread>> {
        self.thread()
    }

    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let thread = self
            .thread()
            .ok_or_else(|| Error::with_message(Errno::ENOENT, "the thread does not exist"))?;
        let posix_thread = thread
            .as_posix_thread()
            .ok_or_else(|| Error::with_message(Errno::ENOENT, "the task is not a POSIX thread"))?;
        let mut printer = VmPrinter::new_skip(writer, offset);

        writeln!(printer, "{}", lsm::task_attr_current(posix_thread)?)?;

        Ok(printer.bytes_written())
    }

    fn write_at(&self, offset: usize, reader: &mut VmReader) -> Result<usize> {
        if offset != 0 {
            return_errno_with_message!(Errno::EINVAL, "the task label offset must be zero");
        }

        let target = self
            .thread()
            .ok_or_else(|| Error::with_message(Errno::ENOENT, "the thread does not exist"))?;
        let current = Thread::current().ok_or_else(|| {
            Error::with_message(Errno::ESRCH, "the current thread does not exist")
        })?;
        if !Arc::ptr_eq(&target, &current) {
            return_errno_with_message!(
                Errno::EPERM,
                "a task may only change its own security label"
            );
        }
        let posix_thread = target
            .as_posix_thread()
            .ok_or_else(|| Error::with_message(Errno::ENOENT, "the task is not a POSIX thread"))?;

        let read_len = reader.remain();
        if read_len == 0 || read_len > MAX_TASK_ATTR_SIZE_BYTES {
            return_errno_with_message!(Errno::EINVAL, "the task attribute size is invalid");
        }

        let mut bytes = vec![0u8; read_len];
        let mut writer = VmWriter::from(bytes.as_mut_slice());
        let copied = reader.read_fallible(&mut writer)?;
        if copied != read_len || bytes.contains(&0) {
            return_errno_with_message!(Errno::EINVAL, "the task attribute value is invalid");
        }
        let value = core::str::from_utf8(&bytes)
            .map_err(|_| Error::with_message(Errno::EINVAL, "the task attribute is not UTF-8"))?;

        lsm::set_task_attr_current(posix_thread, value)?;
        Ok(read_len)
    }
}
