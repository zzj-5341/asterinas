// SPDX-License-Identifier: MPL-2.0

//! Per-inode synchronization and notification extensions.
//!
//! [`FsLockContext`] serializes metadata and content mutations against executable loading.
//! Its guards coordinate inode-level reservations with page-cache write access,
//! then retain the required exclusion after the inode mutex is released.

use alloc::boxed::ThinBox;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    fs::{
        file::{StatusFlags, flock::FlockList},
        vfs::{
            file_privilege,
            inode::{FallocMode, FileOps, Inode},
            notify::FsEventPublisher,
            range_lock::RangeLockList,
        },
    },
    prelude::*,
    vm::page_cache::{ExecWriteAccessGuard, ExecWriteDenialGuard},
};

/// Per-inode synchronization state shared by filesystem operations.
pub struct FsLockContext {
    mutation_lock: Mutex<()>,
    exec_reservation_count: AtomicUsize,
    range_lock_list: RangeLockList,
    flock_list: FlockList,
}

impl FsLockContext {
    pub(self) fn new() -> Self {
        Self {
            mutation_lock: Mutex::new(()),
            exec_reservation_count: AtomicUsize::new(0),
            range_lock_list: RangeLockList::new(),
            flock_list: FlockList::new(),
        }
    }

    fn lock_for_mutation(
        &self,
        acquire_exec_write_access_fn: impl FnOnce() -> Result<Option<ExecWriteAccessGuard>>,
    ) -> Result<InodeMutationGuard<'_>> {
        // An exec transition reserves the counter before waiting for the mutex.
        // Checking both sides of the lock prevents a new mutation from slipping
        // ahead of that reservation.
        if self.exec_reservation_count.load(Ordering::Acquire) > 0 {
            return Err(Error::new(Errno::ETXTBSY));
        }

        let guard = self.mutation_lock.lock();
        if self.exec_reservation_count.load(Ordering::Acquire) > 0 {
            drop(guard);
            return Err(Error::new(Errno::ETXTBSY));
        }
        let exec_write_access = acquire_exec_write_access_fn()?;

        Ok(InodeMutationGuard {
            guard: Some(guard),
            exec_write_access,
        })
    }

    fn lock_for_exec(
        &self,
        acquire_exec_write_denial_fn: impl FnOnce() -> Result<Option<ExecWriteDenialGuard>>,
    ) -> Result<ExecMutationGuard<'_>> {
        // Reserve before taking the mutex so subsequent mutations fail instead
        // of repeatedly winning the mutex while exec waits.
        self.exec_reservation_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| Error::new(Errno::EAGAIN))?;

        let guard = self.mutation_lock.lock();
        let exec_write_denial = match acquire_exec_write_denial_fn() {
            Ok(exec_write_denial) => exec_write_denial,
            Err(error) => {
                drop(guard);
                self.release_exec_reservation();
                return Err(error);
            }
        };

        Ok(ExecMutationGuard {
            context: self,
            guard: Some(guard),
            exec_write_denial,
            owns_exec_reservation: true,
        })
    }

    fn release_exec_reservation(&self) {
        self.exec_reservation_count
            .fetch_update(Ordering::Release, Ordering::Relaxed, |count| {
                count.checked_sub(1)
            })
            .expect("only an active exec reservation can be released");
    }

    /// Returns a reference to the range lock list.
    pub fn range_lock_list(&self) -> &RangeLockList {
        &self.range_lock_list
    }

    /// Returns a reference to the flock list.
    pub fn flock_list(&self) -> &FlockList {
        &self.flock_list
    }
}

/// A guard serializing an inode mutation against `execve()`.
pub struct InodeMutationGuard<'a> {
    guard: Option<MutexGuard<'a, ()>>,
    exec_write_access: Option<ExecWriteAccessGuard>,
}

impl InodeMutationGuard<'_> {
    /// Performs a preflighted write and invalidates privilege metadata.
    pub(crate) fn write_at(
        &self,
        inode: &dyn Inode,
        file_ops: &dyn FileOps,
        offset: usize,
        reader: &mut VmReader,
        status_flags: StatusFlags,
    ) -> Result<usize> {
        let max_len = file_ops.prepare_write_at(offset, reader.remain(), status_flags)?;
        reader.limit(max_len);
        file_privilege::invalidate_for_content_change(inode)?;
        file_ops.write_at(offset, reader, status_flags)
    }

    /// Performs a preflighted resize and invalidates privilege metadata.
    pub(crate) fn resize(&self, inode: &dyn Inode, new_size: usize) -> Result<()> {
        inode.check_resize(new_size)?;
        file_privilege::invalidate_for_content_change(inode)?;
        inode.resize(new_size)
    }

    /// Performs a preflighted allocation and invalidates privilege metadata.
    pub(crate) fn fallocate(
        &self,
        inode: &dyn Inode,
        mode: FallocMode,
        offset: usize,
        len: usize,
    ) -> Result<()> {
        inode.check_fallocate(mode, offset, len)?;
        file_privilege::invalidate_for_content_change(inode)?;
        inode.fallocate(mode, offset, len)
    }
}

impl Drop for InodeMutationGuard<'_> {
    fn drop(&mut self) {
        // Withdraw PageCache write access while the inode mutex still prevents
        // a waiting exec reservation from observing a conflicting writer.
        drop(self.exec_write_access.take());
        drop(self.guard.take());
    }
}

/// A guard excluding content and privilege metadata mutations during `execve()`.
pub struct ExecMutationGuard<'a> {
    context: &'a FsLockContext,
    guard: Option<MutexGuard<'a, ()>>,
    exec_write_denial: Option<ExecWriteDenialGuard>,
    owns_exec_reservation: bool,
}

impl ExecMutationGuard<'_> {
    /// Retains the executable snapshot after releasing the inode mutex.
    pub(crate) fn into_prepared_executable_guard(
        mut self,
        inode: Arc<dyn Inode>,
    ) -> PreparedExecutableGuard {
        drop(self.guard.take());
        self.owns_exec_reservation = false;

        PreparedExecutableGuard {
            inode: Some(inode),
            exec_write_denial: self.exec_write_denial.take(),
        }
    }
}

impl Drop for ExecMutationGuard<'_> {
    fn drop(&mut self) {
        drop(self.guard.take());
        drop(self.exec_write_denial.take());
        if self.owns_exec_reservation {
            self.context.release_exec_reservation();
        }
    }
}

/// A guard protecting executable bytes and credential metadata during image preparation.
pub(crate) struct PreparedExecutableGuard {
    inode: Option<Arc<dyn Inode>>,
    exec_write_denial: Option<ExecWriteDenialGuard>,
}

impl PreparedExecutableGuard {
    /// Finishes preparation while retaining content-write exclusion.
    pub(crate) fn into_executable_write_guard(mut self) -> ExecutableWriteGuard {
        self.release_exec_reservation();
        ExecutableWriteGuard {
            _exec_write_denial: self.exec_write_denial.take(),
        }
    }

    fn release_exec_reservation(&mut self) {
        let Some(inode) = self.inode.take() else {
            return;
        };
        let context = inode
            .fs_lock_context()
            .expect("an executable inode must retain its lock context");
        context.release_exec_reservation();
    }
}

impl Drop for PreparedExecutableGuard {
    fn drop(&mut self) {
        drop(self.exec_write_denial.take());
        self.release_exec_reservation();
    }
}

/// A cloneable guard retaining content-write exclusion.
#[derive(Clone)]
pub(crate) struct ExecutableWriteGuard {
    _exec_write_denial: Option<ExecWriteDenialGuard>,
}

/// A trait that instantiates kernel types for the inode [`Extension`].
///
/// [`Extension`]: super::inode::Extension
pub trait InodeExt {
    /// Gets or initializes the FS event publisher.
    ///
    /// If the publisher does not exist for this inode, it will be created.
    fn fs_event_publisher_or_init(&self) -> &FsEventPublisher;

    /// Returns a reference to the FS event publisher.
    ///
    /// If the publisher does not exist for this inode, a [`None`] will be returned.
    fn fs_event_publisher(&self) -> Option<&FsEventPublisher>;

    /// Gets or initializes the FS lock context.
    ///
    /// If the context does not exist for this inode, it will be created.
    fn fs_lock_context_or_init(&self) -> &FsLockContext;

    /// Returns a reference to the FS lock context.
    ///
    /// If the context does not exist for this inode, a [`None`] will be returned.
    fn fs_lock_context(&self) -> Option<&FsLockContext>;

    /// Locks an inode mutation against an in-progress executable snapshot.
    fn lock_for_mutation(&self) -> Result<InodeMutationGuard<'_>>;

    /// Locks a content mutation and rejects files that back an executable image.
    fn lock_for_content_mutation(&self) -> Result<InodeMutationGuard<'_>>;

    /// Locks an inode for an `execve()` transition.
    fn lock_for_exec(&self) -> Result<ExecMutationGuard<'_>>;
}

impl InodeExt for dyn Inode {
    fn fs_event_publisher_or_init(&self) -> &FsEventPublisher {
        self.extension()
            .group1()
            .call_once(|| ThinBox::new_unsize(FsEventPublisher::new()))
            .downcast_ref()
            .unwrap()
    }

    fn fs_event_publisher(&self) -> Option<&FsEventPublisher> {
        Some(self.extension().group1().get()?.downcast_ref().unwrap())
    }

    fn fs_lock_context_or_init(&self) -> &FsLockContext {
        self.extension()
            .group2()
            .call_once(|| ThinBox::new_unsize(FsLockContext::new()))
            .downcast_ref()
            .unwrap()
    }

    fn fs_lock_context(&self) -> Option<&FsLockContext> {
        Some(self.extension().group2().get()?.downcast_ref().unwrap())
    }

    fn lock_for_mutation(&self) -> Result<InodeMutationGuard<'_>> {
        self.fs_lock_context_or_init()
            .lock_for_mutation(|| Ok(None))
    }

    fn lock_for_content_mutation(&self) -> Result<InodeMutationGuard<'_>> {
        let page_cache = self.page_cache_for_exec_write()?;
        self.fs_lock_context_or_init().lock_for_mutation(|| {
            if self.requires_exec_write_tracking() {
                page_cache
                    .as_ref()
                    .map(|page_cache| page_cache.acquire_exec_write_access())
                    .transpose()
            } else {
                Ok(None)
            }
        })
    }

    fn lock_for_exec(&self) -> Result<ExecMutationGuard<'_>> {
        // Fetching the page cache first also canonicalizes overlayfs files by
        // completing copy-up before any executable bytes are re-read.
        let page_cache = self.page_cache_for_exec_write()?;
        self.fs_lock_context_or_init().lock_for_exec(|| {
            if self.requires_exec_write_tracking() {
                page_cache
                    .as_ref()
                    .map(|page_cache| page_cache.deny_exec_write_access())
                    .transpose()
            } else {
                Ok(None)
            }
        })
    }
}
