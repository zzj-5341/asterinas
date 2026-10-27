// SPDX-License-Identifier: MPL-2.0

//! Allocation probe for the unmodified credential-security implementation.
//!
//! Run from the repository root with the pinned nightly:
//! `rustc --edition=2024 test/host/lsm_cred_alloc.rs -o /tmp/lsm-cred-alloc`
//! `/tmp/lsm-cred-alloc`
//!
//! Only the boot module registry and error types are host shims. This measures
//! security-state allocations, not the kernel's existing credentials or VFS.

#![feature(allocator_api)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering},
    },
};

static TRACK: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static FAIL_AFTER: AtomicIsize = AtomicIsize::new(-1);

struct ProbeAllocator;

// SAFETY: Every successful allocation/deallocation is delegated to System
// with the original layout. Injection only returns null, as GlobalAlloc allows.
unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            if FAIL_AFTER.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n >= 0).then_some(n - 1)
            }) == Ok(0)
            {
                return std::ptr::null_mut();
            }
        }
        // SAFETY: The caller supplies a valid allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: All non-null pointers come from System with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

macro_rules! return_errno_with_message {
    ($errno:expr, $message:expr) => {
        return Err(Error::new($errno))
    };
}

mod prelude {
    pub use std::{any::Any, string::String, sync::Arc, vec::Vec};
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Errno {
        ENOMEM,
        EINVAL,
    }
    #[derive(Debug)]
    pub struct Error(Errno);
    impl Error {
        pub fn new(errno: Errno) -> Self {
            Self(errno)
        }
        pub fn error(&self) -> Errno {
            self.0
        }
    }
    pub type Result<T> = std::result::Result<T, Error>;
}

#[path = "../../kernel/core/src/security/lsm/cred.rs"]
mod cred;

mod modules {
    use super::{OnceLock, cred::LsmState, prelude::*};

    pub struct Module;
    static PROFILE: OnceLock<LsmState> = OnceLock::new();

    pub fn warm_up() {
        PROFILE.set(Arc::new(17usize)).unwrap();
    }
    pub fn active_modules() -> &'static [Module] {
        &[Module]
    }

    impl Module {
        pub fn name(&self) -> &'static str {
            "probe"
        }
        pub fn init_cred_state(&self) -> Result<Option<LsmState>> {
            Ok(None)
        }
        pub fn needs_exec_path(&self, state: Option<&LsmState>) -> bool {
            state.is_none()
        }
        pub fn current_attr(&self, _: Option<&LsmState>) -> Result<Option<String>> {
            Ok(None)
        }
        pub fn prepare_exec_state(
            &self,
            current: Option<&LsmState>,
            path: Option<&str>,
        ) -> Result<Option<LsmState>> {
            Ok(current
                .cloned()
                .or_else(|| (path == Some("/match")).then(|| PROFILE.get().unwrap().clone())))
        }
    }
}

fn measured<T>(fail_after: isize, operation_fn: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    FAIL_AFTER.store(fail_after, Ordering::Relaxed);
    TRACK.store(true, Ordering::Relaxed);
    let result = operation_fn();
    TRACK.store(false, Ordering::Relaxed);
    (result, ALLOCATIONS.load(Ordering::Relaxed))
}

fn main() {
    modules::warm_up();
    let (empty, count) = measured(-1, cred::CredSecurity::init);
    let mut parent = empty.unwrap();
    assert_eq!(count, 0, "initial empty state allocated");
    assert!(parent.needs_exec_path());
    assert_eq!(parent.current_attr().unwrap_err().error(), prelude::Errno::EINVAL);
    let (child, count) = measured(-1, || parent.clone());
    assert_eq!(count, 0, "empty fork/clone state allocated");
    let (candidate, count) = measured(-1, || parent.prepare_exec(Some("/unmatched")));
    assert_eq!(count, 0, "unmatched exec state allocated");
    let (_, count) = measured(-1, || {
        parent = candidate.unwrap();
        drop(child);
    });
    assert_eq!(count, 0, "empty commit/drop allocated");

    // Fail both the entry-vector and snapshot-Arc allocations separately.
    for failure in [0, 1] {
        let (candidate, _) = measured(failure, || parent.prepare_exec(Some("/match")));
        assert_eq!(candidate.unwrap_err().error(), prelude::Errno::ENOMEM);
        assert!(
            parent.get("probe").is_none(),
            "failed preparation changed parent"
        );
    }
    let child = parent.prepare_exec(Some("/match")).unwrap();
    assert!(!child.needs_exec_path());
    assert!(parent.get("probe").is_none());
    assert_eq!(
        child.get("probe").unwrap().downcast_ref::<usize>(),
        Some(&17)
    );
    let (copy, count) = measured(-1, || child.clone());
    assert_eq!(count, 0, "confined fork copied the snapshot allocation");
    drop(copy);
    println!(
        "empty init/clone/unmatched prepare/commit/drop: 0 allocations; both allocation failures preserved parent; confined clone: 0 allocations"
    );
}
