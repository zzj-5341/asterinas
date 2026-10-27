#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Inject failure at every allocation in the production AppArmor policy load."""

import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PROBE = r'''
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as aster_core;
extern crate self as ostd;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static FAIL_AT: AtomicUsize = AtomicUsize::new(usize::MAX);

fn should_fail() -> bool {
    ACTIVE.load(Ordering::Relaxed)
        && COUNT.fetch_add(1, Ordering::Relaxed) == FAIL_AT.load(Ordering::Relaxed)
}

struct FaultAllocator;

// SAFETY: Non-injected operations delegate unchanged to System; injected allocation
// failures return null and leave any existing allocation valid.
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if should_fail() { return std::ptr::null_mut(); }
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if should_fail() { return std::ptr::null_mut(); }
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if should_fail() { return std::ptr::null_mut(); }
        // SAFETY: The caller supplies a live System allocation and valid sizes.
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: All successful allocations above come from System.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Errno { EINVAL, E2BIG, ENOMEM, ENOSPC, EEXIST, EPROTO, EOPNOTSUPP, EPROTONOSUPPORT, EILSEQ }
#[derive(Debug)]
pub struct Error(Errno);
impl Error {
    pub fn new(errno: Errno) -> Self { Self(errno) }
    pub fn error(&self) -> Errno { self.0 }
}
pub type Result<T> = std::result::Result<T, Error>;
pub mod prelude { pub use crate::{Errno, Error, Result}; }
pub mod sync {
    pub struct Mutex<T>(std::sync::Mutex<T>);
    impl<T> Mutex<T> {
        pub const fn new(value: T) -> Self { Self(std::sync::Mutex::new(value)) }
        pub fn lock(&self) -> std::sync::MutexGuard<'_, T> { self.0.lock().unwrap() }
    }
}

#[path = __POLICY_MODULE__]
mod policy;

fn main() {
    let mut args = std::env::args().skip(1);
    let name = args.next().unwrap();
    let failure = args.next().map(|arg| arg.parse::<usize>().unwrap());
    let original = include_bytes!(__FIXTURE__);
    policy::POLICY_STORE.load(original).unwrap();
    let before = policy::POLICY_STORE.snapshot().unwrap();
    let mut incoming = original.to_vec();
    let offset = incoming.windows(8).position(|bytes| bytes == b"observe\0").unwrap();
    incoming[offset..offset + 7].copy_from_slice(name.as_bytes());

    FAIL_AT.store(failure.unwrap_or(usize::MAX), Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Relaxed);
    let result = policy::POLICY_STORE.load(&incoming);
    ACTIVE.store(false, Ordering::Relaxed);

    if failure.is_some() {
        assert_eq!(result.unwrap_err().error(), Errno::ENOMEM);
        assert!(std::sync::Arc::ptr_eq(&before, &policy::POLICY_STORE.snapshot().unwrap()));
    } else {
        result.unwrap();
        assert_eq!(policy::POLICY_STORE.snapshot().unwrap().profiles().len(), 2);
        println!("{}", COUNT.load(Ordering::Relaxed));
    }
}
'''


def main():
    source = PROBE.replace(
        "__POLICY_MODULE__",
        json.dumps((ROOT / "kernel/comps/apparmor/src/policy/mod.rs").as_posix()),
    ).replace(
        "__FIXTURE__",
        json.dumps(
            (ROOT / "test/initramfs/src/regression/security/lsm/apparmor-fixtures/observe.bin").as_posix()
        ),
    )
    with tempfile.TemporaryDirectory(prefix="apparmor-oom-") as directory:
        directory = Path(directory)
        probe = directory / "main.rs"
        binary = directory / ("probe.exe" if os.name == "nt" else "probe")
        probe.write_text(source, encoding="utf-8")
        subprocess.run(
            ["rustc", "--edition=2024", "-C", "opt-level=1", str(probe), "-o", str(binary)],
            cwd=ROOT,
            check=True,
        )
        failures = []
        checked = 0
        for name in ["another", "zzafter"]:
            count = int(subprocess.check_output([str(binary), name], text=True))
            assert count > 0, "the probe did not exercise allocation"
            for index in range(count):
                result = subprocess.run(
                    [str(binary), name, str(index)], capture_output=True, text=True
                )
                if result.returncode:
                    failures.append(
                        f"{name}, allocation {index}: exit {result.returncode}\n{result.stderr}"
                    )
                checked += 1
        if failures:
            raise AssertionError("\n".join(failures))
        print(f"AppArmor OOM: {checked} allocation failure points returned ENOMEM; snapshot unchanged")


if __name__ == "__main__":
    main()
