// SPDX-License-Identifier: MPL-2.0

//! AppArmor support for Asterinas.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

// Set this crate's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "apparmor: "
    };
}

mod policy;
