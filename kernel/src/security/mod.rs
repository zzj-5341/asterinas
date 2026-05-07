// SPDX-License-Identifier: MPL-2.0

pub mod lsm;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "x86_64", feature = "cvm_guest"))] {
        mod tsm;
        mod tsm_mr;
    }
}

pub use self::lsm::{CredsSource, PtraceAccessContext, PtraceAccessKind, PtraceAccessMode};
use crate::prelude::*;

pub(super) fn init() {
    lsm::init();

    #[cfg(target_arch = "x86_64")]
    ostd::if_tdx_enabled!({
        tsm::init();
        tsm_mr::init();
    });
}

/// Runs the LSM stack for a ptrace-style access check.
pub fn ptrace_access_check(context: &PtraceAccessContext<'_>) -> Result<()> {
    lsm::ptrace_access_check(context)
}
