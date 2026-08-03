// SPDX-License-Identifier: MPL-2.0

//! securityfs extensions supplied by active LSM modules.

use super::modules;
use crate::prelude::*;

pub(crate) fn nodes() -> Vec<Arc<dyn aster_systree::SysObj>> {
    modules::active_modules()
        .iter()
        .filter_map(|module| module.securityfs_node())
        .collect()
}
