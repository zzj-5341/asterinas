// SPDX-License-Identifier: MPL-2.0

use super::super::modules;
use crate::{
    fs::{
        file::{AccessMode, CreationFlags, StatusFlags},
        vfs::path::{AbsPathResult, Path, PathResolver},
    },
    prelude::*,
};

/// Runs file open hooks in module order.
pub fn on_file_open(context: &FileOpenContext<'_>) -> Result<()> {
    for module in modules::active_modules() {
        module.on_file_open(context)?;
    }

    Ok(())
}

/// The inputs for checking a file open operation.
pub struct FileOpenContext<'a> {
    target: FileOpenTarget<'a>,
    path_resolver: &'a PathResolver,
    access_mode: AccessMode,
    creation_flags: CreationFlags,
    status_flags: StatusFlags,
}

#[derive(Clone, Copy)]
enum FileOpenTarget<'a> {
    Resolved(&'a Path),
    NewChild { parent: &'a Path, name: &'a str },
    AnonymousChild(&'a Path),
}

impl<'a> FileOpenContext<'a> {
    /// Creates a file open context for an existing path.
    pub(crate) const fn new(
        path: &'a Path,
        path_resolver: &'a PathResolver,
        access_mode: AccessMode,
        creation_flags: CreationFlags,
        status_flags: StatusFlags,
    ) -> Self {
        Self {
            target: FileOpenTarget::Resolved(path),
            path_resolver,
            access_mode,
            creation_flags,
            status_flags,
        }
    }

    /// Creates a file open context for a child that is about to be created.
    pub(crate) const fn new_child(
        parent: &'a Path,
        name: &'a str,
        path_resolver: &'a PathResolver,
        access_mode: AccessMode,
        creation_flags: CreationFlags,
        status_flags: StatusFlags,
    ) -> Self {
        Self {
            target: FileOpenTarget::NewChild { parent, name },
            path_resolver,
            access_mode,
            creation_flags,
            status_flags,
        }
    }

    /// Creates a file open context for an unnamed temporary file.
    pub(crate) const fn new_anonymous_child(
        parent: &'a Path,
        path_resolver: &'a PathResolver,
        access_mode: AccessMode,
        creation_flags: CreationFlags,
        status_flags: StatusFlags,
    ) -> Self {
        Self {
            target: FileOpenTarget::AnonymousChild(parent),
            path_resolver,
            access_mode,
            creation_flags,
            status_flags,
        }
    }

    /// Resolves the caller-visible path name being opened.
    ///
    /// A reachable result is absolute from the caller's root. An unreachable
    /// result contains the same pseudo or partial path representation as
    /// [`PathResolver::make_abs_path`].
    pub fn resolve_path_name(&self) -> AbsPathResult {
        match self.target {
            FileOpenTarget::Resolved(path) => self.path_resolver.make_abs_path(path),
            FileOpenTarget::NewChild { parent, name } => {
                let mut path_result = self.path_resolver.make_abs_path(parent);
                let path = match &mut path_result {
                    AbsPathResult::Reachable(path) | AbsPathResult::Unreachable(path) => path,
                };
                if !path.ends_with('/') {
                    path.push('/');
                }
                path.push_str(name);
                path_result
            }
            FileOpenTarget::AnonymousChild(parent) => {
                let path_name = match self.path_resolver.make_abs_path(parent) {
                    AbsPathResult::Reachable(path_name) | AbsPathResult::Unreachable(path_name) => {
                        path_name
                    }
                };
                AbsPathResult::Unreachable(path_name)
            }
        }
    }

    /// Returns whether this operation will create a new file.
    pub const fn creates_file(&self) -> bool {
        matches!(
            self.target,
            FileOpenTarget::NewChild { .. } | FileOpenTarget::AnonymousChild(_)
        )
    }

    /// Returns the requested access mode.
    pub const fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    /// Returns the open creation flags.
    pub const fn creation_flags(&self) -> CreationFlags {
        self.creation_flags
    }

    /// Returns the open status flags.
    pub const fn status_flags(&self) -> StatusFlags {
        self.status_flags
    }
}
