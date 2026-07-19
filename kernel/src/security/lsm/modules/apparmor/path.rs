// SPDX-License-Identifier: MPL-2.0

use crate::{
    fs::{
        file::{AccessMode, StatusFlags},
        vfs::path::{AbsPathResult, Path, PathResolver},
    },
    prelude::*,
    security::{FileCreateKind, FileDeleteKind, FilePermission, FileSetattrKind},
};

bitflags! {
    /// File permissions requested from an AppArmor profile.
    pub struct AppArmorFilePermission: u32 {
        /// Reads file contents or directory entries.
        const READ = 1 << 0;
        /// Writes file contents.
        const WRITE = 1 << 1;
        /// Executes a file.
        const EXECUTE = 1 << 2;
        /// Appends file contents.
        const APPEND = 1 << 3;
        /// Maps file contents.
        const MMAP = 1 << 4;
        /// Creates a filesystem object.
        const CREATE = 1 << 5;
        /// Deletes a filesystem object.
        const DELETE = 1 << 6;
        /// Creates a hard link.
        const LINK = 1 << 7;
        /// Renames a filesystem object.
        const RENAME = 1 << 8;
        /// Creates a directory.
        const MKDIR = 1 << 9;
        /// Creates a special filesystem node.
        const MKNOD = 1 << 10;
        /// Creates a symbolic link.
        const SYMLINK = 1 << 11;
        /// Changes file attributes.
        const SETATTR = 1 << 12;
    }
}

impl AppArmorFilePermission {
    /// Creates file permissions requested by an open operation.
    pub fn from_open(access_mode: AccessMode, status_flags: StatusFlags) -> Self {
        let mut permissions = Self::empty();

        if access_mode.is_readable() {
            permissions |= Self::READ;
        }
        if access_mode.is_writable() {
            permissions |= if status_flags.contains(StatusFlags::O_APPEND) {
                Self::APPEND
            } else {
                Self::WRITE
            };
        }

        permissions
    }

    /// Creates file permissions requested by an execute operation.
    pub fn for_execute() -> Self {
        Self::EXECUTE
    }

    /// Creates file permissions requested by a create operation.
    pub fn for_create(
        kind: FileCreateKind,
        access_mode: Option<AccessMode>,
        status_flags: StatusFlags,
    ) -> Self {
        let mut permissions = Self::CREATE;
        permissions |= match kind {
            FileCreateKind::Regular => Self::empty(),
            FileCreateKind::Directory => Self::MKDIR,
            FileCreateKind::Device | FileCreateKind::Fifo | FileCreateKind::Socket => Self::MKNOD,
            FileCreateKind::Symlink => Self::SYMLINK,
        };

        if let Some(access_mode) = access_mode {
            permissions |= Self::from_open(access_mode, status_flags);
        }
        permissions
    }

    /// Creates file permissions requested by a delete operation.
    pub fn for_delete(kind: FileDeleteKind) -> Self {
        let mut permissions = Self::DELETE;
        if kind == FileDeleteKind::Directory {
            permissions |= Self::MKDIR;
        }
        permissions
    }

    /// Creates permissions requested on the source of a link operation.
    pub fn for_link_source() -> Self {
        Self::LINK
    }

    /// Creates permissions requested on the target of a link operation.
    pub fn for_link_target() -> Self {
        Self::CREATE | Self::LINK
    }

    /// Creates permissions requested on the source of a rename operation.
    pub fn for_rename_source() -> Self {
        Self::DELETE | Self::RENAME
    }

    /// Creates permissions requested on the target of a rename operation.
    pub fn for_rename_target() -> Self {
        Self::CREATE | Self::RENAME
    }

    /// Creates permissions requested by an attribute-change operation.
    pub fn for_setattr(kind: FileSetattrKind) -> Self {
        match kind {
            FileSetattrKind::Mode
            | FileSetattrKind::Owner
            | FileSetattrKind::Size
            | FileSetattrKind::Times => Self::SETATTR,
        }
    }

    /// Converts generic LSM file permissions into AppArmor permissions.
    pub fn from_file_permission(permissions: FilePermission) -> Self {
        let mut apparmor_permissions = Self::empty();

        if permissions.contains(FilePermission::READ) {
            apparmor_permissions |= Self::READ;
        }
        if permissions.contains(FilePermission::WRITE) {
            apparmor_permissions |= Self::WRITE;
        }
        if permissions.contains(FilePermission::EXECUTE) {
            apparmor_permissions |= Self::EXECUTE;
        }
        if permissions.contains(FilePermission::APPEND) {
            apparmor_permissions |= Self::APPEND;
        }
        if permissions.contains(FilePermission::MMAP) {
            apparmor_permissions |= Self::MMAP;
        }

        apparmor_permissions
    }
}

/// A path as seen through a task's current filesystem root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppArmorPathView {
    /// The path can be traced back to the resolver root.
    Reachable(String),
    /// The path cannot be traced back to the resolver root.
    Unreachable(String),
}

impl AppArmorPathView {
    /// Builds a path view from a resolved VFS path and resolver.
    pub fn from_path(path_resolver: &PathResolver, path: &Path) -> Self {
        match path_resolver.make_abs_path(path) {
            AbsPathResult::Reachable(path_name) => Self::Reachable(path_name),
            AbsPathResult::Unreachable(path_name) => Self::Unreachable(path_name),
        }
    }

    /// Builds a child path view from a parent path and basename.
    pub fn from_child_name(path_resolver: &PathResolver, parent: &Path, name: &str) -> Self {
        match Self::from_path(path_resolver, parent) {
            Self::Reachable(parent_name) => Self::Reachable(join_child_path(parent_name, name)),
            Self::Unreachable(parent_name) => Self::Unreachable(join_child_path(parent_name, name)),
        }
    }

    /// Returns the visible path text.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Reachable(path_name) | Self::Unreachable(path_name) => path_name.as_str(),
        }
    }

    /// Returns whether the path was reachable from the resolver root.
    pub fn is_reachable(&self) -> bool {
        matches!(self, Self::Reachable(_))
    }
}

fn join_child_path(mut parent_name: String, name: &str) -> String {
    if parent_name != "/" {
        parent_name.push('/');
    }
    parent_name.push_str(name);
    parent_name
}

/// A path pattern in an AppArmor rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppArmorPathPattern(String);

impl AppArmorPathPattern {
    /// Creates a path pattern.
    pub fn new(pattern: String) -> Self {
        Self(pattern)
    }

    /// Returns whether the pattern matches a path.
    pub fn matches(&self, path_view: &AppArmorPathView) -> bool {
        glob_matches(self.as_str().as_bytes(), path_view.as_str().as_bytes())
    }

    /// Returns the pattern text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A file rule keyed by an AppArmor path pattern.
#[derive(Clone, Debug)]
pub struct AppArmorPathRule {
    pattern: AppArmorPathPattern,
    permissions: AppArmorFilePermission,
    audit: bool,
    deny: bool,
}

impl AppArmorPathRule {
    /// Creates a path rule.
    pub fn new(
        pattern: AppArmorPathPattern,
        permissions: AppArmorFilePermission,
        audit: bool,
        deny: bool,
    ) -> Self {
        Self {
            pattern,
            permissions,
            audit,
            deny,
        }
    }

    /// Returns the rule permissions.
    pub fn permissions(&self) -> AppArmorFilePermission {
        self.permissions
    }

    /// Returns whether this rule matches a path.
    pub fn matches(&self, path_view: &AppArmorPathView) -> bool {
        self.pattern.matches(path_view)
    }

    /// Returns whether accesses matching this rule should be audited.
    pub fn audit(&self) -> bool {
        self.audit
    }

    /// Returns whether this is a deny rule.
    pub fn deny(&self) -> bool {
        self.deny
    }
}

fn glob_matches(pattern: &[u8], path: &[u8]) -> bool {
    glob_matches_from(pattern, 0, path, 0)
}

fn glob_matches_from(pattern: &[u8], pattern_index: usize, path: &[u8], path_index: usize) -> bool {
    if pattern_index == pattern.len() {
        return path_index == path.len();
    }

    match pattern[pattern_index] {
        b'\\' => match_escaped(pattern, pattern_index, path, path_index),
        b'?' => {
            path_index < path.len()
                && path[path_index] != b'/'
                && glob_matches_from(pattern, pattern_index + 1, path, path_index + 1)
        }
        b'*' => match_star(pattern, pattern_index, path, path_index),
        byte => {
            path_index < path.len()
                && path[path_index] == byte
                && glob_matches_from(pattern, pattern_index + 1, path, path_index + 1)
        }
    }
}

fn match_escaped(pattern: &[u8], pattern_index: usize, path: &[u8], path_index: usize) -> bool {
    let literal_index = pattern_index + 1;
    if literal_index == pattern.len() {
        return path_index < path.len()
            && path[path_index] == b'\\'
            && glob_matches_from(pattern, literal_index, path, path_index + 1);
    }

    path_index < path.len()
        && path[path_index] == pattern[literal_index]
        && glob_matches_from(pattern, literal_index + 1, path, path_index + 1)
}

fn match_star(pattern: &[u8], pattern_index: usize, path: &[u8], path_index: usize) -> bool {
    let is_double_star = pattern_index + 1 < pattern.len() && pattern[pattern_index + 1] == b'*';
    let next_pattern_index = pattern_index + if is_double_star { 2 } else { 1 };

    if glob_matches_from(pattern, next_pattern_index, path, path_index) {
        return true;
    }

    let mut next_path_index = path_index;
    while next_path_index < path.len() {
        if !is_double_star && path[next_path_index] == b'/' {
            return false;
        }

        next_path_index += 1;
        if glob_matches_from(pattern, next_pattern_index, path, next_path_index) {
            return true;
        }
    }

    false
}
