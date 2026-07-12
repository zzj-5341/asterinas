// SPDX-License-Identifier: MPL-2.0

pub(super) mod elf;
mod shebang;

use self::{elf::ElfLoadInfo, shebang::parse_shebang_line};
use crate::{
    fs::{
        file::{InodeType, Permission},
        vfs::{
            inode::Inode,
            inode_ext::{InodeExt, PreparedExecutableGuard},
            path::{FsPath, Path, PathResolver},
        },
    },
    prelude::*,
    vm::vmar::Vmar,
};

/// An executable whose mapped files are protected from concurrent writes.
pub(super) struct PreparedProgramToLoad {
    elf_file: Path,
    elf_headers: elf::ElfHeaders,
    argv: Vec<CString>,
    envp: Vec<CString>,
    ldso: Option<(Path, elf::ElfHeaders)>,
    main_executable_guard: PreparedExecutableGuard,
    ldso_guard: Option<PreparedExecutableGuard>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::process) enum ExecSecurity {
    Ordinary,
    Secure,
}

impl ExecSecurity {
    const fn aux_value(self) -> u64 {
        match self {
            Self::Ordinary => 0,
            Self::Secure => 1,
        }
    }
}

impl PreparedProgramToLoad {
    /// Builds a protected program and resolves its interpreter chain.
    pub(super) fn build_from_file(
        mut elf_file: Path,
        path_resolver: &PathResolver,
        mut argv: Vec<CString>,
        envp: Vec<CString>,
    ) -> Result<Self> {
        // Linux permits at most five recursive shebang interpretations.
        let mut recursive_limit = 5;

        let (elf_headers, main_executable_guard, ldso_file) = loop {
            let inode = elf_file.inode().clone();
            let exec_guard = inode.lock_for_exec()?;
            check_executable_inode(inode.as_ref())?;

            // The write denial keeps the shebang or ELF header stable while it is parsed.
            let mut file_first_page = Box::new([0u8; PAGE_SIZE]);
            let len = inode.read_bytes_at(0, &mut *file_first_page)?;

            let Some(mut new_argv) = parse_shebang_line(&file_first_page[..len])? else {
                let elf_headers = elf::ElfHeaders::parse(&file_first_page[..len])?;
                let ldso_file = elf::lookup_ldso(&elf_headers, &elf_file, path_resolver)?;
                let main_executable_guard =
                    exec_guard.into_prepared_executable_guard(inode.clone());
                break (elf_headers, main_executable_guard, ldso_file);
            };

            if recursive_limit == 0 {
                return_errno_with_message!(Errno::ELOOP, "the recursive limit is reached");
            }
            recursive_limit -= 1;

            let interpreter = {
                let filename = new_argv[0].to_str()?.to_string();
                let fs_path = FsPath::try_from(filename.as_str())?;
                path_resolver.lookup(&fs_path)?
            };

            // Linux releases the script's write denial after selecting its interpreter.
            drop(exec_guard);
            new_argv.extend(argv);
            argv = new_argv;
            elf_file = interpreter;
        };

        let (ldso, ldso_guard) = if let Some(ldso_file) = ldso_file {
            let ldso_inode = ldso_file.inode().clone();
            let ldso_exec_guard = ldso_inode.lock_for_exec()?;
            check_executable_inode(ldso_inode.as_ref())?;
            let ldso_headers = elf::parse_ldso_headers(&ldso_file)?;
            let ldso_guard = ldso_exec_guard.into_prepared_executable_guard(ldso_inode.clone());
            (Some((ldso_file, ldso_headers)), Some(ldso_guard))
        } else {
            (None, None)
        };

        Ok(Self {
            elf_file,
            elf_headers,
            argv,
            envp,
            ldso,
            main_executable_guard,
            ldso_guard,
        })
    }

    /// Returns the ELF file that will be loaded.
    pub(super) fn elf_file(&self) -> &Path {
        &self.elf_file
    }

    /// Loads the protected executable into the specified virtual memory space.
    pub(super) fn load_to_vmar(
        self,
        vmar: &Vmar,
        exec_security: ExecSecurity,
    ) -> Result<ElfLoadInfo> {
        let Self {
            elf_file,
            elf_headers,
            argv,
            envp,
            ldso,
            main_executable_guard,
            ldso_guard,
        } = self;

        let elf_load_info =
            elf::load_elf_to_vmar(vmar, elf_file, elf_headers, ldso, argv, envp, exec_security)?;

        // Linux denies writes to `PT_INTERP` only while the interpreter is mapped.
        drop(ldso_guard);
        let executable_write_guard = main_executable_guard.into_executable_write_guard();
        vmar.process_vm()
            .set_executable_write_guard(executable_write_guard);
        Ok(elf_load_info)
    }
}

fn check_executable_inode(inode: &dyn Inode) -> Result<()> {
    if inode.type_().is_directory() {
        return_errno_with_message!(Errno::EISDIR, "the inode is a directory");
    }

    if inode.type_() == InodeType::SymLink {
        return_errno_with_message!(Errno::ELOOP, "the inode is a symbolic link");
    }

    if !inode.type_().is_regular_file() {
        return_errno_with_message!(Errno::EACCES, "the inode is not a regular file");
    }

    if inode.check_permission(Permission::MAY_EXEC).is_err() {
        return_errno_with_message!(Errno::EACCES, "the inode is not executable");
    }

    Ok(())
}
