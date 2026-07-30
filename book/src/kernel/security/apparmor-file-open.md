# Minimal AppArmor Regular-File Open Policy

Asterinas currently provides a minimal AppArmor implementation:
an exact-path allowlist for regular files enforced at the `file_open` hook,
with manual task confinement.
This interface is not compatible with the Linux AppArmor policy ABI.

## Enable AppArmor

Select AppArmor with the [`lsm=` kernel parameter](../linux-compatibility/kernel-parameters.md#lsm):

```text
lsm=yama,apparmor
```

Mount `securityfs` after mounting `sysfs`:

```sh
mkdir -p /sys/kernel/security
mount -t securityfs none /sys/kernel/security
```

When AppArmor is active, its control files are available under `/sys/kernel/security/apparmor`.

## Load policy

Policy version 0 accepts one profile per write.
Each profile has a name followed by exact absolute-path rules:

```text
version 0
profile example
/etc/example.conf r
/var/lib/example/state rw
```

Each policy write is limited to 4096 bytes,
each profile name to 128 bytes,
and each profile to 1024 rules.
Profile names may contain ASCII letters, digits, `_`, `-`, and `.`.
The profile name `unconfined` is reserved and cannot be loaded.
Rule paths must be canonical absolute paths without ASCII whitespace,
empty components, `.`, or `..`.
They are limited to 4096 bytes and match the resolved VFS path.

The supported permissions are:

| Permission | Allowed regular-file `file_open` operations |
| --- | --- |
| `r` | Open for reading |
| `w` | Open for writing or truncation |
| `rw` | Both sets above |

Write a new profile to `.load`,
or atomically replace an existing profile through `.replace`.
Both operations require `CAP_MAC_ADMIN` in the initial user namespace.
The `profiles` file lists loaded profiles,
and `features/policy_version` reports the accepted policy version.

## Confine a task

Write a loaded profile name to `/proc/self/attr/current`,
then replace the task with the intended program:

```sh
sh -c 'printf %s example > /proc/self/attr/current; exec /path/to/program'
```

Confinement is a one-way transition:
a confined task cannot change or remove its profile.
The label is part of the task credentials and is copied by `fork`.
It remains in effect across `execve`.
Reading the attribute reports `unconfined` or the profile name followed by `(enforce)`.

## Enforcement boundaries

Ordinary VFS permission checks still apply;
AppArmor can only further restrict an operation.
For a confined task,
a regular-file open not covered by an exact matching rule fails with `EACCES`.
An `O_PATH` open requests no file permission and is allowed.
Non-regular files, including directories, FIFOs, and device nodes,
are outside this skeleton and are not checked by AppArmor.

This skeleton invokes `file_open`
only for the `open`, `openat`, and `creat` system-call path,
and only regular files are mediated.
It does not mediate file handles created by other system calls
or by internal kernel operations.
It does not revalidate existing file descriptions inherited across `fork` or `execve`,
received through `SCM_RIGHTS`,
or duplicated through `pidfd_getfd()`.
Those descriptors also are not revalidated when they are later read or written.
The current implementation is therefore not a complete confinement boundary against descriptor-based access.

The `file_open` hook runs after creation.
If `O_CREAT` creates a file and AppArmor denies opening it,
the new directory entry remains.
An unnamed `O_TMPFILE` object is also checked after creation
and cannot match an exact absolute-path rule.

This implementation has no create hook,
non-regular-file mediation,
pathname globs,
profile removal,
automatic attachment,
complain mode,
execute transitions,
network rules,
or capability rules.
