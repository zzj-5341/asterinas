# AppArmor M2 review fixes and release verification

This report supersedes the validation status in the historical October 27 M2 report.
The reviewed M1 base is `7d0055d4be91724072c416d6a6a39de85c25fc50`.
Runtime verification uses `476acb68a14afdcddee13d75efed89a7e6426dca`.
The old M1 and M2 branch references remain available locally.

## Scope and integration

The user requested all retained review fixes, including style findings, followed by fresh release validation and a live walkthrough.
Exact-path attachment, credential binding, and PID/TID queries remain together in M2.
Empty security state still represents `unconfined` without allocating an object or empty container.
This milestone observes labels; it does not enforce AppArmor permissions or implement transitions, stacking, policy replacement, or removal.

M2 was replayed on reviewed M1 in its existing isolated worktree.
Conflict resolution retained M1's fallible policy publication, root-owned securityfs inodes, legacy boot selection, and CI coverage alongside M2's attachment decoding and accounting.
The runtime M2 series contains the `LISTEND` spelling change, the `policy/set_load` capability, and the binding/query implementation.
The subsequent documentation commit records verification without changing the tested runtime source.
New and replayed commits use the requested user identity for both author and committer.

## Resolution ledger

The strict review retained 19 findings in the M2 diff and separately identified two M1 baseline defects.
All are addressed below.

| Finding | Resolution |
| --- | --- |
| `LISTEND` commit spelling | Quote the ABI identifier with backticks in the replayed subject. |
| Repeated pathname limits | Introduce `MAX_ATTACHMENT_PATH_BYTES` and derive the traversal bound from it. |
| Uncited DFA ABI details | Cite pinned Linux sources for accept permissions and default transitions. |
| DFA closure name | Rename the callable to `transition_fn`. |
| Attachment callback names | Use `left`, `right`, `profile`, and `pair`. |
| Missing procfs module documentation | Describe task identity, authorization, and per-open snapshots. |
| Bare procfs function import | Call `template::visit_listed_entries`. |
| Bare path helper import | Call `super::is_dot_or_dotdot`. |
| Credential helper ordering | Place private `collect` after the public operations. |
| Method summary wording | Begin the path-query summary with “Returns whether”. |
| Crate-wide dead-code suppression | Remove it and exercise the path/query methods in the allocation probe. |
| Derive ordering | Place `Eq` before `PartialEq`. |
| Probe callable name | Rename the parameter to `operation_fn`. |
| NixOS suite missing from CI | Retain reviewed M1's matrix entry and verify the actual selector. |
| Plan semantic line breaks | Reflow prose at sentence boundaries. |
| Historical report semantic line breaks | Reflow prose and identify the old validation status as historical. |
| Specification semantic line breaks | Reflow prose and record the reviewed M1 base. |
| Rust documentation semantic line breaks | Separate sentences in attachment and credential documentation. |
| Missing official compatibility documentation | Document exec/execveat and proc attribute behavior in the compatibility page and SCML comments. |
| M1 release registry initialization | Retain unconditional insertion outside `debug_assert!`. |
| M1 securityfs ownership | Retain fixed root ownership and the non-root first-lookup regression. |

A single independent final review checked the integrated diff and confirmed these resolutions.
It found two integration compilation errors: a duplicated `allocator_api` feature declaration and an overly private `PolicyStore::new` used by sibling kernel tests.
Both were reproduced with compiler failures and corrected: remove the duplicate declaration and use `pub(super)` for the constructor.
The subsequent kernel-test compilation and release regression passed.
No second review was used to substitute for compiler or runtime evidence.

## Verification

The command logs, source revisions, exit codes, review notes, and production-function probes are archived under `F:/App_Armor/output/m2-review-fixes-20261028/` in the development workspace.
The remote logs reside in `/root/asterinas-m2-reviewed-20261028/.superpowers/review-20261028/` inside `asterinas-m1-dev`.
Each remote check records a `.command`, `.head`, `.log`, and `.exit` file.

| Check | Result |
| --- | --- |
| Extracted production registry, debug assertions disabled | Old M2: zero modules; integrated M2: three modules, including AppArmor. |
| Extracted securityfs constructor, caller UID/GID 65534 | Old M2: caller owns inode; integrated M2: UID/GID 0. |
| Full release SMP4 regression, `SCHEME=apparmor` | Passed, exit 0; the binding/query test reports 21 checks passed, including all 14 numbered execution cases. |
| Full release SMP4 regression, `SCHEME=apparmor-legacy` | Passed, exit 0. |
| Full release SMP4 regression, `SCHEME=apparmor-precedence` | Passed, exit 0. |
| Full release SMP4 regression, default selection | Passed, exit 0; AppArmor-disabled behavior checked. |
| Policy-store allocation failure probe | All 12 failure points returned `ENOMEM` and preserved the old snapshot. |
| Credential allocation probe, compiled with `-D warnings` | Empty init/clone/unmatched prepare/commit/drop: zero allocations; both failure paths preserve parent state; confined clone: zero allocations. |
| Full `make check` | Passed, exit 0. |
| Full default `make ktest SMP=1` | 550 passed across 18 crate summaries; zero failures, exit 0. |
| Release AppArmor kernel tests, SMP4 | 27 passed, zero failures, exit 0. |
| Release core kernel tests, SMP4 | 159 passed, zero failures, exit 0. |
| Kernel-test compilation for AppArmor/core | Passed after fixing both integration errors. |
| Actual NixOS CI selector | Selected `security-apparmor`, disk size 16384 MiB, timeout 45 minutes. |
| SCML parsing with `sctrace` | Passed, exit 0 after fetching missing build dependencies. |
| Release NixOS image build | Passed after regenerating the normal kernel artifact described below. |
| NixOS `security-apparmor`, release kernel, SMP4 | Both end-to-end tests passed, zero failures, exit 0. |

The registry and ownership probes extract production functions but use host adapters for their surrounding types.
They establish the original defects and the local correction, rather than replacing guest verification.
The release guest regressions also exercise selection and the permanent non-root securityfs ownership test.
The credential allocation measurement covers its state container, not all work performed during exec or procfs reads.
The SCML check parses the edited process/thread pattern file and traces a host command; it does not claim that every syscall in that command belongs to this one category.

The two NixOS cases verify parser compilation/loading/listing/duplicate rejection and text attachment followed by target self-queries and external PID queries.
The kernel is built in release mode; the host-side Rust test harness uses its ordinary development profile.
All planned validation gates passed on the fixed runtime revision.

## Environment and limits

Validation uses Linux/KVM, x86_64, pinned nightly-2026-07-21, and a private OSDK built from the new workspace.
The container is `asterinas/dev:0.18.1-20260926`, which differs from CI's `asterinas/kernel-dev:0.19.0-20261012`.
Local results do not establish a GitHub CI result.
The new workspace has separate test disks and NixOS image; the previous demonstration VM remains untouched.
Cargo commands run serially because component discovery can recursively invoke Cargo.

The initial build used a private OSDK embedding the old workspace path and failed dependency resolution.
Rebuilding OSDK from the new workspace corrected that setup error.
When switching kernel-test payloads, the validation driver touches the bzimage setup build script to force regeneration.
Its existing build script tracks the previous payload file but does not track changes to the `PAYLOAD_FILE` environment variable.
No tracked content is changed by this workaround.

The first NixOS boot exited before login because the packaged ELF was a kernel-test binary.
The serial log showed the kernel-test runner skipping all crates, and QEMU exited with the kernel success code 33.
The normal and test generated base crates share an output binary name in the reused Cargo target directory.
The driver therefore forces the normal generated entry point to relink after the kernel-test traversal, then rebuilds the bzImage and NixOS image.
This is a validation-cache workaround, with the failed serial log and payload hashes retained as evidence.
It does not change the M2 runtime source.

The historical full SMP4 kernel-test failures in xarray `no_leakage` and `remove_shrinks_empty_nodes` have not been reproduced against an equivalent M1 baseline.
They are not claimed to be established baseline defects or a passing full SMP4 kernel-test suite.
This validation separately covers full SMP4 userspace regressions and the relevant release kernel tests.
The unchanged generic exec argument-allocation exhaustion concern remains outside this M2 repair.

## Live walkthrough

The walkthrough used the validated release NixOS image in the separate `apparmor-m2-release-demo` tmux session.
It compared a process started before loading policy, a matching exec after loading, an unmatched executable, and their parent shell.
Target self-queries use shell builtins so that a child `cat` cannot stand in for the target process.
External queries read `/proc/<pid>/attr/current` for the same live PIDs.

The loaded text policy was:

```text
profile m2-release /tmp/aa-m2-release/program {
}
```

It was compiled and loaded inside Asterinas with:

```sh
apparmor_parser --stdout /tmp/aa-m2-release/profile > /tmp/aa-m2-release/policy.bin
apparmor_parser --binary --add /tmp/aa-m2-release/policy.bin
cat /sys/kernel/security/apparmor/profiles
```

| Process | PID in retained session | Self-query | External PID query |
| --- | --- | --- | --- |
| Matching path, started before policy load | 224 | `unconfined` | `unconfined`, including after loading |
| Matching path, executed after policy load | 233 | `m2-release (enforce)` | `m2-release (enforce)` |
| Unmatched path | 235 | `unconfined` | `unconfined` |
| Parent shell | 202 | `unconfined` | `unconfined` |

The assertions completed with `BINDING_AND_PID_QUERY_VERIFIED`.
The three helpers remain blocked on separate FIFO gates, keeping their PIDs available for inspection.
These numeric PIDs describe this retained session and will change after a reboot.

Connect from the development workstation:

```sh
ssh -t zzj@222.20.126.186 "tmux attach -t apparmor-m2-release-demo"
```

At `M2-release#`, inspect the existing policy and processes:

```sh
cat /tmp/aa-m2-release/profile
cat /sys/kernel/security/apparmor/profiles
cat /proc/224/attr/current
cat /proc/233/attr/current
cat /proc/235/attr/current
cat /proc/202/attr/current
```

Do not load the same profile again in this session: duplicate loading is intentionally rejected with `EEXIST`.
To detach while retaining the VM, press Ctrl-b followed by d.
The runnable three-step scripts and complete console transcript are archived in the evidence directory's `live-demo/` subdirectory.

The original `apparmor-m2-demo` session was not stopped or modified.
