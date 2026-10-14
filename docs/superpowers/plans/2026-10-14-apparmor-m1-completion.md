# AppArmor M1 Completion Plan

**Date:** 2026-10-14
**Status:** Completed and validated on 2026-10-15
**Base implementation:** `5f6d576` (eight local AppArmor commits based on `f70c7b0`)
**Goal:** Finish M1 so an Asterinas NixOS user can write an AppArmor v5 text profile, compile it with `apparmor_parser` 5.0.2, load it through securityfs, and query the stored profile.

## 1. Corrected milestone boundary

The kernel does not compile AppArmor text. `apparmor_parser` is a userspace compiler and `.load` accepts its binary ABI stream. Therefore M1 is complete only when both halves below work together:

1. the kernel publishes the supported v5 feature and accepts/queries compiled profiles;
2. Asterinas NixOS supplies a compatible `apparmor_parser` and proves the text-to-kernel path end to end.

M1 still means **load and observe, not enforce**. It does not bind labels to tasks, select profiles during `exec`, interpret permissions, deny operations, or implement policy replacement/removal. Those belong to later milestones.

## 2. Frozen public seams

Implementation must preserve these externally observable contracts:

- `/sys/kernel/security/apparmor/.load`
  - write-only;
  - accepts one AppArmor ABI v5 stream per write;
  - keeps multi-profile publication atomic;
  - rechecks `CAP_MAC_ADMIN` at operation time;
  - rejects an existing name with `EEXIST`.
- `/sys/kernel/security/apparmor/profiles`
  - read-only;
  - returns sorted `<name> (<mode>)\n` records;
  - reports stored profiles, not active enforcement.
- `/sys/kernel/security/apparmor/features/policy/versions/v5`
  - read-only;
  - returns `yes\n`;
  - advertises only the ABI version M1 actually accepts.
- `apparmor_parser`
  - exact userspace version 5.0.2 in the Asterinas NixOS package set;
  - compiles an empty/complain-mode v5 profile against the runtime feature tree;
  - does not require a precompiled fixture for the end-to-end demonstration.

No compatibility is promised for the rest of Linux AppArmor's feature tree or policy lifecycle ABI.

## 3. Scope map

### Kernel seam and VFS adapter

- Modify `kernel/core/src/security/securityfs.rs` to represent the minimum immutable recursive declaration: directories and callback-backed files.
- Modify `kernel/core/src/fs/fs_impls/securityfs/node.rs` and, if required by the existing SysTree adapter, its sibling `mod.rs`/`inode.rs` files.
- Modify `kernel/core/src/fs/fs_impls/securityfs/test.rs` with behavior tests for nested lookup, read permissions, invalid names, and duplicate siblings.
- Preserve the existing flat-directory caller behavior through the same entry representation; do not add mutation, removal, symlinks, per-open callbacks, or general-purpose dynamic trees.

### AppArmor feature publication

- Modify `kernel/comps/apparmor/src/securityfs.rs` to register `.load`, `profiles`, and the static `features/policy/versions/v5` hierarchy together.
- Add a small constant read callback for `yes\n` with normal offset/EOF behavior.
- Modify `test/initramfs/src/regression/security/lsm/apparmor.c` to assert the runtime v5 feature file exists and returns exactly `yes\n`.
- Replace the old assertion that the feature path is absent.

### Asterinas NixOS userspace compiler

- Add `distro/etc_nixos/overlays/apparmor/default.nix` following existing overlay layout.
- Override the AppArmor userspace source consistently so `libapparmor` and `apparmor-parser` are both 5.0.2; do not mix a 5.0.2 parser with the pinned nixpkgs 4.x library.
- Register the overlay in `distro/aster_nixos_installer/templates/aster_configuration.nix`.
- Use the upstream release archive and a fixed content hash. Do not vendor parser sources into the kernel repository.

### End-to-end proof

- Add the smallest NixOS test suite under `test/nixos/tests/security-apparmor/`.
- Its Nix configuration installs only `apparmor-parser`.
- Its Rust test writes a text profile in the guest, verifies parser version 5.0.2, compiles/loads it through the runtime feature tree, then checks `profiles` contains the expected complain-mode record.
- The test also repeats the load and checks that the command fails because the kernel returns `EEXIST`; it must not rely on a checked-in `.bin` file.

### Documentation and audit trail

- Update the M1 design document for the feature tree and userspace parser boundary.
- Update the development report with changed files, exact commands, results, commit range, and any unexecuted gate.
- Keep GitHub issue/PR changes out of scope until the user reviews the local result.

## 4. Execution order (TDD)

### Task 1 — Preserve history and synchronize the base

1. Fetch official `origin/main`.
2. Create `apparmor-m1-complete` at the current local implementation head.
3. Rebase that branch onto the fetched official main.
4. Resolve only conflicts caused by the eight AppArmor commits; do not rewrite unrelated upstream work.
5. Record the old head, new base, and rebased head in the development report.

This happens before new source edits so later review compares the completed change against one current upstream base.

### Task 2 — RED: specify nested securityfs behavior

1. Add focused kernel tests that declare `features/policy/versions/v5`.
2. Cover successful nested lookup and `yes\n` reads at offsets 0, partial offset, and EOF.
3. Cover empty/invalid names and duplicate file-directory siblings with the existing errno conventions.
4. Run `cargo osdk check --ktests` and `cargo osdk test`; record the expected pre-implementation failure.

### Task 3 — GREEN: implement the minimum immutable tree

1. Add one recursive entry declaration to the public seam.
2. Map it into the existing SysTree node model without dynamic mutation.
3. Keep callback error mapping and file mode behavior unchanged.
4. Run formatting, `cargo osdk check --ktests`, and the whole crate ktest command; do not use module-name filters that can silently run zero tests.

### Task 4 — RED/GREEN: publish the AppArmor feature

1. Change the C regression to expect `features/policy/versions/v5 == "yes\n"`.
2. Add/adjust the AppArmor securityfs ktest for offset reads.
3. Register the feature hierarchy and implement the constant callback.
4. Run AppArmor/core checks and the native AppArmor regression.

### Task 5 — RED/GREEN: package parser 5.0.2

1. Add an evaluation/build check that references `pkgs.apparmor-parser` and requires version 5.0.2.
2. Add the paired package overlay with a verified upstream hash.
3. Build the package in the official Asterinas NixOS environment.
4. If upstream 5.0.2 needs an Asterinas-specific portability patch, add only the failing portability fix and document it; do not pre-emptively fork or refactor upstream code.

### Task 6 — RED/GREEN: text-profile end-to-end test

1. Add the NixOS suite and a textual `profile observe flags=(complain) {}` input.
2. First run must fail before the package/feature integration is complete and the failure is recorded.
3. Make the minimum config/test changes needed for:
   `text -> apparmor_parser 5.0.2 -> .load -> profiles`.
4. Run the single test case, then the full suite.

### Task 7 — Final gates and review material

Run, in order:

1. `cargo fmt --all -- --check` (or the repository's narrower documented formatter command if upstream changed it);
2. `cargo osdk check` and `cargo osdk check --ktests` for touched kernel crates;
3. `cargo osdk test` without a module-only filter;
4. `make run_kernel AUTO_TEST=regression`;
5. `make run_kernel AUTO_TEST=regression SCHEME=apparmor`;
6. `make nixos NIXOS_TEST_SUITE=security-apparmor`;
7. `make run_nixos NIXOS_TEST_SUITE=security-apparmor`;
8. `git diff --check`, unsafe-code scan, test-count/output audit, and clean-scope audit.

Any gate that cannot execute is reported as **not run**, never converted into a pass because compilation succeeded.

## 5. Planned local commit sequence

Commits stay local until review:

1. `Extend securityfs with immutable nested directories`
2. `Advertise AppArmor ABI v5 through securityfs`
3. `Package apparmor_parser 5.0.2 for Asterinas NixOS`
4. `Test AppArmor text profile loading on Asterinas NixOS`
5. `Document AppArmor M1 completion and validation`

The rebase is history maintenance, not a feature commit. If one task needs no source change after synchronization, its empty planned commit is omitted.

## 6. Acceptance criteria

M1 is complete only if all of the following are evidenced:

- the feature file reads exactly `yes\n`;
- `apparmor_parser --version` reports 5.0.2 in Asterinas NixOS;
- a profile authored as text inside the guest loads without using a precompiled fixture;
- `profiles` reports `observe (complain)`;
- a duplicate load fails and the original store remains unchanged;
- existing ABI fixture, multi-profile atomicity, permission, and malformed-input tests still pass;
- no label binding or policy enforcement is claimed;
- the final report identifies any gate that was not actually run.

## 7. Risk and rollback

- **Rebase risk:** upstream may have changed LSM, SysTree, NixOS, or test APIs. Keep the pre-rebase head address and work on a new branch so the old implementation remains recoverable.
- **ABI advertisement risk:** exposing v5 lets the parser emit constructs outside M1's frozen subset. The end-to-end test deliberately uses only an empty complain profile; unsupported constructs must continue to fail closed rather than be advertised as supported.
- **Package risk:** parser and `libapparmor` version skew can build yet fail at runtime. The overlay changes both from one source revision and the guest test verifies the executable path.
- **Test-environment risk:** Nix builds and VM gates are resource-intensive. A build-only result is insufficient for final acceptance.

Rollback is commit-granular. The original eight-commit implementation remains reachable by its recorded head even after the completion branch is rebased.

## 8. Execution record

- [x] Task 1 — rebased the eight existing commits from `5f6d576` onto official `01acaa7` on `apparmor-m1-complete`.
- [x] Task 2 — added nested securityfs RED tests.
- [x] Task 3 — implemented the minimum immutable recursive tree; flat callers remain compatible.
- [x] Task 4 — published only `features/policy/versions/v5`; AppArmor regression is 73/73.
- [x] Task 5 — packaged and fully tested parser/libapparmor 5.0.2.
- [x] Task 6 — passed the guest text-profile end-to-end test, including duplicate-load atomicity.
- [x] Task 7 — passed formatting, compile/ktest, default/AppArmor regression, NixOS build/run, whitespace and scope gates.

The final implementation head before the documentation-only commit is `ef3c27d`. Exact commands, results and the note about ineffective standalone crate `cargo osdk test` attempts are recorded in `../reports/2026-10-15-apparmor-m1-completion-report.md`.

## 9. Final-review follow-up (2026-10-15)

This follow-up is limited to the non-blocking findings from the accepted M1 review:

1. Add an explicit ktest assertion that every declared securityfs directory is mode `0555`.
2. Document that multi-profile atomicity is guaranteed per direct `.load` write; the current parser path may split one buffer into multiple writes because `policy/set_load` is not advertised.
3. Record full Linux DFA semantic validation as the first M2 gate before any matcher is executed.
4. Record that the AppArmor overlay affects every Asterinas NixOS configuration using the shared template.
5. Re-run the focused ktest/compile checks and whitespace audit, then update the completion report with the exact result.

Adding `policy/set_load`, changing parser behavior, or introducing repository-wide line-ending policy is outside this follow-up because each would expand M1 behavior rather than close an acceptance gap.

Execution record:

- [x] Directory mode assertions added for the top-level declaration and every nested level.
- [x] Parser atomicity boundary, M2 DFA gate, and global overlay scope documented.
- [x] `cargo osdk check --ktests` for `aster-core`, repository-level `make ktest`, `cargo fmt --all -- --check`, and `git diff --check` passed in the Linux development container.
