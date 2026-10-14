# AppArmor M1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the first AppArmor milestone: a generic `securityfs`, dynamic LSM registration, ABI-v5 profile loading with attachment-DFA validation, atomic in-kernel storage, and a capability-protected `profiles` query interface, without policy binding or enforcement.

**Architecture:** `aster-core` owns two lower-layer seams: dynamic LSM registration and a generic callback-based `securityfs`. The high-level `aster-apparmor` component registers an exclusive legacy-major LSM during bootstrap; only if selected does its LSM initializer publish `/sys/kernel/security/apparmor/{.load,profiles}`. `.load` copies and validates one bounded userspace write before atomically replacing an `Arc<PolicySet>` snapshot; `profiles` formats one immutable snapshot after rechecking `CAP_MAC_ADMIN`.

**Tech Stack:** Rust 2024 `no_std`, Asterinas component system, `aster-core` VFS/SysTree, OSTD synchronization and logging, OSDK kernel tests, C initramfs regression tests, AppArmor userspace parser v5.0.2 fixtures.

**Spec:** [`docs/superpowers/specs/2026-10-10-apparmor-m1-design.md`](../specs/2026-10-10-apparmor-m1-design.md)

**Execution status (2026-10-11):** Tasks 1–6 are complete. The second review
follow-up also added the exact-1024 positive boundary and a parser-v5.0.2
`path_flags` fixture. In Task 7, formatting and the scope audit completed; the
unchecked runtime gates remain incomplete because of the environment failures
recorded in the development report, rather than being silently treated as
passing.

## Global Constraints

- Work stays local: create local commits only; do not push, open a PR, or edit the GitHub issue.
- Base behavior is the checked-out `f70c7b02af4237d17f0d58d0354e6a33562c0459`; preserve unrelated work and the untracked design/plan documents.
- Follow the repository's authoritative coding guidelines under `book/src/to-contribute/coding-guidelines/`:
  - keep every crate below `kernel/` entirely safe with `#![deny(unsafe_code)]`;
  - keep the crate graph layered: `aster-core` exposes registration seams and the high-level component supplies AppArmor;
  - declare shared dependencies in the workspace and use `.workspace = true`;
  - add module docs, use the narrowest visibility, module-qualify free functions/statics, and define `__log_prefix` before modules;
  - validate userspace bytes at `.load`, use checked arithmetic and fallible allocation, and propagate exact errno values;
  - keep user I/O and decoding outside locks; keep check/merge/publish in one mutex critical section;
  - test observable behavior and exact errno values rather than private constants or mock interactions.
- Reuse ConfigFS/SysFS/SysTree patterns. Do not add a new third-party dependency, a general read-write securityfs file variant, unregister support, or an `aa_ns` abstraction.
- M1 accepts exactly the frozen v5 subset. Attachment DFA is validated and retained but never executed. No credentials, exec path, syscall hook, label, task binding, `.replace`, `.remove`, or enforcement changes.
- Use TDD for every non-trivial step: add a test, run it and record the expected failure, implement the smallest behavior, rerun it, then refactor while green.
- Build and test in the official development container. `make test` is host-side testing; VM regression uses `make run_kernel AUTO_TEST=regression`. The design document's §12.5 command has been corrected to the official VM regression form.

## Review Focus

- ABI cursor bounds, Linux `aa_ext` end-position BLOB alignment, and exact `EINVAL`/`EPROTO`/`EOPNOTSUPP`/`EPROTONOSUPPORT` distinctions.
- DFA table-size arithmetic, width/type restrictions, duplicate/missing tables, and state/transition bounds.
- Operation-time `CAP_MAC_ADMIN` checks and the absence of any UID shortcut.
- Atomic multi-profile publication, duplicate handling, total memory charging, and no lost update with concurrent writers.
- No callback errno compression through the generic SysTree attribute error mapping.
- AppArmor absent from securityfs unless selected by `lsm=apparmor,yama`; existing Capability and Yama behavior unchanged.

---

## Task 1: Make the LSM registry extensible without changing existing selection semantics

**Files:**

- Modify: `kernel/core/src/security/lsm/mod.rs`
- Modify: `kernel/core/src/security/lsm/modules/mod.rs`
- Modify: `kernel/core/src/security/lsm/hooks/mod.rs`
- Modify: `kernel/core/src/security/lsm/hooks/alien_access.rs`
- Modify: `kernel/core/src/security/mod.rs`
- Test: `kernel/core/src/security/lsm/modules/mod.rs` (`#[cfg(ktest)]` local tests)

- [x] **Step 1: Add failing registry behavior tests**

  Add private ktests around a local `ModuleRegistry`, using static fake `LsmModule` implementations and literal expected names/errors. Cover:

  ```rust
  #[ktest]
  fn registered_module_can_be_selected_by_name() { /* apparmor is active */ }

  #[ktest]
  fn built_in_or_extension_duplicate_is_rejected() { /* EEXIST */ }

  #[ktest]
  fn sealed_registry_rejects_registration() { /* EBUSY */ }

  #[ktest]
  fn active_modules_initialize_once_in_requested_order() { /* literal call order */ }
  ```

  Also cover empty/whitespace/comma names with `EINVAL`, mandatory Capability preservation, default Yama selection, and AppArmor `EXCLUSIVE` coexisting with non-exclusive Yama.

- [x] **Step 2: Run the focused tests and confirm RED**

  Run inside the official container:

  ```sh
  cd /root/asterinas/kernel/core
  cargo osdk test
  ```

  Expected failure: the dynamic `ModuleRegistry`, public `LsmModule`, and initializer callback do not exist yet.

- [x] **Step 3: Expose only the seam required by a high-level LSM**

  In `lsm/mod.rs`:

  - make `LsmFlags` and its two flags public;
  - make `LsmModule` public and add `fn init(&self) -> Result<()> { Ok(()) }`;
  - expose `pub fn register(&'static dyn LsmModule) -> Result<()>` via the modules implementation;
  - make the two hook traits public;
  - make only the `AlienAccessContext` type public, retaining crate-private construction/accessors.

  Do not alter Capability/Yama hook bodies.

- [x] **Step 4: Implement the sealed dynamic registry**

  Add:

  ```rust
  struct ModuleRegistry {
      is_sealed: bool,
      modules: Vec<&'static dyn LsmModule>,
  }
  ```

  `register` validates names, checks both built-ins and extensions for duplicates, calls `try_reserve(1)`, and pushes only after all checks. `seal` uses `mem::take` so the spinlock is released before building the name map. Build selection from built-ins plus sealed extensions, preserving current command-line ordering, mandatory, legacy-major, and exclusive rules.

- [x] **Step 5: Initialize only the final active stack**

  Change `lsm::init()` to return `Result<()>`, log each selected module, and call its initializer in active order. Keep `security::init()` returning `()` and use an explanatory `expect` before existing TSM initialization.

- [x] **Step 6: Rerun focused and existing LSM tests**

  ```sh
  cd /root/asterinas/kernel/core
  cargo osdk test
  ```

  Expected: all new registry tests and existing Capability/Yama selection tests pass.

- [x] **Step 7: Create a local atomic commit**

  ```sh
  git add kernel/core/src/security
  git commit -m "Add dynamic LSM registration"
  ```

---

## Task 2: Add the generic securityfs filesystem and errno-preserving callbacks

**Files:**

- Create: `kernel/core/src/security/securityfs.rs`
- Create: `kernel/core/src/fs/fs_impls/securityfs/mod.rs`
- Create: `kernel/core/src/fs/fs_impls/securityfs/fs.rs`
- Create: `kernel/core/src/fs/fs_impls/securityfs/inode.rs`
- Create: `kernel/core/src/fs/fs_impls/securityfs/node.rs`
- Create: `kernel/core/src/fs/fs_impls/securityfs/test.rs`
- Modify: `kernel/core/src/security/mod.rs`
- Modify: `kernel/core/src/fs/mod.rs`
- Modify: `kernel/core/src/fs/fs_impls/mod.rs`

- [x] **Step 1: Add failing securityfs ktests through public behavior**

  Add real callback functions backed by local static test state and test:

  - read-only mode `0444`, write-only mode `0666`;
  - missing operation returns `EBADF` regardless of mode;
  - invalid directory/file names, empty file list, and duplicates return their specified errno;
  - duplicate directory registration returns `EEXIST`;
  - callback `EPROTO` survives VFS `write_at` as `EPROTO`;
  - read offset reaches the callback unchanged;
  - root remains parentless and reports `is_root()`;
  - userspace create/unlink attempts fail.

  Use unique literal directory names per global-tree test so tests do not need a production reset API.

- [x] **Step 2: Run the focused test and confirm RED**

  ```sh
  cd /root/asterinas/kernel/core
  cargo osdk test
  ```

  Expected failure: securityfs modules and callback descriptors are absent.

- [x] **Step 3: Implement the minimal public facade**

  Define only:

  ```rust
  pub type ReadCallback = fn(usize, &mut VmWriter) -> Result<usize>;
  pub type WriteCallback = fn(usize, &mut VmReader) -> Result<usize>;

  pub struct SecurityFsFile { /* private fields */ }

  impl SecurityFsFile {
      pub const fn read_only(name: &'static str, read_fn: ReadCallback) -> Self;
      pub const fn write_only(name: &'static str, write_fn: WriteCallback) -> Self;
  }

  pub fn register_directory(
      name: &'static str,
      files: &'static [SecurityFsFile],
  ) -> Result<()>;
  ```

  Represent the closed operation set with a private enum. Validate names and duplicate file entries once at registration; do not add unregister or owned callback tables.

- [x] **Step 4: Implement filesystem, nodes, and inode adapter by reusing SysTree**

  - `SecurityFs` is a singleton anonymous pseudo filesystem with Linux magic `0x73636673`, block size 4096, and name limit 255.
  - `SecurityRootNode` uses root branch fields, mode `0555`, no parent, and an internal `add_child`.
  - `SecurityDirectory` builds one immutable `SysAttrSet`, keeps the static file slice, and linearly locates one of its small number of files.
  - `SecurityFsInode` mirrors `ConfigInode`/`SysFsInode`, rejects creation, and uses dynamic revalidation.
  - Override only `FileOps::read_at` and `write_at`; downcast to `SecurityDirectory` and call its core-`Result` methods directly so `EPROTO`, `E2BIG`, and similar errors do not become `EIO`.
  - Retain SysTree attr callbacks only for its trait contract and perform the documented limited error conversion there.

- [x] **Step 5: Register and export securityfs at the correct initialization point**

  In `fs_impls::init`, initialize securityfs immediately after sysfs. Its initializer creates `/sys/kernel/security` as a sysfs mount point and registers `SecurityFsType`. Re-export only the facade through `aster_core::security::securityfs` and the crate-internal filesystem registration hook needed by it.

- [x] **Step 6: Rerun focused tests and compile the core**

  ```sh
  cd /root/asterinas/kernel/core
  cargo osdk test
  cargo osdk check
  cargo osdk check --ktests
  ```

  Expected: exact errno assertions pass and `aster-core` builds with no new warning.

- [x] **Step 7: Create a local atomic commit**

  ```sh
  git add kernel/core/src/fs kernel/core/src/security
  git commit -m "Add generic securityfs support"
  ```

---

## Task 3: Create the AppArmor crate and validate the frozen attachment DFA format

**Files:**

- Create: `kernel/comps/apparmor/Cargo.toml`
- Create: `kernel/comps/apparmor/src/lib.rs`
- Create: `kernel/comps/apparmor/src/policy/mod.rs`
- Create: `kernel/comps/apparmor/src/policy/dfa.rs`
- Modify: `Cargo.toml` (workspace member only at this stage)

- [x] **Step 1: Scaffold the safe high-level crate without linking it into the kernel**

  Use package name `aster-apparmor`, Rust 2024 workspace edition/lints, `#![no_std]`, `#![deny(unsafe_code)]`, module-level docs, and an `"apparmor: "` log prefix. Add only dependencies already needed by this task (`aster-core`, `ostd`); defer `aster-util` and `component` until the wiring task.

- [x] **Step 2: Add failing DFA tests from one hand-checked minimal matcher**

  Keep the byte encoder under `#[cfg(ktest)]`. Assert one literal valid DFA passes, then mutate one field at a time to cover:

  - short/minimum header, magic, serialized/header size, table truncation/trailing bytes;
  - unknown flags as `EPROTO`, known DIFF/OOB as `EOPNOTSUPP`;
  - invalid/duplicate/missing table id and invalid width;
  - required table widths and matching state/transition lengths;
  - DEFAULT/NEXT/CHECK and BASE+255 bounds;
  - EC, META, 32-bit state tables, BASE DIFF/OOB as `EOPNOTSUPP`;
  - non-zero per-table padding remains accepted.

- [x] **Step 3: Run the focused test and confirm RED**

  ```sh
  cd /root/asterinas/kernel/comps/apparmor
  cargo osdk test
  ```

  Expected failure: `dfa::validate` is unimplemented.

- [x] **Step 4: Implement bounded DFA parsing and validation**

  Implement private `TableView`, `parse_table_set`, `verify_table_shapes`, and `verify_state_bounds`, with `validate` calling them in that order. Use safe byte slices and big-endian conversions only. Use `checked_mul`/`checked_add`; require exact consumption; skip but do not inspect table padding. Keep the public surface to `pub(super) fn validate(&[u8]) -> Result<()>`.

- [x] **Step 5: Rerun DFA tests and crate build**

  ```sh
  cd /root/asterinas/kernel/comps/apparmor
  cargo osdk test
  cargo osdk check
  cargo osdk check --ktests
  ```

- [x] **Step 6: Create a local atomic commit**

  ```sh
  git add Cargo.toml Cargo.lock kernel/comps/apparmor
  git commit -m "Validate AppArmor attachment DFAs"
  ```

---

## Task 4: Decode the exact multi-profile AppArmor ABI-v5 subset

**Files:**

- Create: `kernel/comps/apparmor/src/policy/abi.rs`
- Modify: `kernel/comps/apparmor/src/policy/mod.rs`

- [x] **Step 1: Add failing ABI tests using test-only byte encoders**

  Encode expected bytes independently of production cursor helpers. Cover the specification's complete observable decoder matrix:

  - minimal enforce, complain, attachment, and two-unit streams;
  - name/mode/xmatch length/DFA retention;
  - every strict prefix of a single unit is `EPROTO`;
  - multi-unit prefixes succeed only at complete unit boundaries;
  - bad code/length/NUL, extra bytes, missing second header, unsupported fields/modes/caps;
  - v7 `EPROTONOSUPPORT`, namespace `EOPNOTSUPP`, invalid UTF-8 `EILSEQ`, invalid/oversize names `EINVAL`;
  - two attached profiles where unit one is not 8-byte aligned, proving the second BLOB uses Linux's end-position formula;
  - non-zero BLOB leading padding is `EPROTO`.

  Before asserting the multi-attachment result, assert the test prerequisite `first_unit_len & 7 != 0` so a fixture change cannot silently remove the regression.

- [x] **Step 2: Run the focused test and confirm RED**

  ```sh
  cd /root/asterinas/kernel/comps/apparmor
  cargo osdk test
  ```

- [x] **Step 3: Add the policy domain types with private fields and narrow getters**

  Add `ProfileMode`, `AttachmentMatcher`, `Profile`, and `DecodedPolicy`. Use fallible allocations for owned name/DFA bytes. Keep attachment getters crate-private and do not add execution/matching methods.

- [x] **Step 4: Implement the non-recursive bounded cursor**

  Implement `Code` and `Cursor` exactly as specified. Every position/length operation must be checked. For `aligned_blob`, calculate:

  ```rust
  let data_end = data_start.checked_add(total_len).ok_or(EPROTO)?;
  let rem = data_end & 7;
  let size_before_pad = data_start.checked_sub(rem).ok_or(EPROTO)?;
  let pad = (8 - (size_before_pad & 7)) & 7;
  ```

  Validate the whole leading padding is zero, advance over the entire BLOB once, and return only the DFA slice. Do not align directly from global `data_start`.

- [x] **Step 5: Implement strict header/profile decoding**

  Decode repeated `version + profile` units without synchronization scanning or field reordering. Accept only version 5, zero capabilities, frozen flags/modes, optional validated `aadfa`, and the exact end marker. Return `EOPNOTSUPP` only for well-formed known-but-unimplemented input, and `EPROTO` for corruption.

- [x] **Step 6: Rerun ABI plus DFA tests**

  ```sh
  cd /root/asterinas/kernel/comps/apparmor
  cargo osdk test
  ```

- [x] **Step 7: Create a local atomic commit**

  ```sh
  git add kernel/comps/apparmor/src/policy
  git commit -m "Decode AppArmor ABI v5 profiles"
  ```

---

## Task 5: Add the bounded, atomic global PolicyStore

**Files:**

- Modify: `kernel/comps/apparmor/src/policy/mod.rs`

- [x] **Step 1: Add failing local-store tests**

  Every test creates `PolicyStore::new()` and starts from `snapshot().is_none()`. Cover:

  - one load and a two-profile atomic load, always sorted by name;
  - two successful sequential loads preserve both profiles;
  - duplicate within one blob and conflict with current state return `EEXIST` without mutation;
  - decoder failure preserves the same snapshot pointer and contents;
  - profile-count and charged-byte limits return `ENOSPC`;
  - two concurrent writers never lose one profile;
  - a reader sees only a complete old or complete new snapshot.

  Construct over-limit private `DecodedPolicy` values inside the module test; do not add production reset or test hooks.

- [x] **Step 2: Run the focused test and confirm RED**

  ```sh
  cd /root/asterinas/kernel/comps/apparmor
  cargo osdk test
  ```

- [x] **Step 3: Implement sorted immutable sets and transactional merge**

  Add the four documented limits, `PolicySet`, `PolicyStore`, and the single global store. `PolicySet::try_insert_all` performs checked count/charge validation, sorts incoming profiles, detects adjacent/current conflicts, reserves the full candidate vector, and merges old `Arc<Profile>` plus new profiles. It returns a complete candidate or an error and never mutates current state.

- [x] **Step 4: Keep parsing and user work outside the mutex**

  `PolicyStore::load` validates the input bounds, decodes before locking, then holds one sleepable mutex across current-state validation, candidate construction, and the single `Arc` replacement. `snapshot` only clones the `Arc` under the mutex. Do not add RCU, generation numbers, or a second writer lock.

- [x] **Step 5: Rerun store and all AppArmor ktests**

  ```sh
  cd /root/asterinas/kernel/comps/apparmor
  cargo osdk test
  ```

- [x] **Step 6: Create a local atomic commit**

  ```sh
  git add kernel/comps/apparmor/src/policy/mod.rs
  git commit -m "Store AppArmor profiles atomically"
  ```

---

## Task 6: Drive component/securityfs wiring from end-to-end regression tests

**Files:**

- Create: `kernel/comps/apparmor/src/securityfs.rs`
- Modify: `kernel/comps/apparmor/src/lib.rs`
- Modify: `kernel/comps/apparmor/Cargo.toml`
- Modify: `Cargo.toml` (workspace dependency/default member)
- Modify: `Components.toml`
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/lib.rs`
- Create: `test/initramfs/src/regression/security/lsm/apparmor.c`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/features`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/features-v7`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/demo.profile`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/observe.profile`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/multi.profile`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/multi-attach.profile`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/namespace-base.profile`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/demo.bin`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/observe.bin`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/multi.bin`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/multi-attach.bin`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/namespaced.bin`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/v7-empty.bin`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/generate.sh`
- Create: `test/initramfs/src/regression/security/lsm/apparmor-fixtures/SHA256SUMS`
- Modify: `test/initramfs/src/init`
- Modify: `test/initramfs/src/regression/security/run_test.sh`
- Modify: `test/initramfs/src/regression/security/lsm/Makefile`
- Modify: `test/initramfs/src/regression/security/lsm/module_selection.c`
- Modify: `test/initramfs/src/regression/fs/pseudofs/pseudo_dev_id.c`
- Modify: `OSDK.toml`

- [x] **Step 1: Add fixtures and tests before linking the component**

  Append an `apparmor` OSDK scheme whose `boot.kcmd_args` contains only `lsm=apparmor,yama`; OSDK's scheme inheritance appends it to the default boot arguments. Mount `securityfs` on `/sys/kernel/security` after sysfs and before regression execution.

  Add fixture sources, generator, hashes, and binary packaging. The generator must reject non-Linux hosts and any parser version other than exactly 5.0.2, generate uncompressed v5 fixtures plus the v7 negative fixture, and update `SHA256SUMS`. Check the frozen size/hash table from the spec, including:

  ```text
  multi-attach.bin  3016 bytes
  be5438f6407bbbee631214f30550754ee2f093de8ff5a0e578c0bff084a883bd
  ```

  After the common Makefile include, add explicit `.bin` prerequisites and a copy rule into `$(OBJ_OUTPUT_DIR)/apparmor-fixtures/`; the common rules do not package binary fixtures.

  Add one user-visible C test that branches on effective LSM selection. On default boot, assert securityfs is mounted but the AppArmor directory is `ENOENT`. On the AppArmor scheme, assert the full behavior from spec §12.5 with exact errno values:

  - file existence/modes and absent unsupported files;
  - empty initial query, successful demo/multi-attachment/observe loads, literal sorted output;
  - duplicate/conflicting batch atomicity;
  - truncation, corrupt DFA, corrupt second-BLOB padding, namespace, v7, and oversize failures with unchanged query;
  - capability removal, non-root `CAP_MAC_ADMIN` without DAC override, and operation-time recheck;
  - `EBADF` for the unsupported I/O direction;
  - ordinary capability behavior unchanged before/after loads.

  Use exactly one `write(2)` per policy fixture. Derive mutation offsets from fixture parsing in the test or store named checked offsets next to hash/size assertions; never use an unchecked blind offset.

  Add AppArmor to `module_selection.c` expectations without weakening Yama checks. Add securityfs to pseudo-filesystem major/minor/uniqueness arrays and resize the literal array count. Run `apparmor` from `security/run_test.sh`.

- [x] **Step 2: Run the real AppArmor regression and confirm RED**

  First run the default regression to validate the new mount and the inactive branch, then run the selected scheme:

  ```sh
  cd /root/asterinas
  make run_kernel AUTO_TEST=regression
  make run_kernel AUTO_TEST=regression SCHEME=apparmor
  ```

  Expected: default regression passes; the AppArmor scheme fails because the registered component and `/sys/kernel/security/apparmor` files do not exist yet. Record that failure before writing the wiring code.

- [x] **Step 3: Implement the AppArmor securityfs callbacks**

  Register only:

  ```rust
  static FILES: [SecurityFsFile; 2] = [
      SecurityFsFile::write_only(".load", write_load),
      SecurityFsFile::read_only("profiles", read_profiles),
  ];
  ```

  `check_policy_admin` obtains the current POSIX thread, calls the existing capability LSM hook against the initial user namespace with `CapSet::MAC_ADMIN`, and maps all denial/missing-task cases to `EACCES`. Call it at the beginning of every read/write operation. Copy one entire bounded reader buffer fallibly, require `.load` offset zero, call `POLICY_STORE.load`, and return the original write length. Format `profiles` from one cloned snapshot with `VmPrinter::new_skip` after dropping the store lock. Do not introduce credential mocks or production bypasses; the C regression exercises real task credentials.

- [x] **Step 4: Register the LSM at bootstrap and securityfs only when selected**

  Implement `AppArmorLsm` with empty default-allow hook implementations, `LEGACY_MAJOR | EXCLUSIVE`, and `init()` calling this crate's securityfs registration. The component initializer only calls `lsm::register(&APPARMOR_LSM)` and maps a registration failure to `ComponentInitError::Unknown` after one clear OSTD log message.

- [x] **Step 5: Link the high-level component using repository conventions**

  Add `aster-apparmor` to workspace/default members and workspace dependencies, `Components.toml`, the assembler dependency list, and `extern crate aster_apparmor as _;`. Add `component` and `aster-util` to the crate only now that production code uses them.

- [x] **Step 6: Turn the focused and end-to-end tests GREEN**

  ```sh
  cd /root/asterinas/kernel/comps/apparmor
  cargo osdk test
  cd /root/asterinas
  make kernel
  make run_kernel AUTO_TEST=regression
  make run_kernel AUTO_TEST=regression SCHEME=apparmor
  ```

  Expected: AppArmor ktests pass; default boot leaves the securityfs directory absent; selected boot passes every load/query/permission/atomicity assertion with `lsm=apparmor,yama`.

- [x] **Step 7: Create a local atomic commit**

  ```sh
  git add Cargo.toml Cargo.lock Components.toml OSDK.toml kernel/Cargo.toml kernel/src/lib.rs kernel/comps/apparmor test/initramfs/src
  git commit -m "Expose AppArmor policy loading through securityfs"
  ```

---

## Task 7: Run official formatting, lint, build, and regression gates

**Files:**

- Modify only files required to fix issues found by verification; do not widen M1.

- [x] **Step 1: Format using the repository toolchain**

  ```sh
  cd /root/asterinas
  make format
  git diff --check
  ```

  Inspect the formatter diff and retain only mechanical changes to in-scope files.

- [ ] **Step 2: Run the full static check**

  ```sh
  cd /root/asterinas
  make check
  ```

  Fix every in-scope warning, including workspace lint, license header, typo, C formatting, and unreachable-public findings.

- [ ] **Step 3: Run host and kernel unit suites**

  ```sh
  cd /root/asterinas
  make test
  make ktest
  ```

- [ ] **Step 4: Build the kernel and run both relevant regression modes**

  ```sh
  cd /root/asterinas
  make kernel
  make run_kernel AUTO_TEST=regression
  make run_kernel AUTO_TEST=regression SCHEME=apparmor
  ```

- [x] **Step 5: Audit the final diff against scope and security invariants**

  Confirm:

  - no `unsafe`, task label, namespace, matcher execution, enforcement hook, `.replace`, or `.remove` was added;
  - no parser/formatter/user copy occurs while holding `PolicyStore`'s mutex;
  - every input-derived length/index uses checked arithmetic;
  - existing Capability/Yama paths are behaviorally unchanged;
  - all new public items have a demonstrated cross-crate consumer;
  - fixture binaries match `SHA256SUMS` and the spec's size/hash table;
  - `git status --short` contains only intended implementation, fixture, test, spec, and plan files.

- [x] **Step 6: Commit verification-only fixes locally if any**

  Amend the logical commit that introduced each issue where practical; otherwise create one focused local cleanup commit. Do not push.

## Explicitly Deferred

- `aa_ns`/policy namespaces, labels, profile replacement/removal, attachment matching, policy binding, exec transitions, and enforcement.
- DFA DIFF/OOB/EC and 32-bit state-table encodings until a real golden fixture and execution requirement exist.
- Parser installation in initramfs; regression consumes checked-in reproducible binaries.
- General securityfs per-open authorization hooks or read-write descriptors; M1 has no second consumer proving those abstractions are needed.
