# M1 Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax.

**Goal:** Resolve the 18 retained M1 review comments and the local agent-commit identity constraint.

**Architecture:** Keep the existing M1 loading/query design and its milestone boundaries.
Correct initialization and ownership at their existing boundaries, use fallible runtime allocation, and connect the existing tests to CI.
Work in the isolated `apparmor-m1-reviewed` branch; rebuild only the local M1 commit series, leaving the shared original branch untouched.

**Tech Stack:** Rust nightly-2026-07-21, C regression tests, NixOS tests, GitHub Actions.

**Spec:** `F:/App_Armor/output/reviews/2026-10-27-m1-complete-review.md` and `docs/superpowers/specs/2026-10-10-apparmor-m1-design.md`.

## Global Constraints

- Preserve M1 policy loading/query scope; no task labels or enforcement.
- All kernel code remains safe Rust with `#![deny(unsafe_code)]`.
- No new runtime dependencies.
- New/rewritten author and committer: `zzj-5341 <242576472+zzj-5341@users.noreply.github.com>`.
- Original shared checkout and upstream commits are preserved; no push or merge.
- Do not change the specified capacity-before-duplicate error priority.
- Record unavailable kernel/QEMU/Nix validation explicitly.

## Review Focus

- Release builds must select both AppArmor and Yama.
- OOM at profile and final snapshot allocation must return `ENOMEM` without publication.
- An ordinary first lookup must not own securityfs inodes.
- Legacy and modern selectors must share last-value and precedence behavior.
- CI must execute enabled and disabled paths, including release.

---

### Task 1: Runtime correctness and ownership

**Files:** `kernel/core/src/security/lsm/modules/mod.rs`; `kernel/comps/apparmor/src/{lib.rs,policy/mod.rs}`; `kernel/core/src/fs/fs_impls/securityfs/{inode.rs,test.rs}`.

**Interfaces:** Preserve `register`/`LsmModule`, `PolicyStore::load`/`snapshot` and the securityfs declaration API.

- [x] Add focused release-map, allocation-failure and unprivileged-first-lookup regression checks.
- [x] Run the available reproductions before edits and record the expected failures.
- [x] Execute map insertion outside debug assertions.
- [x] Use `Arc::try_new` and map failures to `ENOMEM` before publication.
- [x] Normalize securityfs inode UID/GID to root in its constructor.
- [x] Run focused checks and retain kernel regression tests even when the runner is unavailable.

### Task 2: Regression selection and CI

**Files:** `OSDK.toml`; `test/initramfs/src/regression/security/lsm/{apparmor.c,module_selection.c}`; `.github/{actions/test/action.yml,workflows/test_x86.yml,workflows/test_nixos_full.yml}`.

**Interfaces:** Consume unchanged boot selectors and the existing test action `scheme` input.

- [x] Exercise default/modern/legacy/both/last-value selector inputs against the real C helpers before fixing.
- [x] Recognize legacy selection and preserve `lsm=` precedence in both helpers.
- [x] Add a normal-user-first-lookup ownership/chmod regression before root lookups warm AppArmor entries.
- [x] Add modern, legacy and precedence schemes to regression CI, including release.
- [x] Register `security-apparmor` in the NixOS suite allowlist.
- [x] Validate matrix selection and compile relevant test sources with an available toolchain.

### Task 3: Source and documentation conventions

**Files:** `kernel/comps/apparmor/src/policy/{abi.rs,dfa.rs,mod.rs}`; `kernel/core/src/{security/securityfs.rs,fs/fs_impls/securityfs/node.rs}`; `book/src/kernel/linux-compatibility/kernel-parameters.md`; new M1 Markdown.

**Interfaces:** Keep actual sibling-crate consumers working; update ktest references when removing bare imports.

- [x] Reduce unused visibility, qualify constants/free functions and use `_fn` callback names.
- [x] Put decode flow before cursor helpers, and derive attributes last.
- [x] Cite a pinned Linux DFA format/validator source and mark M1-specific restrictions.
- [x] Document both boot selectors in the official parameter reference.
- [x] Apply semantic line breaks to added non-RFC Markdown without changing content.
- [x] Clarify known parser same-fd multi-profile limits without expanding M1 scope.
- [x] Run formatting, diff checks and applicable regression probes.

### Task 4: Reviewable history and final verification

**Files:** Local branch history and a new verification report.

**Interfaces:** Reconstruct final M1 tree over upstream base `01acaa7`; preserve existing shared `apparmor-m1-complete` at `0c52710`.

- [x] Commit logical LSM, securityfs, AppArmor, regression/CI, parser, NixOS and documentation units with the required identities.
- [x] Use identifier backticks in commit subjects and avoid review-fixup commits.
- [x] Check every new commit's author/committer and the complete final tree.
- [x] Run a fresh independent whole-change review, address material findings and complete available checks.
- [x] Record exact commands, passed checks and unavailable runtime checks.
