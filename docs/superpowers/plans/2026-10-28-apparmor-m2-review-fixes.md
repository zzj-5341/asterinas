# AppArmor M2 Review Fixes Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task.

**Goal:** Integrate reviewed M1 into M2, address every retained M2 review finding, and verify release attachment and PID queries before a live walkthrough.

**Architecture:** Preserve the old M2 branch and replay its changes on reviewed M1 in the existing isolated worktree.
Keep empty credential security state allocation-free and retain immutable profile sharing.
Use the existing server container and private OSDK for sequential kernel validation.

**Tech Stack:** Safe Rust kernel, C regression tests, NixOS, QEMU/KVM, nightly-2026-07-21.

**Spec:** `docs/superpowers/specs/2026-10-27-apparmor-m2-design.md`.
The fixed review input is `0c527109..02c8e860` and the accepted findings are in `F:/App_Armor/output/reviews/2026-10-28-m2-strict-review.md`.

## Global Constraints

- Exact-path attachment, credential binding, and PID queries stay in one M2 PR.
- Empty security state creates neither an unconfined object nor an empty container.
- M2 does not implement permission enforcement, transitions, or policy replacement.
- New and rewritten commits use author and committer `zzj-5341 <242576472+zzj-5341@users.noreply.github.com>`.
- Preserve the original M1, reviewed M1, and original M2 refs.
- Do not interrupt the existing demo VM or other server workspaces.
- Store command logs and a per-finding resolution ledger; do not infer runtime success from compilation.

## Review Focus

- Release disables debug assertions: explicit AppArmor selection must still work.
- A non-root first lookup must not gain ownership of securityfs interfaces.
- Replaying M2 must preserve M1 OOM propagation, legacy selection, and CI coverage.
- PID snapshots and fork/exec state separation must survive the integration unchanged.
- Documentation must describe observation without implying permission enforcement.

### Task 1: Integrate the reviewed M1 baseline

**Files:** M1-reviewed tree plus the four original M2 commits.
**Interfaces:** Consumes M1 `7d0055d4be91724072c416d6a6a39de85c25fc50`; produces a branch with reviewed M1 ancestry and existing M2 behavior.

- [x] Run extracted production-function checks against old M2 and record the release registry and inode ownership failures.
- [x] Switch this clean linked worktree to `codex/apparmor-m2-reviewed` based on reviewed M1.
- [x] Replay M2 commits, resolving conflicts by preserving both reviewed M1 fixes and the M2 contract.
- [x] Reword the `LISTEND` identifier in its replayed commit subject.
- [x] Run the same production-function checks; expect AppArmor in release and root-owned securityfs metadata.

### Task 2: Resolve all retained M2 findings

**Files:** `kernel/comps/apparmor/src/policy/{dfa,mod}.rs`, `kernel/core/src/security/lsm/{cred,mod}.rs`, procfs `attr.rs`, path `resolver.rs`, `test/host/lsm_cred_alloc.rs`, M2 Markdown, and process/thread Linux compatibility documents.
**Interfaces:** Uses Task 1's integrated tree; preserves public APIs and observable M2 behavior.

- [x] Replace repeated pathname limits with one named constant and add pinned DFA source references.
- [x] Fix module documentation, imports, closure names, callback parameter names, method ordering, and derive ordering.
- [x] Remove global dead-code suppression from the host probe and exercise the intentionally unused query/path methods.
- [x] Apply semantic line breaks and document exec/execveat and proc attribute limitations in the official compatibility artifacts.
- [x] Confirm the inherited NixOS matrix selects `security-apparmor` using its actual selection script.
- [x] Compile and run the allocation probe with warnings denied; expect all assertions to pass and zero empty-state allocations.
- [x] Run formatting, SCML and affected static checks; commit coherent changes with the required identity.

### Task 3: Validate the integrated branch

**Files:** Existing permanent regression/ktest suites, isolated remote validation driver, and `docs/superpowers/reports/2026-10-28-apparmor-m2-review-fixes.md`.
**Interfaces:** Validates Task 2's frozen source manifest; produces command/exit-code evidence.

- [x] Sync only this task's source to its remote build workspace, preserving executable bits and private tools.
- [x] Run policy-store OOM and credential allocation host tests, then `make check` serially.
- [x] Run `make run_kernel AUTO_TEST=regression SCHEME=apparmor RELEASE=1 SMP=4`; require actual label cases and module selection success.
- [x] Run default and legacy/precedence selection regressions in release mode; require expected enabled/disabled behavior.
- [x] Run full default `make ktest SMP=1` and relevant AppArmor/core tests in release; record every failure by name.
- [x] Build and run NixOS `security-apparmor` with the integrated release kernel; require both parser and PID-query tests to pass.
- [x] Record environment differences, exact commands and results; run one independent final review and resolve actionable findings.

### Task 4: Deliver the validated branch and walkthrough

**Files:** Final report and standalone demo instructions/transcript.
**Interfaces:** Uses Task 3's validated source and release image.

- [x] Audit the runtime commits' author and committer identities.
- [x] Keep M2's binding and query diff together against reviewed M1.
- [x] Start a separate release demo session using the validated image.
- [x] Demonstrate a pre-load unconfined process, matching post-load exec, unmatched exec, and unchanged parent label.
- [x] Retain live PIDs and provide concrete commands for the user to inspect them.

After committing the report, audit the final commit identity and clean worktree, then publish to the existing draft [PR #22](https://github.com/zzj-5341/asterinas/pull/22).
Publication status is recorded by the PR and the external execution ledger, since the documentation commit precedes the push.
