# AppArmor M2: exec attachment and task label queries

The user authorized this scope on 2026-10-27.
The initial base was complete M1, `0c527109f239b62151fa2a0ed97eb400fa4b6920`.
The reviewed integration uses M1 `7d0055d4be91724072c416d6a6a39de85c25fc50`,
including its release initialization and securityfs ownership fixes.
One PR delivers attachment, credential binding, procfs queries, and executable regression tests.

## Contract

- An empty credential security snapshot represents unconfined when AppArmor is enabled.
  Initializing, cloning, or committing empty security state allocates no object.
  Existing credential, pathname, and query-output allocations are separate costs.
- Each copied credential has its own mutable snapshot slot.
  Immutable module states and profiles can be shared.
  A child's exec cannot change its parent's label.
  `dup` remains a handle to the same credential, not a fork operation.
- Only an unconfined task acquires an attachment at exec.
  A labelled task keeps its label on every subsequent exec in M2.
  Profile loading never relabels existing tasks.
  There is no permission enforcement or transition-rule support.
- Prepare the complete candidate before the exec point of no return.
  Publish it under the existing process VMAR lock after the existing fallible credential updates, before entering the new image.
  Commit performs no label allocation.
- Use the opened original executable (including a script), relative to the effective root of its mount namespace.
  Ignore argv[0].
  Symlinks resolve to their target; hardlinks retain their separate resolved paths.
  Deleted, anonymous, and unreachable objects do not acquire an initial attachment.
- Accept only structurally validated ABI v5 DFAs proven to encode one absolute literal pathname.
  Validate legacy xmatch acceptance and length.
  Unsupported languages/flags return EOPNOTSUPP; malformed encoding returns EPROTO.
  Reject duplicate literal attachments atomically with EEXIST, even when the profile names differ.
  This is a deliberate subset, not Linux's full matcher.
- `/proc/<pid>/attr/current` names the process main thread; the task/TID path names that thread.
  Existing self/thread-self symlinks retain their meaning.
  Output is `unconfined\n` or `<profile> (<mode>)\n`.
  Modes are metadata, not evidence of enforcement.
  No manual label switching is supported.
- At open, take the process VMAR lock, resolve/revalidate the entry's target, check READ_WITH_FS_CREDS alien access, and capture that target's committed state.
  Format and copy outside the lock.
  Denied access returns EACCES; an unavailable target returns ESRCH.
  An already open descriptor keeps its authorized immutable snapshot across exec/exit and partial reads.
  A new open captures the then-current state.
  No numeric PID lookup retargets the handle.
- Without a selected module supporting current-attribute queries, opening `attr/current` returns EINVAL.
  Writes return EPERM (or VFS access denial).

## Validation

Cover independent parent/child state, empty-state allocation, malformed and unsupported DFAs, duplicate attachments, prepare failure, matching/unmatched exec, re-exec inheritance, PID/TID identity, authorization, short reads, and exec/exit races.
An external observer queries two differently labelled live children and one unconfined child after an explicit post-exec ready signal.
Compare each target's own query with its observer's result.
Test path aliases, scripts, chroot, execveat/fd, and unavailable paths separately.

Retain M1 loader tests and capability/Yama regression.
Add AppArmor-enabled SMP CI and a NixOS text-policy-to-exec-to-PID-query test.
Record actual commands, environment, and failures; compilation alone does not prove runtime behavior.
