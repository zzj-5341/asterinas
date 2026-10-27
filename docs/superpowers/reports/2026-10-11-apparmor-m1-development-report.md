# AppArmor M1 开发报告

> 2026-10-15：本文保留初版 loader 的历史实现与审阅记录。递归 feature tree、
> `apparmor_parser` 5.0.2 Asterinas NixOS 打包、文本端到端测试和最终门禁见
> `2026-10-15-apparmor-m1-completion-report.md`；后者是当前完成状态的准确信息源。

> 日期：2026-10-11
> 实现基线：`f70c7b0`
> 当前实现：`5f6d576c36a6fdbed1650a9b12c5212edc8b4a28`
> 设计文稿：[`../specs/2026-10-10-apparmor-m1-design.md`](../specs/2026-10-10-apparmor-m1-design.md)
> 实施计划：[`../plans/2026-10-10-apparmor-m1-implementation.md`](../plans/2026-10-10-apparmor-m1-implementation.md)

## 1. 结论

AppArmor M1 已完成本地实现，提供：

- 通用 `securityfs` 文件系统及静态文件注册接口；
- 可扩展的 LSM 注册与启动选择机制；
- AppArmor ABI v5 策略单次 write 加载；
- 单 blob 多 profile 解码；
- attachment DFA 的结构和状态边界校验；
- 有界、原子发布的全局 `PolicyStore`；
- `/sys/kernel/security/apparmor/profiles` 用户态查询接口；
- ktest、官方 parser fixture 和 initramfs 原生回归测试。

M1 只保存已验证的 profile 元数据和 attachment matcher，不执行 matcher，
不绑定 task/file，不实施访问控制，也不实现 `aa_ns`、`.replace` 或 `.remove`。

当前实现由八个本地提交组成，未推送或修改 GitHub。

## 2. 用户可见接口

启用 AppArmor scheme 后，启动参数包含：

```text
lsm=apparmor,yama
```

挂载点由 initramfs 初始化：

```sh
mount -t securityfs none /sys/kernel/security
```

加载策略：

```sh
# 完整 ABI v5 blob 必须由一个 write 提交
dd if=policy.bin \
  of=/sys/kernel/security/apparmor/.load \
  bs=1048576 count=1 iflag=fullblock status=none
```

上例只适用于不超过 1 MiB 的 M1 blob。
正式 loader 应直接执行一次
`write(2)` 并校验返回值等于 blob 长度；不能使用可能拆分输出的通用复制循环。

查询已加载策略：

```sh
cat /sys/kernel/security/apparmor/profiles
```

输出按 profile 名称排序：

```text
demo (enforce)
observe (complain)
```

`.load` 是 write-only，`profiles` 是 read-only。
两个操作都会在实际 I/O 时重新检查初始 user namespace 中的 `CAP_MAC_ADMIN`，
而不是只依赖 open-time DAC 检查。

## 3. 总体数据流

```text
userspace write(.load)
    -> operation-time CAP_MAC_ADMIN check
    -> copy complete blob from user memory
    -> ABI v5 bounded decoder
    -> attachment BLOB alignment and DFA validation
    -> build DecodedPolicy outside the store lock
    -> detect duplicates and capacity overflow under one mutex
    -> publish one immutable Arc<PolicySet>

userspace read(profiles)
    -> operation-time CAP_MAC_ADMIN check
    -> clone Arc<PolicySet> snapshot under the mutex
    -> release mutex
    -> format sorted profile lines to userspace
```

解码或批量插入的任一步失败时，当前 `PolicySet` 不变。

## 4. 源码审阅地图

### 4.1 LSM 注册和选择

| 位置 | 关键符号 | 审阅重点 |
|---|---|---|
| `kernel/core/src/security/lsm/mod.rs:25` | `LsmFlags`、`LsmModule`、`register` | 模块 flags、注册公开面和初始化顺序 |
| `kernel/core/src/security/lsm/modules/mod.rs:59` | `ModuleRegistry` | 注册、重名拒绝、seal 后禁止修改 |
| `kernel/core/src/security/lsm/modules/mod.rs:108` | `build_modules_by_name` | mandatory/builtin/动态模块的名称集合 |
| `kernel/core/src/security/lsm/modules/mod.rs:134` | `ModuleSelection` | `lsm=`、legacy `security=`、exclusive 模块语义 |
| `kernel/core/src/security/lsm/modules/mod.rs:332` | ktests | 注册和选择兼容性测试 |

### 4.2 通用 securityfs

| 位置 | 关键符号 | 审阅重点 |
|---|---|---|
| `kernel/core/src/security/securityfs.rs:18` | `SecurityFsFile` | read-only/write-only 回调的最小公开接口 |
| `kernel/core/src/security/securityfs.rs:65` | `register_directory` | 跨 crate 注册入口 |
| `kernel/core/src/fs/fs_impls/securityfs/mod.rs:15` | `init`、`register_directory` | VFS/sysfs 注册和 SysTree 接入 |
| `kernel/core/src/fs/fs_impls/securityfs/fs.rs:21` | `SecurityFs` | singleton、root inode、mount 行为 |
| `kernel/core/src/fs/fs_impls/securityfs/node.rs:16` | `SecurityRootNode`、`SecurityDirectory` | 目录和静态文件集合、名称验证 |
| `kernel/core/src/fs/fs_impls/securityfs/inode.rs:17` | `SecurityFsInode` | mode、read/write 分派、errno 保留 |
| `kernel/core/src/fs/fs_impls/securityfs/test.rs:1` | ktests | mode、非法名称、重复注册和回调 errno |

### 4.3 AppArmor 组件和用户态 ABI

| 位置 | 关键符号 | 审阅重点 |
|---|---|---|
| `kernel/comps/apparmor/src/lib.rs:29` | `APPARMOR_LSM`、component init | `LEGACY_MAJOR | EXCLUSIVE`、LSM 注册和 log prefix |
| `kernel/comps/apparmor/src/securityfs.rs:23` | `FILES` | `.load` 与 `profiles` 的静态声明 |
| `kernel/comps/apparmor/src/securityfs.rs:32` | `check_policy_admin` | operation-time `CAP_MAC_ADMIN` 复检与 `EACCES` 映射 |
| `kernel/comps/apparmor/src/securityfs.rs:44` | `write_load` | offset/size/EFAULT 检查和 store 调用 |
| `kernel/comps/apparmor/src/securityfs.rs:73` | `read_profiles` | 快照读取、offset 和排序输出 |

### 4.4 ABI decoder、DFA 和 PolicyStore

| 位置 | 关键符号 | 审阅重点 |
|---|---|---|
| `kernel/comps/apparmor/src/policy/abi.rs:57` | `Cursor` | 所有读取的边界检查和精确消费 |
| `kernel/comps/apparmor/src/policy/abi.rs:119` | `Cursor::aligned_blob` | Linux `aa_ext` end-position 对齐公式和零 padding |
| `kernel/comps/apparmor/src/policy/abi.rs:193` | `decode` | ABI v5 header、multi-profile 原子解码 |
| `kernel/comps/apparmor/src/policy/abi.rs:228` | `decode_profile` | 冻结字段顺序、名称、mode、attachment 和零规则 |
| `kernel/comps/apparmor/src/policy/dfa.rs:57` | `validate` | 三阶段 DFA 校验入口 |
| `kernel/comps/apparmor/src/policy/dfa.rs:63` | `parse_table_set` | header、table id/width/长度和精确消费 |
| `kernel/comps/apparmor/src/policy/dfa.rs:145` | `verify_table_shapes` | 必需表和 state/transition 数量关系 |
| `kernel/comps/apparmor/src/policy/dfa.rs:182` | `verify_state_bounds` | DEFAULT/NEXT/CHECK/BASE 边界和未支持 flags |
| `kernel/comps/apparmor/src/policy/mod.rs:121` | `PolicySet::try_insert_all` | 排序 merge、重名拒绝和批量原子性 |
| `kernel/comps/apparmor/src/policy/mod.rs:194` | `PolicyStore` | 单 mutex 和不可变 `Arc<PolicySet>` 快照 |
| `kernel/comps/apparmor/src/policy/mod.rs:205` | `PolicyStore::load` | decode-before-lock、容量限制和原子发布 |

### 4.5 配置、fixture 和原生回归

| 位置 | 内容 | 审阅重点 |
|---|---|---|
| `Cargo.toml:30`、`Cargo.toml:173` | workspace member/dependency | workspace 依赖和 lockfile |
| `Components.toml:3` | AppArmor component | 组件发现 |
| `kernel/Cargo.toml:13`、`kernel/src/lib.rs:15` | kernel 链接 | 组件进入最终 kernel |
| `OSDK.toml:32` | `apparmor` scheme | `lsm=apparmor,yama` |
| `test/initramfs/src/init:23` | securityfs mount | 用户态挂载位置 |
| `test/initramfs/src/regression/security/lsm/apparmor.c:177` | selection test | 未选择 AppArmor 时不可见 |
| `test/initramfs/src/regression/security/lsm/apparmor.c:192` | load/query test | 权限、ABI、原子性、errno 和 mutation |
| `test/initramfs/src/regression/security/lsm/apparmor-fixtures/` | parser fixtures | v5.0.2 生成来源、SHA-256 和负例 |

## 5. 支持的 ABI 范围

实现只接受经过 fixture 冻结的 ABI v5 子集：

- version 必须为 `0x00000005`；
- 一个 blob 可以包含多个完整 policy unit；
- profile name 为合法 UTF-8，长度不超过 255，拒绝 namespace/hierarchy 形式；
- mode 支持 `enforce` 和 `complain`；
- 支持无 attachment 或冻结格式的 `aadfa` attachment；
- attachment DFA header flags 必须为 0；
- ACCEPT/ACCEPT2/BASE 为 32-bit；
- DEFAULT/NEXT/CHECK 为 16-bit；
- 不支持 DIFF、OOB、EC table、32-bit state table；
- 不解释 accept permission bits，因为 M1 不执行 matcher；
- table 尾部 padding 与 Linux 一致：跳过但不检查内容；
- BLOB 前导 padding 必须为零。

未支持但可识别的特性返回 `EOPNOTSUPP` 或 `EPROTONOSUPPORT`，
损坏、截断、顺序错误和边界错误返回 `EPROTO`。

## 6. Store、并发和资源限制

固定限制：

| 限制 | 值 | errno |
|---|---:|---:|
| 单次 blob | 1 MiB | `E2BIG` |
| profile 总数 | 1024 | `ENOSPC` |
| store 计费总量 | 16 MiB | `ENOSPC` |
| profile name | 255 bytes | `EINVAL` |

ABI 解码、DFA 校验和分配在 store mutex 外完成。
mutex 只保护读取当前快照、冲突检查和新快照发布；
读取路径在锁内只克隆 `Arc`，格式化和用户内存写入不持锁。

同一 blob 内重名或与已有 store 冲突均返回 `EEXIST`，
整批 profile 不发布。

## 7. 安全边界

- AppArmor crate 使用 `#![no_std]` 和 `#![deny(unsafe_code)]`；
- 整个 AppArmor 新增代码没有 `unsafe`；
- 用户 blob 在进入内部对象前完成长度、类型、顺序、算术和状态边界验证；
- 所有可能溢出的长度/偏移计算使用 checked arithmetic；
- 用户内存复制失败统一映射为 `EFAULT`；
- 权限检查发生在每次 read/write，而不是只在 open 时；
- store 不保存用户指针或对输入 buffer 的借用；
- attachment matcher 只存储，不执行，避免 M1 暗含未审查的 enforcement 语义。

## 8. Asterinas 官方开发规范对照

实现按 `book/src/to-contribute/coding-guidelines/` 审阅：

| 官方规则 | 本实现对应做法 |
|---|---|
| `checked-arithmetic` | Cursor、BLOB、DFA table 和 store 计费使用 checked 运算 |
| `propagate-errors` | 合法失败路径使用 `Result` 和 `?`，无业务失败 `.unwrap()` |
| `atomic-critical-sections` | 冲突检查和整批发布位于一次 mutex 临界区 |
| `no-io-under-spinlock` | 用户 I/O 和格式化不在 store lock 下执行 |
| `validate-at-boundaries` | `.load` 和 ABI/DFA decoder 形成两层不可信输入边界 |
| `deny-unsafe-kernel` | AppArmor crate 明确 `#![deny(unsafe_code)]` |
| `layered-kernel-crates` | AppArmor 作为独立 component crate，仅依赖 core 提供的 seam |
| `narrow-visibility` | decoder、DFA、store 和回调保持 private/`pub(crate)`/`pub(super)` |
| `module-docs` | 新增主要 Rust 模块包含 `//!` 级用途说明 |
| `workspace-deps` | 新 crate 和 kernel 依赖通过 workspace 声明 |
| `log-prefix` | crate root 定义 `apparmor: ` 前缀 |
| `atomic-commits` | 六个 feature 提交分别落地 LSM、securityfs、DFA、ABI、store、wiring；另有一个集中处理审阅意见的修复提交 |
| `test-visible-behavior` | initramfs 回归从 securityfs ABI 验证用户可见行为 |

## 9. 测试和 fixture

### 9.1 ktest

- 动态 LSM 注册、选择、exclusive 和 legacy 参数行为；
- securityfs mode、名称、重复注册、offset 和 errno；
- ABI v5 单/多 profile、mode、255/256 字节名称边界、namespace、`path_flags`、恰好 1024 个成功与 1025 个 `ENOSPC`、截断和尾随垃圾；
- 第二个 attachment 的 unit-relative BLOB 对齐；
- DFA header/table/state/transition 正例与 mutation；
- PolicyStore 排序、批量原子性、partial conflict、容量和并发快照。

### 9.2 官方 parser fixture

| 文件 | 大小 | SHA-256 | 用途 |
|---|---:|---|---|
| `demo.bin` | 1484 | `f877adf70efa115213a45d16cc11ff23d48b33ef5dee337c34ba2ee9008fa3a2` | 单 profile + attachment |
| `observe.bin` | 118 | `912a45cf505271eee29e01e01d6d41abbe32ee540f94a10886746c5874400c16` | complain mode |
| `multi.bin` | 232 | `b7fd47bc42e4c21592258d2e91f59c8cae1face5407cb638aa354f906775134b` | 多 profile 无 attachment |
| `multi-attach.bin` | 3016 | `be5438f6407bbbee631214f30550754ee2f093de8ff5a0e578c0bff084a883bd` | 多 attachment 对齐回归 |
| `path-flags.bin` | 140 | `65199eeff974271abaa45d7f138d86afd5e66eada73a8438d473e37ac57553d9` | parser 生成的 `path_flags` 互操作负例 |
| `namespaced.bin` | 139 | `887958a93d92dd22b8628e622fdbb906f8bdb4c28f985707a0b9599bd6862cc9` | namespace 负例 |
| `v7-empty.bin` | 1322 | `41e4c6dfc12b3990c66278bffbf3ab6260948f0900a0abb0d52dfc0421913a9a` | ABI v7 负例 |

### 9.3 initramfs 回归覆盖

- AppArmor 是否随 `lsm=` 选择而可见；
- 文件 mode 和 `.replace`/`.remove`/`features` 不存在；
- root 与保留 `CAP_MAC_ADMIN` 的非 root 加载；
- operation-time capability recheck；
- profile 排序查询和 offset；
- 单 blob 多 profile/attachment；
- 重复加载、同批重名、已有名称冲突和整批回滚；
- 截断、DFA 损坏、第二 BLOB 非零 padding；
- parser 生成的 `path_flags`、namespace、ABI v7、超限、空 write 和 `EFAULT`。

## 10. 验证结果

### 10.1 六提交基线验证

通过：

- `cargo osdk check`（AppArmor crate）；
- `cargo osdk check --ktests`（AppArmor crate）；
- 完整 `cargo osdk test`（AppArmor crate，不使用模块名空过滤）；
- `make kernel`；
- `make test`；
- `./tools/format_all.sh --check`；
- 变更 C 文件的 `clang-format --dry-run --Werror`；
- `git diff --check f70c7b0..HEAD`；
- fixture 大小和 SHA-256 复核；
- Asterinas/QEMU 中的 AppArmor 原生回归，init 退出码为 0。

全仓 gate 的非零结果：

1.
   `make check` 在本次改动之外的 `osdk/deps/frame-allocator` 缺少 workspace lints 处提前失败；
2.
   `make ktest` 的既有 `ostd::arch::vm::vmx::vmcs::test::switch_and_reuse_vmcs` 失败，AppArmor 批次未报失败；
3.
   `make -C test/initramfs check` 被未修改的 `network/msg_peek.c` clang-format 问题阻塞；
4. 两个官方 `make run_kernel AUTO_TEST=regression` 入口均在分发测试前退出；guest shell 报告 `\r`/未闭合 `then`，但后续逐字节检查确认源码、Nix store 和 cpio 内脚本都是 LF，因此不能把根因简单归为源文件 CRLF，而应限定为当前 init/exec/PTY 测试链问题。

为隔离第 4 项，曾使用只负责挂载 sysfs/proc/securityfs 的临时测试构造器，
直接以 AppArmor regression binary 作为 init 原生运行；所有断言通过并返回 0。
临时构造器已撤销，不在当前提交中。

### 10.2 审阅修复提交 `dadbe08` 的再验证

本轮通过：

- `cargo fmt --check -p aster-core -p aster-apparmor`；
- 在 `kernel/comps/apparmor` 和 `kernel/core` 分别执行 `cargo osdk check --ktests`；
- `clang-format --dry-run --Werror test/initramfs/src/regression/security/lsm/apparmor.c`；
- 强制重编译 `test/initramfs/src/regression/security/lsm`，包括 `apparmor.c`，编译参数含 `-Wall -Werror`；
- `git diff --check`；
- `make kernel`。

本轮没有得到新的运行时 ktest/regression 结论。
恢复容器后，默认
GRUB/OVMF 路径在进入测试 runner 前报告 `no suitable video mode`；Linux
bzImage 兼容路径在 `linux-bzimage-setup` 固定地址分配处 panic，尝试
direct boot 也未进入 runner。
因此新增 Rust ktest 已编译但未执行，新增
用户态断言已编译但未在本轮 VM 中执行；不能据此声称本轮全量测试通过。

### 10.3 二审跟进提交 `5f6d576` 的再验证

本轮新增恰好 1024 个 profile 成功的正边界，并用
`apparmor_parser v5.0.2` 从 `flags=(attach_disconnected)` 源 profile 生成
`path-flags.bin`。
fixture 为 140 字节，SHA-256 为
`65199eeff974271abaa45d7f138d86afd5e66eada73a8438d473e37ac57553d9`；
完整生成脚本重新生成全部七个 fixture 后均命中冻结 hash。
当前容器的
system libapparmor 比 parser 旧，生成时仅为 `--skip-cache` 路径补了一个
临时 cache-header 兼容符号；该临时文件不在仓库中，并且重新生成的其余
六个 fixture 与既有冻结 hash 完全一致。

本轮通过：

- `cargo fmt --check -p aster-core -p aster-apparmor`；
- 两个受影响 crate 的 `cargo osdk check --ktests`；
- AppArmor C 回归的 `clang-format --dry-run --Werror` 和 `-Wall -Werror` 强制重编译；
- `sha256sum -c SHA256SUMS`，包括新增 `path-flags.bin`；
- `git diff --check`；
- `make kernel`。

本轮仍没有新的运行时通过结论：两个 crate 的 `cargo osdk test` 都完成
编译和 ISO 生成，但没有打印测试 runner 的通过/失败统计；两个官方
regression 命令均启动到 `/init`，随后在执行
`/test/run_regression_test.sh` 前述 shell 解析处失败。
用于定位的临时
`script(1)` 绕过和直接 binary init 均已撤销。
故新增 1024 正边界 ktest
与 `path_flags` 用户态断言目前都是“已编译、未在 VM 中执行”。

## 11. 提交序列

| 提交 | 内容 |
|---|---|
| `81a6570` | Add dynamic LSM registration |
| `0b56da4` | Add generic securityfs support |
| `3d9c9bb` | Validate AppArmor attachment DFAs |
| `501dcfd` | Decode AppArmor ABI v5 profiles |
| `c390617` | Store AppArmor profiles atomically |
| `752d1c5` | Expose AppArmor policy loading through securityfs |
| `dadbe08` | Address AppArmor M1 review findings |
| `5f6d576` | Add AppArmor ABI boundary fixtures |

## 12. 与设计文稿的实现差异

没有已知的用户可见行为偏差。

唯一有意的函数布局差异是：设计文稿单列了私有 `copy_policy_blob`，
实现把同一段逻辑直接放在 `write_load` 中，避免只有一个调用者且不增加语义的包装函数。
长度限制、fallible allocation、用户内存复制和 errno 行为保持一致。

## 13. 建议审阅顺序

1. 先读设计文稿第 1、3、4、5、8、9、15、16 节，确认 M1 边界；
2. 审阅 LSM 注册和 generic securityfs，确认公共 seam 是否足够小；
3. 审阅 `securityfs.rs` 的权限和用户内存边界；
4. 审阅 `abi.rs` 的精确字段顺序及 `aligned_blob`；
5. 审阅 `dfa.rs` 的 table shape/state bounds；
6. 审阅 `PolicySet::try_insert_all` 的原子性和容量计费；
7. 最后用 `apparmor.c` 逐项核对用户可见 ABI 和 errno。

## 14. 当前工作区状态

实现提交均已落在本地 HEAD。
以上是 2026-10-11 时的历史状态；当时 `docs/` 尚未跟踪。
M1 完成阶段已把设计、计划和两份报告纳入独立的文档提交，当前提交序列与验证结果以 2026-10-15 完成报告为准。
未创建 PR，未推送远端。
