# AppArmor M1 完成报告

**日期：** 2026-10-15
**分支：** `apparmor-m1-complete`
**上游基线：** `01acaa7eeed755a32fc658e7d732b080061b4872`
**实现 HEAD：** `ef3c27d990f3a7709a72dd5e35c70692a24c38b2`

## 1. 结论

M1 已完成本地实现和运行时验收：Asterinas NixOS 用户可以从文本 profile 开始，使用仓库打包的 `apparmor_parser` 5.0.2 编译 AppArmor ABI v5 策略，通过 securityfs 加载到内核，并从 `profiles` 查询内核保存的 profile。

这里的 “loaded” 仍不等于 “enforced”。M1 不绑定 task label、不在 exec 时选择 profile、不解释权限位，也不会拒绝任何系统调用。label 绑定和 enforcement 属于后续里程碑。

GitHub issue、PR 和远端分支均未修改。本报告对应本地分支和开发服务器容器内的验证结果。

## 2. 最终用户接口

```text
/sys/kernel/security/apparmor/.load
    0666，write-only；回调在操作时检查 CAP_MAC_ADMIN

/sys/kernel/security/apparmor/profiles
    0444，read-only；输出按名称排序的 <name> (<mode>)

/sys/kernel/security/apparmor/features/policy/versions/v5
    0444，read-only；精确返回 yes\n
```

用户态编译器由 `distro/etc_nixos/overlays/apparmor/default.nix` 提供。overlay 从同一 v5.0.2 源同时构建 `libapparmor` 与 `apparmor-parser`，不把 parser 源码放入内核，也不混用 nixpkgs 原有的 4.1.7 库。

## 3. 本轮完成的剩余工作

### 3.1 同步官方 main

- 保留旧实现 head `5f6d576`；
- 获取官方 `origin/main` 的 `01acaa7`；
- 把 8 个既有 AppArmor 提交变基到新基线；
- 在新分支继续开发，没有覆盖旧历史。

### 3.2 递归 securityfs

`SecurityFsDirectory` 提供最小静态递归声明，原有 `register_directory` 兼容入口保留。实现只支持不可变目录、read-only/write-only callback 文件；没有增加动态增删、symlink、per-open 状态或通用策略框架。

验证覆盖：递归 lookup、offset/EOF、目录权限、非法名称、重复子目录和文件/目录重名。任一后代构建失败时，顶层目录不会发布。

### 3.3 v5 feature 发布

AppArmor 被 `lsm=apparmor,yama` 选中后一次注册 `.load`、`profiles` 与 `features/policy/versions/v5`。默认启动不选择 AppArmor，整个 `/sys/kernel/security/apparmor` 仍不存在。

只发布 v5 是有意的兼容边界：更完整的 feature tree 会诱导 parser 生成 M1 尚不接受的 policydb、规则或编码。

### 3.4 parser 5.0.2 打包

上游 5.0.2 相对 nixpkgs 4.1.7 表达式出现两处真实移植差异：

1. 原 `postPatch` 引用 v5 已删除的 `parser/rc.apparmor.functions`；overlay 改为只保留 capability header 替换；
2. v5 parser 需要 `zstd.h`；overlay把现有 `pkgs.zstd` 加入 `buildInputs`。

没有关闭上游测试，没有 vendor 新依赖，也没有修改 parser 业务代码。源码固定输出 hash：

```text
sha256-Kuc5Nrz4iq5MC5AOcJL9Sb54DWNKlEk3b3DW0vpgSZg=
```

### 3.5 文本端到端测试

`test/nixos/tests/security-apparmor` 在客体内执行：

```text
profile observe flags=(complain) {
}
```

流程为：

```text
文本 -> apparmor_parser --stdout -> 118-byte ABI v5 blob
     -> apparmor_parser --binary --add -> securityfs .load
     -> profiles -> observe (complain)
```

测试同时固定 SHA-256 `912a45cf505271eee29e01e01d6d41abbe32ee540f94a10886746c5874400c16`，并断言第二次加载报告 `File exists`、原 store 不变。测试不使用已提交的 `.bin` 作为加载输入。

## 4. 源码审核入口

| 目标 | 入口 |
|---|---|
| LSM 动态注册 | `kernel/core/src/security/lsm/modules/mod.rs` |
| securityfs public seam | `kernel/core/src/security/securityfs.rs` |
| securityfs VFS/SysTree | `kernel/core/src/fs/fs_impls/securityfs/` |
| AppArmor crate 边界 | `kernel/comps/apparmor/src/lib.rs` |
| ABI v5 decoder | `kernel/comps/apparmor/src/policy/abi.rs` |
| attachment DFA validator | `kernel/comps/apparmor/src/policy/dfa.rs` |
| 原子 PolicyStore | `kernel/comps/apparmor/src/policy/mod.rs` |
| `.load`/`profiles`/feature tree | `kernel/comps/apparmor/src/securityfs.rs` |
| parser overlay | `distro/etc_nixos/overlays/apparmor/default.nix` |
| NixOS overlay wiring | `distro/aster_nixos_installer/templates/aster_configuration.nix` |
| initramfs 用户态回归 | `test/initramfs/src/regression/security/lsm/apparmor.c` |
| 文本端到端测试 | `test/nixos/tests/security-apparmor/` |

相对 `01acaa7`，实现共修改/新增 54 个文件，文本统计为 3811 行新增、21 行删除；其中包含大量 ktest、C regression、NixOS e2e、fixture 生成脚本和测试 profile，不能把 3811 行全部视作生产内核代码。

## 5. 本地提交序列

```text
3ccfb11 Add dynamic LSM registration
fd516b9 Add generic securityfs support
56a83c7 Validate AppArmor attachment DFAs
f69e50c Decode AppArmor ABI v5 profiles
0883be5 Store AppArmor profiles atomically
163af95 Expose AppArmor policy loading through securityfs
79cfcbc Address AppArmor M1 review findings
b29841c Add AppArmor ABI boundary fixtures
5595857 Extend securityfs with immutable nested directories
4be5b38 Advertise AppArmor ABI v5 through securityfs
4a9c7f4 Package apparmor_parser 5.0.2 for Asterinas NixOS
ef3c27d Test AppArmor text profile loading on Asterinas NixOS
```

## 6. 验证结果

| 门禁 | 结果 | 关键证据 |
|---|---|---|
| `cargo fmt --all -- --check` | 通过 | exit 0 |
| `cargo osdk check` / `--ktests`，`aster-core` | 通过 | 普通与 ktest 配置均完成 |
| `cargo osdk check` / `--ktests`，`aster-apparmor` | 通过 | 普通与 ktest 配置均完成 |
| `make ktest` | 通过 | KVM runner 实际执行各 workspace 成员，命令 exit 0 |
| `make run_kernel AUTO_TEST=regression` | 通过 | `All regression tests passed.` |
| `make run_kernel AUTO_TEST=regression SCHEME=apparmor` | 通过 | AppArmor 73/73；全局 `All regression tests passed.` |
| parser Nix build | 通过 | 完整上游 tests；产物 `/nix/store/1rlms167nmh6kf255lxfig5sj76ndjga-apparmor-parser-5.0.2` |
| parser 独立 fixture 互操作 | 通过 | 118 bytes、冻结 SHA-256、`cmp` 相同 |
| `make nixos NIXOS_TEST_SUITE=security-apparmor` | 通过 | 16 GiB 稀疏镜像安装成功 |
| `make run_nixos NIXOS_TEST_SUITE=security-apparmor` | 通过 | 1 passed / 0 failed |
| NixOS test clippy / rustfmt / nixfmt | 通过 | exit 0 |
| `git diff --check` | 通过 | 无 whitespace error |

单独在 library crate 目录执行的 `cargo osdk test` 曾只启动到 UEFI、没有 runner 计数，因而没有被当作通过证据；仓库级 `make ktest` 使用官方参数 `-accel kvm`，实际进入 runner 并以 0 退出，替代了该无效尝试。

## 7. RED/GREEN 记录

- feature RED：修改 C regression 后，`stat(features/policy/versions/v5)` 返回 `ENOENT`；递归 securityfs 和 AppArmor 注册完成后变为 73/73。
- parser RED：初次 v5.0.2 构建先因已删除的 `rc.apparmor.functions` 失败，再因缺少 `zstd.h` 失败；两处最小包装修复后，上游完整测试通过。
- userspace 旧状态：固定 nixpkgs 只提供 parser/libapparmor 4.1.7；overlay 后两者均求值为 5.0.2。
- 端到端 GREEN：客体内文本编译、加载、查询和重复拒绝全部通过。没有伪造一次未实际执行的“组合 RED”。

## 8. 保留限制与后续风险

- M1 没有 enforcement。任何“已加载 profile 已保护进程”的演示或文案都是错误的。
- 只接受 ABI v5 冻结子集；capability/file/network 等规则仍返回 `EOPNOTSUPP`。
- attachment DFA 只校验和保存，不执行。
- 没有 namespace、`aa_ns`、task label、`.replace`、`.remove` 或持久化。
- parser 包第一次构建需要运行较长的上游测试；Nix store 缓存后不会重复承担同等成本。
- 当前 feature tree 只声明 v5。扩展任何 feature 前必须先让 decoder/enforcement 真实支持对应编码。

这些限制是 M1 边界，不是本轮遗漏。下一里程碑应从 task label 与 exec 绑定开始，而不是继续扩大 loader ABI。
