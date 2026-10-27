# M1 严格审阅修复与核验

日期：2026-10-27。

本轮处理完整本地 M1 审阅保留的 18 条意见，以及代理提交的身份要求。
修复在独立工作树 `F:\App_Armor\m1-reviewed`、分支 `apparmor-m1-reviewed` 中完成。
共享工作树 `F:\App_Armor\asterinas-latest` 保持原有 `apparmor-m1-complete`，没有修改其受跟踪文件或原有提交。

审阅版本为 `0c527109f239b62151fa2a0ed97eb400fa4b6920`。
整理后的功能序列以 `01acaa7eeed755a32fc658e7d732b080061b4872` 为基线。
原审阅报告位于 `F:\App_Armor\output\reviews\2026-10-27-m1-complete-review.md`。

## 问题闭环

| # | 原意见 | 修复 |
|---|---|---|
| 1 | release 下 LSM 索引为空 | 无条件执行 `insert`，仅将重复检查放入 `debug_assert!`。 |
| 2 | 三处策略 `Arc::new` 在 OOM 时终止内核 | 两个 profile 分支和最终快照使用 `Arc::try_new`；发布前将分配错误映射为 `ENOMEM`。 |
| 3 | 首次查找者成为 securityfs owner | inode 构造器固定 root UID/GID；增加伪造输入 owner 的 ktest 和普通用户首次查找/chmod C 回归。 |
| 4 | 正向测试未接入 CI | x86 增加现代、legacy、优先级三种 release regression；NixOS allowlist 加入 `security-apparmor`。 |
| 5 | 两个 C helper 漏识别 legacy 参数 | 同步实现最后值生效、`lsm=` 优先和缺少 `lsm=` 时的 `security=apparmor` 识别。 |
| 6 | 未使用的跨 crate flat 注册接口 | `register_directory` 收窄为 `#[cfg(ktest)] pub(crate)`；保留实际使用的层次注册接口。 |
| 7 | DFA 缺少格式来源 | 引用固定 Linux v6.12 `match.h`、`match.c`，区分外部格式与 M1 限制。 |
| 8 | review 修正混为收尾提交 | 将最终树按 LSM、securityfs、AppArmor、regression/CI、parser、NixOS、文档重建为七个功能提交。 |
| 9 | 官方参数文档缺失 | 补充 `lsm=`/`security=`、模块、默认值、强制 capability、优先级和示例。 |
| 10 | ABI 裸导入常量 | 改用父模块限定路径，并同步两个嵌套 ktest 引用。 |
| 11 | `Code` 属性顺序 | `repr` 在前，`derive` 最后。 |
| 12 | ABI 阅读顺序 | `decode` 和 profile 流程前置，cursor/token 辅助实现后置。 |
| 13 | `AttachmentMatcher` 属性顺序 | 条件属性在前，`derive` 最后。 |
| 14 | 内部策略项可见性过宽 | 收窄 `DecodedPolicy`、内部上限和 `PolicyStore::new`。 |
| 15 | 裸导入自由函数 | 使用 `aster_systree::is_valid_name`。 |
| 16 | 回调参数未用 `_fn` 后缀 | 构造器参数与 I/O 分派统一为 `read_fn`/`write_fn`。 |
| 17 | 提交标题中的程序名未加反引号 | parser 功能提交标题使用反引号包围 `apparmor_parser`。 |
| 18 | 新增 Markdown 缺少语义换行 | 新增 M1 正文按句子/有意义的分句换行；保留代码块、表格和历史事实。 |

所有新提交的 author 和 committer 均使用：

```text
zzj-5341 <242576472+zzj-5341@users.noreply.github.com>
```

原分支中的 14 个提交保留原状。
没有向 GitHub 推送、改 PR 或发送审阅评论。

## 本轮实际验证

| 检查 | 结果及范围 |
|---|---|
| 运行时边界 RED/GREEN | 修复前 release map 为空、构造器保留 UID 65534；修复后两个生产函数的宿主探针通过。 |
| OOM RED/GREEN | 修复前 profile/快照 Arc 故障使子进程 abort；修复后十个实际分配故障点均返回 `ENOMEM`，旧快照指针不变。 |
| OOM 永久回归 | `python3 tools/tests/apparmor_policy_store_oom.py` 通过；直接引入生产 policy/ABI/DFA 源码，已接入 x86 usermode CI。 |
| 启动参数 RED/GREEN | 两个真实 C helper 共 18 个用例通过；修复前四个 legacy 用例失败。 |
| C 编译 | 两个 LSM C 文件均通过 `gcc -fsyntax-only … -pthread`。 |
| C 格式 | 两个修改的 C 文件通过 task-local clang-format 18.1.8 的 `--dry-run --Werror`。 |
| 内核测试配置编译 | `cargo osdk check --ktests -p aster-core -p aster-apparmor` 通过。 |
| 完整内核普通配置检查 | `cargo osdk check -p asterinas` 通过。 |
| Clippy | `cargo osdk clippy --ktests -p aster-core -p aster-apparmor -- -D warnings` 通过。 |
| release 检查 | `cargo osdk check --ktests -p aster-core -p aster-apparmor --release` 通过。 |
| 格式及补丁 | `cargo +nightly-2026-07-21 fmt --all -- --check` 与 `git diff --cached --check` 通过。 |
| CI 选择 | 实际执行 workflow 的 suite 过滤脚本，改动 security-apparmor 时只选中该套件；三种 enabled scheme 均接到 release regression。 |
| 配置解析 | 三份修改的 GitHub Actions YAML 解析通过，OSDK TOML 解析通过。 |
| NixOS 测试静态检查 | `cargo clippy --locked --manifest-path test/nixos/Cargo.toml -p test-security-apparmor -- -D warnings` 通过；三份 parser/测试 Nix 文件通过 `nix-instantiate --parse`。 |
| 独立复审 | 新上下文 reviewer 检查最终修复 diff，无新增可操作意见；客体测试结果另行记录。 |
| 正式 QEMU ktest | QEMU/KVM 下 AppArmor 20/20、core 156/156 通过，包括新增 inode ownership ktest；命令为各 crate 目录的 `cargo osdk test --kcmd-args=earlycon --qemu-args="-accel kvm" --initramfs=…`。 |

上述编译使用项目固定的 nightly-2026-07-21 和源码对应的 OSDK 0.19.0。
Linux 检查在 WSL Ubuntu 执行，使用已有 vDSO 和 KVM。
为了运行 Nix 测试镜像，仅在测试进程中将 `build-users-group` 设为空。
Windows 检出文件按 Git 索引内容恢复 LF，未产生额外内容变更。
正式测试首次因离线 Git tag 缓存缺失停在依赖解析阶段，后续重试允许获取项目已有依赖。
完整 `make ktest` 批量运行已中断，没有声称整套通过。
基础 OSTD 221 项测试通过；本轮与修复直接相关的两个 crate 另行取得逐项结果。
早先没有串口输出是因为带 core 的镜像要求显式 `earlycon`；启动诊断得到 QEMU guest success 退出码 33。
这没有证实客体启动缺陷。

宿主 OOM 测试使用 std mutex/错误适配与真实分配器，证明本次分配错误传播及快照不变。
它不能替代客体 VFS、调度和用户指针路径验证。
未实际执行的 QEMU regression 和 NixOS parser 端到端测试不记为通过。
在准备独立 release C regression 镜像时，WSL 连续两次在命令启动前报告
`Wsl/Service/CreateInstance/HCS_E_CONNECTION_TIMEOUT`，随后查询显示 Ubuntu 已停止。
因此本轮没有取得 release C regression 的客体结果；没有为恢复它而重启 WSL 或其他服务。
这不影响此前已取得的 176 项相关 ktest、宿主 RED/GREEN 和编译/静态检查证据。

## 保留的 M1 边界

M1 仍是策略加载、校验和查询阶段；task label、attachment 执行与强制执行属于后续阶段。
保持设计规定的容量检查先于重名检查。
DFA 仅校验并保存，执行前仍需后续阶段的语义门禁。

缺少 `policy/set_load` 时，parser 的多 profile 写入使用同一 fd。
第一个 profile 可能已发布，第二次写入因非零 offset 返回 `ESPIPE`。
已在文档中明确该边界，未扩大当前单 profile parser e2e 的承诺。
内核对收到的二进制字段负责，无法恢复 parser 在编译阶段已经省略的源规则。

## 证据位置

完整命令、探针和本轮日志保存在隔离工作树的
`.superpowers/sdd/2026-10-27-m1-review-fixes/`。
该目录被忽略，不随功能提交发布。
永久回归、CI、设计和本报告随整理后的分支保留。
