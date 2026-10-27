# AppArmor M2 Development Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在一个 PR 中交付可演示的 AppArmor label 绑定与进程标签查询：任务在 exec 时绑定 label，用户态能够通过 `/proc/<pid>/attr/current` 查询指定进程已绑定的 label；
同时保证初始 `unconfined`、fork/clone 继承和 exec 提交语义。

**Architecture:** `aster-core` 提供与具体 LSM 无关的凭据安全状态、exec 准备/提交接口和 procfs 查询入口；
`aster-apparmor` 持有 label、profile 引用和 attachment 匹配逻辑。
标签候选在 exec 不可返回点之前生成，在现有凭据提交点发布。

**Tech Stack:** Rust 2024、safe Rust / no_std、Asterinas LSM / credentials / procfs、OSDK ktest、C regression、AppArmor parser 5.0.2、NixOS E2E。

**Spec:** [Issue #3740 的 M2 定义](https://github.com/asterinas/asterinas/issues/3740)、[M1 完成报告](../reports/2026-10-15-apparmor-m1-completion-report.md)。

**状态与证据：** 2026-10-27 用户已授权精确路径 attachment 实施；
验证进度记录在执行日志。
代码核查基于本地 `apparmor-m1-complete` 的 `0c527109f239b62151fa2a0ed97eb400fa4b6920`。
Issue 的里程碑边界和下列用户确认事项是需求；
接口草案、内部任务拆分和受限匹配范围仍是本计划建议，不能表述为已获维护者批准。

**用户已确认的新增要求（2026-10-27）：** `unconfined` 不为每个任务或凭据单独分配对象。
具体边界见第 2 节；
这项确认不代表其余设计建议均已确定。

**用户已确认的交付方式（2026-10-27）：** label 绑定与用户态查询指定进程 label 放在同一个 PR，合起来展示阶段成果。
凭据状态、matcher、exec 接入和查询接口是这个 PR 的内部实现步骤，不分别提交三个 PR；
指定进程查询是必交付项，不只是可选扩展或进程自查。

**实施记录：** Task 0–5 的绑定、查询、精确 attachment、生命周期和系统验证已实现，实测结果及未解决的四核 xarray 单测失败见[交付报告](../reports/2026-10-27-apparmor-m2.md)。
下方保留原始步骤作为设计轨迹，不将每项建议命令或提交拆分标为原样执行。
实际复用 `LsmModule` 默认方法，直接持有 `Arc<Profile>`；
密切相关的接线合并提交，M1 的 `set_load` 兼容修正独立提交。
实际测试镜像与 CI 固定镜像的差异也在报告中单列。

## Global Constraints

- M2 交付 task label 与 exec attachment；
  capability/file 规则执行、enforce/complain 决策和审计属于 M3 及后续阶段。
- M2 使用单一 PR 交付完整绑定—查询闭环；
  内部允许多个聚焦的提交，PR 的演示和验收必须同时覆盖绑定与从另一用户态进程按 PID 查询。
- `.replace`、`.remove`、revision、namespace、hat、label stacking 和 `px/cx/ux/ix` 规则处理不进入 M2。
  标签跨 exec 的阶段性继承不等于实现了 `ix` 权限规则。
- `kernel/` 保持 safe Rust；
  `aster-core` 不依赖 `aster-apparmor`，也不保存 AppArmor 专用类型。
- 延续 parser 5.0.2 与 ABI v5 的明确子集。
  新增可执行语义必须在加载时验证；
  未支持编码返回明确错误，不能静默接受后按“未匹配”处理。
- AppArmor 未选中时，不创建 AppArmor 标签、不执行其 policy lookup 或 matcher；
  不声称完全没有通用 LSM 分发成本。
- `unconfined` 的表示与生命周期必须满足第 2 节的零单独分配要求；
  通用 LSM 状态包装层也必须遵守这一要求。
- 构建/运行验证使用仓库官方 Linux 开发容器和 KVM；
  不能把 Windows 静态阅读、成功编译或 QEMU 启动到固件当作运行测试通过。
- 用户已授权实施此计划的精确路径 attachment 范围。
  创建或重写提交时，author 和 committer 均使用 `zzj-5341 <242576472+zzj-5341@users.noreply.github.com>`；
  推送前检查本次新增/重写提交，不改写其他作者历史。

## Review Focus

1. 已有标签的任务执行无匹配或不同 attachment 的程序：M2 保留旧标签，不能意外变成 `unconfined`。
   （任务 4、5）
2. fork/clone 之后父子凭据是否共享可变标签槽：允许共享不可变 label/profile，不允许一方 exec 改写另一方标签。
   （任务 1、2、5）
3. exec 提交前失败和提交后致命失败：候选状态不能提前可见；
   新映像不能先运行再设置标签。
   （任务 4、5）
4. 符号链接、chroot、脚本解释器、execveat 和无可达路径的 fd：不能用用户输入字符串或解释器路径冒充 attachment 对象。
   （任务 0、3、4、5）
5. DFA 的内存安全之外还有语义与运行成本：非法 accept 值、伪造长度、多匹配路径、压缩回退环和新增内存计费必须有测试。
   （任务 3）
6. 查询指定 PID/TID 时的授权、目标退出及 exec 竞态：返回目标任务已提交的 label，不混入查询者状态、不拼接不同快照、不因重查数字 PID 转到其他任务。
   （任务 2、4、5）

## 1. 现状与开工条件

| 已核查事实 | 对 M2 的影响 |
|---|---|
| M1 已有 `Profile`、`AttachmentMatcher`、`Arc<PolicySet>`、原子加载和 parser fixture | 复用存储与 ABI，不重建一套策略系统 |
| DFA 目前只做结构/索引检查；DIFF、OOB、EC 和 32-bit 状态表被拒绝 | 当前结果不足以直接执行 matcher；被拒绝的编码不必为了 M2 全部实现 |
| `Credentials_` 还没有 LSM 状态，`new_from` 复制凭据；`dup` 共享同一凭据对象 | 标签必须接入实际复制语义，不能只在 `PosixThread` 上加字符串 |
| `ExecCred` 目前是 `Copy`；exec 已有 prepare 和 apply 两阶段 | 放入拥有所有权的安全状态后必须检查并调整 `Copy` 假设 |
| `do_execve` 同时保留原始 `executable_path` 和最后的 `elf_path` | attachment 与文件 capability 的路径来源不能混为一谈 |
| procfs 已有通用 task 目录与按打开文件保存状态的接口 | 可以接入 `attr/current` 并复用线程生命周期处理 |
| 本地 x86 regression workflow 未配置 `SCHEME=apparmor` | 必须补上正向 CI；只存在测试文件不足以验收 |
| 上游 PR #4023 只包含 M1 的第一部分，且核查时仍为 Draft | 本地 M2 可基于完整 M1 继续开发，上游提交必须明确 M1 依赖 |

先处理两条交付线：本地以固定完整 M1 为依赖进行 M2；
上游继续完成 M1 拆分、评审和合入，随后再移植 M2 提交。
避免把 M1 剩余代码混入题为 M2 的 PR。

开工时复核前期 PR #4023 审阅提出的分配失败、重复错误码优先级与 CI 接线问题。
该审阅针对旧 PR 快照，不能直接把全部意见当作当前分支仍未修复；
逐项记录当前提交证据。
影响 M2 共用路径的真实问题应形成独立修复提交。

## 2. 推荐交付范围与语义

最终演示使用没有 capability/file 规则的 profile：

```text
profile demo /usr/bin/demo {
}
```

验收链为：文本编译并加载 → 执行 `/usr/bin/demo` → 另一个有权限的用户态进程读取 `/proc/<demo_pid>/attr/current` → `demo (enforce)` → 目标进程自查得到相同结果 → fork/clone 和后续 exec 保持规定的标签。

演示 helper 进入新用户映像后发送 ready 信号并等待父进程释放；
父进程收到信号后才按 PID 查询，避免用固定 sleep 掩盖 exec 尚未完成的竞态。
测试同时运行两个不同 attachment 的 helper，分别查询其 PID，证明返回的是各目标的 label，而不是查询者的 label。

预期的用户接口示例（实现后的行为）：

```sh
cat "/proc/$demo_pid/attr/current"
# demo (enforce)

cat "/proc/$unconfined_pid/attr/current"
# unconfined
```

其中 `(enforce)` 仅显示 profile 已存储的 mode；
M2 尚未实施权限限制，演示文档必须说明这一点。

| 情形 | 建议的 M2 行为 |
|---|---|
| init 或 AppArmor 初始凭据 | `unconfined` |
| fork、普通 clone、线程 clone、vfork | 继承创建时的不可变 label 引用；各自持有可替换的凭据状态槽 |
| unconfined 执行唯一匹配目标 | 候选标签变为该 profile，成功提交时生效 |
| unconfined 执行无匹配目标 | 保持 `unconfined` |
| 已有 profile 标签后再次 exec | 保留旧标签，包括目标有另一个 profile 的情况；后续显式转换另行实现 |
| exec 提交前任意失败 | 错误返回，旧 label/凭据仍可观察，候选状态释放 |
| 进入既有不可返回区后失败 | 维持现有致命 exec 路径；不能返回旧用户映像 |
| 仅加载新 profile，没有 exec | 不改变既有任务标签 |
| 有权限的用户态进程查询指定 PID | 返回该进程主线程已提交的 label；未绑定时返回 `unconfined` |
| 查询指定 TID | 返回该线程自己的 label，不替换为主线程或查询者 label |

### 已确定：unconfined 的存储约束

用户要求未受约束任务不单独分配 `unconfined` 对象，具体落实为：

- 使用内联空状态（如 `None`、枚举分支）或共享表示；
  不为每个任务/凭据执行 `Arc::new(Label::Unconfined)`，不复制一份允许所有操作的 profile。
- 通用 LSM 层在所有模块均无专属状态时也保持无堆分配的空表示。
  不能把独立对象改名为 `CredSecurity`、空快照或包装容器后，仍为每个 unconfined 凭据分配。
  其他 LSM 确实需要的非空状态不受此限制。
- AppArmor 状态初始化、fork/clone 的空状态复制、无匹配 exec 的候选状态准备及提交，不因表示 unconfined 而新增堆分配。
  原有凭据对象、exec 路径构造和用户态查询输出的分配分别计量，不将此要求夸大为整个 fork/exec 零分配。
- AppArmor 已启用但状态为空时解释为 unconfined；
  模块是否启用由 LSM 选择状态判断。
  准备失败仍返回 `Err`，不能将错误降为 `None` 后继续 exec。
- 实现时记录实际内核目标上的凭据布局增量，以及上述状态生命周期路径的分配次数。
  先前主机简化类型的 8/16 字节结果只作设计参考，不作为内核总开销的验收值。

### 匹配范围的选择

推荐先完成**精确路径 attachment 的可验证子集**，再单独扩展通配模式。
理由是当前已承诺的演示使用精确路径，而通配模式还引入 specificity、冲突选择和更多 DFA 语义。

- 这不是把 `profile.name` 与路径比较，也不是把 `xmatch_len` 当路径字符串。
  必须从官方 parser 生成的 DFA 验证其接受语言确实是一条绝对字面路径。
- 非字面、额外语义和未支持压缩编码在加载时拒绝；
  需记录相对于 M1“只存储”的兼容范围收紧，更新对应 fixture 预期。
- 推荐在 `.load` 中原子拒绝重复精确 attachment（包括不同 profile 名称），使用 `EEXIST`，保证 exec 不依赖插入顺序选第一个。
  这个规则是项目子集设计，并非宣称 Linux 的全部冲突行为相同。
- 若决定 M2 直接支持一般模式，需要增加完整匹配优先级与冲突语义设计、Linux 对照测试及 parser 编码覆盖；
  不能仅扩展一个 `matches()` 方法就宣布完成。

### 路径与查询边界

- attachment 使用已打开执行对象的解析路径；
  对相对路径和符号链接按实际对象处理，不信任 `argv[0]`。
- 路径参考根建议采用当前 mount namespace 的有效根，避免 chroot 把同一对象改名为另一全局策略路径。
  `PathResolver::make_abs_path` 是相对于其 resolver 根的，不能未经区分直接套用。
- 原始脚本作为 attachment 对象；
  解析出来的 shebang/ELF interpreter 不覆盖已选标签。
  本阶段不增加解释器执行权限规则，M6 仍负责完整执行约束。
- 已删除、匿名和不可达对象不能伪造成普通命名路径；
  M2 的观察性行为建议保留旧标签，明确不声明此类初始 attachment 支持。
  M3 开启 enforcement 前必须重新检查这些边界。
- 必须交付 `/proc/<pid>/attr/current`、`/proc/<pid>/task/<tid>/attr/current`，以及对应的 `/proc/self/attr/current`、`/proc/thread-self/attr/current`。
  输出 `unconfined\n` 或 `<profile> (<mode>)\n`；
  只读，无手工切换标签接口。
- cred 是每线程属性。
  `/proc/<pid>/attr/current` 查询进程主线程，线程路径查询指定 TID；
  self 与 thread-self 分别保留现有 procfs 的进程/线程含义，不能将它们混为一谈。
- 查询当前任务不要求 `CAP_MAC_ADMIN`。
  跨进程查询建议复用 `check_alien_access_from(..., AlienAccessMode::READ_WITH_FS_CREDS)`，保留现有凭据和启用 LSM 的授权规则；
  不因本阶段没有 AppArmor enforcement 就取消查询授权。
- 每次重新打开查询入口获取目标当时已提交的标签；
  同一次打开的分段读取使用同一份快照。
  目标身份验证、访问授权和快照捕获须与 exec 提交遵循一致同步边界；
  目标退出、PID 失效或复用不能返回另一个任务的标签。
  具体错误码在任务 0 固定并测试。

## 3. 单一 PR 的内部工作顺序与依赖

拟议 PR 标题：`Add AppArmor exec label attachment and task label queries`。

以下是同一个 PR 内的工作包和提交顺序，不是多个对外 PR：

| 内部工作包 | 内容 | 开发中间验证 |
|---|---|---|
| A：凭据状态、label 与查询 | 任务 1、2 | 按 PID/TID 查询 unconfined；空状态无单独分配；父子状态槽独立 |
| B：安全 attachment 匹配 | 任务 3 | 官方 fixture 可被验证并匹配；非法或不支持 matcher 原子拒绝 |
| C：exec 绑定与系统演示 | 任务 4、5 | 文本策略 → exec → 从另一进程查询目标 label，连同继承、失败处理和 CI 一起通过 |

依赖顺序：完整 M1 → 任务 0 → 工作包 A → B → C → 一个完整 M2 PR。
matcher 的独立研究可以提前进行；
各提交保持清楚的职责和对应测试。
单一 PR 的 ready/完成标准是完整闭环，而不是某个中间工作包已经通过。
M1 的上游依赖仍需在 PR 中明确，不能混入未说明的 M1 变更。

## 4. 任务分解

### Task 0：固定 M2 行为契约与可复现基线

**Files:** 维护本计划；
新增 `docs/superpowers/specs/2026-10-27-apparmor-m2-design.md`；
核对现有 M1 报告与 fixtures。

**交付：** 将第 2 节建议形成明确设计：匹配子集、重复 attachment、已有标签 re-exec、脚本对象、路径参考根、不可达路径、指定 PID/TID 查询权限、快照与精确 errno；
把与 Linux 的差异单列。
保留用户确定的单 PR 交付和 unconfined 零单独分配要求。

- [ ] 核对执行时的完整 M1 HEAD、上游依赖和工作树；
  隔离 M2 工作分支，保留现有未跟踪审阅文档。
- [ ] 用 parser 5.0.2 和固定 feature 文件复现 `demo.bin`、`multi-attach.bin`，记录生成选项和哈希。
- [ ] 对照固定 Linux 源码，逐项固定上述行为和反例；
  精确 attachment 子集须确认能严格验证，不能只以现有几个 fixture 代替验证算法。
- [ ] 复核 M1 共用路径缺陷并安排独立修复；
  记录 AppArmor 正向 CI 的交付位置。
- [ ] 输出设计与验收矩阵；
  将通过设计评审的版本作为后续任务的接口契约。

### Task 1：通用凭据安全状态与生命周期

**Files:** 新增 `kernel/core/src/security/lsm/cred.rs`、`hooks/credential.rs`；
修改 `lsm/mod.rs`、`hooks/mod.rs`、`process/credentials/{credentials_,static_cap,mod}.rs`；
核对 `process/clone.rs` 和 `process/process/init_proc.rs` 的错误传播。

**接口建议：** 由 core 持有可为空的 `CredSecurity` 不可变快照，内部按已选 LSM 标识保存不透明状态；
非空具体状态可采用 `Arc<dyn Any + Send + Sync>`，全空时不分配快照或槽位容器。
不同凭据对象分别持有可替换快照槽；
`new_from` 复制空值或非空快照引用，`dup` 仍表示同一凭据对象。
只为真实消费者开放接口，不把整个 `Credentials` 暴露给高层组件。

建议 hook 的最小形状：`init_cred_state() -> Result<Option<LsmState>>`；
fork/clone 通过不可变引用复制完成生命周期，不另加可变共享状态或全局 PID→label 表。
新增安全状态的 drop 由 Rust 所有权负责。

- [ ] 添加行为测试：初始状态、无状态模块、两个测试模块的状态隔离、复制后互不改写、共享引用最终释放。
- [ ] 添加空状态分配测试：在所有选中模块均返回 `None` 时，core 安全状态的初始化、复制和销毁各产生零次堆分配；
  统计仅覆盖新增安全状态路径，排除原有凭据对象分配。
- [ ] 运行目标编译/ktest，记录新接口尚不存在或行为未实现的失败。
- [ ] 实现最小不透明状态和初始化/复制/销毁路径；
  新增运行时分配走可失败路径，错误传回调用者；
  init 失败采用明确启动失败策略。
- [ ] 运行 core 编译与 `make ktest`，验证 AppArmor 未选中和 Capability/Yama 原有行为。
- [ ] 单独提交通用凭据状态变更，保持 AppArmor 具体类型位于组件内部。

### Task 2：AppArmor label 与只读任务查询

**Files:** 新增 `kernel/comps/apparmor/src/label.rs`；
修改该组件 `lib.rs`；
新增 `kernel/core/src/fs/fs_impls/procfs/pid/task/attr.rs` 并接入 `task/mod.rs`；
核对 `procfs/pid/mod.rs` 继承 task 目录入口和 PID/TID 解析行为；
修改任务 1 的通用 LSM 查询接口。

**接口建议：** `Label::{Unconfined, Profile(Arc<Profile>)}` 可作为组件内的逻辑表示；
空凭据状态映射为 `Unconfined` 值，无需为它构造独立的堆对象。
组件提供 `Label::current_attr(&self) -> Result<String>`；
core 通过选中模块的查询 hook 得到文本，不解释 profile/mode。
M2 只追加策略，直接持有不可变 `Arc<Profile>` 足够；
M4 的稳定 identity/revision 留到出现更新需求时实现。

- [ ] 添加查询测试：`unconfined\n`、enforce/complain 名称格式、PID 主线程与指定 TID 的区别、self/thread-self 各自的解析、短读/offset/EOF、写入失败和目标退出。
- [ ] 添加跨进程授权用例：允许读取的父子关系、既有权限检查拒绝的调用者、不同 UID 场景和适用的 capability 例外；
  查询失败不泄露目标标签。
- [ ] 添加用户态失败用例，先证明 `attr/current` 尚不存在；
  已绑定标签格式可由组件 ktest 直接验证，exec 绑定留到任务 4。
- [ ] 实现 label 与通用查询分发，以入口绑定的目标 task 为数据来源；
  采用 procfs 已有的 per-open handle 能力，使一次打开后的分段读取使用完整的同一份快照；
  在锁外格式化和复制到用户态。
- [ ] 按现有 exec/VMAR 锁顺序完成目标身份检查、跨任务授权和安全状态快照捕获；
  测试目标在查询期间 exec/退出，不通过重新查找数字 PID 切换到其他任务。
- [ ] 验证 fork/clone 的继承、线程隔离和 disabled 行为；
  未选中支持该查询的模块时固定返回行为并纳入 ABI 测试。
- [ ] 验证从空状态查询仍精确输出 `unconfined\n`，且查询不会为凭据安装一个持久的 unconfined 对象；
  输出缓冲区的临时分配单独记录。
- [ ] 与任务 1 组成单一 PR 内的工作包 A；
  将实际启用 AppArmor 的 CI 用例接入，不依赖默认配置跳过测试。

### Task 3：把 attachment 从可存储数据变成可执行的已验证对象

**Files:** 修改 `kernel/comps/apparmor/src/policy/{dfa,abi,mod}.rs`；
按责任新增 `policy/attachment.rs`；
扩充 `test/initramfs/src/regression/security/lsm/apparmor-fixtures/` 的文本、生成脚本和哈希。

**接口建议：** `AttachmentMatcher::matches(&self, path: &str) -> bool` 只用于通过语义校验的实例；
`AttachmentMatcher::literal_path(&self) -> &str` 返回已证明的唯一路径；
`PolicySet::find_attachment(&self, path: &str) -> Option<Arc<Profile>>` 在同一不可变快照上选择。
任何原始 blob 都不能绕过验证构造 matcher。

- [ ] 添加真实 parser fixture 测试：精确命中、前缀/后缀近似不命中、两条不同 attachment、profile 名不同于路径；
  增加非字面 DFA 和伪造 accept/长度的反例。
- [ ] 添加损坏与边界用例：越界表、非法 accept 语义、错误 `xmatch_len`、循环/多分支接受语言、重复 attachment 和总计费超限；
  先记录失败。
- [ ] 实现受限语言的严格验证与匹配。
  accept 位按 ABI v5 的 xmatch 映射解释，不能把“非零”一概当作接受。
  只在已证明字面语言后校验其长度；
  不能将一般模式的 `xmatch_len` 简化为字符串长度。
- [ ] DIFF/OOB/EC/32-bit 状态编码继续拒绝并保留负向测试。
  若扩展支持，必须同时增加对应语义、终止性与 Linux 对照测试；
  这不是默认 M2 工作。
- [ ] 在加载发布前检查 attachment 唯一性，新增索引/缓存纳入存储计费；
  匹配在快照上、策略锁外进行。
  验证匹配步数有明确上界，畸形输入不会造成无限循环。
- [ ] 跑 matcher/ABI/store 的 ktest、fixture 复现和已有 M1 regression；
  完成单一 PR 内的工作包 B。

### Task 4：接入 exec prepare/commit

**Files:** 新增 `kernel/core/src/security/lsm/hooks/exec.rs` 和 `kernel/comps/apparmor/src/exec.rs`；
修改 `kernel/core/src/process/execve.rs`、`process/credentials/{credentials_,static_cap}.rs`、LSM hook 分发；
必要时扩展 `fs/vfs/path/resolver.rs` 的明确路径构造接口。

**接口建议：** `prepare_exec_state(current: Option<&LsmState>, context: &ExecSecurityContext<'_>) -> Result<Option<LsmState>>` 返回候选状态；
`ExecSecurityContext` 提供已经解析的 attachment 路径及明确的不可用原因。
最终 commit 消费候选状态并替换凭据快照，不重新匹配、不做用户 I/O，也不进行新的可失败分配。

当 AppArmor 已启用时，`Ok(None)` 表示候选 unconfined 状态；
有效匹配返回持有对应不可变 profile 的非空状态，错误仍为 `Err`。
候选放进 `ExecCred` 或与它共同拥有的 exec 准备结果，在 prepare 阶段不写入当前 `Credentials_`。
提交时更新其通用安全状态槽；
这不要求复制整份 profile，也不预设当前内核会原子替换整个 cred 指针。

- [ ] 添加失败/继承矩阵测试：unconfined 命中和未命中；
  已有标签 re-exec；
  不同目标 attachment；
  准备成功后 ELF 加载失败、线程集合检查失败；
  父子标签不互相改写。
- [ ] 运行测试，确认当前 exec 未更新标签。
- [ ] 在 `do_execve` 已完成目标识别、尚未 `start_execve` 和终止其他线程之前构造候选状态；
  使用原始执行对象而非 `argv[0]` 或最后的 interpreter 路径。
  选择只读取一次策略快照。
- [ ] 将候选安全状态与 `ExecCred` 一起传递，去除不再成立的 `Copy` 假设；
  在现有 `activate_vmar`/凭据提交区发布，确保新用户映像与成功 exec 的 ptrace 通知之前已生效。
- [ ] 检查现有 `apply_exec_cred` 仍可能失败的步骤。
  让新的安全状态发布发生在必要验证之后，不能错误声称现有全部 UID/capability 字段对任意远程观察者天然原子；
  查询需要遵循同一提交锁/快照规则。
- [ ] 验证候选丢弃、成功提交和不可返回区失败各自的资源释放；
  并发加载不会改变已经准备好的候选，之后的 exec 才看到新策略。
- [ ] 验证 unconfined 且无 attachment 匹配时，候选标签准备及提交的状态层堆分配次数为零；
  另外对有效匹配的分配失败注入错误，确认返回错误且旧标签不变。

### Task 5：端到端验收与 CI 闭环

**Files:** 新增 `test/initramfs/src/regression/security/lsm/apparmor_label.c` 及必要的 helper；
修改同目录 `Makefile`、`security/run_test.sh`；
扩展 `test/nixos/tests/security-apparmor/src/main.rs` 和需要的客体 helper 打包；
修改 `.github/workflows/test_x86.yml`，复用已有 test action 的 `scheme` 输入。

**交付：** 同一个 PR 同时提供目标进程自查和另一用户态进程按 PID 查询的证据。
自查由被测程序自己读取对应 self/thread-self 入口；
外部观察者读取 `/proc/<target_pid>/attr/current`。
不能用观察者自己的 `/proc/self` 冒充目标查询。

- [ ] 添加真实执行测试：加载前运行仍 unconfined；
  加载后匹配 ELF 得到标签；
  未匹配不附着；
  fork/线程 clone/vfork 继承；
  非主线程 exec；
  已有 label 的 re-exec。
- [ ] 测试 helper 在 exec 后发送 ready 信号并保持存活，观察者收到信号后按 PID 查询；
  两个不同标签目标和一个 unconfined 目标得到各自预期结果，自查与外查一致。
- [ ] 验证非主线程 exec 后，按原进程 PID 重新打开查询入口看到已提交标签；
  验证查询与 exec/退出并发时不会出现混合输出、错误目标或越权读取。
- [ ] 加入路径矩阵：绝对/相对路径、symlink、hardlink 的路径差异、chroot、脚本和解释器、execveat/fd、匿名/删除对象的已定义范围；
  不能把缺失测试记为“未匹配测试已覆盖”。
- [ ] 加入故障与权限回归：无效 ELF/解释器、提交前错误保留旧 label、query 短读与目标退出、setuid/file capabilities/ambient/bounding/no_new_privs、Capability/Yama 原有行为。
- [ ] NixOS 用 parser 5.0.2 从新文本生成并加载 attachment profile，再执行已安装 helper；
  由另一进程按 helper 的 PID 读到目标标签，并用 helper 自查交叉验证；
  保留 M1 原有加载/重复拒绝测试。
- [ ] 将 `SCHEME=apparmor` 传到 x86 regression action，保留默认 disabled 配置；
  至少覆盖 SMP 场景。
  报告各 label 用例实际执行数量，全部 skip 不能算通过。
- [ ] 运行下方验收命令并留存 head、环境、日志和退出码；
  用支持范围与实测结果重写 PR 描述及 M2 完成报告。

## 5. 验收门槛

在官方 Linux 容器内执行，具体环境参数沿用执行时仓库配置：

```sh
cargo fmt --all -- --check
cargo osdk check -p aster-core
cargo osdk check --ktests -p aster-core
cargo osdk check -p aster-apparmor
cargo osdk check --ktests -p aster-apparmor
make ktest
make run_kernel AUTO_TEST=regression
make run_kernel AUTO_TEST=regression SCHEME=apparmor
make nixos NIXOS_TEST_SUITE=security-apparmor
make run_nixos NIXOS_TEST_SUITE=security-apparmor
git diff --check
```

这个 M2 PR 还执行仓库要求的 lint/check 门禁。
DFA 变更触发 fixture 重生成及哈希核对；
Nix/客体 helper 变更触发对应格式、编译和打包检查。

完成标准同时包含：

- [ ] 初始任务 unconfined；
  fork/clone 继承且无可变状态串扰。
- [ ] 满足第 2 节 unconfined 零单独分配要求：初始化、空状态复制及无匹配 exec 的状态层分配计数为零；
  附实际内核凭据布局增量，单列路径/查询等其他分配。
- [ ] 匹配程序附着正确 profile，未匹配的 unconfined 程序保持原状态。
- [ ] 标签与 exec 凭据在规定提交区生效，新映像运行前能够观察正确标签。
- [ ] 提交前 exec 失败保留旧状态；
  提交后失败遵循既有致命路径。
- [ ] 另一有权限的用户态进程能按 PID 查询目标进程标签；
  目标自查与外查一致；
  同时覆盖按 TID 查询、权限、短读和 exec/退出竞态。
- [ ] 未启用 AppArmor 时既有 exec/credentials/Capability/Yama 行为保持。
- [ ] 只声明真实支持的 matcher 与 ABI 子集；
  模式字段不被宣传为已实施权限限制。
- [ ] 同一个 PR 同时包含 label 绑定、指定进程查询、可复现演示与对应回归/CI；
  提交历史可分层，但交付不拆成只含基础设施的多个 PR。
- [ ] 本地完整验证与上游 CI/合入状态分别报告；
  “M2 本地完成”不能代替“上游 M2 已交付”。

## 6. 工作量与关键风险

暂不承诺日历工期。
主要不确定性是字面 DFA 的严格语义验证、路径身份边界以及 exec/凭据并发可见性；
接口机械接线相对明确。
任务 0 完成后再依据 matcher 范围、M1 上游修改量和 KVM/Nix 测试资源估算。

应优先投入：**固定行为矩阵 → 凭据标签与查询 → matcher 安全性 → exec 提交 → 系统验证**。
不要以增加权限规则、实现全量 Linux DFA 或提前建设 M4 revision 系统来扩大 M2。

## 7. 固定参考入口

- [现有 exec 准备与提交](../../../kernel/core/src/process/execve.rs)
- [凭据字段、复制和 ExecCred](../../../kernel/core/src/process/credentials/credentials_.rs)
- [当前 DFA 校验](../../../kernel/comps/apparmor/src/policy/dfa.rs)
- [当前 PolicyStore](../../../kernel/comps/apparmor/src/policy/mod.rs)
- [现有 NixOS 文本加载测试](../../../test/nixos/tests/security-apparmor/src/main.rs)
- [Linux 固定参考：DFA 校验与状态执行](https://github.com/torvalds/linux/blob/db2ddb87143519e20a95aa36c60b36107b736a58/security/apparmor/match.c)
- [Linux 固定参考：旧 ABI xmatch 权限映射](https://github.com/torvalds/linux/blob/db2ddb87143519e20a95aa36c60b36107b736a58/security/apparmor/policy_compat.c)
- [Linux 固定参考：attachment 选择与 exec](https://github.com/torvalds/linux/blob/db2ddb87143519e20a95aa36c60b36107b736a58/security/apparmor/domain.c)

Linux 参考来自工作区固定快照的实际阅读，不声称它是执行时最新上游。
它用来确认接口语义和差异，不要求照搬 Linux 内部数据结构。
