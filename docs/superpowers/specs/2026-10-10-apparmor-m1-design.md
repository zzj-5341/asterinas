# AppArmor M1：securityfs 策略加载与查询设计

- 状态：设计定稿（2026-10-10 第三轮复审通过，可进入实现）
- 基线：Asterinas `main`，提交 `f70c7b02af4237d17f0d58d0354e6a33562c0459`（2026-10-10）
- 用户态基线：`apparmor_parser` v5.0.2
- 关联议题：<https://github.com/asterinas/asterinas/issues/3740>

## 1. 结论

第一阶段只实现 AppArmor 的策略控制面闭环：

1. Asterinas 提供通用 `securityfs`，并挂载到 `/sys/kernel/security`。
2. AppArmor 被 `lsm=apparmor` 选中时注册：
   - `/sys/kernel/security/apparmor/.load`
   - `/sys/kernel/security/apparmor/profiles`
3. 用户态把由固定版本 `apparmor_parser` 生成的二进制策略写入 `.load`；一个 write 可以携带一个或多个连续编码的 profile。
4. 内核对整个输入做有界、无 `unsafe` 的解析和校验。
5. 校验成功后，把整批 profile 作为不可变内核对象原子发布到一个全局、易失的 `PolicyStore`。
6. 有 `CAP_MAC_ADMIN` 的用户态进程可从 `profiles` 查询已发布 profile，格式为：

   ```text
   demo (enforce)
   observe (complain)
   ```

本阶段不实现 `aa_ns` 或任何等价的 namespace 层。当前只有一个全局 `PolicyStore`，但不把它命名为“root namespace”，避免产生已经支持 namespace 语义的错误印象。

本阶段会解析、校验并保存可选的 attachment matcher，作为 profile 数据的一部分；但不执行 matcher，也不实现 task label、exec 绑定、权限裁决、audit、`.replace`、`.remove`、v5 之外的 feature 或持久化。运行时只发布真实支持的 `/features/policy/versions/v5`。已加载只是“被内核接受并保存在内存中”，不代表 profile 已经约束任何进程。

## 2. 需要先纠正的两个前提

### 2.1 “load 成功”等于“开始生效”是错误前提

M1 的 load 成功只表示：二进制格式合法、语义属于 M1 子集、名称未冲突、对象已进入内核内存。由于没有 task label 和 exec attachment，任何系统调用都不会因为该 profile 被拒绝。

因此用户态查询接口只能回答“内核当前保存了哪些 profile”，不能回答“哪个进程正在使用哪个 profile”。后者至少要等 task label 落地。

### 2.2 当前 M1 与 issue #3740 原文的 PR1/PR2 划分不同

issue 当前把 credential seam 放在 PR1，把 policy loader 放在 PR2。本设计按已经确认的新范围重排：先交付 securityfs、最小 LSM 注册、load、内存保存和查询；credential seam 延后。当前只修改本地设计，不修改 GitHub issue。

本地 issue 重写稿中的教程 profile 同时含 attachment 和 capability 规则。M1 只保留 attachment、name 和 mode；capability 规则仍属于后续 enforcement 里程碑。因此 M1 的互操作 fixture 使用 `profile demo /usr/bin/demo {}`，不是带 `capability net_bind_service` 的完整教程策略。

### 2.3 本次审查后的方案选择

评估过三个范围：

1. 保留 ABI v7 并实现 `policydb`：与长期 ABI 更接近，但空 profile 也必须解析和解释 policy DFA，M1 工作量和语义面显著扩大。
2. 切到 ABI v5，但继续只收单 profile、拒绝 attachment：decoder 最小，但与本地 M1 对 attachment metadata 的退出标准不一致，也偏离上游一次 load 可携带 profile set 的行为。
3. 切到 ABI v5，支持多 profile 事务，并验证、保存但不执行 attachment matcher：范围仍只覆盖控制面，同时真实 parser fixture 可以通过。

本设计选择方案 3。multi-profile 只扩展 decoder 循环和候选集合事务；attachment 则单独放进 `dfa.rs`，不把 flex table 细节泄漏给 store 或 securityfs。

## 3. 设计约束

### 3.1 必须满足

- 内核 Rust 代码保持 `#![no_std]` 和 `#![deny(unsafe_code)]`。
- AppArmor 作为 `kernel/comps/apparmor` 高层模块存在，不把策略解析塞进 `aster-core`。
- `aster-core` 只提供两个通用 seam：LSM 注册和 securityfs 文件注册。
- `.load` 的输入是官方 AppArmor 二进制策略格式的明确子集，不自造文本协议或 JSON。
- 每次 write 是一个完整事务：失败时可见 profile 集合完全不变。
- 一个 write 至少包含一个、至多包含 `MAX_LOADED_PROFILES` 个 profile；同一 write 中的全部 profile 一次发布。
- 可选 attachment matcher 必须通过 DFA 结构与状态边界完整校验后才保存；M1 不运行该 matcher。
- 对输入长度、profile 数量和累计容量设硬上限。
- 不在持有策略锁时访问用户内存。
- AppArmor 未被选中时，`securityfs` 仍可挂载，但 `apparmor/` 目录不存在。
- AppArmor 被选中时，`features/policy/versions/v5` 返回 `yes\n`，且不宣称支持其他 ABI feature。
- 已加载 profile 按名称排序输出，结果稳定。

### 3.2 M1 明确不支持

- policy namespace，包括顶层 `namespace` 字段和 fully-qualified namespace 名称。
- hats、child profiles、label stacking。
- capability、file、network、mount、signal、ptrace、dbus、IPC、io_uring 等规则。
- `kill`、`unconfined`、`user` profile mode。
- profile rename、旧式 `attach` 字符串、xattr/alternate-name attachment、attachment permission table。
- `.replace`、`.remove`、revision、raw policy export。
- v5 版本声明以外的 `/sys/kernel/security/apparmor/features` 内容。
- 重启后的持久化。

这些字段不是“忽略”，而是返回 `EOPNOTSUPP` 并拒绝整个 write。静默接受但不执行规则会让用户误以为策略已经提供保护，这是不可接受的。

## 4. 支持的二进制 ABI 子集

### 4.1 受支持的策略源形态

无 attachment 的最小 enforce profile：

```text
profile demo {
}
```

最小 complain profile：

```text
profile observe flags=(complain) {
}
```

M1 的主互操作 profile 带 attachment，但只保存 matcher，不用于绑定：

```text
profile demo /usr/bin/demo {
}
```

不能写规则：

```text
# M1 不支持
profile demo {
    capability net_bind_service,
}
```

### 4.2 运行时 feature 与固定 fixture

内核运行时发布同一份最小能力声明：

```text
/sys/kernel/security/apparmor/features/policy/versions/v5 = "yes\n"
```

fixture 生成脚本使用等价的最小 feature 文件：

```text
policy {versions {v5 {yes
}
}
}
```

`apparmor_parser` v5.0.2 在这一配置下生成的 version 值必须精确等于：

```text
0x00000005
```

该值是固定的 kernel policy ABI v5。M1 不接受“5 到 9 的任意版本”，因为那会把未经测试的编码错误地纳入兼容承诺。

不能使用原文稿中的 v7 feature。`apparmor_parser` v5.0.2 在 kernel ABI 大于 5 时，即使 profile 没有规则，也会加入 `mediates_file` 并序列化 `policydb/aadfa`；实测空 `demo` 的 v7 输出为 1322 字节，而不是下节描述的最小流。接受 v7 就必须同时实现 policydb 语义，超出 M1。

### 4.3 接受的字段顺序

整个 write 是一个或多个 `POLICY_UNIT` 的直接串接。每个单元都重复 version header；物理输入末尾才是 EOF，不存在额外的 EOF token：

```text
POLICY_UNIT :=
  NAME("version")
  U32(0x00000005)
  NAME("profile")
  STRUCT
    STRING(<non-empty UTF-8 profile name>)
    [ NAME("aadfa")
      BLOB_ALIGNED(<validated attachment DFA>)
      U32(<non-zero xmatch length>) ]
    NAME("flags")
    STRUCT
      U32(0)                    # hat/debug flags
      U32(0 or 1)               # enforce or complain
      U32(0)                    # audit-all disabled
    STRUCTEND
    U32(0) U32(0) U32(0) U32(0)        # low capability words
    NAME("caps64")
    STRUCT
      U32(0) U32(0) U32(0) U32(0)      # high capability words
    STRUCTEND
  STRUCTEND

STREAM := POLICY_UNIT { POLICY_UNIT }
```

序列化 type code 使用官方值：`U8=0`、`U16=1`、`U32=2`、`U64=3`、`NAME=4`、`STRING=5`、`BLOB=6`、`STRUCT=7`、`STRUCTEND=8`、`LIST=9`、`LISTEND=10`、`ARRAY=11`、`ARRAYEND=12`。policy stream 的整数和长度均为 little-endian；BLOB 内部的 DFA 是第 4.5 节单独规定的 big-endian 格式。

### 4.4 名称约束

- UTF-8 字节长度为 `1..=255`。
- 序列化字符串必须以且只以一个尾部 NUL 结束，字符串内部不能有 NUL。
- 以 `:` 开头的 fully-qualified namespace 名称返回 `EOPNOTSUPP`。
- 包含 `//` 的 child profile 或 hat 名称返回 `EOPNOTSUPP`。
- 包含 Unicode control character（包括换行、回车和 DEL）的名称返回 `EINVAL`，避免破坏 `profiles` 的一行一条记录格式。
- 其他 UTF-8 名称原样保存和显示；不把 profile 名误当作 executable attachment。

### 4.5 attachment matcher 约束

- `aadfa` 只能在 profile name 和 `flags` 之间出现一次；没有 attachment 时该字段必须完全缺失。
- BLOB 长度是 little-endian `u32`，包含 parser 在每个独立 profile 序列化缓冲中加入的前导零。decoder 必须用 Linux `aa_ext` 的 BLOB 结束位置公式反推 padding，不能直接按最终 write 中的全局起点对齐；padding 非零、长度不足或越界返回 `EPROTO`。
- 去掉 padding 后的 DFA 使用 AppArmor flex table 格式：table-set header 和各 table header/data 都是 big-endian。
- 必须校验 magic、header/serialized size、header flags、table id/type、重复/缺失 table、各 table 长度关系以及所有 state/transition 索引。M1 只接受冻结 fixture 已覆盖的 `flags == 0`、无 EC、无 OOB/DIFF、16-bit 状态表形状；已知但未支持的编码返回 `EOPNOTSUPP`，损坏的结构返回 `EPROTO`。
- `xmatch_len` 必须非零；M1 保存该值和已验证的原始 DFA bytes，但不进行匹配，也不声称 attachment 已生效。

## 5. 总体数据流

```text
Bootstrap component init
  -> aster_apparmor::init_component()
  -> lsm::register(&APPARMOR_LSM)

core fs init
  -> securityfs::init()
  -> 注册 securityfs FsType
  -> 在 sysfs 创建 /sys/kernel/security 挂载点

core security init
  -> lsm::active_modules() 封闭注册表并按 lsm=/security= 选择
  -> 仅对被选中的模块调用 LsmModule::init()
  -> AppArmor init 注册 apparmor/{.load,profiles}

userspace write(.load)
  -> MAC_ADMIN 校验
  -> offset/长度校验
  -> 一次性复制用户 buffer
  -> PolicyStore::load()
  -> ABI 全量解码 + attachment DFA 校验
  -> 加锁，检查整批名称重复、profile 数量与总容量
  -> 构造新的不可变 PolicySet
  -> 一次指针替换发布

userspace read(profiles)
  -> MAC_ADMIN 校验
  -> 短暂加锁并 clone Arc<PolicySet>
  -> 释放锁
  -> 按 offset 格式化到用户 buffer
```

## 6. 修改面总览

### 6.1 新增文件

```text
kernel/core/src/security/securityfs.rs
kernel/core/src/fs/fs_impls/securityfs/mod.rs
kernel/core/src/fs/fs_impls/securityfs/fs.rs
kernel/core/src/fs/fs_impls/securityfs/inode.rs
kernel/core/src/fs/fs_impls/securityfs/node.rs
kernel/core/src/fs/fs_impls/securityfs/test.rs

kernel/comps/apparmor/Cargo.toml
kernel/comps/apparmor/src/lib.rs
kernel/comps/apparmor/src/securityfs.rs
kernel/comps/apparmor/src/policy/mod.rs
kernel/comps/apparmor/src/policy/abi.rs
kernel/comps/apparmor/src/policy/dfa.rs

test/initramfs/src/regression/security/lsm/apparmor.c
test/initramfs/src/regression/security/lsm/apparmor-fixtures/features
test/initramfs/src/regression/security/lsm/apparmor-fixtures/features-v7
test/initramfs/src/regression/security/lsm/apparmor-fixtures/demo.profile
test/initramfs/src/regression/security/lsm/apparmor-fixtures/observe.profile
test/initramfs/src/regression/security/lsm/apparmor-fixtures/multi.profile
test/initramfs/src/regression/security/lsm/apparmor-fixtures/multi-attach.profile
test/initramfs/src/regression/security/lsm/apparmor-fixtures/namespace-base.profile
test/initramfs/src/regression/security/lsm/apparmor-fixtures/demo.bin
test/initramfs/src/regression/security/lsm/apparmor-fixtures/observe.bin
test/initramfs/src/regression/security/lsm/apparmor-fixtures/multi.bin
test/initramfs/src/regression/security/lsm/apparmor-fixtures/multi-attach.bin
test/initramfs/src/regression/security/lsm/apparmor-fixtures/namespaced.bin
test/initramfs/src/regression/security/lsm/apparmor-fixtures/v7-empty.bin
test/initramfs/src/regression/security/lsm/apparmor-fixtures/generate.sh
test/initramfs/src/regression/security/lsm/apparmor-fixtures/SHA256SUMS
```

### 6.2 修改文件

```text
Cargo.toml                              # workspace member/dependency
Components.toml                         # apparmor component metadata
kernel/Cargo.toml                       # 链接 aster-apparmor
kernel/src/lib.rs                       # extern crate aster_apparmor as _

kernel/core/src/security/mod.rs          # 导出 securityfs facade
kernel/core/src/security/lsm/mod.rs      # 公共注册接口和 init callback
kernel/core/src/security/lsm/hooks/mod.rs
kernel/core/src/security/lsm/hooks/alien_access.rs
kernel/core/src/security/lsm/modules/mod.rs

kernel/core/src/fs/mod.rs                # core 内 re-export securityfs
kernel/core/src/fs/fs_impls/mod.rs       # 调用 securityfs::init()

test/initramfs/src/init                  # 挂载 securityfs
test/initramfs/src/regression/security/run_test.sh
test/initramfs/src/regression/security/lsm/Makefile
test/initramfs/src/regression/security/lsm/module_selection.c
test/initramfs/src/regression/fs/pseudofs/pseudo_dev_id.c
OSDK.toml                                # apparmor 专用测试 scheme
```

不修改 Credentials、exec、syscall hook 或现有 Capability/Yama 行为。

## 7. 模块与函数设计

### 7.1 `aster-core::security::lsm`：注册和选择 seam

### 公开类型

```rust
pub struct LsmFlags: u32 {
    const LEGACY_MAJOR = 1 << 0;
    const EXCLUSIVE = 1 << 1;
}

pub trait LsmModule:
    LsmAlienAccessHook + LsmCapabilityHook + Sync
{
    fn name(&self) -> &'static str;
    fn flags(&self) -> LsmFlags;
    fn init(&self) -> Result<()> { Ok(()) }
}

pub fn register(module: &'static dyn LsmModule) -> Result<()>;
```

为使高层 crate 能实现 `LsmModule`，`LsmAlienAccessHook`、`LsmCapabilityHook` 改为 public。`AlienAccessContext` 类型改为 public，但 M1 不扩大其构造函数和字段访问器的可见性；AppArmor 只使用两个 hook 的默认 allow 实现。现有 Capability 和 Yama 的 hook 逻辑不改。

### `ModuleRegistry`

文件：`kernel/core/src/security/lsm/modules/mod.rs`

```rust
struct ModuleRegistry {
    sealed: bool,
    modules: Vec<&'static dyn LsmModule>,
}
```

#### `ModuleRegistry::new() -> Self`

- `const fn`。
- 初始 `sealed=false`、空 `Vec`。

#### `ModuleRegistry::register(&mut self, module) -> Result<()>`

- 只负责注册期状态和重复检查，不做模块选择。
- `sealed=true` 返回 `EBUSY`。
- `name()` 为空、含空白或逗号返回 `EINVAL`。
- 与 built-in 或已注册模块重名返回 `EEXIST`。
- `try_reserve(1)` 失败返回 `ENOMEM`，然后 push。

#### `ModuleRegistry::seal(&mut self) -> Vec<&'static dyn LsmModule>`

- 设置 `sealed=true`。
- 用 `core::mem::take` 移出注册列表，避免持有 spin lock 时构造 `BTreeMap`。
- 第二次调用是内部逻辑错误，只会由 `ACTIVE_MODULES: Once` 防止。

### 顶层函数

#### `pub fn register(module) -> Result<()>`

- 获取全局 `SpinLock<ModuleRegistry>`。
- 委托 `ModuleRegistry::register`。
- 这是 bootstrap component 唯一需要调用的 LSM 注册入口。

#### `fn build_modules_by_name() -> BTreeMap<...>`

- 先 seal registry 并释放锁。
- 合并 `ALL_BUILTIN_MODULES` 与扩展模块。
- 重复在 register 时已被阻止；此处若仍重复则 panic，代表内核静态配置错误。

#### `pub(super) fn active_modules() -> &'static [...]`

- 保留现有 `Once<Box<[...]>>`。
- 使用动态构造的 name map 执行现有 `lsm=`、`security=`、mandatory、exclusive 和顺序逻辑。
- 不改变未知模块、重复模块或 exclusive 冲突的现有处理。

#### `pub(super) fn init() -> Result<()>`

- 依次遍历最终 active stack。
- 先记录 `LSM module enabled` 日志，再调用 `module.init()?`。
- 第一个失败立即停止；`security::init()` 对错误 `expect`，因为“模块已选中但控制面未注册”不能作为半初始化状态继续启动。

`kernel/core/src/security/mod.rs` 的 `pub(super) fn init()` 保持无返回值；它用带明确信息的 `expect` 调用 `lsm::init()`，然后继续现有 TSM 初始化。这样不把一次 LSM 初始化错误扩散到整个 kernel init 函数图。

### AppArmor 的 LSM 实现

```rust
struct AppArmorLsm;

static APPARMOR_LSM: AppArmorLsm = AppArmorLsm;

impl LsmModule for AppArmorLsm {
    fn name(&self) -> &'static str { "apparmor" }
    fn flags(&self) -> LsmFlags {
        LsmFlags::LEGACY_MAJOR | LsmFlags::EXCLUSIVE
    }
    fn init(&self) -> Result<()> {
        securityfs::register()
    }
}

impl LsmAlienAccessHook for AppArmorLsm {}
impl LsmCapabilityHook for AppArmorLsm {}
```

这里的空 hook 是明确的 M1 行为：AppArmor 不参与任何裁决。

### 7.2 `aster-core::security::securityfs`：公开文件注册接口

文件：`kernel/core/src/security/securityfs.rs`

### 回调类型

```rust
pub type ReadCallback =
    fn(offset: usize, writer: &mut VmWriter) -> Result<usize>;

pub type WriteCallback =
    fn(offset: usize, reader: &mut VmReader) -> Result<usize>;
```

回调直接返回 `aster_core::Result`。这是必要设计：普通 `SysNode` 的 `AttributeError` 在 VFS 层只能映射成 `EIO`，会丢失 `.load` 所需的 `EPROTO`、`EEXIST`、`E2BIG` 等错误。

### `SecurityFsFile`

```rust
pub struct SecurityFsFile {
    name: &'static str,
    ops: SecurityFsFileOps,
}

enum SecurityFsFileOps {
    ReadOnly(ReadCallback),
    WriteOnly(WriteCallback),
}
```

#### `pub const fn read_only(name, callback) -> Self`

- 创建只读文件描述符。
- 固定初始 mode 为 `0444`。
- 不提供“读写文件”变体，因为 M1 没有调用者。

#### `pub const fn write_only(name, callback) -> Self`

- 创建只写文件描述符。
- 固定初始 mode 为 `0666`，与 Linux AppArmor 根 `.load` 一致。
- mode 只允许请求到达 file operation；真正授权由回调完成。这样只有 `CAP_MAC_ADMIN`、但没有 `CAP_DAC_OVERRIDE` 的非 root 进程不会在 VFS DAC 检查处被提前挡住。

#### 内部 getter

- `name() -> &'static str`
- `perms() -> SysPerms`
- `read_at(...) -> Result<usize>`：write-only 返回 `EBADF`。
- `write_at(...) -> Result<usize>`：read-only 返回 `EBADF`。

### `SecurityFsDirectory`

```rust
pub struct SecurityFsDirectory {
    name: &'static str,
    files: &'static [SecurityFsFile],
    directories: &'static [SecurityFsDirectory],
}
```

它只描述编译期静态、不可变的目录树。每层至少含一个文件或子目录；同层文件名、子目录名以及文件/目录交叉重名都被拒绝。不提供运行时增删、symlink 或 per-open 状态。

### `pub fn register_directory(name, files) -> Result<()>`

签名：

```rust
pub fn register_directory(
    name: &'static str,
    files: &'static [SecurityFsFile],
) -> Result<()>;
```

职责：

- 验证目录名和每个文件名非空，不是 `.`/`..`，不含 `/` 或 NUL，长度不超过 255。
- 空文件数组返回 `EINVAL`。
- 同一数组内重复文件名返回 `EEXIST`。
- 创建一个不可变 `SecurityDirectory`，然后注册到 securityfs root。
- 重复目录名返回 `EEXIST`。
- 不提供 unregister；内建 LSM 生命周期等于 kernel 生命周期。

### `pub fn register_hierarchy(directory) -> Result<()>`

- 递归验证并构造 `SecurityFsDirectory` 声明的完整子树。
- 任一后代非法时整棵树不发布。
- `register_directory` 保留为平坦目录兼容入口，并复用同一实现。

### 7.3 `fs_impls::securityfs`：文件系统实现

### `mod.rs`

#### `pub(super) fn init()`

按顺序执行：

1. 初始化 `SecurityRootNode::singleton()`。
2. 在 `/sys/kernel` 下注册 `EmptyNode::new("security")`，作为 mount point。
3. 向 VFS registry 注册 `SecurityFsType`。

调用位置在 `sysfs::init()` 之后。重复初始化是 kernel bug，使用 `unwrap/expect`。

#### `pub(crate) fn register_directory(...) -> Result<()>`

- 调用 `SecurityDirectory::new`。
- 将其添加到 `SecurityRootNode`。
- 把 `aster_systree::Error` 转换为标准 errno。

#### `#[cfg(ktest)] fn init_for_ktest()`

- 依次初始化 systree、VFS、sysfs、securityfs。
- 只供该模块 ktest 使用。

### `fs.rs`

#### `SecurityFs::singleton() -> &'static Arc<SecurityFs>`

- 用 `spin::Once` 创建唯一实例。
- securityfs 是虚拟易失文件系统；所有 mount 共享同一模型。

#### `SecurityFs::new() -> Arc<Self>`

- 申请匿名 device id。
- `SuperBlock` 参数：
  - magic `0x73636673`，与 Linux `SECURITYFS_MAGIC` 一致；
  - block size `4096`；
  - name max `255`。
- 用 `SecurityFsInode::new_root(SecurityRootNode, sb)` 创建根 inode。

#### `impl FileSystem for SecurityFs`

- `name() -> "securityfs"`。
- `sync() -> Ok(())`，因为没有持久介质。
- `root_inode()` clone 根 inode。
- `sb()` clone superblock。
- `fs_event_subscriber_stats()` 返回成员引用。

#### `impl FsType for SecurityFsType`

- `name() -> "securityfs"`。
- `properties() -> FsProperties::empty()`。
- `create()` 返回 singleton。
- `sysnode() -> None`。

### `node.rs`

#### `SecurityRootNode::singleton() -> &'static Arc<Self>`

- 根节点没有 attrs。
- 实现 `SysBranchNode`，初始权限 `0555`。
- `is_root() -> true`。
- `init_parent(...)` 是 no-op；root 永远没有 parent，与 `ConfigRootNode` 一致。
- 提供内部 `add_child(Arc<SecurityDirectory>)`。

#### `SecurityDirectory::new(directory) -> Result<Arc<Self>>`

- 根据 `files` 构建一次性的 `SysAttrSet`，再递归构建所有子目录。
- 保存静态声明中的 callback 表，不复制函数表。
- 作为 `SysBranchNode` 暴露不可变层级；所有目录权限为 `0555`。

#### `SecurityDirectory::file(name) -> Option<&SecurityFsFile>`

- 对静态小数组做线性查找。
- M1 每层只有极少静态子项，额外 `BTreeMap` 没有收益。

#### `SecurityDirectory::read_file_at(name, offset, writer)`

- 找不到返回 `ENOENT`。
- 委托 descriptor 的 `read_at`。
- 原样传播 callback errno。

#### `SecurityDirectory::write_file_at(name, offset, reader)`

- 找不到返回 `ENOENT`。
- 委托 descriptor 的 `write_at`。
- 原样传播 callback errno。

#### `impl SysNode` 所需的 attr 回调

- 调用上述 read/write 函数。
- 仅在 SysTree 直接调用路径中，把 `EFAULT` 映射为 `PageFault`、`EPERM/EACCES` 映射为 `PermissionDenied`、其余映射为 `AttributeError`。
- 正常 VFS I/O 不走这条错误压缩路径，而由 `SecurityFsInode` 专门实现。

### `inode.rs`

#### `impl SysTreeInodeTy for SecurityFsInode`

- 字段和 `ConfigInode` 保持一致：`node_kind`、`metadata`、`extension`、`RwLock<InodeMode>`、`parent`、`this`。
- `new_arc` 用 `Arc::new_cyclic`。
- 其余 getter/setter 只做字段访问。

#### `impl Inode for SecurityFsInode`

- `fs()` 返回 `SecurityFs::singleton()`。
- `create()` 返回 `EPERM`，用户态不能在 securityfs 创建条目。
- `revalidation_policy()` 与 sysfs 一致，使后注册的 AppArmor 目录可见。

#### `impl FileOps for SecurityFsInode`

只覆盖两个函数，其余沿用 `SysTreeInodeTy` 的 default 实现。

`read_at(offset, writer, flags)`：

1. 要求 `node_kind` 为 `Attr`，否则 `EINVAL`。
2. 把所属 `SysNode` downcast 为 `SecurityDirectory`，失败返回 `EIO`。
3. 调用 `read_file_at`，原样返回 errno。

`write_at(offset, reader, flags)`：

1. 要求 `node_kind` 为 `Attr`，否则 `EINVAL`。
2. downcast 为 `SecurityDirectory`。
3. 调用 `write_file_at`；不在 inode 层强制 offset 为 0，因为每个控制文件自己定义 seek/write 语义。

### 7.4 `kernel/comps/apparmor/src/lib.rs`：组装模块

### crate 属性和依赖

```rust
#![no_std]
#![deny(unsafe_code)]
extern crate alloc;
```

只依赖仓库已有 crate：`aster-core`、`aster-util`、`component`、`ostd`。不增加第三方依赖。

crate 根部先写 `//!` 文档，说明它只负责 M1 的策略加载控制面；随后定义返回 `"apparmor: "` 的 `__log_prefix`，再声明子模块。所有日志使用 `ostd` 日志宏。`securityfs.rs` 和 `policy/mod.rs` 也各自用 `//!` 说明自己的单一职责。

### `#[init_component] fn init() -> Result<(), ComponentInitError>`

- 在 bootstrap stage 调用 `aster_core::security::lsm::register(&APPARMOR_LSM)`。
- 任意注册错误记录一次明确日志并映射为 `ComponentInitError::Unknown`。
- 此时不能注册 securityfs 文件，因为 core 文件系统尚未初始化。

### `AppArmorLsm::init()`

- 仅在 AppArmor 最终被 LSM 选择器选中后执行。
- 调用本 crate 的 `securityfs::register()`。
- 不创建 namespace、label 或 unconfined profile。

### 7.5 `kernel/comps/apparmor/src/securityfs.rs`：AppArmor 用户态接口

### 静态目录树

```rust
static FILES: [SecurityFsFile; 2] = [
    SecurityFsFile::write_only(".load", write_load), // mode 0666, read op absent
    SecurityFsFile::read_only("profiles", read_profiles),
];

static APPARMOR_DIRECTORY: SecurityFsDirectory =
    SecurityFsDirectory::new("apparmor", &FILES, &FEATURE_DIRECTORIES);
```

`FEATURE_DIRECTORIES` 静态声明 `features/policy/versions`，最深层包含只读 `v5` 文件。

### `pub(super) fn register() -> Result<()>`

- 调用 `register_hierarchy(&APPARMOR_DIRECTORY)`，整棵树一次发布。
- 不创建 `.replace`、`.remove` 或 v5 之外的 feature。

### `fn read_v5_support(offset, writer) -> Result<usize>`

- 通过 `VmPrinter::new_skip` 返回 `yes\n`，遵循普通 offset/EOF 语义。
- feature 是公开能力声明，不要求 `CAP_MAC_ADMIN`。

### `fn check_policy_admin() -> Result<()>`

1. `Task::current()` 为空返回 `EACCES`。
2. `as_posix_thread()` 为空返回 `EACCES`。
3. 调用现有 `lsm::hooks::on_capable(CapableContext::new(..., CapSet::MAC_ADMIN))`。
4. 目标 user namespace 固定为 `UserNamespace::get_init_singleton()`。
5. capability hook 的拒绝统一映射为 `EACCES`，对齐 Linux `aa_may_manage_policy` 和 `profiles_open`；不能把 `on_capable` 的 `EPERM` 直接泄漏到该接口。

这样 Capability LSM 仍是最终授权者；AppArmor 不自行读取 UID，也不会绕过现有 capability 语义。

M1 在每次 `read_at/write_at` 回调开始时检查能力，而不为通用 securityfs 增加当前只有 AppArmor 会使用的 per-open callback。因此无权限进程可能成功 `open(2)`，但第一次 read/write 返回 `EACCES`；已打开 fd 的进程在丢失能力后也不能继续操作。Linux 的 `profiles` 在 open 时检查，这是本阶段有意记录的可观察差异，而不是宣称完全一致。

通用 securityfs adapter 对缺失方向的操作统一返回 `EBADF`，所以读取 `.load` 和写入 `profiles` 都得到 `EBADF`。Linux AppArmor 的 `.load` 没有 `.read` file operation，读取通常得到 `EINVAL`；该 errno 差异也是 M1 的有意差异。

### `fn copy_policy_blob(reader: &mut VmReader) -> Result<Vec<u8>>`

- 读取 `reader.remain()`，0 返回 `EINVAL`。
- 大于 `MAX_POLICY_BLOB_SIZE` 返回 `E2BIG`，不分配内存。
- `Vec::try_reserve_exact(len)` 失败返回 `ENOMEM`。
- resize 后用 `read_fallible` 一次复制全部字节。
- page fault 返回 `EFAULT`；不把部分数据传给 decoder。

### `fn write_load(offset, reader) -> Result<usize>`

执行顺序：

1. `check_policy_admin()?`。
2. `offset != 0` 返回 `ESPIPE`，与 Linux AppArmor 完整 write 语义一致。
3. 保存原始 `len`。
4. `copy_policy_blob`，此后不再访问用户内存。
5. `POLICY_STORE.load(&blob)?`。
6. 成功返回原始 `len`。

任何步骤失败都不会改变 store。

### `fn read_profiles(offset, writer) -> Result<usize>`

1. `check_policy_admin()?`。
2. `let snapshot = POLICY_STORE.snapshot()`，只在 clone `Arc` 时持锁。
3. 创建 `VmPrinter::new_skip(writer, offset)`。
4. 对已排序 profiles 输出 `"{} ({})\n"`。
5. 用户页 fault 映射为 `EFAULT`。
6. 返回本次实际写入字节数。

空 store 返回 0。一次 read 的所有行来自同一 snapshot；并发 load 不会让结果混合新旧集合。

### 7.6 `policy/mod.rs`：内核对象和原子 store

### 常量

```rust
const MAX_POLICY_BLOB_SIZE: usize = 1024 * 1024;       // 单次 1 MiB
const MAX_LOADED_PROFILES: usize = 1024;
const MAX_POLICY_STORE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROFILE_NAME_LEN: usize = 255;
```

单个 write 的 profile 数量和 store 总 profile 数量共用 `MAX_LOADED_PROFILES`：一次事务不可能合法加入超过 store 总上限的对象，不再增加一个重复配置项。单次字节上限不能替代累计上限；attachment DFA 使合法 profile 大小可显著增长，攻击者仍可能通过多次合法 write 耗尽内核内存。

### `ProfileMode`

```rust
enum ProfileMode {
    Enforce,
    Complain,
}
```

#### `ProfileMode::decode(raw: u32) -> Result<Self>`

- 0 -> `Enforce`。
- 1 -> `Complain`。
- 2/3/4 是已知但 M1 不支持的 mode，返回 `EOPNOTSUPP`。
- 其他值是损坏格式，返回 `EPROTO`。

#### `ProfileMode::as_str() -> &'static str`

- 返回 `enforce` 或 `complain`，供 `profiles` 输出。

### `Profile`

```rust
struct Profile {
    name: String,
    mode: ProfileMode,
    attachment: Option<AttachmentMatcher>,
}

struct AttachmentMatcher {
    encoded_dfa: Box<[u8]>,
    xmatch_len: u32,
}
```

M1 不保存整个 policy blob。name/mode 保存为语义字段；只有 attachment 的 DFA bytes 需要保留，因为 v5 ABI 不再携带可恢复的原始 attachment path。`encoded_dfa` 已通过 `dfa.rs` 的结构与状态边界完整校验，但 M1 不执行它。

getter：

- `name(&self) -> &str`
- `mode(&self) -> ProfileMode`
- `attachment(&self) -> Option<&AttachmentMatcher>`：crate 内可见，供 decoder/store 测试确认没有丢字段；M1 生产路径不调用 matcher。

### `DecodedPolicy`

```rust
struct DecodedPolicy {
    profiles: Vec<Profile>,
    charge: usize,
}
```

只在 decoder 到 store 之间存在，不对 crate 外暴露。`charge` 是整个输入 blob 的长度，不会因一个 blob 含多个 profile 而重复计费。

### `PolicySet`

```rust
struct PolicySet {
    profiles: Vec<Arc<Profile>>,
    charged_bytes: usize,
}
```

profiles 始终按 name 升序且唯一。

#### `PolicySet::try_insert_all(current, decoded) -> Result<Self>`

1. 检查 `current.len + decoded.profiles.len() <= MAX_LOADED_PROFILES`，加法溢出或超过上限返回 `ENOSPC`。
2. `checked_add(charged_bytes, decoded.charge)`；溢出或超过总上限返回 `ENOSPC`。
3. 对 incoming profile 按 name 做 `sort_unstable_by`；相邻重名返回 `EEXIST`，覆盖同一 blob 内重复。
4. 用双指针归并当前已排序集合与 incoming；名称相等返回 `EEXIST`，覆盖与已加载集合重复。
5. 对候选 Vec `try_reserve_exact(total_len)`，失败返回 `ENOMEM`；归并时旧对象 clone `Arc`，新对象转成 `Arc`。
6. 只有全部 profile 都加入候选后才返回 `PolicySet`；任何错误都不修改 current。

### `PolicyStore`

```rust
struct PolicyStore {
    current: Mutex<Option<Arc<PolicySet>>>,
}

static POLICY_STORE: PolicyStore = PolicyStore::new();
```

一个 sleepable `Mutex` 已足够：读者只持锁 clone 一个 `Arc`，写者需要串行检查并发布。额外的 writer lock 加 RwMutex 不会改善 M1，反而增加锁顺序。

#### `PolicyStore::new() -> Self`

- `const fn`，`current=None`。

#### `PolicyStore::load(&self, blob: &[u8]) -> Result<()>`

1. 再次检查空输入和单次大小，防止未来 crate 内调用绕过 securityfs。
2. 在不持锁时调用 `abi::decode(blob)`。
3. 获取 `current` mutex。
4. 调用 `PolicySet::try_insert_all(current.as_deref(), decoded)` 构造完整候选集合。
5. 候选构造成功后执行唯一一次 `*guard = Some(Arc::new(next))`。
6. 返回成功。

解析、用户内存复制和格式化都不在锁内。重复、容量或分配失败发生在发布前，因此旧 snapshot 保持不变。

#### `PolicyStore::snapshot(&self) -> Option<Arc<PolicySet>>`

- 获取 mutex。
- clone 当前 Arc 或返回 None。
- 立即释放 mutex。

PolicyStore ktest 全部创建各自的 `PolicyStore::new()`，不直接使用进程级 `POLICY_STORE`，因此不需要测试专用 `clear/reset`，也不依赖 ktest 执行顺序。

### 7.7 `policy/abi.rs`：有界二进制 decoder

### `Code`

```rust
#[repr(u8)]
enum Code {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    U64 = 3,
    Name = 4,
    String = 5,
    Blob = 6,
    Struct = 7,
    StructEnd = 8,
    List = 9,
    ListEnd = 10,
    Array = 11,
    ArrayEnd = 12,
}
```

#### `Code::try_from(u8)`

- 0..=12 映射到枚举。
- 其他值返回 `EPROTO`。

### `Cursor<'a>`

```rust
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
```

所有长度运算使用 `checked_add`，越界统一返回 `EPROTO`。

#### `Cursor::new(bytes) -> Self`

- `pos=0`。

#### `Cursor::is_eof() -> bool`

- 仅比较 `pos == bytes.len()`。

#### `Cursor::take(len) -> Result<&'a [u8]>`

- `checked_add(pos, len)`。
- 超过输入返回 `EPROTO`。
- 成功推进 pos。

#### `Cursor::code() -> Result<Code>`

- `take(1)` 后调用 `Code::try_from`。

#### `Cursor::u16_le() -> Result<u16>` / `u32_le() -> Result<u32>`

- 读取固定字节并用 `from_le_bytes`。

#### `Cursor::chunk16() -> Result<&'a [u8]>`

- 先读 u16 长度，再 `take(length)`。
- 不允许隐式截断。

#### `Cursor::name() -> Result<&'a [u8]>`

- 要求下一个 code 是 `Name`。
- 读取 u16 chunk。
- 要求 chunk 以 NUL 结束、NUL 前非空、内部无 NUL。
- 返回不含尾 NUL 的 bytes。

#### `Cursor::string() -> Result<&'a [u8]>`

- 与 `name()` 相同，但 code 必须是 `String`。

#### `Cursor::aligned_blob(name) -> Result<&'a [u8]>`

1. `expect_name(name)` 后要求 code `Blob`。
2. 读取 little-endian `u32` 总长度并转换为 `usize`。
3. 令 length 字段后的当前位置为 `data_start`；用 `checked_add` 计算 `data_end = data_start + total_len`，并要求 `data_end <= input.len()`。
4. 按 Linux `aa_ext` 语义计算：`rem = data_end & 7`；若 `data_start < rem` 则返回 `EPROTO`，否则令 `sz = data_start - rem`，再计算 `pad = (8 - (sz & 7)) & 7`；最后一个表达式等价于 `align_up(sz, 8) - sz`，且不会发生加法溢出。
5. 要求 `pad <= total_len`，且 `data_start..data_start + pad` 全为 0。
6. 一次 `take(total_len)` 推进 cursor，只返回 `data_start + pad..data_end` 的 DFA slice。

不能用 `align_up(data_start, 8) - data_start`。`apparmor_parser` 为每个顶层 profile 新建序列化缓冲后再把结果依次写入最终 stream；当前一 profile 长度不是 8 的倍数时，第二个 profile 的局部对齐基准与全局偏移不同。结束位置公式利用 DFA serialized size 本身为 8 字节倍数，恢复 parser 使用的局部 padding，并与 Linux `unpack_dfa()` 一致。

#### `Cursor::expect_name(expected) -> Result<()>`

- 读取 name 并按字节精确比较。
- 不匹配但 name 本身合法时返回 `EOPNOTSUPP`；损坏格式返回 `EPROTO`。

#### `Cursor::expect_code(expected) -> Result<()>`

- code 不匹配返回 `EPROTO`。

#### `Cursor::u32() -> Result<u32>`

- 要求 code `U32` 后读取 little-endian value。

#### `Cursor::named_u32(name) -> Result<u32>`

- `expect_name(name)` 后 `u32()`。

#### `Cursor::named_struct(name) -> Result<()>`

- `expect_name(name)` 后要求 `Struct`。

#### `Cursor::peek_name() -> Result<Option<&'a [u8]>>`

- 在临时 cursor 上尝试读取 name，不改变原 cursor。
- 下一个 code 不是 `Name` 返回 None。
- 下一个 code 是 Name 但内容损坏返回 `EPROTO`。
- 用于把“格式损坏”和“存在未支持的合法字段”区分开。

#### `Cursor::expect_no_named_field_before(expected) -> Result<()>`

- 如果 `peek_name()` 得到其他合法字段，返回 `EOPNOTSUPP`。
- 否则继续由调用者精确解析 expected。

### 顶层解码函数

#### `pub(super) fn decode(blob: &[u8]) -> Result<DecodedPolicy>`

1. 空输入返回 `EINVAL`，创建 Cursor 和空的 fallible Vec。
2. 当 `!cursor.is_eof()` 时，依次调用 `decode_header` 和 `decode_profile`。
3. 每次 push 前检查 profile 数量小于 `MAX_LOADED_PROFILES`；超过返回 `ENOSPC`。
4. policy unit 之间不允许 padding 或同步扫描；前一 profile `StructEnd` 后的下一个字节必须是下一单元的 `NAME("version")`，否则 `EPROTO`。
5. 返回 `DecodedPolicy { profiles, charge: blob.len() }`。

#### `fn decode_header(cursor) -> Result<()>`

- `named_u32("version")` 必须等于 `0x00000005`；其他 version 返回 `EPROTONOSUPPORT`。
- 若下一个合法 name 是 `namespace`，返回 `EOPNOTSUPP`。

#### `fn decode_profile(cursor) -> Result<Profile>`

1. `named_struct("profile")`。
2. 读取 unnamed STRING profile name。
3. `validate_profile_name`。
4. `decode_attachment`：下一个 name 为 `aadfa` 时解析并保存；为 `flags` 时返回 None；`rename`、`attach`、`perms` 或其他合法字段返回 `EOPNOTSUPP`。
5. `decode_flags`。
6. 若下一个 name 为 v5 `path_flags`，返回 `EOPNOTSUPP`；M1 不接受该字段，但不把已知 ABI 变体误报为损坏。
7. `decode_zero_capabilities`。
8. `decode_zero_caps64`。
9. 下一个 token 必须直接是 profile `StructEnd`；任何合法附加字段（包括 file/policy DFA）返回 `EOPNOTSUPP`。

#### `fn validate_profile_name(raw) -> Result<String>`

- 执行第 4.4 节约束。
- 非 UTF-8 返回 `EILSEQ`。
- namespace/hats 返回 `EOPNOTSUPP`。
- control character 或长度越界返回 `EINVAL`；其他格式损坏返回 `EPROTO`。
- 用 fallible reserve 后复制成 String。

#### `fn decode_attachment(cursor) -> Result<Option<AttachmentMatcher>>`

- 用 `peek_name()` 只区分 `aadfa`、`flags` 和未支持字段，不扫描重排。
- 对 `aadfa` 调用 `aligned_blob("aadfa")`，然后调用 `dfa::validate`；验证完成后才 fallible-copy 为 `Box<[u8]>`。
- 紧随其后的 unnamed `U32` 是 `xmatch_len`，0 返回 `EPROTO`。
- 只接受旧式 packed-permission xmatch；`perms`/`permsv` table 属于未冻结 ABI，返回 `EOPNOTSUPP`。

#### `fn decode_flags(cursor) -> Result<ProfileMode>`

- 解析 named `flags` struct。
- flags 和 audit 字必须为 0，非 0 返回 `EOPNOTSUPP`。
- mode 调用 `ProfileMode::decode`。
- 要求紧随 `StructEnd`。

#### `fn decode_zero_capabilities(cursor) -> Result<()>`

- 精确读取四个 unnamed U32。
- 任意非 0 返回 `EOPNOTSUPP`。

#### `fn decode_zero_caps64(cursor) -> Result<()>`

- 精确读取 named `caps64` struct、四个 unnamed U32 和 `StructEnd`。
- 任意非 0 返回 `EOPNOTSUPP`。

policy decoder 不递归、不扫描寻找同步点、不接受字段重排。最大输入已被限制为 1 MiB，profile 数量最多 1024；DFA validator 也只做有界线性遍历，因此 CPU 和内存消耗有直接上界。

### 7.8 `policy/dfa.rs`：attachment DFA 验证

该模块的外部 interface 只有一个函数：

```rust
pub(super) fn validate(encoded: &[u8]) -> Result<()>;
```

它只验证，不负责策略流 framing，也不提供 match。删除该模块会迫使 `abi.rs` 自己理解 flex table 内部结构，因此这个 seam 有实际 locality。

### `TableView<'a>`

```rust
#[derive(Clone, Copy)]
struct TableView<'a> {
    width: u8,
    len: usize,
    data: &'a [u8],
}
```

#### `TableView::get(index) -> Result<u32>`

- 检查 `index < len`。
- 根据 width 1/2/4 用 safe slice 和 `from_be_bytes` 读取；不做未对齐引用或 `unsafe` cast。

### `fn parse_table_set(encoded) -> Result<[Option<TableView>; 8]>`

1. 先要求 `encoded.len() >= 14`，再读取 big-endian magic `0x1B5E783D`、`header_size`、`serialized_size` 和 offset 12..14 的 flags；要求 `header_size >= 14`、按 8 字节对齐且不大于 `encoded.len()`，并要求 `serialized_size == encoded.len()`，否则返回 `EPROTO`。
2. header flags 必须为 0；0 明确合法。`DIFF_ENCODE=1` 或 `OOB_TRANS=2` 返回 `EOPNOTSUPP`，其他未知 bit 返回 `EPROTO`。
3. 从 `header_size` 开始迭代 table：每个 header 12 字节，wire id 必须是 1..=8 且不能是未支持的 META，width 只允许 1/2/4。
4. 用 `checked_mul/checked_add` 计算 `align_up(12 + len * width, 8)`；高 32 位长度必须为 0、低长度必须非零、table 必须完整落在 encoded 内。
5. 与 Linux `aa_dfa_unpack()` 一致，按对齐后的 table size 跳过每个 table 尾部 0..7 字节 padding，不要求这些字节为 0；padding 不属于 `TableView::data`，但必须落在 `serialized_size` 内。
6. 重复 id、尾随零碎字节或未精确消费输入返回 `EPROTO`。

### `fn verify_table_shapes(tables) -> Result<(usize, usize)>`

- 必须存在 ACCEPT、ACCEPT2、BASE、DEFAULT、NEXT、CHECK。
- ACCEPT/ACCEPT2/BASE 必须为 32-bit；DEFAULT/NEXT/CHECK 必须为 16-bit。32-bit 状态表或 EC table 属于已知但未冻结的编码，返回 `EOPNOTSUPP`；META 或其他未知 table 结构返回 `EPROTO`。
- `accept.len == accept2.len == base.len == default.len == state_count`。
- `next.len == check.len == transition_count`；`state_count >= 2`。

### `fn verify_state_bounds(tables, state_count, transition_count) -> Result<()>`

- 每个 DEFAULT state、NEXT target、CHECK owner 都必须小于 `state_count`。
- BASE 的 `DIFF_ENCODE=0x80000000` 或 `OOB_TRANS=0x20000000` flag 返回 `EOPNOTSUPP`，其他高 8 位 flag 返回 `EPROTO`。
- 无 flag 的 BASE 值与 255 的 checked sum 必须小于 `transition_count`。

`validate` 依次调用上述三个函数。M1 不保留未使用的 `verify_diff_chains` seam：DIFF/OOB、EC 和 32-bit 状态表要等出现真实 golden fixture 且 matcher 需要执行时再一起设计和验证。M1 也不解释 accept permission bit 的业务含义，因为 matcher 不执行；但冻结编码里所有未来可能参与索引或状态跳转的数据都已完成边界校验。

## 8. 错误语义

| 条件 | errno | store 是否变化 |
|---|---:|---|
| 无 `CAP_MAC_ADMIN` | `EACCES` | 否 |
| `.load` offset 非 0 | `ESPIPE` | 否 |
| 空 write | `EINVAL` | 否 |
| 单次输入大于 1 MiB | `E2BIG` | 否 |
| 用户内存读取失败 | `EFAULT` | 否 |
| 用户 buffer、名称或候选 Vec 的 fallible reserve 失败 | `ENOMEM` | 否 |
| 损坏、截断、字段顺序错误、DFA 结构/边界校验失败、单元间/末尾垃圾 | `EPROTO` | 否 |
| version 不是固定 ABI | `EPROTONOSUPPORT` | 否 |
| namespace、规则、`path_flags`、未冻结 attachment 变体或已知未支持 mode | `EOPNOTSUPP` | 否 |
| 非 UTF-8 profile name | `EILSEQ` | 否 |
| profile 名称含 control character 或长度越界 | `EINVAL` | 否 |
| profile 名称在同一 blob 内或与 store 重复 | `EEXIST` | 否 |
| profile 数量或累计 charge 达上限 | `ENOSPC` | 否 |
| 读取 `.load` / 写入 `profiles` | `EBADF` | 否 |
| `.replace`、`.remove` 或 v5 之外的 feature 不存在 | `ENOENT` | 否 |

同一个失败条件在 ktest 和用户态 regression 中必须断言具体 errno，不能只断言“失败了”。`write_load` 的顺序固定为 capability、offset、长度/复制、decode、publish，因此“无能力且 offset 非 0”必须返回 `EACCES`；用一个回归用例固定该优先级。

## 9. 并发和锁

M1 只使用一把 `Mutex<Option<Arc<PolicySet>>>`。

- reader：加锁 -> clone Arc -> 解锁 -> 格式化和写用户页。
- writer：先复制用户页并解码整批 profile -> 加锁 -> 检查当前集合并构造完整候选 -> 一次替换 Arc -> 解锁。
- 两个 writer 被 mutex 串行化，因此都基于自己获得锁时的最新集合，不会丢更新。
- 旧 reader 持有旧 Arc，可完成一致的读取；发布新集合不会使旧引用失效。
- 锁内没有用户 I/O、ABI/DFA 解析或 formatter 工作。候选 Vec 的有界分配发生在 sleepable mutex 内，最坏元素数 1024。

M1 不需要 RCU、generation、stable profile ID 或 task walk；这些都只有在任务持有 label 后才有实际用途。

## 10. 启动和选择行为

### AppArmor 开启

内核命令行：

```text
lsm=apparmor,yama
```

active 顺序为 mandatory Capability、AppArmor、Yama。AppArmor 的 `init()` 注册 securityfs 目录。

### AppArmor 关闭

默认命令行不包含 `apparmor`。`aster-apparmor` crate 虽然已链接并在 bootstrap 注册候选模块，但不会调用它的 `LsmModule::init()`，因此：

```text
/sys/kernel/security/                 # securityfs 可挂载，为空
/sys/kernel/security/apparmor         # ENOENT
```

这比编译 feature 开关更适合当前 LSM 框架，也能测试同一个 kernel image 的 on/off 行为。

## 11. 用户态使用方式

### 11.1 编译策略

```sh
apparmor_parser --stdout ./demo.profile > demo.bin
```

AppArmor 被选中时，parser 会从运行时 feature tree 自动选择 ABI v5。parser 必须是 v5.0.2；Asterinas NixOS 通过仓库 overlay 同时固定 `apparmor-parser` 与 `libapparmor` 为该版本。离线生成 fixture 时仍显式使用仓库内 feature 文件，生成脚本先检查精确版本。

### 11.2 加载

目标系统安装仓库提供的 parser 后，可直接从文本编译并写入 `.load`：

```sh
apparmor_parser --add ./demo.profile
```

原子性边界是一次 `.load` write：用户态用单次 `write(2)` 提交包含多个 profile 的 blob 时，内核整批发布或整批拒绝。当前 feature tree 不发布 `policy/set_load`，因此 libapparmor 5.0.2 会把含多个 profile 的 buffer 拆成多次 `.load` write；`apparmor_parser` 命令路径不承诺跨这些 write 的整批原子性。M1 的文本端到端承诺仅覆盖单 profile，未来只有在实现并发布 `policy/set_load` 对应语义后才能扩大该承诺。

回归测试不在 initramfs 安装 parser，而是对 `.load` 执行一次完整 `write(2)` 写入预编译 fixture。不要用可能拆成多次 write 的通用复制循环。

### 11.3 查询

```sh
cat /sys/kernel/security/apparmor/profiles
```

只有 `CAP_MAC_ADMIN` 可读。这个文件是 M1 感知“内核已 load profile”的正式用户态接口。

## 12. 测试设计

### 12.1 LSM ktest

测试 `ModuleRegistry` 的局部实例，避免污染全局 `Once`：

- 注册后可被 `lsm=apparmor` 选择。
- 与 built-in 重名返回 `EEXIST`。
- 扩展模块之间重名返回 `EEXIST`。
- seal 后注册返回 `EBUSY`。
- AppArmor `EXCLUSIVE` 不影响非 exclusive Yama。
- active init 只调用被选中的模块，并保持命令行顺序。
- 现有 Capability mandatory 和 Yama 默认选择测试保持通过。

### 12.2 securityfs ktest

- `SecurityFsFile::read_only/write_only` 分别得到 `0444/0666`；write-only read 与 mode 无关，仍返回 `EBADF`。
- 非法目录名、非法文件名、空文件表、重复文件名返回预期 errno。
- 重复目录注册返回 `EEXIST`。
- read-only 文件 write 返回 `EBADF`；write-only 文件 read 返回 `EBADF`。
- callback 返回 `EPROTO` 时，VFS `write_at` 仍返回 `EPROTO`，证明没有被压成 `EIO`。
- read offset 原样传给 callback。
- 静态声明与属性表意外不一致时，缺失 callback 文件返回 `ENOENT`，不返回 `EIO`。
- root node 的 `is_root()` 为 true，`init_parent()` 后仍无 parent。
- 用户态不能 create/unlink securityfs 条目。
- 静态声明的每一级目录 mode 都是 `0555`。
- `features/policy/versions/v5` 可递归 lookup，完整读取为 `yes\n`，offset 1 为 `es\n`，EOF 返回 0。
- 重复子目录名或同层文件/目录重名返回 `EEXIST`。

### 12.3 ABI decoder ktest

- 手工构造的 v5 最小 enforce profile 成功。
- complain mode 和带合法 attachment DFA 的 profile 成功，且 name/mode/xmatch_len/DFA bytes 均被保留。
- 两个连续 policy unit 成功；恰好 1024 个 profile 成功，1025 个返回 `ENOSPC`；第二个 header 缺失或同 blob 重名时整笔失败。
- 对单 profile 合法 blob 的每一个严格前缀做 truncation sweep，全部返回 `EPROTO`；对 multi-profile blob，完整 policy unit 串组成的前缀是合法 stream，其他严格前缀返回 `EPROTO`。
- 错误 type code、错误长度、缺 NUL、内部 NUL、单元间/末尾字节返回 `EPROTO`。
- 错误 version 返回 `EPROTONOSUPPORT`。
- 手工构造的 v7 policy header 返回 `EPROTONOSUPPORT`；namespace、`path_flags`、non-zero caps、file/policy DFA 和 attachment perms table 返回 `EOPNOTSUPP`。
- kill/unconfined/user mode 返回 `EOPNOTSUPP`。
- 非 UTF-8 返回 `EILSEQ`。
- 名称含 `\n`、`\r`、DEL 或其他 Unicode control character 返回 `EINVAL`。
- 名称边界 255 成功，256 失败。
- 测试 encoder 构造两个都带最小合法 attachment DFA 的连续 policy unit，并通过名称长度让第一个 unit 的长度不是 8 的倍数；测试先断言 `first_unit_len & 7 != 0`，再断言整个 stream 成功、第二个 DFA bytes 被正确取出并通过 `dfa::validate`。把第二个 BLOB 的任一前导 padding byte 改成非零返回 `EPROTO`。
- attachment BLOB 长度/边界错误、magic/size/type/id 错误、table 缺失/重复或 state/transition 越界返回 `EPROTO`。
- header DIFF/OOB、BASE DIFF/OOB、EC table 或 32-bit DEFAULT/NEXT/CHECK 返回 `EOPNOTSUPP`；header 未知 flag 或 BASE 未知高位 flag 返回 `EPROTO`。
- 在其他字段合法时，把 table 尾部 padding 改成非零仍通过，固定与 Linux 一致的“不校验 table padding”语义；这不影响 BLOB 前导 padding 必须全为零的规则。

测试 encoder 只放在 `#[cfg(ktest)]` 内，逐字节写固定 ABI，不进入生产代码。DFA 错误测试从已知合法的最小 matcher 出发逐字段 mutation，避免为每个错误手写整份 blob。ktest 不使用 `include_bytes!`，也不依赖 `test/initramfs` 下的 fixture；真实 `multi-attach.bin` 的互操作成功路径和 padding mutation 只由第 12.5 节 regression 覆盖。

### 12.4 PolicyStore ktest

- 每个用例创建局部 `PolicyStore::new()`，并断言其初始 snapshot 为 None；不得共享静态 `POLICY_STORE`。
- 第一个 profile load 后可见。
- 多 profile blob 一次 load 后全部可见且按名称排序。
- 两个不同 profile 分两次 load 后同时可见；同 blob 内重名或与已有名称重复均返回 `EEXIST`。
- 本批一个名称与 store 冲突、另一个名称全新时，整批仍不发布，新名称不可见。
- 任意 decode 失败后 snapshot 指针和内容不变。
- profile 数量上限和累计 charge 上限返回 `ENOSPC`；同模块私有测试可直接构造带指定 charge 的 `DecodedPolicy`，不增加生产或全局 reset hook。
- 两个并发 writer 不丢 profile。
- reader 在并发 publish 前后只能看到完整旧集合或完整新集合。

### 12.5 initramfs regression

`apparmor.c` 在两种启动方式下运行：

默认测试：

- 挂载 securityfs 成功。
- `/sys/kernel/security/apparmor` 为 `ENOENT`。
- 现有 Capability/Yama 测试不变。

AppArmor scheme：

```sh
make run_kernel AUTO_TEST=regression SCHEME=apparmor
```

`OSDK.toml` 中该 scheme 只追加 `lsm=apparmor,yama`。测试断言：

1. `.load`、`profiles` 和 `features/policy/versions/v5` 存在；mode 分别为 `0666/0444/0444`，v5 内容精确为 `yes\n`；`.replace/.remove` 不存在且返回 `ENOENT`。
2. 初始 `profiles` 为空。
3. 一次 write 加载官方 parser 生成、含 `/usr/bin/demo` attachment 的 `demo.bin`，读取得到 `demo (enforce)\n`。
4. 一次 write 加载 `multi-attach.bin`，两个 attachment DFA 都被正确解包且两个 profile 都出现；再加载 `observe.bin`，最终输出始终按名称排序。
5. 重复加载 demo、加载与 `multi-attach.bin` 同名的 `multi.bin`、同 blob 内重名或 multi blob 的任一名称与 store 冲突时返回 `EEXIST`，整笔查询不变。
6. 截断 blob、损坏 attachment DFA 或把 `multi-attach.bin` 第二个 BLOB 的 padding 改成非零时返回 `EPROTO`，查询不变。
7. 带 `path_flags` 和 namespace 的 fixture 返回 `EOPNOTSUPP`，v7 fixture 返回 `EPROTONOSUPPORT`，查询不变。
8. 超过 1 MiB 返回 `E2BIG`，查询不变。
9. fork 子进程清除 `CAP_MAC_ADMIN` 后，read/write 返回 `EACCES`；offset 同时非 0 时仍优先 `EACCES`。
10. euid 非 0、effective set 只有 `CAP_MAC_ADMIN` 且没有 `CAP_DAC_OVERRIDE` 的子进程可 open 并操作 `.load/profiles`，证明 `0666` 没有被 DAC 提前拦截。
11. 先 open 后清除 `CAP_MAC_ADMIN`，随后 read/write 返回 `EACCES`，固定 M1 的 operation-time recheck 语义。
12. 读取 `.load`、写入 `profiles` 返回 `EBADF`。
13. 加载前后执行普通 capability 测试，行为完全一致，证明 M1 没有 enforcement。

`pseudo_dev_id.c` 增加 securityfs，验证其匿名设备号与 sysfs/configfs/cgroupfs 不冲突。

### 12.6 Asterinas NixOS 端到端测试

`test/nixos/tests/security-apparmor` 安装 overlay 中的 `apparmor-parser`，并给测试内核追加 `lsm=apparmor,yama`。测试不读取仓库中的二进制 fixture，而是在客体内完成：

1. 验证 parser 版本为 5.0.2、v5 feature 为 `yes`；
2. 写入文本 `profile observe flags=(complain) {}`；
3. 用 `--stdout` 编译并核对 118 字节及冻结 SHA-256；
4. 用 `--binary --add` 加载，查询得到 `observe (complain)`；
5. 重复加载必须报告 `File exists`，查询结果保持不变。

## 13. Fixture 生成与可追溯性

`apparmor-fixtures/generate.sh` 只做四件事：

1. 验证 host 为 Linux 且 parser version 精确为 5.0.2。
2. 使用仓库内 v5 `features` 和 `.profile` 源文件执行 `apparmor_parser --stdout --features-file`；`multi-attach.bin` 的两个 profile 都带 executable attachment；`path-flags.bin` 使用 `flags=(attach_disconnected)` 触发真实 `path_flags` 字段；`namespaced.bin` 以无 attachment 的 `namespace-base.profile` 额外使用 `--namespace m1-test`；`v7-empty.bin` 仅作为负例，使用 `features-v7`。
3. 禁止压缩输出。
4. 更新 `SHA256SUMS`。

二进制 fixture 提交到仓库，让普通 regression build 不需要下载或构建 AppArmor userspace。源 profile、feature 文件、生成命令和 hash 同时提交，避免不可追溯的 opaque blob。

冻结的 v5.0.2 输出如下；生成脚本必须比对完整值：

| fixture | 内容 | 大小 | SHA-256 |
|---|---|---:|---|
| `demo.bin` | `profile demo /usr/bin/demo {}` | 1484 | `f877adf70efa115213a45d16cc11ff23d48b33ef5dee337c34ba2ee9008fa3a2` |
| `observe.bin` | complain、无 attachment | 118 | `912a45cf505271eee29e01e01d6d41abbe32ee540f94a10886746c5874400c16` |
| `multi.bin` | `demo1` + `demo2` 单 blob | 232 | `b7fd47bc42e4c21592258d2e91f59c8cae1face5407cb638aa354f906775134b` |
| `multi-attach.bin` | `demo1 /usr/bin/demo1` + `demo2 /usr/bin/demo2` 单 blob | 3016 | `be5438f6407bbbee631214f30550754ee2f093de8ff5a0e578c0bff084a883bd` |
| `path-flags.bin` | `path-flags` + `flags=(attach_disconnected)` | 140 | `65199eeff974271abaa45d7f138d86afd5e66eada73a8438d473e37ac57553d9` |
| `namespaced.bin` | `--namespace m1-test` + 无 attachment demo | 139 | `887958a93d92dd22b8628e622fdbb906f8bdb4c28f985707a0b9599bd6862cc9` |
| `v7-empty.bin` | v7 空 demo，含 `policydb/aadfa` | 1322 | `41e4c6dfc12b3990c66278bffbf3ab6260948f0900a0abb0d52dfc0421913a9a` |

`multi-attach.bin` 的两个 policy unit 都是 1508 字节。第二个 `aadfa` 的 BLOB data 起点为全局偏移 1559、结束位置为 2932；结束位置公式得到 5 字节 padding，DFA magic 位于 1564。旧的全局起点公式只会得到 1，回归 mutation 固定修改 1559..1563 中的 padding byte，防止该错误再次出现。

`test/initramfs/src/regression/security/lsm/Makefile` 必须在 include 通用 Makefile 后，把 `apparmor-fixtures/*.bin` 显式加入 `all` prerequisites，并用单独规则复制到 `$(OBJ_OUTPUT_DIR)/apparmor-fixtures/`。通用 Makefile 只处理 `*.c`、`*.S` 和 `*.sh`，不会自动打包 `.bin`。`apparmor.c` 使用绝对路径 `/test/security/lsm/apparmor-fixtures/<name>.bin`，不依赖测试当前目录。

回归测试使用官方 fixture；ktest 使用最小手写字节，二者目的不同：前者验证真实互操作，后者精确覆盖错误分支。

## 14. 完成标准

只有同时满足以下条件，M1 才算完成：

- `cargo fmt --check` 通过。
- 受影响 crate 的 clippy/build 通过。
- LSM、securityfs、ABI、PolicyStore ktest 全部通过。
- 默认 regression 证明 AppArmor 关闭时无节点且无行为变化。
- `SCHEME=apparmor` regression 证明官方 v5.0.2 fixture 可 load、可查询、失败原子、权限受控。
- AppArmor 5.0.2 Nix 包通过上游测试，且 Asterinas NixOS 端到端测试证明文本 profile 可编译、加载和查询。
- `git diff --check` 通过。
- 文档明确写出“loaded but not enforced”。

## 15. 为什么 M1 不实现 `aa_ns`

Linux 的 `aa_ns` 同时承担：可见 profile 集合、父子 namespace、unconfined label、revision、锁、策略容量、raw data、securityfs virtualization 和 namespace 生命周期。M1 没有 task label、namespace 切换、replace/remove 或 namespace 可见性，复制这个结构只会得到一个只有 root 实例的空壳。

当前 `PolicyStore` 已覆盖 M1 真正需要的三个 invariant：

- 名称唯一；
- 有界容量；
- 原子发布一致 snapshot。

只有出现下面任一已批准需求时，才设计 namespace 模块：

- policy blob 的 `namespace` 字段需要被接受；
- 不同任务需要看到不同 profile 集合；
- label 持有 namespace 生命周期；
- `.replace/.remove` 需要 namespace revision 或 raw policy export；
- securityfs 查询需要按 namespace 虚拟化。

到那时应从业务语义提炼 `PolicyNamespace`，而不是预先照搬 Linux `aa_ns` 的全部字段。

## 16. 有意留下的限制

- 运行时 feature tree 只提供 `/features/policy/versions/v5`；其余能力保持缺失，避免 parser 生成 M1 尚不接受的规则编码。
- 只接受 ABI v5；v6/v7 的 policydb 留到实际需要规则编码时再增加。
- attachment DFA 只接受冻结 fixture 覆盖的 `flags == 0`、无 EC、无 OOB/DIFF、16-bit 状态表编码；扩展接受面必须先增加相应的真实 golden fixture。
- attachment matcher 只被验证和保存，不执行；M2 开始匹配前必须先定义 exact-path 语义和可执行 DFA 表示，并补齐 Linux `verify_dfa` 的 accept flags、DIFF chain 成环、OOB 语义以及 `xmatch_len` 与 DFA 的一致性校验。
- capability/file 等规则仍被拒绝；M1 的 profile 只是 name、mode 和可选 attachment metadata。
- 不保存原始 policy blob，也不支持导出。
- 不承诺加载顺序，查询固定按 profile name 排序。

这些限制不会阻止 M1 的核心结果：通过 securityfs 把官方格式的最小 profile 加载并保存到内核，并由用户态可靠查询当前已加载集合。
