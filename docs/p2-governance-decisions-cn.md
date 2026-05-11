# P2 治理决策记录

> 本文档记录 P2 级代码质量治理项的复核结论。
> P2 项通常为只读复核、文档约束补充，不涉及行为变更。
> 遵循原则：最佳兼容性、最小破坏性、最小侵入性。

---

## P2-12 Firewall RCU 规则快照优化设计文档

| 字段 | 内容 |
|------|------|
| **编号** | P2-12-RCU |
| **当前决策** | **已完成设计文档，暂不实施** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §4.6 |
| **设计文档** | `docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` |

### 问题描述

P2-12 最小侵入优化（OPT-P2-12b/c）已实施，减少后缀拼接临时分配并移除冗余自拷贝。
剩余较大优化包括：

1. **RCU 规则快照**：使用 `std::atomic_load/store` free functions 实现 C++17 RCU 快照，消除域名表每次查询的 O(N) 深拷贝。
2. **反向 trie / `string_view` 后缀匹配**：替代线性 suffix walk。
3. **单趟 normalize**：替代 `LTrim(RTrim(ToLower(...)))` 三临时串链。

### 设计文档内容

`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` 涵盖：

- 当前问题分析（锁竞争、快照复制开销、后缀匹配线性扫描）
- C++17 RCU 快照方案详设（`FirewallRuleSnapshot` 结构体、读取路径不获取 `Firewall::syncobj_` / `shared_mutex`、写入路径 Copy-Modify-Publish）
- 读写线程安全模型（读取-写入并发安全、写入路径锁保留原因、`atomic_load/store` 行为）
- 为何不用 C++20 `std::atomic<std::shared_ptr<T>>`（项目基线 C++17、free functions vs atomic shared_ptr 对比、迁移路径）
- 语义保持矩阵（必须保持的行为、可接受的变化、不可接受的变化）
- 反向 trie 后缀匹配方案（独立于 RCU 的可选优化）
- 单趟 normalize 方案（独立于 RCU 的可选优化）
- 测试与基准计划（功能正确性、并发正确性、性能基准）
- 五阶段迁移步骤与回滚策略
- 风险评估与实施前置条件

### 暂不实施的原因

1. **无自动化测试基础设施**：项目零测试。RCU 快照修改所有读取路径的核心逻辑，没有回归测试，细微 bug 可能导致所有防火墙查询返回错误结果。
2. **无性能基准工具**：需要基准测试验证 RCU 快照的实际收益，当前项目无基准测试框架。
3. **`ppp::string` / `ppp::unordered_set` 的 move 语义需验证**：快照复制依赖容器的高效 move 构造，需确认不引入意外的深拷贝。
4. **与其它 P2 条目互不依赖**：设计文档已完成，实施时可独立进行。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他修复分支中混入该项的代码改动。
- 本文档和设计文档仅作记录用途，不触发代码行为变更。
- 实施时必须保持所有 public API 签名不变，保持匹配语义不变。

### 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 基本集成测试存在 | 至少覆盖防火墙查询路径 | ❌ 无测试 |
| C-2 | 性能基准工具存在 | 验证 RCU 快照收益 | ❌ 无基准工具 |
| C-3 | `ppp::string` move 语义确认 | 快照复制依赖高效 move | ⚠️ 需验证 |

---

## P2-16 Dispose/Finalize 分级治理尾项复核

| 字段 | 内容 |
|------|------|
| **编号** | P2-16 |
| **当前决策** | **已完成只读复核：3 个类确认假设成立，仅记录治理约束，不改代码** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §15.2、§15.3 |
| **关联治理项** | P1-2（strand/thread-confined `disposed_` 分级复核） |

### 问题描述

P1-2 已完成 §15.2 中 4 个类的分级复核：
- 2 个类改为 `std::atomic_bool`（VEthernetLocalProxyConnection、VEthernetLocalProxySwitcher）
- 2 个类记录约束不改（InternetControlMessageProtocol、ITransmissionQoS）

§15.3 中 1 个类（Timer）记录为单线程生命周期，保持现状。

P2-16 对上述未修改的 3 个类进行二次只读代码复核，确认：
1. P1-2 记录的约束是否仍然成立
2. 是否存在隐式 atomic bool 读取风格问题（参考 P1-3 WebSocket 案例）
3. 是否需要补充治理约束和后续触发条件

### 复核结果

#### InternetControlMessageProtocol（strand-confined）

| 字段 | 内容 |
|------|------|
| **文件** | `ppp/net/asio/InternetControlMessageProtocol.h` / `.cpp` |
| **`disposed_` 类型** | `bool`（plain） |
| **复核结论** | **strand-confined 假设成立，不改** |

**线程模型验证：**

| 路径 | 操作 | 线程 | 验证 |
|------|------|------|------|
| `Echo()` line 364 | 读 `disposed_` | executor 线程 | `Echo()` 由 `VirtualEthernetExchanger::SendEchoToDestination()` 和 `StaticEchoEchoToDestination()` 调用，均在 exchanger 的 executor 线程上；ICMP 协议与 exchanger 共享同一 `io_context` |
| `Finalize()` line 327 | 写 `disposed_` | executor 线程 | `Dispose()` 通过 `boost::asio::post(*context, ...)` 投递 `Finalize()`；析构函数的 `Finalize()` 仅在所有 `EchoAsynchronousContext::owner_` 引用释放后运行 |
| `Dispose()` line 342 | 间接写（post） | 任意线程 → executor | `boost::asio::post` 保证 `Finalize()` 在 executor 线程执行 |

**风格检查：** `if (true == disposed_)` 是 plain bool 读取，非隐式 atomic 转换。无需修改。

#### ITransmissionQoS（mutex-protected）

| 字段 | 内容 |
|------|------|
| **文件** | `ppp/transmissions/ITransmissionQoS.h` / `.cpp` |
| **`disposed_` 类型** | `bool`（plain） |
| **复核结论** | **mutex-protected 假设成立，不改** |

**锁保护验证：**

| 方法 | `disposed_` 操作 | 锁保护 | 验证 |
|------|------------------|--------|------|
| `ReadBytes()` line 89 | 读 | ✅ `SynchronizedObjectScope scope(syncobj_)` | 在 `for (;;)` 循环内 |
| `EndRead()` line 128 | 读 | ✅ `SynchronizedObjectScope scope(syncobj_)` | 在 `else` 分支内 |
| `BeginRead()` line 146 | 读 | ✅ `SynchronizedObjectScope scope(syncobj_)` | 在 `for (;;)` 循环内 |
| `Finalize()` line 182 | 写 | ✅ `SynchronizedObjectScope scope(syncobj_)` | 在 `for (;;)` 循环内 |

**原子成员说明：** `bandwidth_`（`std::atomic<Int64>`）和 `traffic_`（`std::atomic<UInt64>`）用于无锁跨线程读取（`IsPeek()`、`GetBandwidth()`），与 `disposed_` 的锁保护模式不矛盾。

**风格检查：** 所有 `disposed_` 读写均在锁内，无隐式 atomic 转换问题。

#### Timer（single-thread）

| 字段 | 内容 |
|------|------|
| **文件** | `ppp/threading/Timer.h` / `.cpp` |
| **`_disposed_` 类型** | `bool`（plain） |
| **复核结论** | **单线程假设成立，不改** |

**线程模型验证：**

| 路径 | 操作 | 线程 | 验证 |
|------|------|------|------|
| `Start()` line 86 | 读 `_disposed_` | executor 线程 | `Start()` 由用户代码在 executor 线程调用 |
| `Next()` line 120 | 读 `_disposed_` | executor 线程 | `Next()` 由 async_wait 回调调用，运行在 executor 线程 |
| `Finalize()` line 53/59 | 写 `_disposed_` | executor 线程 | `Dispose()` 通过 `boost::asio::post` 投递；析构函数在所有 `shared_ptr` 释放后运行（async_wait 回调持有 `self` 引用） |

**`tick_event_guard_` 说明：** `tick_event_guard_`（`std::atomic<bool>`）是独立的回调许可开关。`OnTick()` 在执行用户回调前读取该 guard，`Finalize()` 清除该 guard 并释放回调表。跨线程 `Dispose()` 是允许路径，会通过 `boost::asio::post` 回到 executor 执行 `Finalize()`；若未来出现析构或直接 `Finalize()` 不再满足 executor 生命周期约束的路径，需要重新评估。该 guard 与 `_disposed_` 的 plain `bool` 设计不矛盾——`_disposed_` 的正常读写都在 executor 线程上，不需要 atomic。

**风格检查：** `_disposed_` 是 plain bool 读取，非隐式 atomic 转换。`tick_event_guard_` 已使用显式 `load(acquire)` / `store(release)` 风格。

### 治理文档补充

| 文件 | 修改 | 描述 |
|------|------|------|
| `docs/p2-governance-decisions-cn.md` | 新增治理记录 | 记录 `disposed_` 线程模型复核结果、后续触发条件和非阻断约束 |
| `docs/openppp2-deep-code-audit-cn.md` | 更新 §15 | 同步 P2-16 复核状态，不宣称全仓生命周期治理完全完成 |

### 未变更项

- **未改变任何 `disposed_` 类型**：3 个类的 `disposed_` 保持 plain `bool`。
- **未改变任何业务逻辑**：仅补充治理文档。
- **未改变 public API**：所有类的 public/protected 接口签名不变。
- **未改变 Finalize 调用顺序**：保持原有 cleanup 顺序。
- **未原子化**：确认无需原子化的类保持原样。

### 后续触发条件

| 触发条件 | 影响类 | 动作 |
|---|---|---|
| `InternetControlMessageProtocol::Echo()` 被从非 executor 线程调用 | InternetControlMessageProtocol | 升级 `disposed_` 为 `std::atomic_bool` |
| `ITransmissionQoS` 的 `disposed_` 出现锁外读写路径 | ITransmissionQoS | 升级 `disposed_` 为 `std::atomic_bool` 或将锁外路径纳入锁保护 |
| `Timer` 被跨线程直接调用 `Start()`/`Stop()`/mutating setter，或析构路径不再满足 executor 生命周期约束 | Timer | 重新评估并按需升级 `_disposed_` 为 `std::atomic_bool` |
| 新增使用 `disposed_` + `Finalize()` 模式的类 | 新类 | 按 §15.1–§15.3 分级评估 |

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 本文档仅作记录用途，不触发代码行为变更。
- 本文档和 `docs/openppp2-deep-code-audit-cn.md` §15 的修改与其他 P1/P2 条目互不依赖。

---

*创建时间：2026-05-11*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §15*
