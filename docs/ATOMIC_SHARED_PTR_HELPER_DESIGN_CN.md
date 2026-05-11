# `std::atomic_load/store(shared_ptr*)` 兼容 Helper 设计文档

> 编号：S-4-HELPER
> 状态：**设计文档，暂不实施**
> 决策日期：2026-05-11
> 关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §14.6 S-4、§16
> 关联设计文档：`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` §3.3、§4
> 语言标准：C++17

---

## 1. 背景与动机

### 1.1 项目现状

项目锁定 C++17（`CMakeLists.txt` 中 `set(CMAKE_CXX_STANDARD 17)`）。为保护 `shared_ptr` 成员在跨 strand/线程并发读写中的控制块完整性，已在以下位置使用 `std::atomic_load/store` free functions：

| 成员 | 文件 | 保护方式 |
|------|------|----------|
| `WebSocket::socket_` | `ppp/transmissions/templates/WebSocket.h` | `std::atomic_load/store` |
| `ITcpipTransmission::socket_` | `ppp/transmissions/ITcpipTransmission.cpp` | `std::atomic_load/store` |
| `ITransmission::protocol_` | `ppp/transmissions/ITransmission.cpp` | `std::atomic_load/store` |
| `ITransmission::transport_` | `ppp/transmissions/ITransmission.cpp` | `std::atomic_load/store` |
| `VEthernet::fragment_` | `ppp/ethernet/VEthernet.cpp` | `std::atomic_exchange/load` |
| `VEthernet::netstack_` | `ppp/ethernet/VEthernet.cpp` | `std::atomic_exchange/load` |
| `VNetstack::TapTcpLink::socket` | `ppp/ethernet/VNetstack.cpp` | `std::atomic_exchange/load/store` |
| `VNetstack::sync_ack_byte_array_` | `ppp/ethernet/VNetstack.cpp` | `std::atomic_load/store` |
| `VNetstack::sync_ack_tap_driver_` | `ppp/ethernet/VNetstack.cpp` | `std::atomic_load/store` |

未来 Firewall RCU 规则快照（`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`）也会使用同一模式。

### 1.2 为什么不直接使用 `std::atomic<std::shared_ptr<T>>`

| 维度 | C++17 free functions | C++20 `std::atomic<std::shared_ptr<T>>` |
|------|----------------------|------------------------------------------|
| 标准状态 | C++17 可用 | C++20 起可用 |
| C++20 弃用 | free functions 起被标记 deprecated | N/A |
| C++26 移除 | **free functions 计划被移除** | N/A |
| 项目基线 | ✅ 可用 | ❌ 不可用 |
| CAS 支持 | ✅ `atomic_compare_exchange_*` free functions | ✅ `compare_exchange_weak/strong` |
| 原子 exchange | ✅ `atomic_exchange` free function | ✅ `exchange()` |
| lock-free | ❌ 实现为全局 spinlock 表 | 部分平台已 lock-free |

**结论：** 项目基线为 C++17，`std::atomic<std::shared_ptr<T>>` 不可用。必须使用 free functions。引入兼容 helper 是为未来 C++20 迁移做准备的最低成本方案。

---

## 2. C++20/C++26 迁移风险

### 2.1 弃用时间线

| C++ 标准 | free functions 状态 | 项目影响 |
|----------|---------------------|----------|
| C++17 | 正常可用 | ✅ 当前基线 |
| C++20 | `[[deprecated]]` | 编译警告（`-Wdeprecated-declarations`） |
| C++23 | `[[deprecated]]` | 同上，部分编译器可能默认 `-Werror` |
| C++26 | **计划移除** | 编译错误 |

### 2.2 实际风险评估

- **短期（C++17 基线不变）：** 零风险。所有调用在 C++17 下完全合规。
- **中期（若升级 C++20）：** 编译警告。可通过 `-Wno-deprecated-declarations` 临时抑制，或迁移到 `std::atomic<std::shared_ptr<T>>`。
- **长期（C++26）：** 若项目升级到 C++26 而未迁移，将产生编译错误。必须在此之前完成迁移。

### 2.3 编译器实现差异

| 编译器 | `atomic_load/store(shared_ptr*)` 实现 | lock-free | 性能特征 |
|--------|--------------------------------------|-----------|----------|
| libstdc++ (GCC) | 全局 spinlock 表（hash table of mutexes） | ❌ | ~20-50ns/调用 |
| libc++ (Clang) | 全局 spinlock 表 | ❌ | ~20-50ns/调用 |
| MSVC STL | 全局 spinlock 表 | ❌ | ~20-50ns/调用 |

三种主流实现均使用全局 spinlock 表，不是 lock-free。高频路径（如每包 read/write）可能产生 spinlock contention，但当前项目中 `atomic_load/store` 调用频率远低于 spinlock contention 阈值，可接受。

---

## 3. Helper API 设计

### 3.1 设计目标

1. **零行为变更：** 现有调用模式不改变，仅包装为命名函数。
2. **编译期版本检测：** C++20+ 时通过 `static_assert` 或编译器诊断提示迁移。
3. **最小侵入：** 单头文件，无运行时开销（inline 展开），无新依赖。
4. **便于 grep 迁移：** 统一命名后，C++20 迁移时可通过 `grep -r atomic_load_compat` 精确定位所有调用点。

### 3.2 API 原型

```cpp
// ppp/net/AtomicSharedPtr.h（未来新增，暂不实施）

#pragma once

#include <memory>      // std::shared_ptr
#include <utility>     // std::move

namespace ppp {
namespace net {

/**
 * @brief C++17 兼容的 atomic shared_ptr 读取包装。
 *
 * 封装 std::atomic_load(shared_ptr*) free function。
 * C++20 迁移时，删除此函数，改用 std::atomic<std::shared_ptr<T>>::load()。
 *
 * @tparam T shared_ptr 指向的类型（含 cv 限定符）
 * @param p 指向 shared_ptr 对象的指针，不得为 nullptr
 * @return p 指向的 shared_ptr 的原子副本
 *
 * @note 线程安全：参照 C++17 §[util.smartptr.shared.atomic]
 * @note 性能：主流实现为全局 spinlock 表，非 lock-free
 */
template<class T>
std::shared_ptr<T> atomic_load_compat(const std::shared_ptr<T>* p) noexcept
{
    // C++20+: 此包装仍调用 free function 以保持接口一致。
    // 迁移时直接删除此函数，改用 atomic<shared_ptr<T>>::load()。
    return std::atomic_load(p);
}

/**
 * @brief C++17 兼容的 atomic shared_ptr 写入包装。
 *
 * 封装 std::atomic_store(shared_ptr*, shared_ptr) free function。
 * C++20 迁移时，删除此函数，改用 std::atomic<std::shared_ptr<T>>::store()。
 *
 * @tparam T shared_ptr 指向的类型（含 cv 限定符）
 * @param p 指向 shared_ptr 对象的指针，不得为 nullptr
 * @param r 要存储的值，调用后 r 仍保持有效（与 std::atomic_store 行为一致）
 *
 * @note 线程安全：参照 C++17 §[util.smartptr.shared.atomic]
 * @note 性能：同 atomic_load_compat
 */
template<class T>
void atomic_store_compat(std::shared_ptr<T>* p, std::shared_ptr<T> r) noexcept
{
    std::atomic_store(p, std::move(r));
}

} // namespace net
} // namespace ppp
```

### 3.3 为什么暂不提供 `atomic_exchange_compat`

**标准事实：C++17 提供 `shared_ptr` 版 atomic exchange/CAS free functions。**

C++17 `shared_ptr` atomic free functions（§[util.smartptr.shared.atomic]）覆盖以下操作：

- `std::atomic_is_lock_free(const shared_ptr<T>*)`
- `std::atomic_load(const shared_ptr<T>*)`
- `std::atomic_load_explicit(const shared_ptr<T>*, memory_order)`
- `std::atomic_store(shared_ptr<T>*, shared_ptr<T>)`
- `std::atomic_store_explicit(shared_ptr<T>*, shared_ptr<T>, memory_order)`
- `std::atomic_exchange(shared_ptr<T>*, shared_ptr<T>)`
- `std::atomic_exchange_explicit(shared_ptr<T>*, shared_ptr<T>, memory_order)`
- `std::atomic_compare_exchange_weak/strong(shared_ptr<T>*, shared_ptr<T>*, shared_ptr<T>)`
- `std::atomic_compare_exchange_weak_explicit/strong_explicit(...)`

因此，当前代码中的：

```cpp
std::shared_ptr<IPFragment> fragment =
    std::atomic_exchange(&fragment_, std::shared_ptr<IPFragment>());
```

在 C++17 下应匹配标准提供的 `shared_ptr` atomic free function overload，
不依赖 `shared_ptr` 为 `TriviallyCopyable`，也不应被描述为非标准行为。

**设计决策：** 本阶段仍不提供 `atomic_exchange_compat` 包装。理由：

- 当前 helper 目标只覆盖最常见的 `atomic_load/store` 迁移封装，避免扩大 API 面。
- `exchange` 常用于 exactly-once take-and-clear 语义，调用点需要逐一审查外部同步、生命周期与重复 Dispose 风险，不能与普通 load/store 机械同等处理。
- 如果 C++17 代码确实需要唯一取走语义，应直接显式使用标准 `std::atomic_exchange(shared_ptr*)` free function，或使用 strand/mutex 保护复合操作。
- C++20 迁移时，已有 `std::atomic_exchange` free function 调用点应直接映射到 `std::atomic<std::shared_ptr<T>>::exchange()`。
- 不把 `atomic_load + atomic_store({})` 包装成 exchange 风格 helper，避免误导使用者以为两次独立原子操作具备 atomic exchange 语义。

### 3.4 Base/Derived 显式转换规则

#### 问题描述

当 `shared_ptr<Derived>` 需要存储到 `shared_ptr<Base>` 类型的原子成员时，`std::atomic_store` 的模板推导会失败：

```cpp
// 假设 Derived : Base
std::shared_ptr<Base> base_ptr;
std::shared_ptr<Derived> derived_ptr = std::make_shared<Derived>();

// ❌ 编译错误：模板推导失败
// atomic_store 的签名是：
//   template<class T>
//   void atomic_store(shared_ptr<T>* p, shared_ptr<T> r);
// 编译器从第一个参数推导 T = Base，
// 从第二个参数推导 T = Derived，推导冲突。
std::atomic_store(&base_ptr, derived_ptr);
```

#### 解决方案

**显式转换：** 在调用 `atomic_store` 前，将 `shared_ptr<Derived>` 显式转换为 `shared_ptr<Base>`：

```cpp
// ✅ 正确：显式转换
std::shared_ptr<Base> base_compatible = derived_ptr;  // 隐式向上转换
std::atomic_store(&base_ptr, base_compatible);

// ✅ 或使用 std::static_pointer_cast
std::atomic_store(&base_ptr, std::static_pointer_cast<Base>(derived_ptr));

// ✅ 或使用 std::dynamic_pointer_cast（需要 RTTI）
std::atomic_store(&base_ptr, std::dynamic_pointer_cast<Base>(derived_ptr));
```

#### Helper 中的处理

Helper 包装保持与 `std::atomic_store` 相同的签名约束，不引入隐式转换：

```cpp
template<class T>
void atomic_store_compat(std::shared_ptr<T>* p, std::shared_ptr<T> r) noexcept
{
    // T 必须完全匹配，不接受 Base/Derived 隐式转换
    std::atomic_store(p, std::move(r));
}
```

**理由：** 隐式转换会掩盖类型不匹配的潜在问题。显式转换是安全的，因为：
1. 向上转换（Derived → Base）在 `shared_ptr` 中是零开销的（仅指针调整或无调整）。
2. 转换失败（类型不兼容）在编译期即可发现。
3. 保持与标准 `atomic_store` 行为完全一致，降低迁移成本。

#### 当前仓库中的 Base/Derived 场景

经搜索，当前仓库中**没有**直接将 `shared_ptr<Derived>` 存储到 `shared_ptr<Base>` 原子成员的场景。所有 `atomic_store` 调用的源类型与目标类型完全一致：

| 成员类型 | atomic_store 源类型 | 匹配 |
|----------|---------------------|------|
| `shared_ptr<IWebsocket>` | `shared_ptr<IWebsocketObject>` | ✅ 完全匹配（`IWebsocketObject` 直接构造为 `IWebsocket`） |
| `shared_ptr<Ciphertext>` | `shared_ptr<Ciphertext>` | ✅ 完全匹配 |
| `shared_ptr<tcp::socket>` | `shared_ptr<tcp::socket>` | ✅ 完全匹配 |

> **注：** `WebSocket.h:83` 的 `std::atomic_store(&socket_, websocket)` 中，`websocket` 的类型是 `std::shared_ptr<IWebsocket>`（通过 `make_shared_object<IWebsocketObject>(...)` 构造后赋值给 `std::shared_ptr<IWebsocket>` 变量），模板推导一致，不触发 Base/Derived 问题。

#### 未来 Firewall RCU 场景

`FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` §2.5 已正确处理此问题：

```cpp
// 4. 显式转换为 const 快照指针后原子发布，避免 C++17 atomic_store 模板推导冲突
std::shared_ptr<const FirewallRuleSnapshot> published = std::move(new_snap);
std::atomic_store(&snapshot_, std::move(published));
```

这里 `new_snap` 是 `shared_ptr<FirewallRuleSnapshot>`（non-const），`snapshot_` 是 `shared_ptr<const FirewallRuleSnapshot>`。通过显式赋值到 `shared_ptr<const ...>` 变量，避免了 `const` 限定符差异导致的模板推导冲突。

---

## 4. "移出"（Take-and-Clear）模式的限制

### 4.1 当前模式

代码库中存在"取出并清空"的模式：

```cpp
// WebSocket.h Finalize()
std::shared_ptr<IWebsocket> socket = std::atomic_load(&socket_);
std::atomic_store(&socket_, std::shared_ptr<IWebsocket>());

// VEthernet.cpp ReleaseAllObjects()
std::shared_ptr<IPFragment> fragment = std::atomic_exchange(&fragment_, std::shared_ptr<IPFragment>());
```

### 4.2 `atomic_load` + `atomic_store({})` 不等价于 `atomic exchange`

上述 `atomic_load` + `atomic_store({})` 是**两次独立的原子操作**，不保证唯一取走语义：

```
线程 A                          线程 B
──────────────────────────────  ──────────────────────────────
local_A = atomic_load(&ptr)     local_B = atomic_load(&ptr)
  // local_A = X                  // local_B = X（同一个对象！）
atomic_store(&ptr, {})          atomic_store(&ptr, {})
  // ptr = null                   // ptr = null
local_A->Dispose()              local_B->Dispose()
  // double-Dispose! ⚠️
```

### 4.3 当前代码为何安全

经审查，当前所有"移出"模式均在以下条件下使用：

1. **WebSocket::Finalize()：** `disposed_.exchange(true, acq_rel)` 保证 one-shot，仅一个线程进入 Finalize。
2. **VEthernet::ReleaseAllObjects()：** 在 strand 保护下执行，不存在并发调用。
3. **VNetstack::TapTcpLink：** 在 strand 保护下执行。

因此，当前代码的"移出"模式是安全的——不是因为 `atomic_load + atomic_store({})` 保证了原子性，而是因为外部同步机制（strand/disposed_ one-shot）保证了互斥。

### 4.4 Helper 不包装 "移出" 模式的理由

- C++17 下若需要 exactly-once take-and-clear，应直接使用标准 `std::atomic_exchange(shared_ptr*)` free function，或通过 strand/mutex 保护复合操作。
- "移出"语义无法仅通过 `atomic_load/store` 两次独立操作实现。
- C++20 迁移后，`std::atomic_exchange` free function 调用点应迁移到 `std::atomic<std::shared_ptr<T>>::exchange()`。
- 提供一个基于 `atomic_load + atomic_store({})`、看起来像 atomic exchange 但实际不是的 helper 会误导使用者。

---

## 5. 替换范围

### 5.1 需要替换的调用点

当引入 helper 后，以下调用点应逐步替换（**当前不实施，仅记录**）：

| 调用点 | 文件 | 替换为 |
|--------|------|--------|
| `std::atomic_load(&socket_)` | `WebSocket.h` (6 处) | `ppp::net::atomic_load_compat(&socket_)` |
| `std::atomic_store(&socket_, ...)` | `WebSocket.h` (2 处) | `ppp::net::atomic_store_compat(&socket_, ...)` |
| `std::atomic_load(&socket_)` | `ITcpipTransmission.cpp` (4 处) | `ppp::net::atomic_load_compat(&socket_)` |
| `std::atomic_store(&socket_, ...)` | `ITcpipTransmission.cpp` (1 处) | `ppp::net::atomic_store_compat(&socket_, ...)` |
| `std::atomic_load(&protocol_)` | `ITransmission.cpp` (3 处) | `ppp::net::atomic_load_compat(&protocol_)` |
| `std::atomic_load(&transport_)` | `ITransmission.cpp` (3 处) | `ppp::net::atomic_load_compat(&transport_)` |
| `std::atomic_store(&protocol_, ...)` | `ITransmission.cpp` (2 处) | `ppp::net::atomic_store_compat(&protocol_, ...)` |
| `std::atomic_store(&transport_, ...)` | `ITransmission.cpp` (2 处) | `ppp::net::atomic_store_compat(&transport_, ...)` |
| `std::atomic_load(&snapshot_)` | Firewall RCU（未来） | `ppp::net::atomic_load_compat(&snapshot_)` |
| `std::atomic_store(&snapshot_, ...)` | Firewall RCU（未来） | `ppp::net::atomic_store_compat(&snapshot_, ...)` |

### 5.2 不替换的调用点

以下调用点使用 `atomic_exchange`，不在 helper 范围内：

| 调用点 | 文件 | 原因 |
|--------|------|------|
| `std::atomic_exchange(&fragment_, ...)` | `VEthernet.cpp` | 使用 `atomic_exchange`，非 helper 范围 |
| `std::atomic_exchange(&netstack_, ...)` | `VEthernet.cpp` | 同上 |
| `std::atomic_exchange(&socket, ...)` | `VNetstack.cpp` | 同上 |
| `std::atomic_load(&link->socket)` | `VNetstack.cpp` (4 处) | 可替换，但需与同文件 `atomic_exchange` 统一评估 |
| `std::atomic_load/store(&sync_ack_*)` | `VNetstack.cpp` (6 处) | 可替换 |
| `std::atomic_load(&fragment_)` | `VEthernet.cpp` (2 处) | 可替换，但需与同文件 `atomic_exchange` 统一评估 |
| `std::atomic_load(&netstack_)` | `VEthernet.cpp` (7 处) | 可替换，但需与同文件 `atomic_exchange` 统一评估 |

---

## 6. 测试要求

### 6.1 编译验证

- 引入 helper 头文件后，全平台编译通过（Linux/macOS/Windows/Android）。
- 无新增编译警告（特别是 `-Wdeprecated-declarations`，当前 C++17 下不应触发）。

### 6.2 行为等价验证

- 替换调用点后，helper 调用与直接调用 `std::atomic_load/store` 的行为完全等价。
- 由于 helper 是 inline 函数且直接委托给 `std::atomic_load/store`，行为等价性由编译器保证。

### 6.3 并发正确性

- 当前项目无自动化测试（`AGENTS.md` 明确指出 "There are zero tests"）。
- 并发正确性只能通过代码审查保证。
- 替换调用点后，必须逐一审查：
  - [ ] 所有对同一 `shared_ptr` 成员的读写是否统一使用 helper（不要混用 helper 和直接调用）。
  - [ ] "移出"模式是否保持了外部同步保护（strand/disposed_ one-shot）。
  - [ ] 新增的 `shared_ptr` 并发访问是否遵循 §16 的规范。

### 6.4 C++20 迁移验证

- 迁移时，将 `ppp::net::atomic_load_compat` 替换为 `atomic_member.load()`。
- 将 `ppp::net::atomic_store_compat` 替换为 `atomic_member.store()`。
- 删除 helper 头文件。
- 全平台编译通过，无 deprecated 警告。

---

## 7. 实施计划

### 阶段 1：新增 helper 头文件（低风险，当前不实施）

1. 创建 `ppp/net/AtomicSharedPtr.h`。
2. 包含 `atomic_load_compat` 和 `atomic_store_compat` 模板。
3. 添加 `#include` 到 `ppp/stdafx.h`（可选，或在使用点单独 include）。

### 阶段 2：替换调用点（中风险，当前不实施）

1. 替换 WebSocket.h 中的 `atomic_load/store` 调用。
2. 替换 ITcpipTransmission.cpp 中的调用。
3. 替换 ITransmission.cpp 中的调用。
4. 替换 VNetstack.cpp 中的 `atomic_load/store` 调用（不含 `atomic_exchange`）。
5. 替换 VEthernet.cpp 中的 `atomic_load` 调用（不含 `atomic_exchange`）。

### 阶段 3：C++20 迁移（未来）

1. 将成员类型从 `shared_ptr<T>` 改为 `std::atomic<std::shared_ptr<T>>`。
2. 将 `atomic_load_compat(&member)` 替换为 `member.load()`。
3. 将 `atomic_store_compat(&member, val)` 替换为 `member.store(val)`。
4. 将 `atomic_exchange` 调用替换为 `member.exchange()`。
5. 删除 `AtomicSharedPtr.h`。
6. 全平台编译验证。

### 回滚策略

每个阶段可独立回滚。helper 头文件是纯新增文件，删除即可恢复原始状态。

---

## 8. 与现有文档的关联

| 文档 | 关联内容 |
|------|----------|
| `docs/openppp2-deep-code-audit-cn.md` §14.6 S-4 | 本文档的前身；S-4 提出的 `atomic_load_compat` 包装方案 |
| `docs/openppp2-deep-code-audit-cn.md` §16 | `shared_ptr` 并发访问规范；本文档 §3.4 和 §4 补充了 Base/Derived 和 exchange 限制 |
| `docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` §3.3、§4 | RCU 快照使用同一 `atomic_load/store` 模式；§4.4 已引用 helper 方案 |
| `docs/CONCURRENCY_MODEL_CN.md` | 并发模型概述；本文档补充了 `shared_ptr` atomic 访问的具体约束 |
| `docs/p2-governance-decisions-cn.md` P2-12 | Firewall RCU 治理决策；本文档为其提供 `atomic_load/store` 使用规范 |

---

## 9. 决策记录

### 9.1 提供 `atomic_load_compat` / `atomic_store_compat`

**决策：** 提供。理由：
- 最低成本的 C++20 迁移准备。
- 统一命名便于 grep 迁移。
- 纯包装，零运行时开销。

### 9.2 不提供 `atomic_exchange_compat`

**决策：** 不提供。理由：
- 当前 helper 仅覆盖 `atomic_load/store` 迁移封装，避免扩大 API 面。
- 当前使用 `atomic_exchange` 的位置需要逐一审查外部同步和 exactly-once 语义，无法仅通过 helper 保证安全性。
- C++17 若需要真正原子 exchange，直接使用标准 `std::atomic_exchange(shared_ptr*)` free function；本 helper 不重新包装该 API。
- C++20 迁移后直接使用 `std::atomic<std::shared_ptr<T>>::exchange()`。

### 9.3 不提供隐式 Base/Derived 转换

**决策：** 不提供。理由：
- 保持与标准 `atomic_store` 行为完全一致。
- 显式转换是安全的且零开销。
- 隐式转换会掩盖类型不匹配。

### 9.4 不在 helper 中添加 `static_assert(__cplusplus >= 202002L)` 错误

**决策：** 不添加。理由：
- S-4 原始方案中的 `static_assert(false, ...)` 在 C++20 下会导致编译错误，即使项目尚未迁移。
- C++20 迁移时应直接删除 helper，而非依赖 `static_assert` 提示。
- 使用 `#if __cplusplus >= 202002L` 分支提供不同实现更合理，但当前两种实现完全相同，无需分支。

---

*创建时间：2026-05-11*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §14.6 S-4、§16*
*关联设计文档：`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`*
*关联治理项：S-4（`atomic_load/store(shared_ptr*)` 兼容 helper）*
