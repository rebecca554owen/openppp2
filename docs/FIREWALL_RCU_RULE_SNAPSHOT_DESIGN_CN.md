# Firewall RCU 规则快照优化设计文档

> 编号：P2-12-RCU
> 状态：**设计文档，暂不实施**
> 决策日期：2026-05-11
> 关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §4.6
> 关联源码：`ppp/net/Firewall.h`、`ppp/net/Firewall.cpp`
> 语言标准：C++17

---

## 1. 当前问题

### 1.1 锁竞争模型

`Firewall` 类使用 `std::shared_mutex`（别名 `SynchronizedObject`）保护所有规则容器：

| 操作类型 | 锁模式 | 方法 |
|----------|--------|------|
| 写入（增删规则） | `std::unique_lock`（排他锁） | `DropNetworkPort`、`DropNetworkSegment`、`DropNetworkDomains`、`Clear`、`LoadWithRules` |
| 读取（匹配查询） | `std::shared_lock`（共享锁） | `IsDropNetworkPort`、`IsDropNetworkSegment`、`IsDropNetworkDomains` |

读取路径是热路径——每个 DNS 查询、每个连接建立、每个数据包路由都可能触发一次 `IsDropNetworkDomains()` 调用。写入路径是冷路径——仅在规则配置加载或动态更新时触发。

### 1.2 `IsDropNetworkDomains` 的快照复制开销

当前实现（`Firewall.cpp:355-367`）在每次域名查询时复制完整的 `network_domains_`（`ppp::unordered_set<ppp::string>`）：

```cpp
// 当前实现：每次查询复制整个域名表
NetworkDomainsTable domains_snapshot;
{
    SharedSynchronizedObjectScope scope(syncobj_);
    try
    {
        domains_snapshot = network_domains_;  // ← O(N) 深拷贝
    }
    catch (const std::bad_alloc&)
    {
        // fail-safe: 复制失败返回 false
        return false;
    }
}
// 然后对 domains_snapshot 执行后缀匹配
```

**性能影响：**

| 规则规模 | 每次查询复制成本 | 1000 QPS 下的开销 |
|----------|-----------------|-------------------|
| 100 条域名 | ~100 次 string 构造 + hash 节点分配 | 每秒 100,000 次堆分配 |
| 1,000 条域名 | ~1,000 次 string 构造 + hash 节点分配 | 每秒 1,000,000 次堆分配 |
| 10,000 条域名 | ~10,000 次 string 构造 + hash 节点分配 | 每秒 10,000,000 次堆分配 |

### 1.3 `IsDropNetworkPort` 和 `IsDropNetworkSegment` 的锁开销

这两个方法虽然不复制规则表，但仍需在每次调用时获取 `shared_lock`：

- **`IsDropNetworkPort`**（`Firewall.cpp:219`）：`SharedSynchronizedObjectScope scope(syncobj_)`
- **`IsDropNetworkSegment`**（`Firewall.cpp:287-288, 303-304`）：`SharedSynchronizedObjectScope scope(syncobj_)`

`std::shared_mutex` 的 `lock_shared()` 在高并发下存在原子计数器竞争，且写者会被所有读者阻塞（writer starvation 或读者侧 cache-line bouncing）。

### 1.4 后缀匹配的线性扫描开销

`IsSameNetworkDomains`（`Firewall.cpp:389-449`）对域名执行线性后缀遍历：

```
输入: "sub.evil.com"
标签: ["sub", "evil", "com"]
后缀候选:
  1. "sub.evil.com"        (精确匹配)
  2. "evil.com"            (从标签 1 开始)
  3. "com"                 (从标签 2 开始，但 label_size < 2 时跳过)
```

每个候选都需要字符串拼接（`next += '.'; next.append(label)`），然后执行 hash lookup。对于长域名（如 `a.b.c.d.e.example.com`），候选数量为 O(L)（L = 标签数）。

---

## 2. C++17 RCU 快照方案

### 2.1 核心思想

RCU（Read-Copy-Update）的核心是：

1. **读取者**：获取不可变快照的 `shared_ptr`，无需持锁即可执行匹配。
2. **写入者**：构建新规则表的副本，修改后通过原子操作发布新快照。
3. **内存回收**：旧快照通过 `shared_ptr` 引用计数自动回收（最后一个读取者释放时销毁）。

### 2.2 数据结构设计

```cpp
// Firewall.h — 新增

/**
 * @brief 包含所有防火墙规则的不可变快照。
 *
 * 通过 std::shared_ptr<const FirewallRuleSnapshot> 在读写线程之间共享。
 * 写入者创建新快照并原子发布；读取者获取快照的 shared_ptr 副本后即可
 * 不持有 Firewall 业务锁即可访问所有规则表。旧快照在最后一个读取者释放 shared_ptr 后自动销毁。
 */
struct FirewallRuleSnapshot
{
    /// 协议无关的端口黑名单
    ppp::unordered_set<int>                         ports;
    /// TCP 端口黑名单
    ppp::unordered_set<int>                         ports_tcp;
    /// UDP 端口黑名单
    ppp::unordered_set<int>                         ports_udp;
    /// 域名黑名单（精确 + 后缀匹配）
    ppp::unordered_set<ppp::string>                 network_domains;
    /// CIDR 网段黑名单
    ppp::unordered_map<Int128, int>                 network_segments;
};
```

### 2.3 成员变量变更

```cpp
class Firewall
{
public:
    // ... 保持现有 public API 不变 ...

private:
    // === 当前实现（将被替换）===
    // SynchronizedObject                           syncobj_;
    // ppp::unordered_set<int>                      ports_;
    // ppp::unordered_set<int>                      ports_tcp_;
    // ppp::unordered_set<int>                      ports_udp_;
    // NetworkDomainsTable                          network_domains_;
    // NetworkSegmentTable                          network_segments_;

    // === RCU 实现 ===
    /// @brief 当前规则快照，通过 std::atomic_load/store 保护。
    /// 初始值为 empty snapshot（所有容器为空）。
    std::shared_ptr<const FirewallRuleSnapshot>     snapshot_;
};
```

### 2.4 读取路径（不持 Firewall 业务锁）

```cpp
bool Firewall::IsDropNetworkPort(int port, bool tcp_or_udp) noexcept
{
    if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
        return false;
    }

    // 获取不可变快照 — 不持 Firewall 业务锁；atomic_load 是否 lock-free 由标准库实现决定
    auto snap = std::atomic_load(&snapshot_);

    // 在不可变快照上执行查找
    if (snap->ports.count(port))
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
        return true;
    }

    const auto& target_set = tcp_or_udp ? snap->ports_tcp : snap->ports_udp;
    if (target_set.count(port))
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
        return true;
    }

    return false;
}
```

```cpp
bool Firewall::IsDropNetworkDomains(const ppp::string& host) noexcept
{
    // ... 前置校验和 IP 解析不变 ...

    // 获取不可变快照 — 不持 Firewall 业务锁
    auto snap = std::atomic_load(&snapshot_);

    // 直接在快照上执行匹配，无需复制
    auto contains = [&snap](const ppp::string& s) noexcept
    {
        return snap->network_domains.count(s) > 0;
    };

    bool blocked = IsSameNetworkDomains(host_lower, contains);
    if (blocked)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
    }
    return blocked;
}
```

```cpp
template <typename T>
static bool Firewall_IsDropNetworkSegment(
    const boost::asio::ip::address& ip,
    T __ip,
    int max_prefix,
    const Firewall::NetworkSegmentTable& network_segments) noexcept
{
    // ... 算法不变，仅参数类型从引用改为 const 引用 ...
}
```

### 2.5 写入路径（Copy-Modify-Publish）

```cpp
bool Firewall::DropNetworkPort(int port) noexcept
{
    if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
        return false;
    }

    // 1. 获取当前快照
    auto old_snap = std::atomic_load(&snapshot_);

    // 2. 拷贝快照
    auto new_snap = std::make_shared<FirewallRuleSnapshot>();
    new_snap->ports             = old_snap->ports;
    new_snap->ports_tcp         = old_snap->ports_tcp;
    new_snap->ports_udp         = old_snap->ports_udp;
    new_snap->network_domains   = old_snap->network_domains;
    new_snap->network_segments  = old_snap->network_segments;

    // 3. 修改新快照
    bool inserted = new_snap->ports.emplace(port).second;

    // 4. 显式转换为 const 快照指针后原子发布，避免 C++17 atomic_store 模板推导冲突
    std::shared_ptr<const FirewallRuleSnapshot> published = std::move(new_snap);
    std::atomic_store(&snapshot_, std::move(published));

    ppp::diagnostics::SetLastErrorCode(
        inserted ? ppp::diagnostics::ErrorCode::Success
                 : ppp::diagnostics::ErrorCode::FirewallDropPortAlreadyExists);
    return inserted;
}
```

**关键点：** 写入路径仍然需要复制整个规则表，但写入是冷路径（仅在规则加载/更新时触发），一次复制的成本被所有后续读取的零拷贝收益摊销。

### 2.6 `Clear()` 实现

```cpp
void Firewall::Clear() noexcept
{
    // 发布一个全新的空快照
    auto empty_snap = std::make_shared<FirewallRuleSnapshot>();
    std::shared_ptr<const FirewallRuleSnapshot> published = std::move(empty_snap);
    std::atomic_store(&snapshot_, std::move(published));
    // 旧快照在所有读者释放 shared_ptr 后自动销毁
}
```

### 2.7 构造函数初始化

```cpp
Firewall() noexcept
    : snapshot_(std::make_shared<FirewallRuleSnapshot>())
{}
```

---

## 3. 线程安全模型

### 3.1 读取-写入并发安全

| 场景 | 安全性保证 |
|------|-----------|
| 多个读取者并发读 | ✅ 安全：`shared_ptr` 的 control block 在 `atomic_load` 下是线程安全的；`const` 快照本身无竞争 |
| 一个写入者发布新快照 | ✅ 安全：`atomic_store` 是原子操作，读取者要么看到旧快照，要么看到新快照，不会看到撕裂状态 |
| 读取者与写入者并发 | ✅ 安全：读取者持有的 `shared_ptr` 副本指向旧快照，写入者不影响正在使用的快照 |
| 多个写入者并发 | ⚠️ 需要序列化：当前使用 `shared_mutex` 排他锁保护写入路径，确保 "read-modify-write" 快照更新是原子的 |

### 3.2 为何保留写入路径的锁

虽然读取路径不再需要锁，但写入路径仍然需要序列化，原因如下：

1. **Read-Modify-Write 原子性**：`DropNetworkPort` 需要读取当前快照 → 复制 → 修改 → 发布。如果两个写入者并发执行，可能发生 lost update：
   - 写入者 A 读取快照 V1，复制为 V2A
   - 写入者 B 读取快照 V1，复制为 V2B
   - 写入者 A 发布 V2A
   - 写入者 B 发布 V2B（覆盖了 A 的修改）

2. **解决方案**：保留 `std::shared_mutex`，但仅在写入路径使用 `unique_lock`。读取路径不获取 `Firewall::syncobj_`，仅通过 `std::atomic_load` 获取快照；该原子操作是否 lock-free 由标准库实现决定。

```cpp
class Firewall
{
private:
    SynchronizedObject                              syncobj_;      // 仅保护写入路径
    std::shared_ptr<const FirewallRuleSnapshot>     snapshot_;      // 读取路径使用 atomic_load
};
```

### 3.3 `std::atomic_load/store` free functions 行为

```cpp
// C++17 标准 §[util.smartptr.shared.atomic]
// 实现方式：主流实现使用全局 spinlock 表（hash table of mutexes）
// 性能特征：每次调用约 20-50ns（取决于平台和竞争程度）
// 相比之下：std::shared_mutex::lock_shared() 约 30-80ns + cache-line bouncing

// 使用方式：
auto snap = std::atomic_load(&snapshot_);          // 读取
std::atomic_store(&snapshot_, published_snapshot);  // 写入；类型需与 snapshot_ 完全一致
```

### 3.4 `shared_ptr` 控制块的线程安全性

`std::shared_ptr` 的引用计数操作（增加/减少）是原子的。`std::atomic_load/store` 保证对同一 `shared_ptr` 对象的并发读写不会导致 data race（控制块撕裂）。

**关键约束：** 不要混用普通 copy/move 与 `atomic_load/store` 操作同一个 `shared_ptr` 成员。如果一个成员在某些路径使用 `atomic_load/store`，则**所有**对它的读写都必须使用 `atomic_load/store`。

---

## 4. 为何不用 C++20 `std::atomic<std::shared_ptr<T>>`

### 4.1 项目基线限制

当前项目强制使用 C++17（`CMakeLists.txt` 中 `set(CMAKE_CXX_STANDARD 17)`）。`std::atomic<std::shared_ptr<T>>` 是 C++20 标准（§[util.smartptr.atomic]），在 C++17 下不可用。

### 4.2 C++17 free functions vs C++20 atomic shared_ptr

| 特性 | C++17 `atomic_load/store` free functions | C++20 `atomic<shared_ptr<T>>` |
|------|----------------------------------------|-------------------------------|
| 标准状态 | C++17 可用，C++20 起弃用，C++26 移除 | C++20 可用 |
| 接口风格 | 全局函数 `std::atomic_load(&ptr)` | 成员函数 `ptr.load()` / `ptr.store()` |
| CAS 操作 | 不支持 | 支持 `compare_exchange_weak/strong` |
| `exchange()` | 不支持（需 load + store 两步，非原子交换） | 支持（原子交换） |
| 实现 | 全局 spinlock 表 | 实现自由（lock-free 或 spinlock） |
| 可移植性 | 主流编译器全部支持 | 需要编译器 + 标准库支持 |

### 4.3 迁移路径

当项目升级到 C++20 时：

```cpp
// C++17（当前）
std::shared_ptr<const FirewallRuleSnapshot> snapshot_;

auto snap = std::atomic_load(&snapshot_);
std::atomic_store(&snapshot_, published_snapshot);

// C++20（未来）
std::atomic<std::shared_ptr<const FirewallRuleSnapshot>> snapshot_;

auto snap = snapshot_.load();
snapshot_.store(new_snap);

// C++20 还支持 CAS，可用于不持业务锁的写入合并：
auto expected = snapshot_.load();
auto desired = make_modified_copy(expected);
while (!snapshot_.compare_exchange_weak(expected, desired)) {
    expected = snapshot_.load();
    desired = make_modified_copy(expected);
}
```

### 4.4 兼容性包装建议

建议在项目中引入兼容性包装（参考 `docs/openppp2-deep-code-audit-cn.md` §14.6 S-4）：

```cpp
// ppp/net/AtomicSharedPtr.h（未来新增）

template<class T>
std::shared_ptr<T> atomic_load_compat(const std::shared_ptr<T>* p) noexcept
{
#if __cplusplus >= 202002L
    // C++20+: 使用 std::atomic<std::shared_ptr<T>> 的成员函数
    // 但此包装仍调用 free function 以保持接口一致
    // 迁移时直接删除此包装，改用 atomic<shared_ptr<T>>::load()
    return std::atomic_load(p);
#else
    return std::atomic_load(p);
#endif
}

template<class T>
void atomic_store_compat(std::shared_ptr<T>* p, std::shared_ptr<T> r) noexcept
{
    std::atomic_store(p, std::move(r));
}
```

---

## 5. 语义保持要求

### 5.1 必须保持的行为

| 行为 | 当前实现 | RCU 实现 | 是否变化 |
|------|----------|----------|----------|
| 端口精确匹配 | `ports_.find(port)` | `snap->ports.count(port)` | ❌ 不变 |
| TCP/UDP 协议匹配 | `ports_tcp_.find(port)` / `ports_udp_.find(port)` | `snap->ports_tcp.count(port)` / `snap->ports_udp.count(port)` | ❌ 不变 |
| 域名精确匹配 | `contains(host)` | `contains(host)` | ❌ 不变 |
| 域名后缀匹配 | 线性后缀遍历 + hash lookup | 相同算法 | ❌ 不变 |
| CIDR 段匹配 | 遍历 prefix + mask + hash lookup | 相同算法 | ❌ 不变 |
| IP 地址自动路由到段匹配 | `IsDropNetworkDomains` 中检测 IP 格式 | 相同逻辑 | ❌ 不变 |
| 错误码设置 | `SetLastErrorCode(...)` | 相同错误码 | ❌ 不变 |
| 重复插入返回 false | `emplace().second` | 相同逻辑 | ❌ 不变 |
| CIDR prefix 取较小值 | `if (prefix < now) { now = prefix; }` | 相同逻辑 | ❌ 不变 |
| `LoadWithFile` → `LoadWithRules` 委托 | 不变 | 不变 | ❌ 不变 |
| 规则文件解析（`drop ip/port/dns`） | 不变 | 不变 | ❌ 不变 |

### 5.2 行为变化（预期且可接受）

| 变化 | 描述 | 影响 |
|------|------|------|
| 快照版本 | 读取者看到的是发布时刻的规则快照，而非实时最新值 | 规则更新与查询之间存在极短窗口（纳秒级），可接受 |
| 写入路径不持有读取锁 | 写入不再阻塞读取 | ✅ 正面改进 |
| 内存占用 | 写入期间存在新旧两个快照副本 | 瞬态双倍内存，写入完成后旧快照自动释放 |

### 5.3 不可接受的行为变化

- ❌ 不得改变 `IsSameNetworkDomains` 的匹配语义（精确 + 后缀）
- ❌ 不得改变错误码体系
- ❌ 不得改变 public API 签名
- ❌ 不得改变 `LoadWithRules` 的解析逻辑
- ❌ 不得引入新的头文件依赖（除 `<memory>`，已在 `stdafx.h` 中包含）

---

## 6. 额外优化：反向 trie 后缀匹配（可选，独立于 RCU）

### 6.1 当前后缀匹配的问题

`IsSameNetworkDomains` 的后缀遍历是 O(L²)（L = 标签数）：

```
"a.b.c.d.example.com" → 标签: [a, b, c, d, example, com]
候选:
  i=1: "b.c.d.example.com"    → hash lookup
  i=2: "c.d.example.com"      → hash lookup
  i=3: "d.example.com"        → hash lookup
  i=4: "example.com"          → hash lookup
  i=5: "com"                  → hash lookup
```

每次候选都需要字符串拼接（O(domain_length)），总计 O(L × domain_length)。

### 6.2 反向 trie 方案

将域名标签反转后插入 trie：

```
规则: "evil.com"          → trie: com → evil → (terminal)
规则: "ads.tracker.net"   → trie: net → tracker → ads → (terminal)
规则: "malware.org"       → trie: org → malware → (terminal)

查询: "sub.evil.com"
标签: [sub, evil, com]
从 trie 根开始: com → evil → (命中！) → 返回 true
```

**优势：**
- 查询时间 O(L)（L = 标签数），无需字符串拼接
- 内存共享公共后缀（`com` 节点被所有 `.com` 规则共享）
- 天然支持 `string_view` 避免分配

**实现复杂度：**
- 需要实现 trie 节点结构
- 需要将 `unordered_set<string>` 替换为 trie
- 需要更新 `DropNetworkDomains` 和 `IsSameNetworkDomains`
- 侵入性中等，建议作为独立优化项

### 6.3 更简单的替代方案：`string_view` 后缀匹配

不改变数据结构，仅优化匹配过程：

```cpp
bool Firewall::IsSameNetworkDomains(
    std::string_view host,
    const std::function<bool(std::string_view)>& contains) noexcept
{
    // 精确匹配
    if (contains(host)) return true;

    // 后缀匹配：使用 string_view 避免分配
    auto dot_pos = host.find('.');
    while (dot_pos != std::string_view::npos)
    {
        std::string_view suffix = host.substr(dot_pos + 1);
        if (suffix.size() >= 2 && contains(suffix))  // 至少 "x.y"
        {
            return true;
        }
        dot_pos = host.find('.', dot_pos + 1);
    }
    return false;
}
```

**注意：** 此方案需要将 `NetworkDomainsTable` 的 key 类型从 `ppp::string` 改为支持 `string_view` 查找的容器（如 `std::unordered_set<std::string>` 配合透明 hash），或在查找时临时构造 `ppp::string`。侵入性较低，但需要验证 `ppp::string` 与 `std::string_view` 的互操作性。

---

## 7. 额外优化：单趟 normalize（可选，独立于 RCU）

### 7.1 当前 normalize 问题

`IsDropNetworkDomains` 和 `DropNetworkDomains` 中的 normalize 使用三步链式调用：

```cpp
ppp::string host_lower = LTrim(RTrim(ToLower(host)));
```

这会产生 3 个临时字符串（或至少 2 个，取决于实现是否有 RVO）。

### 7.2 单趟 normalize 方案

```cpp
ppp::string NormalizeHost(std::string_view input) noexcept
{
    // 找到第一个非空白字符
    auto start = input.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return {};

    // 找到最后一个非空白字符
    auto end = input.find_last_not_of(" \t\r\n");
    input = input.substr(start, end - start + 1);

    // 单趟转换为小写
    ppp::string result;
    result.reserve(input.size());
    for (char c : input)
    {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}
```

**优势：** 从 3 次分配减少到 1 次（`reserve` 后 `push_back` 不会重新分配）。

---

## 8. 测试与基准计划

### 8.1 功能正确性测试

| 测试场景 | 验证内容 | 优先级 |
|----------|----------|--------|
| 空规则表查询 | 所有 `Is*` 方法返回 false | 高 |
| 单条端口规则 | `IsDropNetworkPort` 精确命中 | 高 |
| 协议分离规则 | TCP/UDP 独立命中 | 高 |
| 单条域名规则（精确） | `IsDropNetworkDomains` 精确命中 | 高 |
| 单条域名规则（后缀） | 子域名匹配 | 高 |
| 单条 CIDR 规则 | `IsDropNetworkSegment` 命中 | 高 |
| IPv6 CIDR 规则 | 128-bit 地址匹配 | 高 |
| 规则更新后查询 | 新规则立即可见（RCU 发布后） | 高 |
| `Clear()` 后查询 | 所有 `Is*` 方法返回 false | 高 |
| `LoadWithFile` 端到端 | 文件解析 → 规则匹配 | 中 |
| 注释行跳过 | `#` 开头行被忽略 | 中 |
| 无效输入 | 空字符串、超长域名、非法端口 | 中 |

### 8.2 并发正确性测试

| 测试场景 | 验证内容 | 优先级 |
|----------|----------|--------|
| 并发读取 | 多线程同时 `IsDropNetworkDomains` | 高 |
| 读写并发 | 一个线程 `DropNetworkPort`，多个线程 `IsDropNetworkPort` | 高 |
| 写写并发 | 两个线程同时 `DropNetworkPort`（不同端口） | 高 |
| 快照一致性 | 读取者看到的快照在查询期间不被修改 | 高 |
| 内存回收 | 旧快照在所有读者释放后正确销毁 | 中 |

### 8.3 性能基准

| 基准 | 指标 | 目标 |
|------|------|------|
| **RCU vs 当前实现：100 条域名规则** | 每次查询耗时（ns） | RCU ≤ 当前实现 × 0.3 |
| **RCU vs 当前实现：1,000 条域名规则** | 每次查询耗时（ns） | RCU ≤ 当前实现 × 0.1 |
| **RCU vs 当前实现：10,000 条域名规则** | 每次查询耗时（ns） | RCU ≤ 当前实现 × 0.05 |
| **端口查询并发吞吐** | QPS（8 线程） | RCU ≥ 当前实现 × 2 |
| **CIDR 段查询并发吞吐** | QPS（8 线程） | RCU ≥ 当前实现 × 2 |
| **写入延迟** | 单次 `DropNetworkPort` 耗时 | ≤ 当前实现 × 1.5（可接受小幅增加） |
| **内存峰值** | 写入期间额外内存 | ≤ 规则表大小 × 2（瞬态） |

### 8.4 基准测试代码骨架

```cpp
// benchmark_firewall.cpp（未来新增）

static void BM_Firewall_IsDropNetworkDomains_100(benchmark::State& state)
{
    Firewall fw;
    for (int i = 0; i < 100; i++)
    {
        fw.DropNetworkDomains("rule" + std::to_string(i) + ".example.com");
    }
    for (auto _ : state)
    {
        benchmark::DoNotOptimize(fw.IsDropNetworkDomains("sub.rule50.example.com"));
    }
}
BENCHMARK(BM_Firewall_IsDropNetworkDomains_100);
```

---

## 9. 迁移步骤

### 阶段 1：准备（低风险）

1. **新增 `FirewallRuleSnapshot` 结构体**：在 `Firewall.h` 中定义，不影响现有代码。
2. **新增 `snapshot_` 成员**：与现有 `syncobj_` + 容器成员并存，通过编译期开关切换。
3. **新增兼容性包装**（可选）：`atomic_load_compat` / `atomic_store_compat`，便于未来 C++20 迁移。

### 阶段 2：读取路径迁移（中风险）

4. **迁移 `IsDropNetworkPort`**：从 `shared_lock` + 容器直接查找改为 `atomic_load(&snapshot_)` + 快照查找。
5. **迁移 `IsDropNetworkSegment`**：同上。
6. **迁移 `IsDropNetworkDomains`**：移除 `domains_snapshot = network_domains_` 复制，改为直接使用快照。
7. **验证所有 `Is*` 方法的语义不变**。

### 阶段 3：写入路径迁移（中风险）

8. **迁移 `DropNetworkPort`（两个重载）**：改为 Copy-Modify-Publish 模式。
9. **迁移 `DropNetworkSegment`**：同上。
10. **迁移 `DropNetworkDomains`**：同上。
11. **迁移 `Clear`**：发布空快照。
12. **迁移 `LoadWithRules`**：确保规则加载期间的批量操作仍高效。

### 阶段 4：清理（低风险）

13. **移除旧的容器成员**：`ports_`、`ports_tcp_`、`ports_udp_`、`network_domains_`、`network_segments_`。
14. **保留 `syncobj_`**：仅保护写入路径的 read-modify-write 序列。
15. **更新文档和注释**。

### 阶段 5：可选优化（独立）

16. **反向 trie 后缀匹配**：替换 `unordered_set<string>` 为 trie 结构。
17. **`string_view` 后缀匹配**：不改变数据结构，仅优化匹配过程。
18. **单趟 normalize**：替换 `LTrim(RTrim(ToLower(...)))` 链。

### 回滚策略

每个阶段都是可独立回滚的。如果发现问题，可以：

1. 编译期开关：通过 `#define PPP_FIREWALL_RCU_SNAPSHOT 0` 回退到旧实现。
2. Git 回滚：每个阶段作为独立 commit，可精确回滚。

---

## 10. 风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| `shared_ptr` control block 内存泄漏 | 低 | 高 | 确保所有路径都通过 `atomic_store` 发布，不保留裸 `shared_ptr` 引用 |
| 写入路径忘记发布快照 | 低 | 高 | 所有 `Drop*` 方法使用统一的 Copy-Modify-Publish helper |
| 写写并发 lost update | 中 | 中 | 保留 `syncobj_` 排他锁保护写入路径 |
| `atomic_load` 性能不如预期 | 低 | 低 | 全局 spinlock 表开销约 20-50ns，远低于当前 `shared_lock` + 全表复制 |
| 旧快照内存延迟回收 | 低 | 低 | 最后一个读者释放 `shared_ptr` 后自动回收，无内存泄漏 |
| C++17 free functions 在 C++26 被移除 | 高（远期） | 中 | 引入 `atomic_load_compat` 包装，升级时替换为 `atomic<shared_ptr<T>>` |

---

## 11. 实施前置条件

| 序号 | 条件 | 说明 | 当前状态 |
|------|------|------|----------|
| C-1 | 无自动化测试 | 功能正确性需通过代码审查保证 | ❌ 无测试 |
| C-2 | `ppp::string` 类型确认 | 需确认 `ppp::string` 支持 move 语义和 `noexcept` 构造 | ⚠️ 需验证 |
| C-3 | `ppp::unordered_set` / `ppp::unordered_map` 支持 move | 快照复制需要高效 move | ⚠️ 需验证 |
| C-4 | 性能基准工具存在 | 需要基准测试验证收益 | ❌ 无基准工具 |
| C-5 | `shared_ptr<const T>` 确认可哈希容器支持 | `unordered_set/map` 的 `const` 版本需支持 move 构造 | ⚠️ 需验证 |

---

## 12. 时间线估计

| 阶段 | 工作量 | 依赖 |
|------|--------|------|
| 阶段 1（准备） | 0.5 天 | 无 |
| 阶段 2（读取路径） | 1 天 | 阶段 1 |
| 阶段 3（写入路径） | 1 天 | 阶段 2 |
| 阶段 4（清理） | 0.5 天 | 阶段 3 |
| 阶段 5（可选优化） | 2-3 天 | 阶段 4 |
| **总计** | **3-6 天** | — |

---

## 13. 总结

| 维度 | 当前实现 | RCU 实现 |
|------|----------|----------|
| 读取路径锁 | `shared_lock` 每次获取 | 不获取 `shared_mutex`，仅执行 `atomic_load`（是否 lock-free 由标准库实现决定） |
| 域名查询复制 | O(N) 深拷贝 | 零拷贝（`shared_ptr` 副本） |
| 写入路径 | `unique_lock` + 直接修改 | `unique_lock` + Copy-Modify-Publish |
| 并发读取吞吐 | 受 `shared_lock` 限制 | 近乎线性扩展 |
| 内存模型 | 单份规则表 + 查询时临时副本 | 新旧快照共存（瞬态双倍） |
| 代码复杂度 | 低 | 中 |
| C++ 标准要求 | C++17 | C++17（free functions） |
| C++20 迁移成本 | — | 低（替换为 `atomic<shared_ptr<T>>`） |

---

*创建时间：2026-05-11*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md` §4.6*
*关联治理项：P2-12（Firewall 规则匹配热路径优化）*
