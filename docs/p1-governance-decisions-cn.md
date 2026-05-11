# P1 治理决策记录

> 本文档记录 P1 级代码质量治理项中**暂不修改、仅记录在案**的条目。
> 每条包含：问题描述、当前决策、原因分析、后续可选方案、生效约束。
> 遵循原则：最佳兼容性、最小破坏性、最小侵入性。

---

## 1.8 消除 `system()` shell 拼接

| 字段 | 内容 |
|------|------|
| **编号** | P1-8 |
| **当前决策** | **暂不治理，只记录在案** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |

### 问题描述

项目中存在 **25 处** `system()` 调用，分散于跨平台核心代码和三个平台目录中。主要用途：

| 文件 | 行号 | 用途 | 平台 |
|------|------|------|------|
| `ppp/app/client/VEthernetNetworkSwitcher.cpp` | 1085, 1188 | 网络切换 shell 命令 | 跨平台 |
| `ppp/stdafx.cpp` | 1123, 1128 | `system("cls")` / `system("clear")` 清屏 | 跨平台 |
| `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp` | 84, 352, 598 | IPv6 路由管理 (`ip -6 route ...`) | Linux |
| `linux/ppp/tap/TapLinux.cpp` | 257, 684, 695 | TAP 接口配置 (`ip addr/route ...`) | Linux |
| `linux/ppp/diagnostics/UnixStackTrace.cpp` | 33 | `addr2line` 调用 | Linux |
| `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp` | 217, 238, 242, 271, 306, 414 | IPv6 路由管理 (`route -n inet6 ...`) | macOS |
| `darwin/ppp/tun/utun.cpp` | 143, 190, 223 | utun 接口配置 (`ifconfig`/`route`) | macOS |
| `windows/ppp/win32/Win32Native.cpp` | 777 | `system("pause")` | Windows |
| `windows/ppp/app/client/lsp/PaperAirplaneLspY.cpp` | 327 | `system("pause")` | Windows |

其中存在 shell 字符串拼接的高风险路径：

- **Linux/macOS IPv6 辅助模块**：将动态接口名、地址拼入 `ip` / `route` 命令字符串后传入 `system()`。
- **Linux TAP 模块**：`TapLinux.cpp` 注释已标明 `system()` 执行阻塞式 `fork()+exec()`，且命令中含动态参数。
- **VEthernetNetworkSwitcher**：网络切换逻辑中构造 shell 命令并执行。

### 暂不治理的原因

1. **跨平台命令执行改造侵入性较高**：替换 `system()` 需要为 Linux/macOS/Windows 分别实现进程管理器（如 `posix_spawn` / `CreateProcess` / `fork+exec`），涉及三个平台目录的同步修改。
2. **需要平台集成测试**：IPv6 路由管理、TAP 接口配置等命令的输出解析依赖 shell 行为，替换后必须在各平台实际验证。
3. **按最小破坏性原则暂缓**：当前主流程聚焦于 P0/P1 阻断问题修复，该项不属于阻断项。
4. **与 §2 文档任务及其他 P1 修复任务互不依赖**：治理该项不会影响其他并行任务。

### 后续可选治理方案

按侵入性从低到高排列：

| 方案 | 描述 | 侵入性 | 前置条件 |
|------|------|--------|----------|
| **A. 参数校验过渡** | 对拼接前的参数做白名单/正则校验，拦截注入风险，保留 `system()` 调用 | 低 | 无 |
| **B. 局部替换高风险路径** | 仅替换含动态参数拼接的 `system()` 调用（约 12 处），使用 `fork+exec` 或 `posix_spawn` | 中 | 平台集成测试 |
| **C. 统一 ProcessRunner** | 引入 `ppp/system/ProcessRunner` 抽象层，统一替代全部 25 处调用 | 高 | 全平台测试 + API 设计评审 |

**推荐路径**：先实施方案 A 作为短期加固，再按平台逐步推进方案 B；方案 C 作为长期目标。

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 不得在其他 P1 修复分支中混入该项的代码改动。
- 本文档仅作记录用途，不触发代码变更。

---

## 1.12 CodeQL / govulncheck / npm audit / OSV

| 字段 | 内容 |
|------|------|
| **编号** | P1-12 |
| **当前决策** | **暂不治理，只记录在案** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |

### 问题描述

CodeQL、govulncheck、npm audit、OSV-Scanner 等静态/依赖扫描工具可用于检测已知漏洞和代码安全问题。当前项目未启用任何此类扫描。

### 暂不治理的原因

1. **CI 噪音与误报**：在当前代码规模和依赖结构下，扫描工具会产生大量误报，增加维护负担。
2. **避免改变 release gate 行为**：引入扫描作为 CI 阻断条件会影响现有发布流程稳定性。
3. **项目现状限制**：该项目目前无自动化测试、无 linter，CI 仅检查编译通过。骤然加入扫描 gate 破坏性过大。
4. **与其它 P1 条目互不依赖**：治理该项不影响任何其它并行任务。

### 后续可选治理方案

按侵入性从低到高排列，各方案互不排斥：

| 方案 | 描述 | 侵入性 | 说明 |
|------|------|--------|------|
| **A. Report-only 扫描** | CI 中添加扫描步骤，仅生成报告 artifact，不阻断流水线 | 低 | 适合初期观察误报率 |
| **B. 分级 gate** | 对 C++ 核心（`ppp/`）和 Go 后端（`go/`）分别设定不同严重级别阈值，低级别仅 warn，高级别才 block | 中 | 需先积累误报基线 |
| **C. Nightly 或手动触发扫描** | 扫描放在独立 scheduled workflow（nightly cron 或 `workflow_dispatch`）中，与主构建流水线解耦 | 低 | 推荐首选方案 |

### 当前约束

- **不新增 CI workflow 或扫描 job。**
- **不修改任何现有 CI workflow 文件。**
- **不作为 P0 或当前 release 的阻断条件。**
- 本文档仅作记录用途，不触发代码或 CI 变更。

### 注意事项

- `common/` 下的 vendored 第三方库（lwIP、nlohmann/json、aesni 等）以及示例配置文件（`*.json`）若未来被扫描覆盖，需要配置 allowlist 排除。这些文件当前可以正常分发。
- `go/guardian/webui/` 下的 Svelte/Vite 前端依赖若未来启用 `npm audit`，需注意 devDependencies 与 production dependencies 的区分。
- Geo rules 相关数据文件若被 OSV-Scanner 或类似工具扫描，可能触发误报，同样需要 allowlist。

---

## P1-2 strand/thread-confined `disposed_` 分级复核

| 字段 | 内容 |
|------|------|
| **编号** | P1-2 |
| **当前决策** | **已完成分级复核：2 个类改为 atomic，2 个类记录约束不改** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §15.2 |

### 问题描述

审计文档 §15.2 列出四个候选类的 `disposed_` 标志可能存在跨线程读写的 data race（UB）。需要逐一复核每个类的 `disposed_` 生命周期、读写路径和线程模型，判断是否需要改为 `std::atomic_bool`。

### 分级复核结果

| 类名 | 分类 | 是否修改 | 理由 |
|------|------|----------|------|
| **VEthernetLocalProxyConnection** | **跨线程** | **是 → `std::atomic_bool`** | `IsPortAging()` 从 switcher 定时器线程读 `disposed_`；`Finalize()` 在连接 strand 上写 `disposed_`；析构函数可在任意线程直接调用 `Finalize()`。三者可并发。 |
| **VEthernetLocalProxySwitcher** | **跨线程** | **是 → `std::atomic_bool`** | accept 回调在 SocketAcceptor 的 io_context 线程用 `while (!disposed_)` 轮询；`Finalize()` 在 switcher 的 context 线程写；`Dispose()` 可从任意线程调用。acceptor 的平台实现（Unix/Win32）在独立的 accept 循环中触发回调，与 switcher context 线程不同。 |
| **InternetControlMessageProtocol** | **strand-confined** | **否** | `Dispose()` 通过 `boost::asio::post` 将 `Finalize()` 投递到 executor 线程；`Echo()` 按文档契约在 executor 线程调用；析构函数仅在所有 `shared_ptr` 引用释放后运行（`EchoAsynchronousContext` 持有 `owner_` 引用），此时无人可读 `disposed_`。生命周期语义保证无并发访问。 |
| **ITransmissionQoS** | **mutex-protected** | **否** | 所有 `disposed_` 读写均在 `SynchronizedObjectScope scope(syncobj_)` 锁内完成（`ReadBytes`、`EndRead`、`BeginRead`、`Finalize`）。互斥锁提供 happens-before 关系，无需原子化。 |

### 代码修改详情

#### VEthernetLocalProxyConnection

| 文件 | 修改 |
|------|------|
| `ppp/app/client/proxys/VEthernetLocalProxyConnection.h` | `bool disposed_` → `std::atomic_bool disposed_`；`IsDisposed()` 和 `IsPortAging()` 使用 `.load(acquire)` |
| `ppp/app/client/proxys/VEthernetLocalProxyConnection.cpp` | `Finalize()` 使用 `.store(true, release)`；`Run()` 和 `SendBufferToPeer()` 使用 `.load(acquire)` |

跨线程路径分析：
- **写端**：`Finalize()` 在连接的 strand/socket executor 上运行（通过 `Dispose()` 的 `boost::asio::post`）；析构函数可在任意线程直接调用 `Finalize()`。
- **读端**：`IsPortAging()` 在 `VEthernetLocalProxySwitcher::Update()` 的定时器回调中调用，运行在 switcher 的 context 线程上，与连接 strand 不同。
- **读端**：`IsDisposed()` 是 public 方法，可从任意线程调用。

#### VEthernetLocalProxySwitcher

| 文件 | 修改 |
|------|------|
| `ppp/app/client/proxys/VEthernetLocalProxySwitcher.h` | `bool disposed_` → `std::atomic_bool disposed_` |
| `ppp/app/client/proxys/VEthernetLocalProxySwitcher.cpp` | `Finalize()` 使用 `.store(true, release)`；`Open()`、`CreateAlwaysTimeout()` 和 accept 回调使用 `.load(acquire)` |

跨线程路径分析：
- **写端**：`Finalize()` 通过 `Dispose()` 的 `boost::asio::post(*context_, ...)` 在 switcher 的 context 线程运行。
- **读端**：accept 回调（`while (!disposed_)`）在 `SocketAcceptor` 的平台 accept 循环线程运行（Unix: `UnixSocketAcceptor` 的 async_accept 回调；Windows: `Win32SocketAcceptor` 的 accept 回调），与 switcher context 线程不同。

### 未修改类的约束记录

#### InternetControlMessageProtocol（strand-confined）

**不改代码，记录约束：**

- 该类的 `disposed_` 所有读写路径在同一个 executor 线程上序列化。
- `Dispose()` 通过 `boost::asio::post(*context, ...)` 将 `Finalize()` 投递到 executor 线程。
- `Echo()` 按头文件文档契约必须在 executor 线程调用。
- 析构函数的 `Finalize()` 调用仅在所有 `shared_ptr` 引用释放后发生，此时 `Echo()` 不可能正在运行。
- **后续验证建议**：确认 `Echo()` 的调用方确实遵循 executor 线程契约；如有违反，需升级为 atomic。

#### ITransmissionQoS（mutex-protected）

**不改代码，记录约束：**

- 该类的 `disposed_` 所有读写均在 `syncobj_` 互斥锁保护下。
- `ReadBytes()`、`EndRead()`、`BeginRead()` 中的 `disposed_` 检查均在 `SynchronizedObjectScope` 内。
- `Finalize()` 中的 `disposed_ = true` 也在 `SynchronizedObjectScope` 内。
- `bandwidth_` 和 `traffic_` 已是 `std::atomic`，用于无锁跨线程读取，与 `disposed_` 的锁保护模式不冲突。
- **后续验证建议**：确认无路径在锁外读取 `disposed_`；当前代码审计未发现此类路径。

### 未变更项

- **未改变 public API**：所有类的 public/protected 接口签名不变。
- **未改变业务逻辑**：仅将 `bool` 升级为 `std::atomic_bool`，读写语义不变。
- **未改变 Finalize 调用顺序**：保持原有 cleanup 顺序，未引入 exchange 级别的 exactly-once 保护（现有析构+Dispose 双路径已是幂等安全的）。
- **未修改 `docs/openppp2-deep-code-audit-cn.md`**。

### 后续验证建议

| 序号 | 验证项 | 说明 | 优先级 |
|------|--------|------|--------|
| V-1 | ThreadSanitizer (TSan) 验证 | 对修改的两个类启用 TSan 构建运行，确认无 data race 报告 | 高 |
| V-2 | VEthernetLocalProxySwitcher Finalize 顺序 | 当前 `disposed_` 在 `acceptor->Dispose()` 之后设置；accept 回调在窗口期可能看到 `disposed_==false`。考虑将 `disposed_` 设置提前到 `acceptor->Dispose()` 之前 | 中 |
| V-3 | InternetControlMessageProtocol Echo 线程契约 | 确认所有 `Echo()` 调用方在 executor 线程上执行 | 低 |

---

## P1-4 Android TLS CA 加载路径复核

| 字段 | 内容 |
|------|------|
| **编号** | P1-4 |
| **当前决策** | **已完成最小治理：补充诊断 + noexcept 修复 + 文档化** |
| **是否 P0 阻断** | 否 |
| **是否当前 release 阻断** | 否 |
| **决策日期** | 2026-05-11 |
| **关联审计文档** | `docs/openppp2-deep-code-audit-cn.md` §14.5 S-1 |

### 问题描述

审计文档 S-1 指出：Android 上 `set_default_verify_paths()` 被 `#if !defined(__ANDROID__)` 跳过，担心 `verify_peer=true` 时缺少 CA 来源，导致验证静默降级。

### 复核结论

**当前 Android CA 加载路径并非静默不安全。** 完整的 CA 来源顺序如下：

| 优先级 | CA 来源 | 平台 | 说明 |
|--------|---------|------|------|
| 1 | `cacert.pem` 文件 | 全平台 | 由 `chnroutes2_cacertpath_default()` 返回 `./cacert.pem`；仅当文件存在时尝试加载 |
| 2 | 内置根证书 (`root_certificates.hpp`) | 全平台 | 当 `cacert.pem` 加载失败时回退；包含 Mozilla 根 CA 集合（约 150+ 个根证书） |
| 3 | 系统默认 CA 路径 | 非 Android | `set_default_verify_paths()`；Android 跳过（Android 不通过标准 OpenSSL 文件系统路径暴露系统 CA 存储） |

**关键发现：**

1. **不会静默降级**：即使 `cacert.pem` 不存在，内置根证书作为 fallback 提供有效的 CA 数据。`verify_peer=true` 始终有 CA 来源可验证。
2. **fail-closed 行为**：如果所有 CA 加载路径均失败（概率极低——内置证书是硬编码 PEM 数据），信任存储为空，所有握手必然失败。这是正确的安全行为，不是静默跳过验证。
3. **存在 noexcept 违规 bug**：原代码调用 `load_root_certificates(*ssl_context)` 的抛异常重载，在 `noexcept` 函数 `CreateClientSslContext` 中可能导致 `std::terminate`。**已修复为使用非抛异常重载 `load_root_certificates(*ssl_context, ec)`。**

### 治理措施（已完成）

| 修改 | 文件 | 描述 |
|------|------|------|
| **noexcept 修复** | `ppp/ssl/SSL.cpp` | `load_root_certificates(*ssl_context)` → `load_root_certificates(*ssl_context, ec)`，使用非抛异常重载 |
| **Android 诊断** | `ppp/ssl/SSL.cpp` | 当 `verify_peer=true` 但所有 CA 加载失败时，通过 `SetLastErrorCode(SslHandshakeFailed)` 记录诊断 |
| **文档化注释** | `ppp/ssl/SSL.cpp` | 完善 client/server SSL context 中 Android 分支的 doxygen 注释，说明 CA 来源链、跳过原因和 fail-closed 语义 |

### 未变更项

- **未改变正常平台行为**：非 Android 路径完全不受影响。
- **未新增 Java/Kotlin bridge**：不引入 JNI CA 导出机制。
- **未修改构建系统**：不改 build.gradle 或 CMakeLists.txt。
- **未降级 verify_peer**：verify_peer 始终按调用者要求设置，不做任何静默跳过。
- **未修改 `docs/openppp2-deep-code-audit-cn.md`**。

### 剩余需真机/模拟器验证项

| 序号 | 验证项 | 说明 | 优先级 |
|------|--------|------|--------|
| V-1 | `cacert.pem` 在 Android APK 中的实际路径 | `chnroutes2_cacertpath_default()` 返回 `./cacert.pem`，需确认 Android NDK 进程的 CWD 是否指向 APK 可写目录 | 高 |
| V-2 | 内置根证书在 Android BoringSSL 下的解析兼容性 | `root_certificates.hpp` 使用 `add_certificate_authority()` 接口，需在 Android BoringSSL 上验证 PEM 解析无异常 | 高 |
| V-3 | BoringSSL `X509_STORE_get0_objects` / `sk_X509_OBJECT_sort` API 可用性 | 预排序逻辑已在代码中，需确认 Android BoringSSL 版本是否导出这两个符号 | 中 |
| V-4 | `verify_peer=true` 且 `cacert.pem` 缺失时握手行为 | 预期：使用内置根证书成功握手；需端到端验证 | 中 |
| V-5 | `verify_peer=true` 且所有 CA 路径失败时的诊断输出 | 预期：`SetLastErrorCode(SslHandshakeFailed)` 被设置；需确认日志可见 | 低 |

### 当前约束

- 不得将该项作为 P0 或当前 release 的阻断条件。
- 剩余验证项（V-1 至 V-5）需在 Android 真机或模拟器上进行，不在本次静态代码复核范围内。
- 本文档和 `ppp/ssl/SSL.cpp` 的修改与其他 P1 条目互不依赖。

---

*创建时间：2026-05-11*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md`*
