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

*创建时间：2026-05-11*
*关联审计文档：`docs/openppp2-deep-code-audit-cn.md`*
