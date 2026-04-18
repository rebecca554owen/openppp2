# Stage-1 分析报告

## 范围与方法
- 本报告汇总 Stage-1 在诊断覆盖、IPv6 托管路径一致性、TCPLink/VNetstack 锁分析、受保护内存区域、Android 同步、风格规范漂移、以及疑似未使用代码上的发现。
- 证据来自源码直接审查，并给出代表性行号引用（非完整调用图）。
- 引用基于当前工作区状态，用于驱动 Stage-2/3/4 实施计划。

## 1) 按模块分组的 `SetLastErrorCode` 覆盖缺口

### 当前覆盖快照
- 诊断中心 API 已存在于 `ppp/diagnostics/Error.h:34`，实现于 `ppp/diagnostics/Error.cpp:24`，错误码目录在 `ppp/diagnostics/ErrorCodes.def:1`。
- 启动/配置路径有显式覆盖，例如：
  - `ppp/app/ApplicationInitialize.cpp:289`
  - `ppp/app/ApplicationInitialize.cpp:319`
  - `ppp/app/ApplicationConfig.cpp:40`
  - `ppp/app/ApplicationNetwork.cpp:209`
- Linux IPv6 服务端 prepare/finalize 已有较细粒度错误映射，例如：
  - `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:606`
  - `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:659`
  - `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:742`

### 缺口模块分组
- `ppp/ethernet/*` 的失败返回路径大多静默（无 `SetLastErrorCode`），包括核心 TCP 路径入口：
  - `ppp/ethernet/VNetstack.cpp:260`
  - `ppp/ethernet/VNetstack.cpp:358`
  - `ppp/ethernet/VNetstack.cpp:721`
- `ppp/net/*` 多数 socket/protocol 失败以 bool/null 返回，未回填诊断码。
- Android 桥接层（`android/libopenppp2.cpp`）使用独立数值错误枚举，未映射到 `ppp::diagnostics::ErrorCode`。
- 客户端 exchanger 路径仅见 1 处显式死锁信号上报：
  - `ppp/app/client/VEthernetExchanger.cpp:403`

### 额外 API 漂移
- `GetLastErrorCodeSnapshot()` 在 `ppp/diagnostics/Error.cpp:11` 有定义，并在 UI 使用 `ppp/app/ConsoleUI.cpp:290`，但 `ppp/diagnostics/Error.h:1` 未声明。
- `RegisterErrorHandler()` 仅存储 handler，Stage-1 未发现派发调用点：
  - 写入路径：`ppp/diagnostics/ErrorHandler.cpp:40`
  - 存储字段：`ppp/diagnostics/ErrorHandler.h:29`

## 2) IPv6 六条规则缺口与分平台修复

### 六条规则（客户端托管路径）
- 规则-1：抓取原始状态（`CaptureClientOriginalState`）。
- 规则-2：应用地址（`ApplyClientAddress`）。
- 规则-3：应用默认路由（`ApplyClientDefaultRoute`）。
- 规则-4：应用子网路由（`ApplyClientSubnetRoute`，Nat66 路径）。
- 规则-5：应用 DNS（`ApplyClientDns`）。
- 规则-6：任一步失败即回滚（`RestoreClientConfiguration`）。

### 跨平台分发证据
- 统一分发 API 位于 `ppp/ipv6/IPv6Auxiliary.cpp:56`、`ppp/ipv6/IPv6Auxiliary.cpp:71`、`ppp/ipv6/IPv6Auxiliary.cpp:87`、`ppp/ipv6/IPv6Auxiliary.cpp:103`、`ppp/ipv6/IPv6Auxiliary.cpp:119`、`ppp/ipv6/IPv6Auxiliary.cpp:134`。
- 客户端应用端串行执行六规则入口在 `ppp/app/client/VEthernetNetworkSwitcher.cpp:749` 到 `ppp/app/client/VEthernetNetworkSwitcher.cpp:795`。

### 缺口
- 缺口-A（诊断）：分平台 apply/restore helper 大多仅返回 `false`，未设置 `SetLastErrorCode`。
  - Windows 示例：`windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:165`、`windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:250`、`windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:253`
  - Darwin 示例：`darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp:269`、`darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp:309`、`darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp:349`
  - Linux 示例：`linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:760`、`linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:802`、`linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:842`
- 缺口-B（回滚可验证性）：Linux 回滚重放默认路由时未检查结果，见 `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:897`。
- 缺口-C（平台支持判定）：共享 `ClientSupportsManaged()` 在 `ppp/ipv6/IPv6Auxiliary.cpp:45` 已存在，但客户端又定义了本地重复 helper：`ppp/app/client/VEthernetNetworkSwitcher.cpp:54`。
- 缺口-D（Android 托管 IPv6）：Android 构建走 mobile/Linux 集成（`android/libopenppp2.cpp:32`），而客户端托管门控仍是桌面平台白名单（`ppp/app/client/VEthernetNetworkSwitcher.cpp:54`）。

### 分平台修复方向
- Windows：
  - 保持多默认路由快照/恢复逻辑为基础（`windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:148`、`windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:287`）。
  - 为地址/路由/dns/恢复失败添加分步 `SetLastErrorCode` 映射。
- Darwin：
  - 保留 shell token 安全检查（`darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp:10`）。
  - 在 `SetRoute`/`DeleteRoute` 与 ifconfig 失败点增加诊断映射。
- Linux：
  - 保留服务端 prepare/finalize 现有细粒度诊断（`linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:606` 起）。
  - 客户端路径补齐诊断并加强回滚验证（`linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:897`）。

## 3) TCPLink/VNetstack 死锁分析与锁序图

### 锁对象与区域
- L1：VNetstack 流表互斥量 `syncobj_`（`ppp/ethernet/VNetstack.h:257`）。
- L2：每客户端 SYSNAT 互斥量 `sysnat_synbobj_`（`ppp/ethernet/VNetstack.h:177`）。
- L3：进程级 SYSNAT 全局互斥量 `openppp2_sysnat_syncobj()`（`ppp/ethernet/VNetstack.cpp:54`）。

### 已观测加锁顺序
- `VNetstack::Update()` 先拿 L1，在 SYSNAT 分支下再拿 L2：
  - L1 于 `ppp/ethernet/VNetstack.cpp:545`
  - L2 于 `ppp/ethernet/VNetstack.cpp:584`
- `TapTcpClient::AckAccept()` 先拿 L2，再拿 L3：
  - L2 于 `ppp/ethernet/VNetstack.cpp:1197`
  - L3 于 `ppp/ethernet/VNetstack.cpp:1238`
- `TapTcpClient::Finalize()` 先拿 L2，再拿 L3：
  - L2 于 `ppp/ethernet/VNetstack.cpp:1071`
  - L3 于 `ppp/ethernet/VNetstack.cpp:1074`

### 锁序图（当前）
```text
L1 (syncobj_) -> L2 (sysnat_synbobj_) -> L3 (openppp2_sysnat_syncobj)
```

### 风险评估
- Stage-1 未发现明确的 L3->L1 反向路径，因此暂未证实硬环死锁。
- 但多级锁顺序目前依赖隐式约定，未来回归风险较高。
- 另有 exchanger 更新重入保护（不属于 VNetstack 锁图）：
  - 保护与告警点：`ppp/app/client/VEthernetExchanger.cpp:401` 与 `ppp/app/client/VEthernetExchanger.cpp:403`

## 4) 受保护区域：UDP 共享 64KB 缓冲与 `nullof` 用法

### UDP 共享 64KB 缓冲
- 全局大小常量为 `PPP_BUFFER_SIZE = 65536`，定义在 `ppp/stdafx.h:336`。
- 每 io_context 的缓存缓冲由 executors 分配：
  - `ppp/threading/Executors.cpp:173`
  - `ppp/threading/Executors.cpp:198`
- 使用该共享缓冲进行异步接收的代表点：
  - 客户端 static-echo 接收：`ppp/app/client/VEthernetExchanger.cpp:1935`
  - 服务端 static-echo 接收：`ppp/app/server/VirtualEthernetSwitcher.cpp:2229`
- 保护要求：同一共享缓冲拥有者/context 只允许单个未完成接收，或改为每 socket 独占缓冲/strand 所有权。

### `nullof` 受保护区域
- 原语定义使用空引用解引用模式：`ppp/stdafx.h:1049`。
- 同步包装路径中的代表调用点：
  - `ppp/app/client/VEthernetExchanger.cpp:1137`
  - `ppp/app/server/VirtualEthernetDatagramPort.cpp:62`
  - `ppp/app/protocol/VirtualEthernetLinklayer.cpp:830`
  - `android/libopenppp2.cpp:1531`
- 风险：将未定义行为封装在工具函数后不易被代码审查识别；Stage-2 需要在热点路径先替换。

## 5) Android 同步检查清单

- 将 Android 错误输出与诊断管线对齐（桥接枚举 -> `ErrorCode`），避免 JNI 可见错误与核心日志脱节：
  - Android 枚举区：`android/libopenppp2.cpp:125`
  - 诊断 API：`ppp/diagnostics/Error.h:34`
- 明确 Android 托管 IPv6 策略，并去除重复平台门控：
  - 本地门控：`ppp/app/client/VEthernetNetworkSwitcher.cpp:54`
  - 共享门控：`ppp/ipv6/IPv6Auxiliary.cpp:45`
- 确保移动端构建与 Linux IPv6 helper 预期一致：
  - Android CMake 包含 linux 源：`android/CMakeLists.txt:124`
- 校验 JNI 回调线程与生命周期释放时序：
  - JNI post 路径：`android/libopenppp2.cpp:351`
  - stop/release 路径：`android/libopenppp2.cpp:1264`

## 6) 风格违规（`nullptr`->`NULLPTR`、常量侧比较、格式）

### 规范基线
- 项目基线宏为 `#define NULLPTR nullptr`，位于 `ppp/stdafx.h:17`。
- 现有风格以常量侧比较（如 `NULLPTR == x`）为主。

### 违规与漂移
- 存在非常量侧空值比较示例：
  - `ppp/stdafx.cpp:167`（`s == NULLPTR`）
  - `ppp/DateTime.cpp:104`（`s == NULLPTR`）
  - `ppp/DateTime.cpp:109`（`s != NULLPTR`）
  - `ppp/net/Ipep.cpp:204`（`p != NULLPTR`）
- 项目内注释/说明仍有 `nullptr` 文案（若策略要求统一需收敛）：
  - `ppp/transmissions/ITransmissionQoS.h:74`
  - `ppp/net/native/tcp.h:136`
- 工具函数处存在轻微格式不一致：
  - `ppp/stdafx.h:1049`（`nullof` 花括号间距）。

## 7) 疑似未使用代码候选（函数/全局/文件）

### 函数
- `ppp::ipv6::auxiliary::ClientSupportsManaged()` 疑似无调用：
  - 声明：`ppp/ipv6/IPv6Auxiliary.h:91`
  - 定义：`ppp/ipv6/IPv6Auxiliary.cpp:45`
  - 客户端实际使用本地重复 helper：`ppp/app/client/VEthernetNetworkSwitcher.cpp:54`
- Linux helper `ReadDefaultRoute()` 疑似无调用：
  - 声明：`linux/ppp/ipv6/IPv6Auxiliary.h:14`
  - 定义：`linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:521`

### 全局 / 存储状态
- 错误处理器列表在当前 Stage-1 视图下仅写不读（只注册未派发）：
  - 存储：`ppp/diagnostics/ErrorHandler.h:29`
  - 追加：`ppp/diagnostics/ErrorHandler.cpp:46`

### 文件级跟进候选
- 诊断 API/头文件漂移提示接口面不完整或历史残留：
  - 未声明但被导出并调用：`ppp/diagnostics/Error.cpp:11` 与 `ppp/app/ConsoleUI.cpp:290`
  - 头文件缺失声明：`ppp/diagnostics/Error.h:1`

## Stage-2/3/4 实施计划

## Stage-2（安全与可观测性基线）
- 为 IPv6 六规则在 Windows/Darwin/Linux 客户端路径补齐可追踪 `SetLastErrorCode` 映射。
- 在 `ppp/ethernet/*` 关键失败出口（`Open`、`Input`、`CloseTcpLink`、accept 路径）补齐诊断覆盖。
- 固化并文档化锁序 `L1->L2->L3`，在调试构建加入轻量断言。
- 收敛 `nullof`：在高频调用点引入安全 optional-yield 包装并标记遗留点。

## Stage-3（行为一致性与重构）
- 统一托管 IPv6 能力探测，移除本地重复 helper，改为共享能力 API。
- 完成 Android 诊断桥接，保持 JNI 错误码与 `ErrorCode` 同步。
- 加固 Linux/Darwin 回滚验证（默认路由重放结果检查、可操作错误码）。
- 修复诊断 API/头文件漂移（补 `GetLastErrorCodeSnapshot` 声明并加测试，或移除调用）。

## Stage-4（清理与治理）
- 在调用图验证后清理已确认未使用 helper/状态。
- 在项目自有代码中执行空值比较与 `nullptr` 文案策略收敛（第三方目录排除）。
- 在 CI 加入锁序注解、失败分支诊断覆盖、风格回归检查。
- 同步更新 EN/CN 文档并纳入发版门禁清单。
