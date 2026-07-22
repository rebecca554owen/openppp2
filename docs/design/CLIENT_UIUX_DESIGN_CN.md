# OpenPPP2 Client 管理器 UI/UX 设计
> Status: Active
> Type: Design
> Last verified: 169943b

> 状态：v2，证据驱动重写（替代初版）
> 日期：2026-07-19
> 范围：Windows/macOS Client 管理器（Tauri + Svelte），配套 `SUB_CLIENT_DESIGN_CN.md`
> 预览：`docs/design/mockups/client-connected.html`

## 0. 修订说明

初版的问题：界面元素建立在编造的数据上。本版的规则是——**每个出现在屏幕上的字段，都必须能指到一行现存代码**；指不到的，要么删掉，要么明确标注为"需要新增"并列入 §6 决策清单。数据可得性结论来自对 `go/ppp`、`ppp/`、`android/` 及两个 Flutter 客户端的代码核查。

## 1. 数据可得性矩阵（本设计的事实基础)

| 信息 | 客户端能拿到吗 | 依据 |
|---|---|---|
| 节点名称 / 副标题 | ✅ 订阅 `nodes[].name` / `subtitle` | `go/ppp/Subscription.go:402-416` |
| 节点地址:端口 | ✅ 解析订阅 `nodes[].server`（`ppp://host:port/` URI） | 同上 |
| 协议/传输/密钥 | ✅ 订阅 `nodes[].key.*` | 同上 |
| 用户 GUID | ✅ 订阅 `client.guid` | `Subscription.go:414` |
| 订阅更新时间 | ✅ 顶层 `updatedAt` | `Subscription.go:421-424` |
| 节点延迟 | ⚠️ wrapper 自测 TCP ping（引擎无此能力） | 参考实现 `ya-vpn/lib/services/tcping.dart` |
| 连接状态/握手事件 | ⚠️ 配置开 `telemetry.enabled` 后解析 stderr 事件流 | `ppp/app/client/VEthernetExchanger.cpp:1114/1128/1165`；门控 `ppp/diagnostics/Telemetry.cpp:50` |
| 进程退出 | ✅ 退出码 0/-1 + stderr 一行错误三元组 | `ppp/facade/ApplicationBootstrap.cpp:11-27` |
| 连接时长 | ✅ wrapper 本地计时 | — |
| 上传/下载速度、累计流量 | ✅ 需 stats 导出补丁（§6.1，已采纳）；数据现成，每秒已在 `OnTick` 里采样 | `ppp/app/ApplicationMainLoop.cpp:671-694`、`GetTransmissionStatistics`（`:559-588`） |
| 链路质量（quality%/等级/错误计数） | ✅ 同上补丁；`LinkTelemetry` 快照现成 | `ApplicationMainLoop.cpp:426-466`、`:684-692` |
| 活动链路数（mux_active_links） | ✅ 同上补丁；`RuntimeSnapshot` 序列化现成 | `ppp/app/runtime/RuntimeSnapshotJson.h:77-108` |
| 结构化运行态（phase/effective_path/last_error） | ✅ 同上补丁；`GetRuntimeSnapshotJson()` 已存在 | `ppp/app/PppApplication.cpp:115-117` |
| TUN IP/网关/掩码、本地代理端口 | ✅ wrapper 自有（启动参数和自己生成的配置） | `--tun-ip/--tun-gw/--tun-mask`、`client.http-proxy/socks-proxy` |
| 进程 PID/版本/运行时长 | ✅ wrapper 自有 + 快照 | `ApplicationMainLoop.cpp:121-122` |
| 流量额度/剩余量/到期时间 | ❌ 订阅不含，仅管理端 API 与服务器间内部协议有 | `go/ppp/User.go:29-35`、`Subscription.go:414` |
| 节点在线状态 | ❌ 订阅不含，仅管理端 `/api/v1/servers` | `go/ppp/Admin.go:81` |
| 节点负载 | ❌ **代码中不存在此概念** | 全仓无此字段 |

### 矩阵直接推出的设计结论

1. **主屏是"状态 + 指标 + 节点表"。** 连接后首屏按重要性排：连接状态 → 本机运行指标（速度/累计流量/链路质量/活动链路）→ 节点表。
2. **速度/流量等指标依赖 §6.1 的 stats 导出补丁（已确认采纳）**。数据在 C++ 进程内全部现成，补丁只是把已序列化好的 JSON 写到进程外。补丁落地前 UI 先按"指标区隐藏"降级，不留空壳。
3. **延迟必须由 wrapper 自测**，测的是客户端→节点 TCP 握手耗时，语义是"直连参考延迟"，UI 上不假装它是隧道内 RTT。
4. 节点列表的字段就是订阅实际下发的字段：名称、副标题、地址。地区旗标订阅不产出（文档契约预留了 `flag` 但生成端不写），v1 不做旗标，靠名称即可。
5. **"连接数"的诚实口径**：引擎没有"经过隧道的 TCP 会话数"这种计数，可展示的是 mux 多链路的**活动链路数**（`mux_active_links`）和**有效路径**（`effective_path`：直连/中继）。UI 用词必须是"活动链路"，不许写成"连接数"。

## 2. 信息架构

```text
侧边导航
├── 连接          状态、当前节点、会话事件（主屏）
├── 节点          全量节点表：名称/地址/延迟/连接操作、收藏
├── 订阅          订阅 URL 管理、updatedAt、手动刷新、缓存状态
├── 日志          telemetry 事件流：过滤、搜索、导出
├── ── 高级 ──
├── 配置          原始 JSON、路由/DNS/代理（方案 §4 高级模式）
└── 设置          开机启动、托盘行为、退出时断开/保留

托盘：状态图标 + 当前节点 + 断开/连接 + 最近节点切换
```

没有"诊断"页：v1 能诊断的东西（进程是否活着、最后一条错误、订阅是否拉得动）全部内联在"连接"屏和"日志"屏，不值得单开一页。

## 3. 主屏设计（连接）

```text
┌────────────────────────────────────────────────────┐
│ ● 已连接                                  [断开]    │
│   东京 01 · 47.102.x.x:32000                        │
│   延迟 32 ms（直连参考）· 已连接 02:14:36            │
├────────────────────────────────────────────────────┤
│ 本机（stats 导出，1s 刷新）                           │
│   ↓ 12.4 Mbps   ↑ 2.1 Mbps   链路质量 99.2% 优      │
│   累计 ↓ 1.8 GB ↑ 214 MB     活动链路 4/4 · 直连     │
│   TUN 10.8.0.2/24 gw 10.8.0.1 · 代理 127.0.0.1:1080 │
├────────────────────────────────────────────────────┤
│ 会话事件                                            │
│   19:03:11  session established role=main          │
│   19:03:09  exchanger connected                    │
│   19:03:07  tcp connected 47.102.x.x:32000         │
├────────────────────────────────────────────────────┤
│ 常用节点                          全部节点 →        │
│   东京 01    47.102.x.x:32000    32 ms   [当前]    │
│   大阪 02    103.85.x.x:24000    48 ms   [连接]    │
│   新加坡 01  156.234.x.x:20000   86 ms   [连接]    │
└────────────────────────────────────────────────────┘
```

- 状态行就是 Hero。状态点 + 一个词（已连接/连接中/未连接/已断开），右侧一个动作按钮。没有旋钮、没有辉光、没有动画装饰。
- **本机指标卡**：纯文本等宽数字行，不画图。速度是 wrapper 对累计字节数做 1s 差分得出（与 Android `ReportTransmissionStatistics` 同一套路）；链路质量和活动链路直接透传快照字段；TUN/代理是 wrapper 自己的启动参数。stats 补丁未落地时整张卡隐藏，不显示"--"占位。
- "会话事件"卡片直接展示 telemetry 解析结果——它既是状态证据（用户能看到握手确实成功了），也是排障入口（点进去就是日志屏）。
- 常用节点表是第二动作区：一键切换。延迟数值旁边不配色阶圆点以外的装饰。

### 节点屏

全量表格，列：收藏 | 名称 | 副标题 | 地址 | 延迟（未连接时对全部节点轮测，连接后只测当前节点）| 操作。搜索框过滤名称/地址。没有的东西不出现：无负载列、无在线徽标（客户端无从知晓）。

### 订阅屏

订阅 URL 卡片：地址、名称（`name`）、节点数、上次成功同步时间、订阅文档 `updatedAt`、手动刷新、Token 轮换提示文案。拉取失败时显示"使用 N 小时前的缓存"（方案 §5），缓存文件存在性即缓存状态，不需要编造 ETag 细节。

## 4. 状态模型（来自真实事件，不是想象)

wrapper 的状态机输入只有三个：进程存活、stderr 事件流、退出码。

```text
disconnected ──启动进程──> connecting
connecting ──"exchanger connected"/"session established"──> connected
connecting ──"handshake failed error=N"/"tcp connect failed"──> 重试或 error
connected ──进程退出, exit 0──> disconnected
connected ──进程退出, exit -1──> error（显示 stderr 错误三元组原文）
任何状态 ──订阅刷新失败──> 状态不变 + 顶栏"使用缓存"提示
```

| 场景 | 界面表达（全部内联，无弹窗） |
|---|---|
| 连接中 | 状态点黄色 + 事件卡实时滚动 `tcp connect → exchanger connected → session established`，进度感来自真实事件而不是进度条动画 |
| 握手失败 | 事件卡显示 `handshake failed error=N` 原文，状态转 error，按钮变"重试" |
| ppp 异常退出 | 状态行红色"已断开 · 退出码 -1" + stderr 三元组原文一行 + [查看日志] [重新连接] |
| 订阅不可达 | 订阅屏和顶栏显示"使用 X 前的缓存"，节点照常可用 |
| 额度耗尽/到期 | 客户端**无法预知**；表现为握手被拒，事件流里出现认证失败——UI 如实显示该事件，不提前编造额度 UI |
| Windows 提权 | 首次启动前一次性 UAC，失败则状态行内联提示 |

已知坑（实现时必须处理）：Windows 失败路径有 `PauseWindowsConsole()` 会等按键挂住进程（`ppp/app/PppApplication.cpp:57-61`），wrapper 需以无控制台方式创建进程并验证该路径；非 TTY 下 TUI 自动禁用，stdout 静默是**正常现象**，不要误判为卡死。

## 5. 视觉系统（反"模板感"的约束）

- **单色系**：背景 `#0B0D10`，卡片 `#101318`，边框 `rgba(255,255,255,.07)`。唯一彩色是状态色（绿/黄/红/灰），只用于状态点、状态词、关键按钮。禁止大面积渐变、辉光、毛玻璃。
- **主按钮是白底黑字**，不是发光彩色按钮。交互重量靠对比度，不靠光效。
- **数字一律 tabular-nums**；地址、GUID、事件行用等宽字体——这是网络工具，终端感是优点不是缺点。
- **表格优先**：节点用表格不用卡片网格。表格是数据的诚实形态，卡片网格是营销页的形态。
- 密度：13px 基准字号，行高 1.5，页边距 24px。不追求"大气留白"，桌面工具一屏要装得下 15 个节点。
- 动效只保留：状态切换 150ms 颜色过渡、事件行新条目淡入。`prefers-reduced-motion` 下全关。

## 6. 差距清单（决策点）

### 6.1 stats 导出（已采纳，UI 按其设计)

给桌面 ppp 加 `--stats-json=<path|stdout>` 开关：在已有的 1s `OnTick` 里把现成数据写成一行 JSON。数据零新增采集——`OnTick` 本来就在采样（`ApplicationMainLoop.cpp:671-694`），序列化函数本来就有（`RuntimeSnapshotJson.h:77-108`），改动只是加出口。不涉及 wire 协议，不违反 SUB_CLIENT_DESIGN §8（那指的是节点管理协议命令）。

契约（每秒一行，NDJSON）：

```json
{
  "type": "ppp-stats",
  "version": 1,
  "monotonic_ms": 8080123,
  "rx_bytes": 1932734464,
  "tx_bytes": 224690176,
  "link": { "quality_percent": 99.2, "grade": "Good",
            "error_count": 12, "success_count": 14803 },
  "runtime": { "phase": "Connected", "role": "client",
               "requested_mux_mode": "...", "effective_mux_mode": "...",
               "mux_active_links": 4, "p2p_state": "...",
               "effective_path": "direct",
               "last_error": { "code": 0, "severity": "", "retryable": false,
                               "user_message_key": "", "diagnostic_detail": "" } }
}
```

| 字段 | 来源 |
|---|---|
| `rx_bytes`/`tx_bytes`（隧道层累计字节） | `GetTransmissionStatistics`（`ApplicationMainLoop.cpp:559-588`） |
| `link.*` | `LinkTelemetryGlobal::GetInstance().GetTotal().GetSnapshot()`（`:426-466`） |
| `runtime.*` | 直接嵌入 `SerializeRuntimeSnapshot` 的输出（`RuntimeSnapshotJson.h:77-108`） |

wrapper 语义：速度 = 相邻两行 `rx_bytes`/`tx_bytes` 差分 ÷ 间隔；累计流量直接透传；`effective_path` 映射为"直连/中继"；`last_error` 结构化后替代解析 stderr 文本（同时解决 §6.3）。

### 6.2 Sub 订阅文档扩展（可选，v1.x）

在 `nodes[]` 增加 `flag`（文档契约已预留，生成端补上即可）和地区/备注；若运营需要客户端展示额度，在顶层增加可选 `quota` 字段。不改现有字段语义，老客户端解析器容忍未知字段。

### 6.3 退出时结构化错误落盘（并入 6.1）

进程退出前把 `RuntimeSnapshot.last_error` 写入最终一行 stats 或单独 `last-error.json`，wrapper 不再依赖解析 stderr 行。

stats 补丁未落地前，UI 按"本机指标卡整体隐藏"降级，其余界面完整成立。

## 7. 落地映射（Tauri + Svelte)

- Rust 侧：`process.rs` 管 ppp 生命周期（无控制台创建、退出码捕获）；`stats.rs` 消费 `--stats-json` 的 NDJSON 行（差分算速度）；`telemetry.rs` 逐行解析 stderr 事件为结构化 enum；`pinger.rs` TCP ping；`config.rs` 移植 `openppp2/android/lib/models/remote_subscription.dart` 的订阅解析与 `ya-vpn/lib/services/profile_store.dart` 的 `defaultJson`/`effectiveJson` 合并逻辑（两份都是现成参考实现）。
- 前端：`connection.ts` 状态机（§4）是唯一事实源；`stats.ts` 1s store（速度/累计/质量/链路）；事件流 append-only store；节点表虚拟滚动。
- 采样：stats 1s（引擎 OnTick 固有节奏）；延迟 30s 轮测（未连接时全节点，连接时仅当前节点，与 ya-vpn 行为一致）；事件流实时推送。

## 8. 预览

`docs/design/mockups/client-connected.html` 单文件预览。右上角可切换 已连接/连接中/未连接/异常 四态。界面上出现的每一个字段都对应 §1 矩阵中 ✅/⚠️ 的行；额度、负载不出现，因为它们不存在。预览中的速度/流量数字是模拟数据，代表 §6.1 stats 导出落地后的显示效果。
