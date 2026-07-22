# 桌面客户端手动节点与启动参数设计
> Status: Active
> Type: Design
> Last verified: 169943b

## 目标

Windows/macOS 客户端支持不依赖订阅的单节点新增、编辑、删除和连接，并让“配置”页对齐移动端已有的启动参数语义。仅暴露 C++ 桌面运行时真实支持的字段，不展示 Android 专属能力。

## 数据模型

手动节点沿用订阅 v1 的 `SubscriptionNode` 结构，持久化到桌面端 `preferences.json` 的 `manualNodes` 数组。节点 ID 由后端生成并带 `manual:` 前缀；订阅节点保持原 ID。运行时将两类节点合并展示，但保留 `source: manual | subscription` 供 UI 判断是否可编辑。

手动节点字段分为：

- 基本信息：名称、副标题。
- 服务器：`ppp://` URI、GUID、带宽。
- 加密：`protocol`、`protocol-key`、`transport`、`transport-key`、`kf/kx/kl/kh`、`masked/plaintext/delta-encode/shuffle-data`。
- 本地代理：HTTP/SOCKS bind 与 port。
- 高级：完整 JSON。结构化字段和 JSON 使用同一配置对象，保存前由后端校验。

## 启动参数

全局启动参数持久化为 `launchOptions`。订阅节点或手动节点自带的 `options` 覆盖同名全局值；空值不生成 CLI 参数，以保留 C++ 默认和服务端自动分配行为。

桌面端支持：

| 字段 | C++ 参数 |
|---|---|
| `tunIp` | `--tun-ip` |
| `tunMask` | `--tun-mask` |
| `gateway` | `--tun-gw` |
| `dns1/dns2` | 合并为 `--dns` |
| `mux` | `--tun-mux` |
| `muxMode` | `--mux-mode` |
| `vnet` | `--tun-vnet` |
| `blockQuic` | `--block-quic` |
| `staticMode` | `--tun-static` |

`route/routePrefix/mtu/mark` 属于移动 VPN 平台层，分应用代理是 Android 专属，本轮不在桌面端伪造支持。

## 后端接口

- `client_bootstrap` 返回合并节点、全局启动参数和现有设置。
- `client_upsert_manual_node` 新增或更新手动节点并原子保存偏好。
- `client_delete_manual_node` 删除手动节点；正在使用的节点不可删除。
- `client_connect` 从手动节点和订阅节点的合并视图查找目标，生成配置并合并启动参数。

所有写入由 Rust 校验节点名称、服务器 URI、JSON 对象、密钥对象和端口范围。前端只做即时提示，不能替代后端校验。

## 界面

节点页工具栏增加带加号图标的“添加节点”按钮。手动节点行显示“本地”来源，并提供编辑、删除图标；订阅节点只读。编辑器使用单层模态窗口，桌面宽度不超过 760px，移动宽度退化为全屏滚动，不嵌套卡片。

配置页改为结构化启动参数表单，按“虚拟网卡、DNS、多路复用、网络策略”分区；原始 appsettings JSON 保留在“高级 JSON”折叠区。

## 验收

- 无订阅时可新增一个节点，重启后仍存在并可连接。
- 手动节点可编辑、删除；订阅节点不可编辑。
- 启动参数按全局值加节点覆盖规则生成真实 CLI 参数。
- 非法 URI、端口、密钥或 JSON 不落盘。
- 现有订阅刷新、收藏、延迟探测、托盘和 raw JSON 工作流不回归。
- Windows release EXE 内嵌前端，桌面 1120x760 与窄屏均无重叠或横向页面溢出。
