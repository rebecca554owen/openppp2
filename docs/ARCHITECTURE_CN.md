# 系统架构

[English Version](ARCHITECTURE.md)

## 系统形态

OPENPPP2 是一个单进程隧道运行时，使用共享协议核心，并在不同平台上挂接各自的网络接入实现。

主要层次如下：

1. 入口与生命周期
2. 配置模型
3. 传输与握手
4. 隧道控制/数据协议
5. 客户端与服务端编排
6. 平台集成
7. 可选管理后端

## 入口与生命周期

`main.cpp` 是统一入口。

它负责：

- 解析命令行参数
- 加载 `appsettings.json`
- 选择客户端或服务端模式
- 准备平台网络环境
- 构造客户端或服务端运行时
- 输出运行状态与统计信息

这样做的好处是：进程生命周期集中在一个地方，不会分散在多个二进制的多套启动路径里。

## 配置模型

`ppp/configurations/AppConfiguration.*` 是运行时的权威配置模型。

它负责：

- 默认值
- JSON 加载
- 规范化和裁剪
- 校验与字段整形

重点配置组包括：

- `key`
- `tcp`
- `udp`
- `mux`
- `websocket`
- `server`
- `client`
- `vmem`
- `ip`

整个工程高度依赖配置驱动，很多运行时行为不是通过编译期开关分叉，而是由这个对象决定。

## 传输层

`ppp/transmissions/` 提供传输抽象层。

关键类：

- `ITransmission`：握手、帧化、密钥管理、读写流程
- `ITcpipTransmission`：面向 TCP 的 socket 实现
- `IWebsocketTransmission`：WS/WSS 集成
- `ITransmissionQoS`：吞吐整形挂钩
- `ITransmissionStatistics`：流量统计

这一层应理解为“字节传输和会话引导层”，而不是包路由层。

## 隧道协议层

`ppp/app/protocol/` 定义内部隧道协议。

关键类：

- `VirtualEthernetLinklayer`：隧道动作与消息分发
- `VirtualEthernetInformation`：会话策略信封
- `VirtualEthernetPacket`：分组容器与序列化辅助
- `VirtualEthernetMappingPort`：反向映射状态
- `VirtualEthernetLogger`：隧道日志抽象

主要动作包括：

- 信息交换与保活
- NAT 和 LAN 信令
- TCP 建链 / 数据 / 关闭中继
- UDP sendto 中继
- echo 与静态路径控制
- MUX 控制
- FRP 风格反向映射控制

## 服务端运行时

服务端核心是 `ppp/app/server/VirtualEthernetSwitcher.*`。

职责包括：

- 为启用的传输类型创建监听器
- 认证并接纳会话
- 创建和维护 exchanger
- 管理防火墙与命名空间缓存
- 统计隧道流量
- 管理 IPv6 请求、租约与邻居/代理状态
- 与可选管理后端协作

围绕它的辅助类负责 TCP/IP 中继、静态数据报行为以及服务端交换操作。

## 客户端运行时

客户端核心是：

- `ppp/app/client/VEthernetNetworkSwitcher.*`
- `ppp/app/client/VEthernetExchanger.*`

职责包括：

- 打开虚拟网卡
- 选择本地协议栈行为（`lwip`、vnet、路由策略）
- 连接服务端
- 管理重连与保活
- 维护路由与 bypass 集
- 应用 DNS 规则与 DNS 重定向行为
- 暴露本地 HTTP / SOCKS 代理入口
- 管理反向映射与可选 MUX / 静态模式
- 应用服务端下发的 IPv6 状态

`VEthernetNetworkSwitcher` 主要负责本地系统/网络集成，`VEthernetExchanger` 主要负责远端会话关系。

## 平台层

### Windows

`windows/` 包含：

- TAP / Wintun 集成
- Win32 路由与防火墙辅助
- 本地代理与 PaperAirplane 钩子
- 原生 socket 与注册表辅助逻辑

### Linux

`linux/` 包含：

- TAP 集成
- 路由保护
- 诊断与栈回溯辅助
- Linux 特有网络辅助代码

### macOS

`darwin/` 包含基于 `utun` 的支持及 macOS 特化逻辑。

### Android

`android/` 包含共享运行时在 Android 上的特化分支。

## 可选管理后端

`go/` 目录下的 Go 服务不是数据面，而是辅助管理系统。

从代码结构看，它主要承担：

- 节点注册与查询
- 用户状态与策略查询
- 流量统计
- 基于 Redis 和 MySQL 的持久化
- 与 C++ 服务端运行时的 webhook 风格协同

从 C++ 侧接入该系统的桥梁主要是 `VirtualEthernetManagedServer`。

## 数据面与控制面

该工程在代码中划分出了有价值的边界：

- 数据面：包转发、connect/push/sendto、本地虚拟网卡 I/O
- 控制面：握手、信息交换、保活、映射注册、mux/static 建立、IPv6 下发、后端认证

这一边界对可维护性非常重要。阅读或修改系统时，应尽量保持这两类关注点分离。

## 阅读仓库的建议顺序

建议按照以下顺序理解代码：

1. `main.cpp`
2. `ppp/configurations/AppConfiguration.*`
3. `ppp/transmissions/*`
4. `ppp/app/protocol/*`
5. `ppp/app/server/*`
6. `ppp/app/client/*`
7. 对应目标平台目录
8. 如果需要受管部署能力，再看 `go/`

## 设计理念

- 一个可执行程序，一个协议核心
- 显式本地状态优先于隐藏式编排
- 隧道动作尽量独立于底层传输
- 通过配置和控制消息驱动策略，而不是堆砌平台特例
- 仅在主机操作系统确有必要时做平台分化

## 相关文档

- [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)
- [`TRANSMISSION_PACK_SESSIONID_CN.md`](TRANSMISSION_PACK_SESSIONID_CN.md)
- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
- [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
