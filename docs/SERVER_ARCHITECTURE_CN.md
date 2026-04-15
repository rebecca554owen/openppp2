# 服务端架构

[English Version](SERVER_ARCHITECTURE.md)

## 范围

本文解释 `ppp/app/server/` 下的真实服务端运行时。服务端是覆盖网络会话交换节点，不是简单的 socket 接收器。

## 运行时定位

服务端是一个多入口 overlay 节点。它接收传输连接，把连接分配给会话对象，转发流量，并在需要时与管理后端交互。

## 核心拆分

最重要的边界是 `VirtualEthernetSwitcher` 和 `VirtualEthernetExchanger`。

| 类型 | 负责什么 |
|---|---|
| `VirtualEthernetSwitcher` | 监听器、连接接收、会话路由、主会话管理 |
| `VirtualEthernetExchanger` | 单会话处理、转发、加解密、保活 |

## 服务端流程

1. 打开启用的监听器
2. 接收新连接
3. 分类连接
4. 创建或附着 exchanger
5. 完成握手
6. 构造会话信封
7. 转发流量
8. 维护映射、IPv6 和统计

## `VirtualEthernetSwitcher`

这个对象负责服务端环境：

- 多协议监听
- 接收连接
- 创建和替换会话
- 判断主会话与额外连接
- 协调映射与 namespace cache

## `VirtualEthernetExchanger`

这个对象负责一个会话：

- 握手处理
- TCP 转发
- UDP 转发
- 数据加解密
- 连接状态维护
- 向客户端下发信息

## 监听集合

服务端可以暴露 TCP 和基于 WebSocket 的入口。实际启用哪些入口取决于配置。

## 管理与策略

服务端可以咨询管理后端获取策略、统计和可达性信息。后端是可选项，数据面留在 C++ 进程中。

## 数据面

服务端处理 TCP 和 UDP 转发；启用时，static UDP 是单独路径。

## 配置的作用

`AppConfiguration` 决定启用哪些监听器、是否启用后端、以及 IPv6 和 mapping 的行为。

## 相关文档

- `ARCHITECTURE_CN.md`
- `CLIENT_ARCHITECTURE_CN.md`
- `TUNNEL_DESIGN_CN.md`
