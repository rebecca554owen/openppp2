# 客户端架构

[English Version](CLIENT_ARCHITECTURE.md)

## 范围

本文描述 `ppp/app/client/` 里的真实客户端运行时，不是通用 VPN 介绍。它是覆盖网络在宿主机侧的边缘节点。

## 运行时定位

客户端主要做两件事：

- 整形本地宿主网络
- 维护远端隧道会话

## 核心拆分

两个核心类型是：

- `VEthernetNetworkSwitcher`
- `VEthernetExchanger`

这是最重要的架构边界。

| 类型 | 负责什么 |
|---|---|
| `VEthernetNetworkSwitcher` | 虚拟网卡、路由、DNS、bypass、本地流量分类、代理表面 |
| `VEthernetExchanger` | 远端会话、握手、保活、密钥状态、static 路径、IPv6、映射 |

## 客户端流程

1. 构建本地网络上下文
2. 创建虚拟网卡环境
3. 分类流量
4. 打开远端传输会话
5. 完成握手
6. 交换会话信息
7. 应用路由、DNS、代理、映射和可选 IPv6 状态
8. 进入稳态转发

## `VEthernetNetworkSwitcher`

这个对象负责宿主机网络侧：

- 创建虚拟网卡
- 修改路由
- 修改 DNS
- 流量分类
- bypass 策略
- 把服务端返回的数据重新注入本地网络

它决定哪些流量进入隧道，哪些留在本地。

## `VEthernetExchanger`

这个对象负责远端会话侧：

- 建立传输连接
- 完成客户端握手
- 维持会话保活
- 管理密钥
- 维护 static 路径状态
- 注册映射
- 应用 IPv6

## 宿主集成

客户端也负责本地代理表面和平台相关虚拟网卡行为。因此它是宿主集成层，而不是单纯的拨号器。

## 边界

route/DNS/bypass 留在 switcher 中，远端连接和握手留在 exchanger 中。这条边界是客户端设计的核心。

## 相关文档

- `ARCHITECTURE_CN.md`
- `SERVER_ARCHITECTURE_CN.md`
- `TUNNEL_DESIGN_CN.md`
