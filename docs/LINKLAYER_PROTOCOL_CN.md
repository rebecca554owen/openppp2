# 链路层协议指南

[English Version](LINKLAYER_PROTOCOL.md)

## 范围

本文描述 `VirtualEthernetLinklayer` 实现的内部隧道动作协议。

## 为什么需要这一层

OPENPPP2 需要一套统一词汇来表达会话信息、保活、LAN/NAT 信令、TCP 中继、UDP 中继、反向映射、static 路径协商和 mux 协商。

## 操作码分组

`VirtualEthernetLinklayer` 定义的动作家族包括：

- `INFO`、`KEEPALIVED`
- `FRP_ENTRY`、`FRP_CONNECT`、`FRP_CONNECTOK`、`FRP_PUSH`、`FRP_DISCONNECT`、`FRP_SENDTO`
- `LAN`、`NAT`、`SYN`、`SYNOK`、`PSH`、`FIN`、`SENDTO`、`ECHO`、`ECHOACK`、`STATIC`、`STATICACK`
- `MUX`、`MUXON`

代码中的实际值是：

- `INFO = 0x7E`
- `KEEPALIVED = 0x7F`
- `FRP_ENTRY = 0x20` 到 `FRP_SENDTO = 0x25`
- `LAN = 0x28` 到 `STATICACK = 0x32`
- `MUX = 0x35`
- `MUXON = 0x36`

## 各家族含义

- `INFO` 承载会话信息和扩展数据
- `KEEPALIVED` 是心跳路径
- `LAN` 和 `NAT` 承载子网与穿透信令
- `SYN` / `SYNOK` / `PSH` / `FIN` 在隧道内模拟逻辑 TCP
- `SENDTO` 承载 UDP 中继
- `ECHO` / `ECHOACK` 支持 echo 式健康检查
- `STATIC` / `STATICACK` 协商 static 分组路径
- `MUX` / `MUXON` 协商多路复用
- `FRP_*` 承载反向映射控制和数据

## `INFO` 载荷

`INFO` 由基础 `VirtualEthernetInformation` 和可选扩展 JSON 组成。扩展路径主要用于 IPv6 分配和状态字段。

## 方向性

代码不会接受任何方向上的所有动作。client 和 server 的处理器会强制角色合法性，遇到不该来的方向会拒绝。

## 为什么要单独拆这层

它是隧道的语义中心。把控制动作显式建模，比把它们隐藏在一条平坦字节流里更容易维护。

## 相关文档

- `TRANSMISSION_CN.md`
- `TUNNEL_DESIGN_CN.md`
- `PACKET_FORMATS_CN.md`
