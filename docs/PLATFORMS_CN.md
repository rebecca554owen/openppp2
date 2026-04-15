# 平台集成

[English Version](PLATFORMS.md)

## 范围

本文解释 OPENPPP2 如何把共享运行时核心落到不同宿主网络模型上。

## 核心思想

共享核心负责配置、传输、握手、链路动作、路由策略和会话管理。平台层负责虚拟接口、路由、DNS、socket protect 和宿主 IPv6 行为。

## 构建阶段拆分

根构建会选择平台源集：

- Windows: `windows/*`
- Linux: `linux/*`
- macOS: `darwin/*`
- Android: 通过独立 `CMakeLists.txt` 构建 `android/*`

## Windows

Windows 侧有多条宿主集成路径：

- Wintun（可用时）
- TAP-Windows 回退
- 基于 WMI 的接口配置
- 基于 IP Helper 的路由 API
- DNS cache flush
- 可选 proxy 和 QUIC 相关行为

## Linux

Linux 使用 native tun/tap 和 Linux 特化的 IPv6、protect 辅助能力。

## macOS

macOS 使用 utun/TAP 风格集成，以及平台特化的路由和 IPv6 辅助。

## Android

Android 作为 shared library 构建，依赖宿主 app 和 JNI glue 进入 VPN 风格集成。

## 为什么显式保留平台代码

因为虚拟接口、路由、DNS 和 IPv6 的宿主行为在不同操作系统里并不一样，不能靠一个假的统一抽象完全掩盖。

## 相关文档

- `ARCHITECTURE_CN.md`
- `DEPLOYMENT_CN.md`
- `OPERATIONS_CN.md`
