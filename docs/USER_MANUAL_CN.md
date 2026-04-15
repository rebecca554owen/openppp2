# 用户手册

[English Version](USER_MANUAL.md)

## 定位

本文是面向使用者的 OPENPPP2 运行手册。

## OPENPPP2 是什么

OPENPPP2 是一个单二进制、多角色、跨平台的虚拟网络运行时。它能以 client 或 server 运行，并可叠加路由、DNS steering、反向映射、静态数据路径、MUX、平台集成以及可选管理后端。

## 先决定什么

在写配置和运行命令之前，先决定：

- 节点角色
- 部署形态
- 宿主平台
- 这是全隧道、分流、代理边缘、服务发布边缘，还是 IPv6 服务边缘

## 基本运行模型

- `server` 是默认角色
- 用 `--mode=client` 进入 client
- 使用显式配置路径
- 用管理员/root 权限运行

## 宿主会被改什么

根据平台和角色，OPENPPP2 可能修改：

- 虚拟网卡
- 路由
- DNS 行为
- 代理行为
- IPv6 行为
- 防火墙或 socket protect 设置

## 推荐阅读顺序

1. `ARCHITECTURE_CN.md`
2. `STARTUP_AND_LIFECYCLE_CN.md`
3. `CONFIGURATION_CN.md`
4. `CLI_REFERENCE_CN.md`
5. `PLATFORMS_CN.md`
6. `DEPLOYMENT_CN.md`
7. `OPERATIONS_CN.md`

## 相关文档

- `README_CN.md`
- `SOURCE_READING_GUIDE_CN.md`
