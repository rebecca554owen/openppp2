# 部署模型

[English Version](DEPLOYMENT.md)

## 范围

本文解释 OPENPPP2 如何按源码树进行部署。

## 核心事实

- C++ 运行时是单一可执行程序 `ppp`
- 它可以以 client 或 server 角色运行
- 可选 Go 后端可由 server 通过 `server.backend` 接入

## 硬性要求

- 必须具备管理员/root 权限
- 必须有真实配置文件

`LoadConfiguration(...)` 会先查显式 `-c` / `--config`，再查 `./config.json`，最后查 `./appsettings.json`。

## 部署面的拆分

OPENPPP2 的部署可以拆成四个面：

- host surface：网卡、路由、DNS、权限
- listener surface：TCP/UDP/WS/WSS 入口
- data plane surface：会话、映射、static path、IPv6 transit
- management surface：可选 Go 后端

## 客户端部署

客户端部署会创建虚拟网卡，准备 route/DNS/bypass 输入，打开 `VEthernetNetworkSwitcher`，再建立远端 exchanger 会话。

## 服务端部署

服务端部署会通过 `VirtualEthernetSwitcher` 打开监听器、firewall、namespace cache、datagram socket、可选管理后端和可选 IPv6 transit。

## Go 后端

Go 后端是可选的，只用于 managed deployment，不属于核心 data plane。

## 相关文档

- `CONFIGURATION_CN.md`
- `PLATFORMS_CN.md`
- `OPERATIONS_CN.md`
