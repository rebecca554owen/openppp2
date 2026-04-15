# 管理后端

[English Version](MANAGEMENT_BACKEND.md)

## 角色定位

`go/` 目录下的 Go 服务是 OPENPPP2 的管理与持久化侧，而不是分组数据面。

## 它做什么

后端为 C++ 服务端运行时提供：

- 节点认证
- 用户查询
- 额度与过期状态
- 流量记账
- HTTP 管理接口
- Redis 与 MySQL 持久化

## 主要形态

后端围绕 `ManagedServer` 构建。

它会：

- 从 OS args 读取管理配置
- 连接 Redis 和 MySQL
- 暴露 WebSocket 控制链路
- 暴露 HTTP 管理接口
- 运行后台 tick loop
- 同步用户和服务端状态

## 线协议

控制协议由 8 位十六进制长度前缀加 JSON 数据包组成。

已观察到的命令包括：

- `1000` ECHO
- `1001` CONNECT
- `1002` AUTHENTICATION
- `1003` TRAFFIC

## 为什么分开

C++ 负责网卡、路由、socket、会话和转发。Go 负责业务状态、存储和管理接口。

## 相关文档

- `DEPLOYMENT_CN.md`
- `OPERATIONS_CN.md`
- `SECURITY_CN.md`
