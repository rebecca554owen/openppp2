# 运维与排障

[English Version](OPERATIONS.md)

## 范围

本文解释 OPENPPP2 在构建和部署之后的运维行为。

## 核心运维模型

把进程当成状态迁移来读：

- 配置加载
- 环境准备
- client 或 server 打开
- steady-state tick loop
- 可选重启或关闭
- cleanup 与 rollback

## 启动失败分类

- 权限失败
- 重复实例失败
- 配置发现/加载失败
- client 本地环境准备失败
- server open 流水线失败

## Tick Loop

`PppApplication::OnTick(...)` 是顶层运维心跳，负责：

- 控制台刷新
- Windows working-set 优化
- auto restart
- link restart
- VIRR 刷新
- vBGP 刷新

## 重启行为

重启可能是设计行为，可能由以下条件触发：

- `auto_restart`
- 链路重连阈值
- 改写 route file 的 route-source 更新

## 清理

`PppApplication::Dispose()` 会释放服务端、恢复 Windows QUIC 偏好、清理 system HTTP proxy、释放客户端并停止 tick timer。

## 相关文档

- `STARTUP_AND_LIFECYCLE_CN.md`
- `DEPLOYMENT_CN.md`
- `PLATFORMS_CN.md`
