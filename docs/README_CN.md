# 按任务查找文档

> Status: Current
> Type: Navigation
> Last verified: 2026-07-22
> Parent index: [仓库 README](../README_CN.md) · English: [Documentation by Task](README.md)

[English](README.md)

本页用于选择原生 `ppp` 树的当前有效文档。请进入链接的分类页面；本索引本身不是配置或运维参考手册。

## 首次使用路径

1. [构建与首次运行](getting-started/USER_MANUAL_CN.md)
2. [配置参考](reference/CONFIGURATION_CN.md) 和 [CLI 参考](reference/CLI_REFERENCE_CN.md)
3. [运维检查清单与故障排查](operations/OPERATIONS_CN.md)

## 按任务浏览

| 任务 | 当前权威页面 |
|---|---|
| 安装、本地构建与首次验证 | [快速开始](getting-started/README_CN.md) |
| 配置字段、CLI 行为、错误和协议格式 | [参考手册](reference/README_CN.md) |
| 路由、DNS、代理模式、管理、IPv6 和平台 | [任务指南](guides/README_CN.md) |
| 部署、安全、监控和故障响应 | [部署与运维](operations/README_CN.md) |
| 运行时、传输、协议、并发和源码级架构 | [架构](architecture/README_CN.md) |
| 源码阅读、构建、测试和兼容性 | [开发文档](development/README_CN.md) |
| 接口状态、实现边界和已知缺口 | [项目接口全景图](reference/PROJECT_INTERFACE_MAP_CN.md) |

## 运行时定位

原生程序的常规启动路径为：

```text
main.cpp
  -> ppp::facade::RunApplication()
  -> PppApplication::GetInstance().Run()
  -> PreparedArgumentEnvironment()
  -> Executors::Run()
  -> RunPreparedApplication()
  -> PppApplication::Main()
```

根 CMake 项目生成 `ppp` 和 `openppp2_lib`；仅在配置 `-DENABLE_TESTS=ON` 时纳入 `tests/`。应用准备阶段会加载配置，并在运行时进入 `Main()` 前解析客户端、服务端或代理模式。修改启动或关闭行为前，请先阅读[启动与生命周期](architecture/STARTUP_AND_LIFECYCLE_CN.md)。

`go/`、`go/guardian/`、`android/`、`ios/` 和 `desktop/client/` 是独立清单管理的配套或平台表面，而非根 CMake target。它们的本地文档定义各自的构建方式与就绪边界。

## 文档状态边界

请使用上方当前有效页面作为受支持的操作指导。`archive/`、`adr/` 和 `design/` 目录保留历史依据、决策、计划和证据；除非当前页面明确说明，否则不得将其作为当前配置或部署指令。这对导航页面提供英中文配对；使用其他当前页面前，请先核对其状态、语言配对和父级索引元数据。
