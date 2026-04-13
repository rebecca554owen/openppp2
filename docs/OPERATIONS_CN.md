# 运维与排障

[English Version](OPERATIONS.md)

## 构建验证

### Windows

优先使用：

```bat
build_windows.bat Release x64
```

要求：

- Visual Studio 2022
- Ninja
- 脚本能够发现 vcpkg toolchain

### Linux / WSL

```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j32
```

要求：

- CMake
- 支持 C++17 的 GCC 或 Clang
- 除非显式覆盖，否则第三方依赖位于 `/root/dev`

## 初始运行检查

在深入排查隧道行为前，先确认：

- 配置文件路径正确
- 角色正确：`--mode=client` 或 `--mode=server`
- 监听端口未被占用
- WSS 所需证书和私钥存在
- TUN/TAP 虚拟网卡创建成功
- 路由、DNS 规则、bypass 文件路径正确

## 常用运行命令

```bash
ppp --help
```

```bash
ppp --mode=server --config=./appsettings.json
```

```bash
ppp --mode=client --config=./appsettings.json
```

## 运行时重点观察项

程序会输出关键运行状态，例如：

- 当前模式
- 远端 URI 或监听端点
- 代理状态
- 传输统计
- 服务端会话数
- 客户端网络状态
- DNS 与 IPv6 相关状态

在做更深的抓包之前，优先看控制台输出。

## 常见故障类型

### 1. 构建失败

常见原因：

- Windows 下缺少 vcpkg 依赖
- Linux 下 `/root/dev` 缺少第三方库
- 编译器过旧或标准选项不对

### 2. 服务端已监听，但客户端无法连接

常见原因：

- 监听端口错误
- 本机防火墙或云安全组阻断
- WSS 证书与私钥不匹配
- 反向代理没有正确转发 WS/WSS

### 3. 客户端连接了，但没有流量通过

常见原因：

- TUN IP / 网关 / 掩码不匹配
- 路由未按预期生效
- 分流 bypass 列表过宽
- DNS 规则把流量导向了隧道外
- 服务端策略拒绝或会话已过期

### 4. 反向映射不工作

常见原因：

- `server.mapping` 未启用
- `client.mappings` 配置错误
- 本地服务没有监听在配置的 `local-ip:local-port`

### 5. IPv6 表现不稳定

常见原因：

- 服务端 IPv6 模式未启用
- 把 Linux 专有的服务端 IPv6 数据面预期套用到其他平台
- 分配的前缀 / 网关与本地路由状态不一致

## 日志与证据采集

遇到较严重问题时，建议收集：

- 完整控制台输出
- 实际生效的配置文件
- 启动前后的路由表
- 本机防火墙状态
- 物理网卡与虚拟网卡两侧抓包
- 启用 `server.backend` 时的后端日志

不要只保留被过滤过的片段，优先保留完整输出。

## 变更验证纪律

当代码改动涉及平台特化路径时，应在对应平台验证：

- Windows 改动：在 Windows 上构建
- Linux 改动：在 Linux / WSL 上构建
- macOS 改动：发布前在 macOS 工具链验证
- Android 改动：在 Android / NDK 工具链验证

如果只是文档改动，则不需要重新构建二进制。

## 运维基线

- 每个部署角色保留一份已知正常配置
- 路由列表和 DNS 规则纳入变更管理
- 初次上线时不要同时启用太多功能
- 先验证一种传输方式，再逐步叠加 mux、mapping、static、IPv6 等能力

## 建议排障顺序

1. 检查配置与运行输出
2. 检查监听、路由、DNS、防火墙状态
3. 检查客户端与服务端会话建立
4. 检查虚拟网卡和物理网卡上的数据流
5. 只有在数据面基础成立后，再检查后端集成

## 相关文档

- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
- [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
- [`SECURITY_CN.md`](SECURITY_CN.md)
