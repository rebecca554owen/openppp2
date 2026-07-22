# 用户手册
> Status: Active
> Type: Guide
> Last verified: 7bba7e4
>
> **用途：**在不依赖过期配置示例的前提下启动原生 `ppp` 运行时。
> **适用对象：**运行本仓库原生可执行程序的运维人员和开发者。
> **上一层索引：**[快速开始](README_CN.md) · **English：**[User Manual](USER_MANUAL.md)

## 范围

本文说明从本树构建或随配置提供的原生 `ppp` 可执行程序。它不是完整字段参考；在暴露服务或更改网络策略前，请阅读[配置参考](../reference/CONFIGURATION_CN.md)和[CLI 参考](../reference/CLI_REFERENCE_CN.md)。

运行时有三种文档化的命令角色：

| 角色 | 调用方式 | 重要边界 |
|---|---|---|
| Server | `--mode=server`（或省略 `--mode`） | 非 proxy 运行需要管理员/root 权限。 |
| Client | `--mode=client` | 非 proxy 运行需要管理员/root 权限。 |
| Proxy | `--mode=proxy` | 原生权限检查会跳过，但监听地址暴露和配置仍由运维人员负责。 |

请使用上表中的精确角色名。解析器接受更宽泛的输入；这种宽容性不是配置契约。

## 1. 准备私有配置

`ppp` 加载 JSON object。请为目标角色建立私有配置，并使用明确的文件名，例如 `config.json`。

- `appsettings-server-minimal.json` 是本树中的紧凑结构示例，**不能直接用于生产**；请替换其中的共享密钥材料，并自行设置监听、地址池和网络策略。
- `appsettings.json` 是更完整的仓库示例，不是部署模板。不要公开或复用其中的端点、密钥、证书、密码或本地地址。
- Client 和 server 对端需要兼容的共享协议/传输设置。请按权威配置参考设置 client 目标或 server 监听等角色专用值。

只允许必须运行进程的账户读取配置和证书/密钥文件。不要把凭据写入 shell 历史或 issue。

## 2. 控制配置选择

优先提供明确且可读的配置路径，并从受控的工作目录运行：

```bash
./ppp --mode=server --config=./config.json
./ppp --mode=client --config=./config.json
./ppp --mode=proxy --config=./config.json
```

加载器按以下顺序尝试候选文件：

1. 由 `--config` 指定的可读路径（也接受 `-c`、`--c` 或 `-config`），
2. `./config.json`，
3. `./appsettings.json`。

如果较早候选文件无法读取或加载，加载过程可以继续尝试后面的候选文件。因此，不要认为无效的显式路径一定能阻止选择工作目录中的配置。

Windows 上，请从提升权限的管理员会话启动 client/server。类 Unix 主机上，请以所需的 root 权限启动这两种模式。Proxy 是此权限检查的例外，并不意味着其监听地址默认安全。

## 3. 有意识地添加可观测性

`--stats-json` 接受可写文件路径，并以 NDJSON 输出运行时统计。例如：

```bash
./ppp --mode=client --config=./config.json --stats-json=./stats.ndjson
```

将输出视为本地运维数据。选择可写且不含机密的位置，并在进程外安排轮转或采集。当前实现也识别字面值 `stdout`。

## 4. 本地提供路由和 DNS 规则文件

原生选项默认使用本地规则文件：

| 用途 | 选项 | 默认文件名 |
|---|---|---|
| Bypass IP 列表 | `--bypass=./ip.txt` | `./ip.txt` |
| DNS 规则 | `--dns-rules=./dns-rules.txt` | `./dns-rules.txt` |
| Firewall 规则 | `--firewall-rules=./firewall-rules.txt` | `./firewall-rules.txt` |

应传入已审查的本地文件，不要把这些输入当作通用远程 URL。路由和 DNS 策略会改变连通性；请先在测试环境验证。运维模型见[路由与 DNS](../guides/ROUTING_AND_DNS_CN.md)。

## 5. 预期会影响宿主机

非 proxy client 运行会初始化平台网络接口，并可能按配置和参数应用路由或 DNS 行为。首次运行请使用可恢复或已充分了解的主机，保留恢复路径；可正常停止时不要强制终止进程。

### Android 系统代理边界

内置 Android `PppVpnService` 会刻意**不**通过 `VpnService.Builder` 发布原生 HTTP 代理。原生监听器只有在 `Builder.establish()` 提供 TUN 描述符、并开始原生 `run()` 后才能真正拥有端口；若更早发布系统代理，其他本地应用就可能抢先绑定并截获代理流量。

即使 Android 启动选项请求 proxy-only 或自动应用处理，也受此限制。请使用全隧道模式，或者仅在确认原生监听器已可用后，再将可信客户端手动配置为使用本地 HTTP/SOCKS 端点。

Server、client、proxy 和平台行为有意分布在不同代码路径中。生产部署前请检查：

- [平台说明](../guides/PLATFORMS_CN.md)
- [Proxy 模式](../guides/PROXY_MODE_CN.md)
- [部署](../operations/DEPLOYMENT_CN.md)
- [运维](../operations/OPERATIONS_CN.md)
- [安全](../operations/SECURITY_CN.md)

## 排障时先检查什么

| 现象 | 检查项 |
|---|---|
| 生效的设置不对 | 确认工作目录和三个配置候选文件；确保目标 `--config` 文件可读且是有效 JSON。 |
| Client 或 server 在联网前退出 | 确认所需的管理员/root 权限；非零返回时查看 facade 写出的诊断三元组。 |
| 第二个实例拒绝启动 | 进程持有角色/配置实例锁；请正常停止已有实例，或选择正确的配置。 |
| 自动化把 help 当作失败 | `--help` 会输出帮助，但当前启动路径返回非零并写出诊断；脚本必须显式处理这一行为。 |
| 路由或 DNS 变化不符合预期 | 移除未审查的本地规则文件，检查实际选项，并在重试前按路由/DNS 和平台指南复核。 |
| Android 代理流量被本地截获 | 不要在原生监听器取得端口前将其发布为 Android 系统代理；遵循上面的 Android 边界。 |

## 后续阅读

- [配置参考](../reference/CONFIGURATION_CN.md)
- [CLI 参考](../reference/CLI_REFERENCE_CN.md)
- [启动与生命周期](../architecture/STARTUP_AND_LIFECYCLE_CN.md)
- [路由与 DNS](../guides/ROUTING_AND_DNS_CN.md)
- [部署](../operations/DEPLOYMENT_CN.md)
