# 命令行参考
> Status: Active
> Type: Reference
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> Peer link: [English](CLI_REFERENCE.md)

## 范围

本文档说明当前启动参数解析和 Console UI。它与[配置参考](CONFIGURATION_CN.md)互补：JSON 提供持久设置，CLI 只影响本次进程启动。本文记录有源码依据的当前行为，不是正式的选项注册表、退出码表或自动化兼容性承诺。

解析器同时接受 `--name=value` 和 `--name value`。参数内容可能被 shell 解释时，必须加引号。

## 会影响行为的启动顺序

`PreparedArgumentEnvironment()` 按下列顺序处理相关输入：

1. 应用 `--tun-flash`。
2. 读取 `--stats-json`；若是文件路径，以 `"wb"` 打开后立即关闭。
3. 处理 `--help`。
4. 加载配置。
5. 应用 MUX/debug 覆盖，解析模式，再应用代理默认值和代理端口覆盖。
6. 构建网络接口设置并配置 telemetry。

由此可知：

- `--stats-json` 的文件可能在显示帮助或加载配置**之前**就被创建或截断。`stdout` 不会预先打开。传输统计可用时，之后每个样本都写成一行 NDJSON；文件目的地会在该次写入中以追加模式（`"ab"`）重新打开。
- `--help` 在加载配置前处理。当前帮助路径记录 `AppHelpRequested` 并返回非零的准备状态；脚本不能假定 `--help` 的退出状态为 `0`。
- 正常使用 `--pull-iplist` 仍需要可加载的配置，因为一次性拉取动作之前会先进行参数准备。

## 配置文件

### `--config=<path>`

别名：`-c`、`--c`、`-config`、`--config`。

加载器依次尝试可读取的显式路径、`./config.json`、`./appsettings.json`。为保证启动可复现，建议显式指定路径：

```bash
ppp --mode=server --config=./server.json
```

## 模式与代理行为

### `--mode=<value>`

别名：`--m`、`-mode`、`-m`。值会先去除空白并转小写：

| 输入 | 选择的模式 |
|---|---|
| 精确等于 `proxy` | proxy |
| 任意以 `c` 开头的值 | client |
| 空值或其他任意值 | server |

`--mode=proxy` 与 `c` 前缀规则不同。代理模式，以及配置中 `client.proxy-only=true`，都会强制本地 HTTP/SOCKS 监听绑定到 `127.0.0.1`。缺失或非正端口默认分别为 HTTP `8080`、SOCKS `1080`；之后才应用 `--proxy-http-port` 和 `--proxy-socks-port`。

仅代理客户端启动使用代理路径而非真实 TUN，并跳过客户端路由、旁路列表、DNS 规则和 geo-rules 设置。它还会强制关闭最终的 static transport 设置，因此不会发起由 static mode 触发的 `STATIC`/`STATICACK` 交互。

## 核心启动选项

| 选项 | 当前行为 |
|---|---|
| `--tun-flash=[yes|no]` | 启动最先应用，设置默认 flash/TOS。 |
| `--stats-json=<path|stdout>` | 仅在传输统计可用时输出运行期 NDJSON。文件路径会在启动期以 `wb` 预打开，之后每个可用 runtime 样本追加一行。 |
| `--rt=[yes|no]` | 开启/关闭实时调度偏好；解析器默认值为 `yes`。 |
| `--auto-restart=<seconds>` | 按解析出的非负秒数请求重启；`0` 关闭。 |
| `--link-restart=<count>` | 按十进制解析并存入 8 位阈值。格式错误或负数变为 `0`；应使用 `0..255`，不要依赖更大的值。 |
| `--firewall-rules=<file>` | 防火墙规则路径；默认 `./firewall-rules.txt`。 |
| `--dns=<ip-list>` | 提供本次启动使用的 DNS 地址列表。 |

## 客户端与 TUN 选项

| 选项 | 当前行为 |
|---|---|
| `--block-quic=[yes|no]` | 客户端行为。启用后会拒绝目标 UDP 端口 443 的数据包，并返回 ICMP Port Unreachable，促使客户端回退 TCP；它不是通用 QUIC 协议解析器。 |
| `--tun-ip=<IPv4>` | 默认 `10.0.0.2`。对于普通客户端，显式传入会隐式开启 static mode，即使 `--tun-static=no`；proxy-only 启动会强制关闭最终的 static transport 设置。 |
| `--tun-gw=<IPv4>` | 虚拟网关；默认 `10.0.0.1`。 |
| `--tun-mask=<bits-or-netmask>` | 接受数值前缀或 IPv4 子网掩码；默认 `255.255.255.252`（`/30`）。 |
| `--tun-static=[yes|no]` | 显式 static-tunnel 开关。 |
| `--tun-host=[yes|no]` / `--tun-vnet=[yes|no]` | 两者默认都是 `yes`。 |
| `--tun-mux=<connections>` | 严格十进制连接数；格式错误或负数为 `0`（关闭）。内部存储为 `uint16_t`，应使用 `0..65535`，不要依赖更大的值。 |
| `--tun-mux-acceleration=<0..3>` | `0..3` 是支持的设置。解析器先将严格十进制输入收窄到无符号字节，再清除结果大于 `3` 的值；越界输入不是可依赖的校验接口。 |
| `--mux-mode=<compat|flow|balance|stripe>` / `--mux-mode-turbo=[yes|no]` | 在配置加载后应用的 MUX 启动设置。`turbo` 仅对 `flow` 有意义；生成的帮助列出 `--mux-mode`，但当前未列出 `--mux-mode-turbo`。 |
| `--nic=<interface>` / `--ngw=<ip>` | 物理 NIC 与网关提示。 |
| `--tun-ipv6=<IPv6>` | 仅当输入可解析为 IPv6 时请求该地址。 |

平台专用选项仍由条件编译决定：Linux 有 `--bypass-nic`、`--tun-route`、`--tun-protect`、`--tun-ssmt`；macOS 有 `--tun-ssmt`；Linux/macOS 有 `--tun-promisc`；Windows 有 `--tun-lease-time-in-seconds`（默认 `7200`），以及供非 proxy 客户端启动使用、解析器接受的 `--set-http-proxy=[yes|no]`。

## 旁路列表、VIRR 与一次性拉取

### `--bypass=<file1|file2>`

默认值是 `./ip.txt`。多个文件以 `|` 分隔。必须给整个参数加引号，避免 shell 将管道字符解释为 pipeline：

```bash
ppp --mode=client --config=./client.json \
  "--bypass=./cn.txt|./local.txt"
```

仅代理运行时不会安装旁路路由。

### `--virr=<output-path/country>`

VIRR 在客户端可用后安排路由列表刷新。与源码兼容的参数形式为 `output-path/country`，例如：

```bash
ppp --mode=client --config=./client.json --virr=ip.txt/CN
```

列表根据 `virr.update-interval`（默认 `86400` 秒）刷新，失败重试使用 `virr.retry-interval`（默认 `300` 秒）。输出文件只有属于当前 bypass 集合时才会影响旁路路由。

### `--pull-iplist=<output-path/country>`

这是一次性对应操作。应使用可加载配置，并采用相同形式：

```bash
ppp --config=./appsettings.json --pull-iplist=ip.txt/CN
```

解析器在第一个 `/` 处分割表达式，因此 `ip.txt/CN` 是安全的简单形式。输出路径自身包含 `/` 时，也可使用源码支持的 `<` 分隔符（该形式对 shell 敏感，必须加引号）。

## 帮助与工具行为

`--help` 会打印生成的选项列表。它是帮助/诊断路径，不保证成功退出状态；详见上文启动顺序的说明。帮助横幅并非完整的解析器契约：当前没有列出 `--mux-mode-turbo` 和 Windows 的 `--set-http-proxy`。

### 解析器支持的 MUX 与 Windows 控制项

| 选项 | 当前解析器边界 |
|---|---|
| `--mux-mode-turbo=[yes|no]` | 在配置加载后设置 `mux.turbo`。解析器接受该参数，但生成的帮助未列出。 |
| `--debug-key=<secret>` | 为仅调试用途的 peer 控制路径设置 `mux.debug.key`。 |
| `--mux-mode-set=<value>` | 启动后保存一次性的、仅调试用途的 peer mode 请求。帮助列出 `compat|flow`；解析器本身会存储给定字符串，且不存在单独版本化的控制 API。 |
| `--set-http-proxy=[yes|no]` | 仅 Windows 的解析器输入。仅用于非 proxy 客户端启动，且生成的帮助未列出。 |

Windows 还提供文档列出的网络 helper，例如 `--system-network-reset`、`--system-network-optimization`、协议优先级开关和 `--no-lsp <program>`。这些是一次性平台操作，不是隧道设置。

## Console UI 命令

全屏 Console UI 仅在启用且 stdout 是终端时使用；否则程序使用纯文本输出。内置命令使用命名空间：

| 命令 | 操作 |
|---|---|
| `openppp2` 或 `openppp2 help` | 显示命令帮助。 |
| `openppp2 restart` / `openppp2 reload` | 请求重启。 |
| `openppp2 exit` | 请求退出。 |
| `openppp2 info` | 打印最新缓存的运行时状态行。 |
| `openppp2 clear` | 清空命令输出区域。 |
| `openppp2 telemetry ...` | 查询/控制进程内 telemetry 过滤器与最低级别（`status`、`help`、`log`、`metric`、`span`、`level`、`all`、`quiet`、`clear`）。 |

未知输入会被拒绝，并显示错误和帮助提示。它**绝不会**被交给系统 shell，也不会作为 shell 命令执行。

## 源码锚点

- 启动准备与网络接口解析 — `ppp/app/ApplicationConfig.cpp`
- 模式解析与 loopback 代理默认值 — `ppp/app/ApplicationMode.cpp`
- proxy-only 启动及跳过的 route/DNS/geo 设置 — `ppp/app/ApplicationClientBootstrap.cpp`
- 重启/统计循环行为 — `ppp/app/ApplicationInitialize.cpp`、`ppp/app/ApplicationMainLoop.cpp`
- bypass/VIRR/pull 解析 — `ppp/app/ApplicationNetwork.cpp`
- 一次性 pull 与 help 分发 — `ppp/app/PppApplication.cpp`
- 帮助文本 — `ppp/app/ApplicationHelp.cpp`
- Console UI 命令分发 — `ppp/app/ConsoleUI.cpp`
