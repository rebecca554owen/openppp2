# 命令行参考

[English Version](CLI_REFERENCE.md)

## 定位

本文解释 `ppp` 真实的命令行，而不是只复述帮助输出。CLI 是启动期整形层，不是全部
配置模型。大多数行为调优在 `appsettings.json` 中完成；CLI 标志是在配置文件被完整
解析之前应用的覆盖参数和平台 helper 操作。

源码锚点：

- `main.cpp::PrintHelpInformation()` — 帮助文本生成
- `main.cpp::GetNetworkInterface()` — CLI 解析和 `NetworkInterface` 填充
- `main.cpp::IsModeClientOrServer()` — 模式检测

---

## 高层启动流程

```mermaid
flowchart TD
    A["main()"] --> B["解析 CLI 参数\nGetNetworkInterface()"]
    B --> C{"--mode=?"}
    C -->|"以 'c' 开头"| D["客户端模式"]
    C -->|"server（默认）"| E["服务端模式"]
    D --> F["加载 --config 文件\n（显式 / config.json / appsettings.json）"]
    E --> F
    F --> G["应用 CLI 覆盖参数\n（dns, bypass, firewall-rules 等）"]
    G --> H{"是否有平台\nhelper 标志?"}
    H -->|"有（仅 Windows）"| I["执行 helper 操作\n然后退出"]
    H -->|"无"| J["PppApplication::Run()\n启动 VPN"]
    J --> K["ConsoleUI 或纯文本 banner"]
```

---

## CLI 参数分组

CLI 大致分为：

1. 角色选择
2. 配置文件
3. 运行时整形
4. 客户端网络整形
5. 路由与 DNS 输入
6. 服务端策略输入
7. 平台 helper 命令（仅 Windows）
8. 工具命令

---

## 角色选择

### `--mode=[client|server]`

- **默认：** `server`
- **别名：** `--m`、`-mode`、`-m`
- 只要值以 `c` 开头（不区分大小写），就进入客户端模式。

这个参数决定整个启动分支：

- **客户端模式** 创建/使用虚拟网卡路径（`VEthernetNetworkSwitcher`、
  `VEthernetExchanger`、虚拟 TUN/TAP NIC）
- **服务端模式** 打开监听器和 server switcher 路径（`VirtualEthernetSwitcher`、
  `VirtualEthernetExchanger`）

```mermaid
flowchart TD
    A["--mode=<value>"] --> B{"value[0] == 'c'?"}
    B -->|"是：客户端"| C["创建虚拟 NIC\n启动 VEthernetNetworkSwitcher\n连接到服务端"]
    B -->|"否：服务端"| D["打开监听器\n启动 VirtualEthernetSwitcher\n接受客户端连接"]
```

**示例：**

```bash
ppp --mode=server --config=./server.json
ppp --mode=client --config=./client.json
ppp -m=client -c=./client.json
```

---

## 配置文件

### `--config=<path>`

别名：`-c`、`--c`、`-config`、`--config`

未指定时的查找顺序：

1. 命令行显式路径（如果已提供）
2. `./config.json`
3. `./appsettings.json`

生产环境建议始终显式指定路径，避免意外从工作目录加载到错误配置文件。

**示例：**

```bash
ppp --mode=server --config=/etc/ppp/server.json
ppp --mode=client -c=/home/user/.config/client.json
```

---

## 运行时整形

### `--rt=[yes|no]`

进程级 real-time 调度偏好。`yes` 时进程尝试提升调度优先级，适用于低延迟服务器。

### `--dns=<ip-list>`

覆盖本次运行的本地 DNS 列表。接受逗号或分号分隔的 IP 地址列表。写入
`NetworkInterface::DnsAddresses`，不会替代 DNS rules 或服务端 DNS 逻辑。

**示例：**

```bash
ppp --mode=client -c=./client.json --dns=8.8.8.8,1.1.1.1
```

### `--tun-flash=[yes|no]`

早期设置默认 flash/TOS 倾向。控制虚拟网卡是否为数据包打上加速转发 DSCP 位。

### `--auto-restart=<seconds>`

进程级自动重启计时器。指定秒数到期后，进程通过 `ShutdownApplication(true)` 发起
优雅重启。`0` 关闭定时器。

**示例：**

```bash
ppp --mode=client -c=./client.json --auto-restart=3600
```

### `--link-restart=<count>`

VPN 链路重连次数超过 `count` 时触发进程重启，用于检测陈旧状态并强制清洁重启。

---

## 服务端输入

### `--block-quic=[yes|no]`

`yes` 时阻止本次运行中的 QUIC 相关 UDP 流量。阻止 QUIC 会迫使 HTTPS 连接走 TCP，
在某些配置下可能改善隧道性能。

### `--firewall-rules=<file>`

防火墙规则文件，文件中包含服务端应用于转发流量的 IP 范围和端口规则。
默认：`./firewall-rules.txt`。

**示例：**

```bash
ppp --mode=server -c=./server.json --firewall-rules=/etc/ppp/firewall.txt
```

---

## 客户端输入

### `--lwip=[yes|no]`

选择客户端网络栈行为。`yes` 时使用 lwIP TCP/IP 栈处理虚拟 NIC 包；`no` 时走
宿主网络栈路径。

### `--vbgp=[yes|no]`

启用 vBGP（虚拟 BGP）路由更新。启用时客户端定期从服务端拉取更新的路由表。
刷新节奏由配置文件里的 `vbgp.update-interval` 控制。

### `--nic=<interface>`

物理网卡提示，告诉客户端哪块物理网卡用作 VPN 隧道流量的出口接口。
在多宿主主机上使用。

**示例：**

```bash
ppp --mode=client -c=./client.json --nic=eth0
```

### `--ngw=<ip>`

物理网关提示，指定物理网卡的下一跳网关，用于在 VPN 路由之外保留默认路由。

### `--tun=<name>`

虚拟网卡名称，覆盖操作系统分配的 TUN/TAP 接口名称。

**示例：**

```bash
# Linux
ppp --mode=client -c=./client.json --tun=ppp0

# Windows
ppp --mode=client -c=./client.json --tun="PPP Adapter"
```

### `--tun-ip=<ip>`

分配给虚拟网卡的 IPv4 地址。

### `--tun-ipv6=<ip>`

分配给虚拟网卡的 IPv6 地址。

### `--tun-gw=<ip>`

虚拟网卡的网关地址，即分配给 TUN 接口的服务端侧网关地址。

### `--tun-mask=<bits>`

虚拟网卡 IPv4 子网的网络前缀长度（CIDR 表示法数字）。
例如 `24` 表示 `/24` 子网掩码（`255.255.255.0`）。

### `--tun-vnet=[yes|no]`

控制子网转发行为。`yes` 时整个虚拟子网的流量都通过隧道路由，支持 LAN-to-LAN
互通。

### `--tun-host=[yes|no]`

控制是否偏向 host 网络。`yes`（默认）时以虚拟网卡的网关作为默认路由，将所有
主机流量路由过 VPN。

### `--tun-static=[yes|no]`

启用静态隧道模式。`yes` 时使用 `PACKET_HEADER` static packet 格式而非常规
transmission 包格式。参见 `PACKET_FORMATS_CN.md`。

### `--tun-mux=<connections>`

MUX 连接数，设置并行复用底层连接的数量。`0` 表示关闭 MUX。MUX 开启时，握手中
的 `nmux` 标志会反映 mux 状态。

**示例：**

```bash
ppp --mode=client -c=./client.json --tun-mux=4
```

### `--tun-mux-acceleration=<mode>`

MUX 加速模式，控制复用连接如何分配流量。有效值取决于构建配置。

### `--tun-promisc=[yes|no]`

混杂模式开关，仅在 Linux 和 macOS 上使用。`yes` 时虚拟 NIC 接受所有帧，无论
目的 MAC 地址。某些网桥配置需要此选项。

### `--tun-ssmt=<threads>` 或 `--tun-ssmt=<N>[/<mode>]`

SSMT（服务端侧多线程）调优。Linux 上 `mq` 模式表示每个 worker 线程打开一个
TUN 队列，支持跨 CPU 核心并行处理包。macOS 上只文档化线程数形式。

**示例：**

```bash
# Linux：4 个 worker 线程 + multi-queue
ppp --mode=client -c=./client.json --tun-ssmt=4/mq

# macOS：4 个 worker 线程
ppp --mode=client -c=./client.json --tun-ssmt=4
```

### `--tun-route=[yes|no]`

Linux 路由兼容开关，控制客户端是否修改系统路由表为 VPN 子网添加路由。

### `--tun-protect=[yes|no]`

Linux 路由保护开关。`yes` 时客户端为 VPN 服务端 IP 地址添加一条经物理网关的
主机路由，防止路由环路。

### `--tun-lease-time-in-seconds=<sec>`

Windows 虚拟网卡的 DHCP 租约时间，控制虚拟 NIC 在续约之前持有 DHCP 租约的时长。
仅在 Windows 上生效。

---

## 路由输入

### `--bypass=<file1|file2>`

旁路 IP 列表文件。此文件中列出的 IP 地址和段通过物理 NIC（绕过 VPN 隧道）路由，
而不是通过虚拟网卡。多个文件可用 `|` 分隔。默认：`./ip.txt`。

**示例：**

```bash
ppp --mode=client -c=./client.json --bypass=./cn.txt|./local.txt
```

### `--bypass-nic=<interface>`

Linux 上用于旁路列表处理的接口，旁路路由添加时使用此接口作为出口。

### `--bypass-ngw=<ip>`

旁路列表的网关提示，旁路路由将以此 IP 作为下一跳。

### `--virr=[file/country]`

启用 IP-list 刷新行为（VIRR：虚拟 IP 路由刷新）。参数为文件路径或国家代码。
启用时客户端定期重新下载并应用旁路 IP 列表。刷新节奏由配置文件里的
`virr.update-interval` 和 `virr.retry-interval` 控制。

**示例：**

```bash
ppp --mode=client -c=./client.json --virr=CN
```

### `--dns-rules=<file>`

DNS 规则文件，文件中指定域名模式及其目标 DNS 服务器或转发行为。
默认：`./dns-rules.txt`。

**示例：**

```bash
ppp --mode=client -c=./client.json --dns-rules=/etc/ppp/dns-rules.txt
```

---

## 平台 helper（仅 Windows）

这些是修改系统网络配置的 helper 操作，不是隧道启动参数；执行指定操作后即退出。

| 标志 | 操作 |
|------|------|
| `--system-network-reset` | 将 Windows 网络栈重置为默认值 |
| `--system-network-optimization` | 应用推荐的 TCP/UDP 调优参数 |
| `--system-network-preferred-ipv4` | 在 Windows 绑定顺序中将 IPv4 设为优先 |
| `--system-network-preferred-ipv6` | 在 Windows 绑定顺序中将 IPv6 设为优先 |
| `--no-lsp <program>` | 以绕过 LSP（分层服务提供程序）的方式启动 `<program>` |

**示例：**

```cmd
ppp --system-network-reset
ppp --system-network-optimization
ppp --system-network-preferred-ipv4
ppp --no-lsp "C:\Program Files\MyApp\app.exe"
```

---

## 工具命令

### `--help`

打印列出所有 CLI 标志及其简要说明的帮助输出，然后退出。帮助输出由
`main.cpp::PrintHelpInformation()` 生成。

### `--pull-iplist [file/country]`

为指定国家代码或从指定 URL/文件下载 IP 列表（旁路列表），写入目标文件后退出。
适用于隧道启动前预填充旁路列表。

**示例：**

```bash
ppp --pull-iplist CN
ppp --pull-iplist ./cn.txt
```

---

## Console UI 命令与布局

运行期 Console UI 是独立交互界面，不等同于启动参数 CLI。仅当 stdout 连接到终端时
才处于活动状态。

源码锚点：

- `ppp/app/ConsoleUI.cpp::ExecuteCommand(...)` — 命令分发
- `ppp/app/ConsoleUI.cpp::RenderFrame(...)` — 帧渲染
- `ppp/app/ConsoleUI.cpp::BuildStatusBarText(...)` — 状态栏构建

### 内置 Console 命令

| 命令 | 别名 | 操作 |
|------|------|------|
| `openppp2 help` | `help` | 打印可用命令列表 |
| `openppp2 restart` | `restart` | 通过 `ShutdownApplication(true)` 优雅重启 |
| `openppp2 reload` | `reload` | restart 的别名 |
| `openppp2 exit` | `exit` | 通过 `ShutdownApplication(false)` 退出 |
| `openppp2 info` | `status` | 将当前信息快照打印到命令输出区 |
| `openppp2 clear` | `clear` | 清空命令输出环形缓冲区并重置滚动 |
| *（其他任意输入）* | | 作为 shell 命令执行，将输出捕获到命令区 |

### 键盘控制

| 按键 | 操作 |
|------|------|
| `Up` / `Down` | 命令历史导航 |
| `Left` / `Right` | 在编辑行中移动光标 |
| `Home` | 信息区滚动到顶部 |
| `End` | 信息区滚动到底部 |
| `Backspace` / `Delete` | 删除光标前 / 当前位置字符 |
| `PageUp` / `PageDown` | 命令输出区向上 / 向下滚动 |
| `Ctrl+A` | 光标移至行首 |
| `Ctrl+E` | 光标移至行尾 |
| `Enter` | 执行命令 |

### 布局

TUI 帧分为以下区域：

1. **头部**（10 行固定）：顶部边框、提示行、ASCII 艺术字、空行、分隔符
2. **信息区**（动态，约中间区域的 60%）：可滚动 VPN 状态行，`Home`/`End` 控制
3. **命令区**（动态，约中间区域的 40%）：可滚动命令输出，`PageUp`/`PageDown` 控制
4. **输入行**（1 行）：带反显光标的编辑器
5. **状态栏**（1 行）：错误 + VPN 状态 + 速度

完整的布局规范参见 `TUI_DESIGN_CN.md`。

### 状态栏语义

状态栏文本由以下部分拼接：

- `vpn:<state>` — 当前 VPN 连接状态（如 `Established`、`Connecting`、`Disconnected`）
- 可选 `note:<最新状态队列文本>` — 最近一次 `UpdateStatus` 文本
- `err:<FormatErrorString(snapshot)>` — 格式化的最后一次错误描述
- `err_age:<seconds>s` — 基于 `GetLastErrorTimestamp()` 差值计算的自上次错误以来的秒数
- `diag_ts:<诊断原始时间戳>` — 用于关联的原始诊断时间戳

状态栏读取进程级诊断快照，目标是在不中断数据面线程的情况下显示最近一次失败上下文。

---

## 记住这些默认值

| 标志 | 默认值 |
|------|--------|
| `--mode` | `server` |
| `--config` | 先 `./config.json`，再 `./appsettings.json` |
| `--dns` | 配置文件中的首选 DNS 对（解析失败时回退） |
| `--bypass` | `./ip.txt` |
| `--dns-rules` | `./dns-rules.txt` |
| `--firewall-rules` | `./firewall-rules.txt` |
| `--tun-host` | `yes` |
| `--rt` | `no` |
| `--tun-mux` | `0`（关闭） |

---

## 典型使用示例

### 服务端

```bash
# 最简服务端启动
ppp --mode=server --config=/etc/ppp/server.json

# 带自定义防火墙规则和 real-time 调度的服务端
ppp --mode=server --config=/etc/ppp/server.json \
    --firewall-rules=/etc/ppp/firewall.txt \
    --rt=yes
```

### 客户端（Linux）

```bash
# 基本客户端
ppp --mode=client --config=/etc/ppp/client.json

# 带旁路列表、MUX 和 DNS 覆盖的客户端
ppp --mode=client --config=/etc/ppp/client.json \
    --bypass=./cn.txt \
    --tun-mux=4 \
    --dns=8.8.8.8,8.8.4.4 \
    --tun-ssmt=4/mq

# 带路由保护和每小时自动重启的客户端
ppp --mode=client --config=/etc/ppp/client.json \
    --tun-protect=yes \
    --auto-restart=3600
```

### 客户端（Windows）

```cmd
rem 先优化网络栈（以管理员身份运行一次）
ppp --system-network-optimization

rem 启动客户端
ppp --mode=client --config=C:\ppp\client.json --tun-lease-time-in-seconds=86400
```

### 工具

```bash
# 下载中国 IP 旁路列表后退出
ppp --pull-iplist CN

# 显示帮助
ppp --help
```

---

## 错误码参考

CLI 相关错误码（来自 `ppp/diagnostics/Error.h`）：

| ErrorCode | 说明 |
|-----------|------|
| `ConfigFileNotFound` | 在所有查找路径均未找到配置文件 |
| `ConfigFileParseFailed` | 配置文件 JSON 解析失败 |
| `ModeInvalid` | `--mode` 值无法识别 |
| `DnsAddressParseError` | `--dns` 值包含无效 IP 地址 |
| `BypassFileNotFound` | `--bypass` 文件未找到 |
| `DnsRulesFileNotFound` | `--dns-rules` 文件未找到 |
| `FirewallRulesFileNotFound` | `--firewall-rules` 文件未找到 |
| `NetworkInterfaceNotFound` | `--nic` 指定的接口未找到 |
| `GatewayAddressParseError` | `--ngw` 或 `--bypass-ngw` 值无效 |
| `TunAddressParseError` | `--tun-ip`、`--tun-ipv6` 或 `--tun-gw` 值无效 |

---

## 相关文档

- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md) — 完整的 `appsettings.json` 结构
- [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md) — 传输层详情
- [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md) — 系统架构概述
- [`ERROR_HANDLING_API_CN.md`](ERROR_HANDLING_API_CN.md) — 错误码体系
- [`TUI_DESIGN_CN.md`](TUI_DESIGN_CN.md) — Console UI 布局与行为
