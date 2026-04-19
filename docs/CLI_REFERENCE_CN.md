# 命令行参考

[English Version](CLI_REFERENCE.md)

## 定位

本文解释 `ppp` 真实的命令行，而不是只复述帮助输出。CLI 是启动期整形层，不是全部配置模型。

锚点：

- `main.cpp::PrintHelpInformation()`
- `main.cpp::GetNetworkInterface()`
- `main.cpp::IsModeClientOrServer()`

## 分类

CLI 大致分为：

- 角色选择
- 运行时整形
- 客户端网络整形
- 路由与 DNS 输入
- 服务端策略输入
- 平台 helper command
- 工具命令

## 角色选择

### `--mode=[client|server]`

- 默认：`server`
- 别名：`--m`、`-mode`、`-m`
- 只要值以 `c` 开头，就进入 client

这个参数决定整个启动分支：

- client 走虚拟网卡和交换器路径
- server 走监听器和 server switcher 路径

示例：

```bash
ppp --mode=server --config=./server.json
ppp --mode=client --config=./client.json
```

## 配置文件

### `--config=<path>`

别名：

- `-c`
- `--c`
- `-config`
- `--config`

查找顺序：

1. 命令行显式路径
2. `./config.json`
3. `./appsettings.json`

生产环境建议始终显式指定。

## 运行时整形

### `--rt=[yes|no]`

进程级 real-time 偏好。

### `--dns=<ip-list>`

覆盖本次运行的本地 DNS 列表。它会写入 `NetworkInterface::DnsAddresses`，不会替代 DNS rules 或 server 侧 DNS 逻辑。

### `--tun-flash=[yes|no]`

早期设置默认 flash/TOS 倾向。

### `--auto-restart=<seconds>`

进程级自动重启计时器，`0` 关闭。

### `--link-restart=<count>`

链接重连次数超过阈值后触发重启。

## 服务端输入

### `--block-quic=[yes|no]`

阻止当前运行中的 QUIC 相关行为。

### `--firewall-rules=<file>`

防火墙规则文件。帮助输出默认值为 `./firewall-rules.txt`。

## 客户端输入

### `--lwip=[yes|no]`

选择客户端使用的网络栈行为。

### `--vbgp=[yes|no]`

启用 vBGP 路由更新。刷新节奏由配置文件里的 `vbgp.update-interval` 控制。

### `--nic=<interface>`

物理网卡提示。

### `--ngw=<ip>`

网关提示。

### `--tun=<name>`

虚拟网卡名称。

### `--tun-ip=<ip>` / `--tun-ipv6=<ip>` / `--tun-gw=<ip>` / `--tun-mask=<bits>`

虚拟网卡地址输入。

### `--tun-vnet=[yes|no]`

控制 subnet 转发行为。

### `--tun-host=[yes|no]`

控制是否偏向 host 网络。默认 `yes`。

### `--tun-static=[yes|no]`

启用静态隧道模式。

### `--tun-mux=<connections>`

MUX 连接数，`0` 表示关闭。

### `--tun-mux-acceleration=<mode>`

MUX 加速模式。

### `--tun-promisc=[yes|no]`

混杂模式开关，仅在 Linux 和 macOS 上使用。

### `--tun-ssmt=<threads>` 或 `--tun-ssmt=<N>[/<mode>]`

SSMT 调优。Linux 上 `mq` 表示每个 worker 打开一个 tun 队列；macOS 只文档化线程数形式。

### `--tun-route=[yes|no]`

Linux 路由兼容开关。

### `--tun-protect=[yes|no]`

Linux 路由保护开关。

### `--tun-lease-time-in-seconds=<sec>`

Windows DHCP 租约时间。

## 路由输入

### `--bypass=<file1|file2>`

旁路 IP 列表文件。默认 `./ip.txt`。

### `--bypass-nic=<interface>`

Linux 上用于旁路列表处理的接口。

### `--bypass-ngw=<ip>`

旁路列表的网关提示。

### `--virr=[file/country]`

启用 IP-list 刷新行为。刷新节奏由配置文件里的 `virr.update-interval` 和 `virr.retry-interval` 控制。

### `--dns-rules=<file>`

DNS 规则文件。默认 `./dns-rules.txt`。

## 平台 helper

### 仅 Windows

- `--system-network-reset`
- `--system-network-optimization`
- `--system-network-preferred-ipv4`
- `--system-network-preferred-ipv6`
- `--no-lsp <program>`

这些是 helper action，不是 tunnel 启动参数。

## 工具命令

### `--help`

显示帮助。

### `--pull-iplist [file/country]`

下载 IP list，完成后退出。

## Console UI 命令与布局

运行期 Console UI 是独立交互界面，不等同于启动参数 CLI。

锚点：

- `ppp/app/ConsoleUI.cpp::ExecuteCommand(...)`
- `ppp/app/ConsoleUI.cpp::RenderFrame(...)`
- `ppp/app/ConsoleUI.cpp::BuildStatusBarText(...)`

### 支持命令

- `help`：打印可用命令。
- `restart`：请求进程级重启（`ShutdownApplication(true)`）。
- `exit`：请求进程退出（`ShutdownApplication(false)`）。
- `clear`：清空日志缓冲并重置滚动偏移。
- `status`：打印与底部状态栏一致的文本。

滚动与编辑器导航由交互键盘输入驱动。

### 布局契约

每帧渲染由以下区域组成：

1. 可滚动日志区
2. 固定命令编辑行（`cmd> ...`）
3. 固定状态栏行

渲染与输入均为非阻塞，并在专用 UI 线程中执行；主运行时 I/O 线程不会被控制台刷新或按键处理阻塞。

### 键盘控制

- `Up` / `Down`：命令历史导航。
- `Left` / `Right`：编辑器内移动光标。
- `Home` / `End`：光标跳到行首/行尾。
- `Backspace` / `Delete`：删除光标前/当前位置字符。
- `PageUp` / `PageDown`：日志区按页滚动。
- `Ctrl+Up` / `Ctrl+Down`：日志区按行滚动。

Windows 与非 Windows 构建都支持主动编辑输入以及历史/滚动控制。

### 状态栏语义

状态栏文本由三部分拼接：

- `vpn:<state>`
- 可选 `note:<最新状态队列文本>`
- `err:<FormatErrorString(snapshot)>`
- 基于 `GetLastErrorTimestamp()` 差值的 `err_age:<seconds>s`
- `diag_ts:<诊断原始时间戳>`

状态栏读取进程级诊断快照，目标是在不中断数据面线程的情况下给出最近一次失败上下文。

## 记住这些默认值

- `--mode` 默认 `server`
- `--dns` 解析失败时回退到首选 DNS 组合
- `--bypass` 默认 `./ip.txt`
- `--dns-rules` 默认 `./dns-rules.txt`
- `--firewall-rules` 默认 `./firewall-rules.txt`

## 相关文档

- `CONFIGURATION_CN.md`
- `TRANSMISSION_CN.md`
- `ARCHITECTURE_CN.md`
- `ERROR_HANDLING_API_CN.md`
