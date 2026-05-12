# 用户手册

[English Version](USER_MANUAL.md)

## 定位

本文是面向使用者的 OPENPPP2 运行手册，涵盖 OPENPPP2 是什么、如何运行、如何为常见场景配置，以及预期宿主变化。

---

## OPENPPP2 是什么

OPENPPP2 是一个单二进制、多角色、跨平台的虚拟网络运行时。它能以 client 或 server 运行，并可叠加路由、DNS steering、反向映射、静态数据路径、MUX、平台集成以及可选管理后端。

```mermaid
flowchart TD
    A[OPENPPP2] --> B[客户端模式]
    A --> C[服务端模式]
    B --> D[虚拟 NIC + 隧道]
    B --> E[分流或全隧道路由]
    B --> F[DNS steering]
    B --> G[MUX / Static UDP]
    C --> H[会话路由]
    C --> I[TCP + UDP 转发]
    C --> J[IPv6 transit]
    C --> K[可选 Go backend]
```

---

## 先决定什么

在写配置和运行命令之前，先决定：

| 决策 | 选项 |
|------|------|
| 节点角色 | `client` 或 `server` |
| 部署形态 | 单节点、多服务端、managed |
| 宿主平台 | Linux、Windows、macOS、Android |
| 隧道模式 | 全隧道、分流、代理边缘、服务发布边缘、IPv6 服务边缘 |

---

## 基本运行模型

| 场景 | 命令 |
|------|------|
| 以服务端启动（默认） | `./ppp` |
| 以服务端启动并指定配置 | `./ppp --config=/etc/openppp2/appsettings.json` |
| 以客户端启动 | `./ppp --mode=client` |
| 以客户端启动并指定配置 | `./ppp --mode=client --config=./appsettings.json` |

要求：
- Windows 上需要管理员权限；Linux/macOS/Android 上需要 root。
- 配置文件在可访问的路径上。

---

## 宿主会被改什么

根据平台和角色，OPENPPP2 可能修改：

| 宿主元素 | 客户端 | 服务端 |
|---------|--------|--------|
| 虚拟 NIC | 会创建 | 不创建 |
| OS 路由表 | 会修改（添加/保护路由） | 不修改 |
| DNS 配置 | 可能覆写 | 不修改 |
| 系统 HTTP 代理 | 可能设置 | 不设置 |
| IPv6 设置 | 如果启用 IPv6 | 如果启用 `server.ipv6` |
| 防火墙规则 | 不修改 | 可能设置规则 |

---

## 推荐阅读顺序

1. [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md) — 系统整体设计
2. [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md) — 进程如何启动和停止
3. [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md) — 配置文件参考
4. [`CLI_REFERENCE_CN.md`](CLI_REFERENCE_CN.md) — 命令行参数
5. [`PLATFORMS_CN.md`](PLATFORMS_CN.md) — 平台特定说明
6. [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md) — 部署检查清单
7. [`OPERATIONS_CN.md`](OPERATIONS_CN.md) — 故障排查

---

## 快速开始

### 服务端快速开始

| 步骤 | 操作 | 示例 |
|------|------|------|
| 1 | 获取发布包 | `openppp2-linux-amd64-simd.zip` |
| 2 | 解压并进入目录 | `mkdir -p openppp2 && cd openppp2` |
| 3 | 编辑服务端配置 | 设置 `tcp.listen.port`、`key.*` 字段 |
| 4 | 启动运行时 | `sudo ./ppp` |

最简服务端配置：

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "tcp": {
    "listen": { "port": 20000 }
  },
  "server": {
    "node": 1,
    "subnet": true
  }
}
```

### 客户端快速开始

| 步骤 | 操作 | 示例 |
|------|------|------|
| 1 | 创建安装目录 | `mkdir -p /opt/openppp2` |
| 2 | 解压发布包 | `unzip openppp2-linux-amd64.zip -d /opt/openppp2` |
| 3 | 编辑客户端配置 | 设置 `client.guid`、`client.server`、`key.*`（需与服务端匹配） |
| 4 | 以 root 启动 | `sudo ./ppp --mode=client` |

最简客户端配置：

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "client": {
    "guid": "{F4519CF1-7A8A-4B00-89C8-9172A87B96DB}",
    "server": "ppp://192.168.0.1:20000/"
  }
}
```

---

## 隧道模式选择

```mermaid
flowchart TD
    A[选择隧道模式] --> B{所有流量走隧道？}
    B -->|是| C[全隧道模式]
    B -->|否| D{基于域名的 steering？}
    D -->|是| E[分流 + DNS 规则]
    D -->|否| F[按 IP-list 分流]
    C --> G[设置默认路由走隧道]
    E --> H[配置 dns-rules 文件]
    F --> I[配置 bypass IP 列表]
```

| 模式 | 说明 | 关键配置 |
|------|------|---------|
| 全隧道 | 所有流量走隧道 | 无 bypass 列表时的默认行为 |
| 分流 | 特定 IP 绕过隧道 | `client.bypass` IP 列表 |
| DNS steering | 基于域名的 resolver 选择 | `client.dns-rules` |
| 服务发布 | 服务端通过 FRP 发布本地服务 | `server.mappings` |
| IPv6 服务 | 服务端提供 IPv6 transit | `server.ipv6` |

---

## 配置参考重点

### 核心字段

| 参数 | 类型 | 示例 | 说明 | 适用范围 |
|------|------|------|------|---------|
| `concurrent` | int | `4` | IO 线程并发数 | 两者 |
| `key.kf` | int | `154543927` | 协议密钥因子 | 两者 |
| `key.protocol` | string | `"aes-128-cfb"` | 加密算法 | 两者 |
| `key.transport` | string | `"aes-256-cfb"` | 传输加密算法 | 两者 |

### 客户端字段

| 参数 | 类型 | 示例 | 说明 |
|------|------|------|------|
| `client.guid` | string | `"{F4519CF1-...}"` | 客户端唯一标识符 |
| `client.server` | string | `"ppp://192.168.0.1:20000/"` | 服务端连接地址 |
| `client.server-proxy` | string | `"http://user:pass@proxy:8080/"` | 连接服务端的代理 |
| `client.bandwidth` | int | `10000` | 带宽限制，Kbp/s |
| `client.bypass` | array | `["/etc/bypass.txt"]` | IP bypass 列表来源 |
| `client.dns-rules` | array | `["rules:///etc/dns.txt"]` | DNS 规则来源 |

### 服务端字段

| 参数 | 类型 | 示例 | 说明 |
|------|------|------|------|
| `server.node` | int | `1` | 服务端节点 ID |
| `tcp.listen.port` | int | `20000` | TCP 隧道监听端口 |
| `websocket.listen.ws` | int | `20080` | WebSocket 监听端口（0 = 禁用） |
| `websocket.listen.wss` | int | `20443` | TLS WebSocket 监听端口（0 = 禁用） |
| `server.backend` | string | `"ws://backend:80/ppp/webhook"` | 可选管理后端 |
| `server.ipv4-pool.network` | string | `"10.0.0.0"` | IPv4 地址池（客户端分配用） |
| `server.ipv4-pool.mask` | string | `"255.255.255.0"` | IPv4 地址池子网掩码 |

---

## DNS Rules List

| 项目 | 说明 | 链接 |
|------|------|------|
| 主 DNS rules list | 定期更新的中国大陆域名直连规则 | [github.com/liulilittle/dns-rules.txt](https://github.com/liulilittle/dns-rules.txt) |

DNS 规则文件格式：

```
# 将这些域名路由到本地 DNS
.example.com 192.168.1.1
.localnet.com 192.168.1.1

# 将这些路由到特定上游
.google.com 8.8.8.8
.cloudflare.com 1.1.1.1
```

---

## HTTPS Certificate Configuration

| 项目 | 说明 | 位置 |
|------|------|------|
| 运行时根证书 | 将 `cacert.pem` 放入运行目录 | `ppp` 旁边的 `cacert.pem` |
| 镜像仓库 | 证书备用来源 | [github.com/liulilittle/cacert.pem](https://github.com/liulilittle/cacert.pem) |
| CURL CA bundle | 官方 CA 提取页 | [curl.se/docs/caextract.html](https://curl.se/docs/caextract.html) |

---

## 常见场景

### 场景 1：Linux 全隧道客户端

```bash
# 1. 安装
mkdir -p /opt/openppp2
cd /opt/openppp2
unzip openppp2-linux-amd64-simd.zip

# 2. 编辑 appsettings.json — 设置 client.server 和 key 字段

# 3. 运行
sudo ./ppp --mode=client
```

预期效果：所有流量经服务端转发。

### 场景 2：带中国大陆分流的客户端

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://server-ip:20000/",
    "bypass": [
      "https://raw.githubusercontent.com/liulilittle/china-list/main/cidr.txt"
    ]
  }
}
```

预期效果：中国大陆 IP 直连，其余流量走隧道。

### 场景 3：带管理 Backend 的服务端

```json
{
  "tcp": {
    "listen": { "port": 20000 }
  },
  "server": {
    "node": 1,
    "subnet": true,
    "backend": "ws://192.168.0.100/ppp/webhook"
  }
}
```

预期效果：客户端会话由 Go backend 认证并计费。

### 场景 4：Nginx 反向代理的 WebSocket 服务端

```json
{
  "websocket": {
    "host": "your-domain.com",
    "path": "/tun",
    "listen": {
      "ws": 8080
    }
  }
}
```

然后配置 Nginx 将 WebSocket 代理到 8080 端口。

客户端连接字符串：

```
ppp://ws/192.168.0.1:443/
```

---

## 连接 URL 格式

| 格式 | 协议 | 示例 |
|------|------|------|
| `ppp://host:port/` | 原始 TCP | `ppp://1.2.3.4:20000/` |
| `ppp://ws/host:port/` | WebSocket | `ppp://ws/1.2.3.4:443/` |
| `ppp://wss/host:port/` | TLS WebSocket | `ppp://wss/1.2.3.4:443/` |

---

## 附录 1：UDP Static Aggligator

| 参数 | 类型 | 示例值 | 说明 | 适用范围 |
|------|------|--------|------|---------|
| `udp.static.aggligator` | int | `4` | 聚合链路数 | `client` |
| `udp.static.servers` | array | `["1.0.0.1:20000"]` | 聚合或转发服务器列表 | `client` |

| 条件 | 含义 |
|------|------|
| `udp.static.aggligator > 0` | 启用聚合器模式，必须配置 `servers` |
| `udp.static.aggligator <= 0` | 启用静态隧道模式 |

```json
"udp": {
  "static": {
    "aggligator": 2,
    "servers": ["192.168.1.100:6000", "10.0.0.2:6000"]
  }
}
```

---

## 附录 2：Linux 路由转发

### 开启 IPv4 和 IPv6 转发

向 `/etc/sysctl.conf` 添加：

```conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
```

应用：

```bash
sysctl -p
```

### 双网卡路由示例

```bash
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j MASQUERADE
```

### Bypass SNAT 示例

```bash
iptables -A FORWARD -s 192.168.0.0/24 -d 0.0.0.0/0 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -d 192.168.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j SNAT --to 192.168.0.20
```

---

## 附录 3：Windows 软路由转发

| 项目 | 示例 |
|------|------|
| 虚拟网关工具 | VGW |
| 下载地址 | [github.com/liulilittle/vgw-release](https://github.com/liulilittle/vgw-release) |

VGW 示例参数：

| 参数 | 类型 | 示例值 | 说明 |
|------|------|--------|------|
| `--ip` | string | `192.168.0.40` | 虚拟网关 IP |
| `--ngw` | string | `192.168.0.1` | 主路由网关 |
| `--mask` | string | `255.255.255.0` | 子网掩码 |
| `--mac` | string | `30:fc:68:88:b4:a9` | 自定义虚拟 MAC |

---

## 附录 4：Android 部署

Android 部署使用 VPNService API。OPENPPP2 以原生库形式嵌入：

```mermaid
flowchart TD
    A[Android App] --> B[VPNService]
    B --> C[JNI 桥接]
    C --> D[OPENPPP2 C++ 运行时]
    D --> E[连接到服务端的隧道]
```

关键点：
- 需要在 `AndroidManifest.xml` 中声明 `BIND_VPN_SERVICE` 和 `INTERNET` 权限。
- JNI 函数：`run(config_json)`、`stop()`、`release()`。
- 不需要 root；使用 Android VPNService 框架。
- 错误码以整数返回，映射到 `ppp::diagnostics::ErrorCode`。

---

## 附录 5：IPv6 Transit（服务端）

在服务端启用 IPv6 transit：

```json
{
  "server": {
    "ipv6": {
      "cidr": "fdec:1234::/64"
    }
  }
}
```

这允许客户端获得 IPv6 地址，并通过服务端访问 IPv6 目标。

详见 [`IPV6_TRANSIT_PLANE_CN.md`](IPV6_TRANSIT_PLANE_CN.md)。

---

## 附录 6：FRP 反向映射（服务发布）

通过服务端发布本地服务：

```json
{
  "server": {
    "mappings": [
      {
        "local-ip": "127.0.0.1",
        "local-port": 22,
        "remote-port": 10022,
        "protocol": "tcp"
      }
    ]
  }
}
```

这会将 `localhost:22` 发布为服务端的 `server-ip:10022`。

---

## 故障排查速查

| 症状 | 最可能原因 | 解决方式 |
|------|---------|---------|
| 进程立即退出 | 权限缺失 | 以 root/管理员运行 |
| "configuration not found" | 配置路径错误 | 使用 `--config=/绝对路径` |
| 无法连接服务端 | 网络或防火墙 | 先用 `nc` 或 `telnet` 测试 |
| 隧道内 DNS 不工作 | DNS 路由缺失 | 检查 bypass 列表是否覆盖 DNS 服务器 |
| 会话频繁断开 | 保活失败 | 检查 `keepalive.*` 配置值 |
| 退出后路由未恢复 | 强制杀进程 | 使用 SIGTERM 优雅关闭 |

---

## 相关文档

- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
- [`CLI_REFERENCE_CN.md`](CLI_REFERENCE_CN.md)
- [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
- [`OPERATIONS_CN.md`](OPERATIONS_CN.md)
- [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
- [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md)
- [`SECURITY_CN.md`](SECURITY_CN.md)
- [`MANAGEMENT_BACKEND_CN.md`](MANAGEMENT_BACKEND_CN.md)
