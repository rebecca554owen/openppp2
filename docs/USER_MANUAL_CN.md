# 用户手册

[English Version](USER_MANUAL.md)

## 定位

本文是面向使用者的 OPENPPP2 运行手册。

## OPENPPP2 是什么

OPENPPP2 是一个单二进制、多角色、跨平台的虚拟网络运行时。它能以 client 或 server 运行，并可叠加路由、DNS steering、反向映射、静态数据路径、MUX、平台集成以及可选管理后端。

## 先决定什么

在写配置和运行命令之前，先决定：

- 节点角色
- 部署形态
- 宿主平台
- 这是全隧道、分流、代理边缘、服务发布边缘，还是 IPv6 服务边缘

## 基本运行模型

- `server` 是默认角色
- 用 `--mode=client` 进入 client
- 使用显式配置路径
- 用管理员/root 权限运行

## 宿主会被改什么

根据平台和角色，OPENPPP2 可能修改：

- 虚拟网卡
- 路由
- DNS 行为
- 代理行为
- IPv6 行为
- 防火墙或 socket protect 设置

## 推荐阅读顺序

1. `ARCHITECTURE_CN.md`
2. `STARTUP_AND_LIFECYCLE_CN.md`
3. `CONFIGURATION_CN.md`
4. `CLI_REFERENCE_CN.md`
5. `PLATFORMS_CN.md`
6. `DEPLOYMENT_CN.md`
7. `OPERATIONS_CN.md`

## 快速开始

### 服务端快速开始

| 步骤 | 操作 | 示例 |
|------|------|------|
| 1 | 获取发布包 | `openppp2-linux-amd64-simd.zip` |
| 2 | 解压并进入目录 | `mkdir -p openppp2 && cd openppp2` |
| 3 | 编辑服务端配置 | 按需设置 `server.backend` |
| 4 | 启动运行时 | `./ppp` |

### 客户端快速开始

| 步骤 | 操作 | 示例 |
|------|------|------|
| 1 | 创建安装目录 | `C:\openppp2` |
| 2 | 解压发布包 | `openppp2-windows-amd64.zip` |
| 3 | 编辑客户端配置 | 设置 `client.guid`、`client.server` 等字段 |
| 4 | 以管理员启动 | `ppp --mode=client` |

## DNS Rules List

| 项目 | 说明 | 链接 |
|------|------|------|
| 主 DNS rules list | 定期更新的中国大陆域名直连规则 | [github.com/liulilittle/dns-rules.txt](https://github.com/liulilittle/dns-rules.txt) |

## HTTPS Certificate Configuration

| 项目 | 说明 | 位置 / 链接 |
|------|------|-------------|
| 运行时根证书 | 将 `cacert.pem` 放入运行目录 | `cacert.pem` |
| 镜像仓库 | 证书备用来源 | [github.com/liulilittle/cacert.pem](https://github.com/liulilittle/cacert.pem) |
| CURL CA bundle | 官方 CA 提取页 | [curl.se/docs/caextract.html](https://curl.se/docs/caextract.html) |

## 配置参考重点

| 参数 | 类型 | 示例值 | 说明 | 适用范围 |
|------|------|--------|------|----------|
| `client.server` | string | `ppp://192.168.0.24:20000/` | 服务端连接地址 | `client` |
| `client.server-proxy` | string | `http://user:pass@192.168.0.18:8080/` | 连接服务端时使用的代理 | `client` |
| `client.bandwidth` | int | `10000` | 带宽限制，Kbp/s | `client` |
| `server.backend` | string | `ws://192.168.0.24/ppp/webhook` | 可选管理后端 | `server` |
| `virr.update-interval` | int | `86400` | IP-list 刷新间隔，秒 | `client` |
| `vbgp.update-interval` | int | `3600` | vBGP 刷新间隔，秒 | `client` |

## 附录 1：UDP Static Aggligator

| 参数 | 类型 | 示例值 | 说明 | 适用范围 |
|------|------|--------|------|----------|
| `udp.static.aggligator` | int | `4` | 聚合链路数 | `client` |
| `udp.static.servers` | array[string] | `1.0.0.1:20000` | 聚合或转发服务器列表 | `client` |

### 行为

| 条件 | 含义 |
|------|------|
| `udp.static.aggligator > 0` | 启用聚合器模式，必须配置 `servers` |
| `udp.static.aggligator <= 0` | 启用静态隧道模式 |

### 示例

```json
"udp": {
  "static": {
    "aggligator": 2,
    "servers": ["192.168.1.100:6000", "10.0.0.2:6000"]
  }
}
```

## 附录 2：Linux 路由转发

### 开启 IPv4 和 IPv6 转发

```conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
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

## 附录 3：Windows 软路由转发

### 示例工具

| 项目 | 示例 |
|------|------|
| 虚拟网关工具 | `VGW` |
| 下载地址 | [github.com/liulilittle/vgw-release](https://github.com/liulilittle/vgw-release) |

### 示例参数

| 参数 | 类型 | 示例值 | 说明 |
|------|------|--------|------|
| `--ip` | string | `192.168.0.40` | 虚拟网关 IP |
| `--ngw` | string | `192.168.0.1` | 主路由网关 |
| `--mask` | string | `255.255.255.0` | 子网掩码 |
| `--mac` | string | `30:fc:68:88:b4:a9` | 自定义虚拟 MAC |

