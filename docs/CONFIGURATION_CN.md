# 配置模型

[English Version](CONFIGURATION.md)

## 定位

本文是 `AppConfiguration` 以及启动期整形逻辑的总说明。OPENPPP2 不把配置当成普通 JSON。它按四步处理：

1. `Clear()` 建立安全默认值
2. `Load(...)` 合并 JSON
3. `Loaded()` 修正、裁剪、清理、派生运行值
4. `main.cpp` 用 CLI 做本次启动的本机覆盖

锚点：

- `ppp/configurations/AppConfiguration.h`
- `ppp/configurations/AppConfiguration.cpp`
- `main.cpp::LoadConfiguration(...)`
- `main.cpp::GetNetworkInterface(...)`
- `main.cpp::PreparedArgumentEnvironment(...)`

## 核心结论

缺失字段通常不是“没有行为”，而是回退到默认值。无效字段通常会被规范化，而不是原样放行。某些字段在对应子系统关闭时会被清空。

## 配置结构

`AppConfiguration` 主要由这些块组成：

- `concurrent`
- `cdn`
- `ip`
- `udp`
- `tcp`
- `mux`
- `websocket`
- `key`
- `vmem`
- `server`
- `client`

## `Clear()` 的默认值

`Clear()` 里的关键默认值包括：

- `concurrent = Thread::GetProcessorCount()`
- `cdn[*] = IPEndPoint::MinPort`
- UDP DNS timeout / TTL / cache / redirect 默认值
- TCP 和 MUX timeout 默认值
- WebSocket 监听默认关闭
- key 字段默认值，如 `kf`、`kh`、`kl`、`kx`、`sb`
- `server.subnet = true`
- `server.mapping = true`
- server IPv6 默认关闭
- client GUID 哨兵值
- client 带宽默认 `0`
- Windows 上 `paper_airplane.tcp = true`

## `Loaded()` 的规范化规则

`Loaded()` 才是真正的整形层。重要规则有：

- `concurrent < 1` 回退为 CPU 核数
- `server.node` 不能小于 `0`
- `server.ipv6.prefix_length` 会被限制在合法范围
- 非正 timeout 会回退到默认值
- 非法端口会变成 `IPEndPoint::MinPort`
- 负数 keepalive 会变成 `0`
- 字符串字段会先去空白
- 空 GUID 会回退为哨兵值
- 无效 IP 会被清空
- 不支持的 key protocol / transport 会回退默认值
- WebSocket 条件不满足时会直接关掉监听
- `vmem` 的路径或大小不合法时会整体清空
- `server.ipv6.static_addresses` 会被过滤成合法、唯一、同前缀的 IPv6 地址

## IPv6

IPv6 服务不是单纯开关。它会校验 mode、CIDR、prefix length、gateway 和静态地址。

如果平台不支持服务端 IPv6 数据面，相关配置会被禁用并清空。如果前缀不合法，IPv6 服务也会被关闭。

## WebSocket

WebSocket 依赖合法的 host 和 path。条件不满足时，`ws` 和 `wss` 会一起关闭。若 `wss` 关闭，证书字段也会被清空，避免保留无效 TLS 状态。

## client.mappings

`client.mappings` 不是直接照单全收。它会先验证端点、IP、端口和地址类型，再重建成最终列表。它可以接受单个对象或数组形式。

## CLI 和 JSON 的分工

JSON 负责持久节点形态。CLI 负责本次启动的宿主机细节。例如：

- `--mode` 决定 client 还是 server
- `--dns` 写入本次运行的 DNS 输入
- `--nic`、`--ngw`、`--tun-*`、`--bypass*`、`--dns-rules` 影响当前宿主机环境

## 实际建议

持久配置放 JSON，宿主机差异放 CLI。不要指望 CLI 替代整个配置模型。

## 相关文档

- `README_CN.md`
- `CLI_REFERENCE_CN.md`
- `TRANSMISSION_CN.md`
- `ARCHITECTURE_CN.md`
