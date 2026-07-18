# OPENPPP2 远程订阅格式
> Status: Active
> Type: Guide
> Last verified: 63fc030

> **用途：**说明本主题的当前行为、配置或实现边界。
> **适用对象：**OPENPPP2 用户、运维人员与开发者。
> **当前状态：**当前有效。
> **最后核对依据：**当前仓库结构、实现路径与文档链接，2026-07-18。
> **上一层索引：**[返回索引](README_CN.md)


本文定义 iOS 和 Android 客户端用于远程拉取节点的订阅格式。订阅端点必须返回 UTF-8 JSON，建议使用 HTTPS。

## HTTP 约定

- 请求方法：`GET`
- 推荐响应头：`Content-Type: application/json; charset=utf-8`
- 客户端可发送：
  - `Accept: application/json`
  - `User-Agent: OpenPPP2/<platform>`
- 服务端可发送：
  - `ETag`：后续可用于增量刷新
  - `Cache-Control`：控制客户端缓存
- 响应体最大建议 2 MB。客户端应拒绝过大的订阅。

## 顶层结构

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "name": "Example Nodes",
  "profilePrefix": "Example",
  "updatedAt": "2026-06-30T12:00:00Z",
  "nodes": []
}
```

字段说明：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `type` | string | 是 | 固定为 `openppp2-subscription` |
| `version` | number | 是 | 当前为 `1` |
| `name` | string | 否 | 订阅名称 |
| `profilePrefix` | string | 否 | 导入 profile 名称前缀 |
| `updatedAt` | string | 否 | ISO-8601 更新时间 |
| `nodes` | array | 是 | 节点列表 |

## 节点结构

节点支持两种形式：

1. 完整配置：`config` 直接包含 OPENPPP2 客户端 `appsettings.json` 对象。
2. 精简配置：使用 `server`、`key`、`websocket` 等字段覆盖客户端默认模板。

```json
{
  "id": "hk-01",
  "name": "Hong Kong 01",
  "subtitle": "HK / BGP",
  "flag": "HK",
  "enabled": true,
  "server": "ppp://hk.example.com:20000/",
  "bandwidth": 0,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "protocol-secret",
    "transport": "aes-256-cfb",
    "transport-key": "transport-secret",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "websocket": {
    "host": "",
    "path": "/",
    "verify-peer": true
  },
  "client": {
    "guid": "{F4569420-4E49-4CBA-9C36-94E722C8E363}",
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  },
  "options": {
    "tunIp": "10.0.0.2",
    "tunMask": "255.255.255.0",
    "tunPrefix": 24,
    "gateway": "10.0.0.1",
    "route": "0.0.0.0",
    "routePrefix": 0,
    "dns1": "8.8.8.8",
    "dns2": "1.1.1.1",
    "mtu": 1400,
    "mux": 0,
    "vnet": false,
    "blockQuic": true,
    "staticMode": false,
    "allowLan": true
  }
}
```

字段说明：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 是 | 节点稳定 ID。客户端用它识别更新同一节点 |
| `name` | string | 是 | 导入后的 profile 名称 |
| `subtitle` | string | 否 | 列表副标题 |
| `flag` | string | 否 | 短文本图标；移动端不要求 emoji |
| `enabled` | bool | 否 | `false` 时客户端跳过该节点 |
| `server` | string | 精简必填 | OPENPPP2 服务端 URI |
| `bandwidth` | number | 否 | 写入 `client.bandwidth` |
| `key` | object | 精简必填 | 写入 `appsettings.key` |
| `websocket` | object | 否 | 写入 `appsettings.websocket` |
| `client` | object | 否 | 合并到 `appsettings.client` |
| `options` | object | 否 | 移动端启动参数 |
| `config` | object/string | 完整配置必填 | 完整 `appsettings.json` 对象或 JSON 字符串 |

## server URI

`server` 写入 `client.server`，支持：

| URI | 传输 |
| --- | --- |
| `ppp://host:port/` | TCP |
| `ppp://ws/host:port/` | WebSocket |
| `ppp://wss/host:port/` | TLS WebSocket |

IPv6 地址必须使用中括号：`ppp://[2001:db8::1]:20000/`。

## 完整示例

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "name": "OPENPPP2 Demo",
  "profilePrefix": "Demo",
  "updatedAt": "2026-06-30T12:00:00Z",
  "nodes": [
    {
      "id": "demo-hk-01",
      "name": "Hong Kong 01",
      "subtitle": "hk.example.com:20000",
      "flag": "HK",
      "server": "ppp://hk.example.com:20000/",
      "key": {
        "kf": 154543927,
        "kx": 128,
        "kl": 10,
        "kh": 12,
        "protocol": "aes-128-cfb",
        "protocol-key": "N6HMzdUs7IUnYHwq",
        "transport": "aes-256-cfb",
        "transport-key": "HWFweXu2g5RVMEpy",
        "masked": false,
        "plaintext": false,
        "delta-encode": false,
        "shuffle-data": false
      }
    },
    {
      "id": "demo-wss-01",
      "name": "WSS 01",
      "server": "ppp://wss/wss.example.com:443/",
      "key": {
        "protocol": "aes-128-cfb",
        "protocol-key": "protocol-secret",
        "transport": "aes-256-cfb",
        "transport-key": "transport-secret"
      },
      "websocket": {
        "host": "wss.example.com",
        "path": "/openppp2",
        "verify-peer": true
      }
    }
  ]
}
```

## 客户端导入规则

- `id` 相同的订阅节点会更新已导入 profile，不重复新增。
- 导入来源记录在 profile 内部元数据，不影响 native `appsettings.json`。
- `enabled: false` 的节点不导入；已经导入的旧节点不会自动删除。
- `config` 优先级最高；没有 `config` 时使用默认客户端配置模板并合并节点字段。
- 客户端只接受 `http` 和 `https` 订阅 URL；生产环境建议只发布 HTTPS。
