# 系统架构

[English Version](ARCHITECTURE.md)

## 文档范围

本文档是 OPENPPP2 的顶层架构地图，旨在为读者提供一个全面的系统架构视图。它之所以放在 transport、client、server、routing、platform、deployment、operations 等深度技术文档之后，是因为它的任务与那些文档不同。本文不试图把每一个机制再详细重讲一遍，而是帮助读者理解：整个系统是如何分层的，主要子系统之间如何关联，哪些边界最重要，以及如何正确导航源码而不将其简单理解为“一个 VPN”。

OPENPPP2 定位为虚拟以太网基础设施产品，这与大多数终端 VPN 产品有本质区别。它不仅仅提供加密隧道，而是构建了一套完整的网络基础设施运行时，涵盖虚拟接口集成、隧道内控制与转发逻辑、路由与 DNS  steering、反向服务映射、可选 static packet 与 MUX 路径、平台特化宿主网络变更，以及可选外部管理后端。

## 核心源码结构

本文档主要基于以下代码结构进行描述：

```mermaid
graph TD
    subgraph "入口层"
        A[main.cpp]
    end
    
    subgraph "配置层"
        B[ppp/configurations/AppConfiguration.*]
    end
    
    subgraph "传输层"
        C[ppp/transmissions/*]
    end
    
    subgraph "协议层"
        D[ppp/app/protocol/*]
    end
    
    subgraph "客户端运行时"
        E[ppp/app/client/*]
    end
    
    subgraph "服务端运行时"
        F[ppp/app/server/*]
    end
    
    subgraph "平台层"
        G[windows/*]
        H[linux/*]
        I[darwin/*]
        J[android/*]
    end
    
    subgraph "管理后端"
        K[go/*]
    end
    
    A --> B
    A --> C
    A --> E
    A --> F
    B --> C
    C --> D
    E --> G
    E --> H
    E --> I
    E --> J
    F --> G
    F --> H
    F --> I
    F --> J
    F --> K
```

## 最短但尽量准确的描述

OPENPPP2 是一套跨平台网络运行时，围绕以下结构构建：

| 组件 | 说明 |
|------|------|
| **ppp 可执行程序** | C++ 主程序，提供 client 和 server 两种运行模式 |
| **共享核心** | protected transport 与 tunnel protocol core，包含协议处理、加密、帧化 |
| **客户端运行时** | 虚拟接口集成、路由控制、DNS  steering、代理服务 |
| **服务端运行时** | 连接接受、会话管理、转发与映射、策略消费 |
| **平台集成层** | Windows、Linux、macOS、Android 各自的宿主网络变更 |
| **管理后端** | 可选的 Go 语言实现的管理后台 |

从架构层面看，OPENPPP2 不能被简单描述为 VPN client、VPN server、proxy 或 custom transport 中的某一种。源码表明，它在不同层里同时包含了这些概念，是一个综合性的网络基础设施运行时。

## 最重要的架构分割

整个仓库里，最重要的架构分割是 **共享协议与运行时核心** 和 **平台集成层** 的分离。

### 共享核心（tunnel semantics）

共享核心拥有 tunnel semantics，负责网络协议的处理和转发，主要包括：

| 功能模块 | 说明 | 关键源码 |
|----------|------|----------|
| 配置规范化 | 将 JSON 配置和命令行参数规范化为运行时模型 | `AppConfiguration.*` |
| 握手与传输 | 建立受保护的传输连接，完成密钥交换 | `ITransmission.*` |
| 链路层动作 | 隧道内的控制信令与数据转发协议 | `VirtualEthernetLinklayer.*` |
| 客户端运行时 | 虚拟网卡管理、路由 DNS 控制、代理服务 | `VEthernetNetworkSwitcher.*` |
| 服务端运行时 | 连接接受、会话交换、转发映射 | `VirtualEthernetSwitcher.*` |
| static packet 与 MUX | UDP static 路径和多路复用逻辑 | `VirtualEthernetDatagramPort*`, `vmux*` |
| policy envelope | 管理后端策略下发与 IPv6 分配 | `VirtualEthernetInformation.*` |

### 平台层（host consequences）

平台层拥有 host consequences，负责与本地操作系统交互，主要包括：

| 功能模块 | 说明 | 关键源码 |
|----------|------|----------|
| 虚拟接口创建 | 创建或接入虚拟网卡 | `windows/tap.*`, `linux/tun.*` |
| 路由变更 | 修改系统路由表 | 各平台路由操作代码 |
| DNS 变更 | 修改系统 DNS 配置 | 各平台 DNS 操作代码 |
| socket 保护 | 避免流量递归进入隧道 | `protect` 与 `bypass` 逻辑 |
| IPv6 设置 | 平台特化 IPv6 接口配置 | 各平台 IPv6 代码 |

这个分割非常重要，它解释了为什么 OPENPPP2 一方面是跨平台的，另一方面在很多地方高度依赖平台实现。

```mermaid
flowchart TD
    subgraph 共享核心
        A[配置模块] --> B[握手与传输]
        B --> C[链路层协议]
        C --> D[客户端运行时]
        C --> E[服务端运行时]
        D --> F[static packet 与 MUX]
        E --> F
        F --> G[policy 与 IPv6]
    end
    
    subgraph 平台层
        H[虚拟接口] --> I[路由变更]
        I --> J[DNS 变更]
        J --> K[socket 保护]
        K --> L[IPv6 设置]
    end
    
    D --> H
    E --> H
```

## 运行时入口与生命周期

`main.cpp` 是整个 C++ 侧的架构根。系统没有把主要生命周期拆散到许多二进制或半独立启动器里，而是集中在一个统一入口完成顶层 orchestration。

### 启动流水线

在启动时，`main.cpp` 负责以下步骤：

```mermaid
flowchart TD
    A[程序入口] --> B[权限校验]
    B --> C[单实例检测]
    C --> D[加载配置]
    D --> E[规范化配置]
    E --> F[解析网络参数]
    F --> G[角色选择 client/server]
    G --> H{选择结果}
    H -->|client| I[创建客户端环境]
    H -->|server| J[创建服务端环境]
    I --> K[创建 Switcher]
    J --> K
    K --> L[启动 Tick 循环]
    L --> M[输出运行状态]
    M --> N[等待关闭信号]
    N --> O[清理资源]
```

### 主要运行时对象

OPENPPP2 的运行时对象按照生命周期和职责划分：

| 对象层级 | 负责内容 | 关键类型 |
|----------|----------|----------|
| 进程级 | 进程生命周期管理 | `PppApplication` |
| 环境级 | 虚拟网卡/监听器生命周期 | `*Switcher` |
| 会话级 | 远端连接生命周期 | `*Exchanger` |
| 连接级 | 传输连接生命周期 | `ITransmission` |

这种分层使得代码结构清晰，职责边界明确。

## 一个二进制、两个主角色、若干可选平面

C++ 主二进制有两个主角色：**client mode** 和 **server mode**。但每个角色本身都不是单一行为，而是多个 plane 的组合。

### 客户端平面

client 模式可能包含以下平面：

| 平面 | 说明 | 启用条件 |
|------|------|----------|
| adapter 与 host integration | 虚拟网卡创建与管理 | 默认启用 |
| exchanger 与远端 session | 与服务端的连接与会话 | 默认启用 |
| route 与 DNS steering | 路由控制和 DNS 策略 | 默认启用 |
| 本地 proxy surface | HTTP/SOCKS 代理服务 | 配置启用 |
| static 与 MUX optional plane | UDP static 路径或多路复用 | 配置启用 |
| managed IPv6 apply | 接收并应用服务端 IPv6 配置 | 配置启用 |
| reverse mapping 注册 | 向服务端注册反向映射 | 配置启用 |

### 服务端平面

server 模式可能包含以下平面：

| 平面 | 说明 | 启用条件 |
|------|------|----------|
| acceptor 与 handshake | 接受并处理客户端连接 | 默认启用 |
| session switch | 会话管理与交换 | 默认启用 |
| forwarding 与 mapping | 数据转发与端口映射 | 默认启用 |
| static datagram surface | UDP static 路径服务 | 配置启用 |
| firewall 与 namespace cache | 防火墙规则与命名空间缓存 | 配置启用 |
| managed backend integration | 管理后端连接 | 配置启用 |
| IPv6 transit optional plane | IPv6 转发与邻居代理 | 配置启用 |

```mermaid
flowchart TD
    A[ppp 可执行程序] --> B[client mode]
    A --> C[server mode]
    
    subgraph client
        B --> B1[adapter 与 host integration]
        B --> B2[exchanger 与远端 session]
        B --> B3[route 与 DNS steering]
        B --> B4[本地 proxy surface]
        B --> B5[static 与 MUX optional plane]
        B --> B6[managed IPv6 apply]
        B --> B7[reverse mapping 注册]
    end
    
    subgraph server
        C --> C1[acceptor 与 handshake]
        C --> C2[session switch]
        C --> C3[forwarding 与 mapping]
        C --> C4[static datagram surface]
        C --> C5[firewall 与 namespace cache]
        C --> C6[managed backend integration]
        C --> C7[IPv6 transit optional plane]
    end
```

## 配置对象作为架构组件

`AppConfiguration` 不仅仅是配置文件解析器，而是整个系统中非常核心的架构组件。它定义了：

- 整个 runtime 的配置词汇表
- runtime 在未指定时的默认行为
- 文本配置如何被规范化为可运行的 operational intent

这很重要，因为很多系统把配置文档当成附属内容。而在 OPENPPP2 中，配置本身就是架构的一部分。它不仅仅选择数值，也选择重大运行时行为：

| 配置项 | 影响的行为 |
|--------|------------|
| `server.listen.*` | 开哪些 listener |
| `server.backend` | 是否需要管理后端 |
| `ipv6.mode` | IPv6 模式：none、NAT66、GUA |
| `static.*` | 是否启用 static 模式 |
| `mux.*` | 是否启用多路复用 |
| `dns.*` | DNS 重定向与缓存 |
| `key.*` | 加密密钥与算法选择 |

## Protected Transmission 层与 Tunnel Action 层

整个仓库里，一个非常重要的概念边界是 **protected transmission** 和 **tunnel action protocol** 的分离。

### Protected Transmission 层

protected transmission 主要位于 `ppp/transmissions/`，关心：

| 功能 | 说明 |
|------|------|
| carrier transport 选择 | TCP、WebSocket、WSS 等 |
| handshake sequencing | 握手顺序和密钥交换 |
| 密钥派生 | 基于 `ivv` 的工作密钥重建 |
| 帧化与加密 | 数据的加密封装和解封装 |
| 读写流水线 | 异步 IO 操作 |

```mermaid
flowchart LR
    subgraph 客户端
        A[应用数据] --> B[加密/帧化]
        B --> C[TCP/WS/WSS]
    end
    
    subgraph 传输通道
        C -.->|加密隧道| D[网络传输]
    end
    
    subgraph 服务端
        D --> E[TCP/WS/WSS]
        E --> F[解密/解帧]
        F --> G[应用数据]
    end
```

### Tunnel Action 层

tunnel action protocol 主要位于 `ppp/app/protocol/VirtualEthernetLinklayer.*`，关心：

| 功能 | 说明 |
|------|------|
| 会话信息 | INFO 消息传递 |
| 保活 | KEEPALIVED 消息 |
| 虚拟子网转发 | LAN、NAT 消息 |
| UDP 中继 | SENDTO、ECHO 消息 |
| TCP 中继 | SYN、SYNOK、PSH、FIN 消息 |
| 反向映射 | MAPPING 消息 |
| static 路径协商 | STATIC 消息 |

这两种协议的分离使得 OPENPPP2 能够灵活支持多种传输载体，同时保持统一的隧道控制语义。

## 核心类型及其关系

### 客户端核心类型

| 类型 | 职责 | 关键文件 |
|------|------|----------|
| `VEthernetNetworkSwitcher` | 宿主机网络环境管理 | `VEthernetNetworkSwitcher.*` |
| `VEthernetExchanger` | 远端会话管理 | `VEthernetExchanger.*` |
| `VEthernetNetworkTcpipStack` | TCP/IP 协议栈 | `VEthernetNetworkTcpipStack.*` |
| `VEthernetNetworkTcpipConnection` | TCP 连接管理 | `VEthernetNetworkTcpipConnection.*` |
| `VEthernetDatagramPort` | UDP 数据报端口 | `VEthernetDatagramPort.*` |
| `VEthernetHttpProxySwitcher` | HTTP 代理 | `VEthernetHttpProxySwitcher.*` |
| `VEthernetSocksProxySwitcher` | SOCKS 代理 | `VEthernetSocksProxySwitcher.*` |

### 服务端核心类型

| 类型 | 职责 | 关键文件 |
|------|------|----------|
| `VirtualEthernetSwitcher` | 服务端环境管理 | `VirtualEthernetSwitcher.*` |
| `VirtualEthernetExchanger` | 会话交换管理 | `VirtualEthernetExchanger.*` |
| `VirtualEthernetNetworkTcpipConnection` | TCP 连接管理 | `VirtualEthernetNetworkTcpipConnection.*` |
| `VirtualEthernetManagedServer` | 管理服务端 | `VirtualEthernetManagedServer.*` |
| `VirtualEthernetDatagramPort` | UDP 端口管理 | `VirtualEthernetDatagramPort.*` |
| `VirtualEthernetDatagramPortStatic` | static UDP 端口 | `VirtualEthernetDatagramPortStatic.*` |
| `VirtualEthernetNamespaceCache` | 命名空间缓存 | `VirtualEthernetNamespaceCache.*` |
| `VirtualEthernetMappingPort` | 映射端口 | `VirtualEthernetMappingPort.*` |

```mermaid
classDiagram
    class VEthernetNetworkSwitcher {
        +管理虚拟网卡
        +控制路由/DNS
        +流量分类
    }
    
    class VEthernetExchanger {
        +建立远端连接
        +维护会话状态
        +处理重连
    }
    
    class VirtualEthernetSwitcher {
        +接受客户端连接
        +管理会话
        +转发数据
    }
    
    class VirtualEthernetExchanger {
        +处理单个会话
        +转发 TCP/UDP
        +维护连接状态
    }
    
    VEthernetNetworkSwitcher --> VEthernetExchanger
    VirtualEthernetSwitcher --> VirtualEthernetExchanger
```

## 连接协议与数据平面

OPENPPP2 支持多种连接协议，形成不同的数据平面：

### 原生 TCP 直连（ppp://）

| 特性 | 说明 |
|------|------|
| 协议前缀 | `ppp://` |
| 传输方式 | 原生 TCP 直连 |
| 适用场景 | 低延迟、高吞吐量直接连接 |
| 端口 | 默认 20000 |

### WebSocket 明文（ws://）

| 特性 | 说明 |
|------|------|
| 协议前缀 | `ws://` |
| 传输方式 | WebSocket 明文 |
| 适用场景 | CDN 转发、HTTP 代理环境 |
| 端口 | 默认 80 |

### WebSocket SSL（wss://）

| 特性 | 说明 |
|------|------|
| 协议前缀 | `wss://` |
| 传输方式 | SSL 加密 WebSocket |
| 适用场景 | CDN 转发、HTTPS 代理环境 |
| 端口 | 默认 443 |

```mermaid
flowchart LR
    subgraph 客户端
        A[应用数据]
    end
    
    A --> B{协议选择}
    B -->|ppp://| C[原生 TCP]
    B -->|ws://| D[WebSocket]
    B -->|wss://| E[WebSocket SSL]
    
    C --> F[服务端]
    D --> F
    E --> F
    
    F --> G[隧道处理]
    G --> H[虚拟网卡]
```

## 数据流向架构

### 客户端数据流向

```mermaid
flowchart TD
    subgraph 客户端主机
        A[本地应用] --> B[虚拟网卡 TUN/TAP]
        B --> C[VEthernetNetworkSwitcher]
        C --> D{流量分类}
        D -->|需要隧道| E[VEthernetExchanger]
        D -->|绕过隧道| F[物理网卡]
        E --> G[加密/传输]
        G --> H[网络]
    end
    
    subgraph 网络
        H --> I[服务端]
    end
    
    subgraph 服务端
        I --> J[解密/接收]
        J --> K[VirtualEthernetSwitcher]
        K --> L{转发决策}
        L -->|UDP| M[VirtualEthernetDatagramPort]
        L -->|TCP| N[VirtualEthernetTcpipConnection]
        L -->|映射| O[VirtualEthernetMappingPort]
    end
```

### 服务端数据流向

```mermaid
flowchart TD
    subgraph 客户端
        A[本地应用] --> B[虚拟网卡]
    end
    
    subgraph OPENPPP2 隧道
        B --> C[加密传输]
        C --> D[服务端]
    end
    
    subgraph 服务端
        D --> E[VirtualEthernetSwitcher]
        E --> F{数据类型}
        F -->|TCP 转发| G[外部 TCP 服务器]
        F -->|UDP 转发| H[外部 UDP 服务器]
        F -->|端口映射| I[映射端口]
        F -->|static UDP| J[Static Datagram Port]
    end
```

## 安全架构边界

OPENPPP2 的安全模型是多层组成的，需要明确信任边界：

### 信任边界

| 边界 | 位置 | 信任内容 |
|------|------|----------|
| 客户端主机 | 本地运行环境 | 操作系统、网络栈、路由配置 |
| 服务端主机 | 服务端运行环境 | 操作系统、网络栈、防火墙 |
| 传输网络 | 客户端与服务端之间 | 网络运营商、ISP、云服务商 |
| 管理后端 | 可选组件 | 策略下发、身份验证 |
| 配置文件 | 本地存储 | 密钥、证书、后端凭证 |

### 安全特性（不含 PFS 声明）

OPENPPP2 实现了连接级工作密钥派生的 **前向安全保证（Forward Security Assurance, FP）**，但需要明确：

- **不是 PFS**：系统没有实现传统意义上的 Perfect Forward Secrecy（PFS）
- **FP 机制**：每次会话使用动态派生的密钥，即使密钥被获取，也无法解密历史流量
- **密钥交换**：基于预共享密钥和会话特定的 `ivv` 参数派生工作密钥
- **密钥轮换**：会话期间可通过握手重新协商密钥

```mermaid
flowchart TD
    subgraph 安全层次
        A[预共享密钥] --> B[密钥派生函数]
        B --> C[ivv 参数]
        C --> D[工作密钥]
        D --> E[数据加密]
    end
    
    F[密钥派生] -.->|每次会话| G[新密钥]
    G --> E
    
    style F fill:#f9f,stroke:#333
    style G fill:#f9f,stroke:#333
```

## 平台差异化

OPENPPP2 在不同平台上存在实现差异，主要体现在：

### 虚拟网卡实现

| 平台 | 接口类型 | 驱动方式 |
|------|----------|----------|
| Windows | TAP | Windows TUN/TAP driver |
| Linux | TUN | tun/tap kernel module |
| macOS | utun | utun interface |
| Android | TUN | VPN Service API |

### 网络特性支持

| 特性 | Windows | Linux | macOS | Android |
|------|---------|-------|-------|---------|
| 路由表修改 | ✅ | ✅ | ✅ | ✅ |
| DNS 修改 | ✅ | ✅ | ✅ | ✅ |
| 混杂模式 | N/A | ✅ | ✅ | N/A |
| RAW socket | ✅ | ✅ | ✅ | ✅ |
| IPv6 | ✅ | ✅ | ✅ | ✅ |

## 与传统 VPN 的本质区别

OPENPPP2 与传统 VPN 产品有本质区别：

| 特性 | 传统 VPN | OPENPPP2 |
|------|----------|----------|
| 架构定位 | 终端安全连接 | 虚拟以太网基础设施 |
| 网络模型 | 点对点隧道 | 虚拟交换机/路由器 |
| 功能范围 | 加密通道 | 完整网络栈（路由/DNS/代理/映射） |
| 扩展性 | 有限 | 支持 static、MUX、IPv6 |
| 平台集成 | 插件形式 | 内核级集成 |
| 管理方式 | 集中式 | 分布式+可选管理后端 |

## 源码导航建议

对于想深入阅读 OPENPPP2 源码的读者，建议按以下顺序：

1. **从入口开始**：`main.cpp` 理解整体流程
2. **配置模型**：`AppConfiguration.*` 理解配置系统
3. **传输层**：`ITransmission.*` 理解加密和传输
4. **客户端**：`VEthernetNetworkSwitcher.*` + `VEthernetExchanger.*`
5. **服务端**：`VirtualEthernetSwitcher.*` + `VirtualEthernetExchanger.*`
6. **平台代码**：根据需要选择对应平台目录

## 总结

OPENPPP2 是一个复杂的多层系统，其架构核心在于：

1. **统一入口**：一个二进制支持 client/server 两种角色
2. **核心与平台分离**：共享核心处理协议逻辑，平台层处理 OS 集成
3. **多层平面**：每个角色由多个可选平面组成
4. **配置即架构**：配置对象本身就是架构组件
5. **协议分层**：protected transmission 与 tunnel action 分离
6. **FP 而非 PFS**：实现了前向安全保证但不是传统 PFS

理解这些架构原则对于正确使用和扩展 OPENPPP2 至关重要。

## 相关文档

| 文档 | 说明 |
|------|------|
| [STARTUP_AND_LIFECYCLE_CN.md](STARTUP_AND_LIFECYCLE_CN.md) | 启动、进程所有权与生命周期控制 |
| [CLIENT_ARCHITECTURE_CN.md](CLIENT_ARCHITECTURE_CN.md) | 客户端运行时架构 |
| [SERVER_ARCHITECTURE_CN.md](SERVER_ARCHITECTURE_CN.md) | 服务端运行时架构 |
| [TRANSMISSION_CN.md](TRANSMISSION_CN.md) | 传输层与受保护隧道模型 |
| [SECURITY_CN.md](SECURITY_CN.md) | 安全模型与防御性解读 |
| [CONFIGURATION_CN.md](CONFIGURATION_CN.md) | 配置模型与参数字典 |
