# MUX 按流交付设计说明（mux-perflow-delivery / flow v2）

> 状态：设计 + 首版实现已落地（接收端 per-flow 定序能力）。本文件是仓库内的稳定设计参考，配合 spec `.kiro/specs/mux-perflow-delivery/`（design / requirements / tasks）。技术术语保留英文。

## 定位

本特性是 GitHub issue #5（`--mux-mode` 调度策略）的"真正多链路聚合"阶段，即 **flow v2**：在已实现的发送侧调度器（`compat`/`flow`/`balance`/`stripe`）之上，新增**接收端按连接（per-flow）定序**这一可协商能力，消除接收端队头阻塞（HOL blocking）。当前启用场景是 `balance`、`stripe`，以及 `flow` 开启 `mux.turbo` 时。

## 为什么需要它（根因）

当前 VMUX 线协议用**单一全局序号窗口**：

```cpp
// ppp/app/mux/vmux_net.h —— 9 字节 packed
typedef struct { uint32_t seq; uint8_t cmd; uint32_t connection_id; } vmux_hdr;
// status_.tx_seq_  发送端单调递增（每帧 ++，不分连接）
// status_.rx_ack_  接收端严格按全局 seq 交付，乱序帧进全局 rx_queue_
```

后果：`balance`/`stripe` 把不同连接的帧发往不同链路后，接收端仍按单一全局 `rx_ack_` 串行交付。`flow+turbo` 还会动态预热额外承载，进一步提高跨链路乱序概率。慢链路上某个 seq 未到，全局 `rx_ack_` 停步，所有连接被一起扣押。**瓶颈在接收端的全局定序，不在发送侧分发。** 所以 `balance` 与 `flow+turbo` 只有在 flow v2 之上才真正有用。

## 核心设计

### 1. 可协商的接收定序模式（安全闸门）

新增 `receiver_ordering_mode { ordering_compat=0, ordering_flow_v2=1 }`。**只有双方都声明支持，才启用 flow v2，否则回退 compat。** compat 对端绝不能被静默当作 flow-v2 接收端（否则误交付乱序数据）。

协商三态：

| Client 声明 | Server 声明/支持 | 结果 |
|---|---|---|
| FLOW_V2 | FLOW_V2 | FLOW_V2 |
| FLOW_V2 | COMPAT / 旧版（字段缺失） | COMPAT |
| COMPAT / 旧版 | FLOW_V2 | COMPAT |
| COMPAT | COMPAT | COMPAT |

安全不变式：`agreed==FLOW_V2 ⟺ 双方 bit0 都为 1`。降级永远安全（fail-safe），绝不静默升级。

### 2. 协商承载：MUX 帧追加 1 字节能力位（实现细节，偏离原设计）

> **与 spec design.md 的偏离**：design.md 设想把协商结果放在 `MUXON` 帧的 `ordering_mode` 字节。实测代码里 **MUXON 是 per-linklayer 的 seq/ack 握手**，而**会话级**的 mux 能力协商走的是 **MUX 帧的客户端→服务端发送 + 服务端回显 MUX**（`VEthernetExchanger`/`VirtualEthernetExchanger::OnMux`）。因此实现把能力位放在 **MUX 帧尾部**（双向都发 MUX，天然双向协商），未改动 MUXON。三态判定与安全性与原设计完全一致。

```cpp
// VirtualEthernetLinklayer.cpp（packed），尾部追加可选字节
typedef struct {
    Byte il; uint16_t vlan; uint16_t max_connections; Byte acceleration;
    Byte ordering_caps;   // bit0 = FLOW_V2；旧端不发送该字节
} VirtualEthernetLinklayer_MUX_IL;
```

向后兼容：解析所需长度仍只覆盖**原有**字段（`sizeof(struct) - 1 - sizeof(Byte)`），`ordering_caps` 按"可选尾部"读取——旧端不发就当 0（=COMPAT）。客户端在 MUX 里声明 `bit0 = mode_requires_flow_v2(mux.mode, mux.turbo)`；服务端 `OnMux` 计算 `agreed = peer_bit0 && mode_requires_flow_v2(local_mode, local_turbo)`，把 `agreed` 回显在它发回的 MUX 帧里；两端在建链前调用 `vmux_net::set_ordering_mode(agreed)`。

### 3. 序号方案：复用 `vmux_hdr.seq`，零线格式扩容

FLOW_V2 下，对 per-flow 数据帧（`cmd_push`/`cmd_fin`），`seq` 解释为该 `connection_id` 的 **per-flow DSN**：

- 发送端为每连接维护 `tx_flow_seq_[connection_id]`（DSN 从 1 起，0 保留给控制帧占位）。
- 接收端按 `connection_id` 用独立 `flow_rx_next_` 定序，独立 reorder 缓冲。
- 控制帧（除 `cmd_fin`）以 `seq=0` 占位，不消耗 DSN，接收端忽略其 DSN。

**诚实的权衡**：`seq` 字段二义（全局 vs per-flow），但换来零 header 扩容、零跨版本对齐风险；安全性完全由能力协商保证（compat 端永不进入 per-flow 解释路径）。若未来要链路质量可观测或 striping 的 per-link seq，再用新的能力位演进到"扩展 header"。

### 4. 接收端 per-flow 交付

每个 `connection_id` 一个 `flow_rx_context`：

```cpp
struct flow_rx_context {
    uint32_t          flow_rx_next_         = 0;     // 期望的下一个 DSN
    rx_packet_ssqueue flow_reorder_;                // map<DSN, 帧>，packet_less 处理回绕
    uint64_t          oldest_buffered_tick_ = 0;     // 最老缓冲帧入队 tick（超时基准）
    size_t            buffered_bytes_       = 0;     // 当前缓冲字节（内存上界）
    bool              primed_               = false; // 已用首帧初始化 flow_rx_next_
    bool              fin_seen_             = false; // 已交付 FIN
};
```

`packet_input_flow()`：控制帧旁路（不进 DSN 闸门）；数据帧首帧 priming（以首个 DSN 初始化）；命中 `flow_rx_next_` 立即交付并连续回放；未来帧入有界 reorder 缓冲；过期/重复帧丢弃。一条慢链路只卡它自己那个连接，不影响其它连接。

### 5. 有界内存 + 超时驱逐（活性）

- 每连接缓冲 `buffered_bytes_ <= mux.flow.reorder.bytes`；超限时 `flow_force_advance` 跳过最老缺口。
- `update()` 周期调用 `flow_evict_expired`：缺口超过 `mux.flow.reorder.timeout`（毫秒）就跳过缺口推进 `flow_rx_next_`。
- 每次实际跳过递增遥测 `mux.rx.flow.evict`。
- 第一版**无重传**：被跳过的缺口字节由被隧道的上层 TCP 重传补偿。

### 6. 发送侧不绑定，接收状态不回退

当前 `balance` 发送侧保持竞争法，不做 per-connection link binding；`stripe` 才是实验性逐包轮询。承载链路掉线或 runtime shrink 时，发送侧后续帧继续由剩余可用链路竞争发送。接收侧 `flow_rx_context` 保留、`flow_rx_next_` 不回退；在途丢帧表现为该连接自己的 DSN 缺口，由超时驱逐保活。

## 配置项

| 键 | 类型 | 默认 | 作用 |
|---|---|---|---|
| `mux.flow.reorder.bytes` | int (>0) | 1048576 | 每连接 reorder 缓冲字节上界 |
| `mux.flow.reorder.timeout` | int (>0, ms) | 2000 | 缺口等待超时 |

不再有独立 `mux.flow-v2` 配置项；`balance` / `stripe` 自动声明 flow v2，`compat` / `flow` 不声明。两端都处于需要 flow v2 的模式且都支持能力字节时才会启用；任一端不支持或当前模式不需要则回退 compat。

## 第一版明确不保证

- 不在 mux 层重传（靠上层 TCP）。
- 无拥塞控制 / 无 per-flow ACK 反馈。
- `seq` 字段二义，无独立链路质量序号。
- 内存换吞吐：最坏 `max_connections × flow.reorder.bytes`。
- `stripe` 仍实验性；本特性只为其提供接收端定序基础。
- 协商是会话级一次性，建链后不热切换。

## 代码触点

- `ppp/app/mux/vmux_net.h` / `.cpp`：`receiver_ordering_mode`、`flow_rx_context`、`packet_input_flow`、`deliver_one`、`flow_force_advance`、`flow_evict_expired`、`maybe_release_flow`、`set_ordering_mode`、`post_internal` 的 DSN 分支、`forwarding` 分流。
- `ppp/app/protocol/VirtualEthernetLinklayer.h` / `.cpp`：MUX_IL 追加 `ordering_caps`，`DoMux`/`OnMux` 增参与长度容忍解析。
- `ppp/app/server/VirtualEthernetExchanger.cpp` / `ppp/app/client/VEthernetExchanger.cpp`：协商 `agreed` 并 `set_ordering_mode`。
- `ppp/configurations/AppConfiguration.h` / `.cpp`：`mux.mode` / `mux.flow.reorder.*`。

详见 spec：`.kiro/specs/mux-perflow-delivery/{design,requirements,tasks}.md`。
