# OpenPPP2 Linux 单虚拟网卡多队列模型方案说明

## 1. 背景

当前项目在 Linux 下已经具备一部分多线程读取虚拟网卡的基础能力：

- `TapLinux::OpenDriver()` 已尝试使用 `IFF_MULTI_QUEUE` 打开同名 tun 设备。
- `TapLinux::Ssmt(context)` 可以再次打开同名设备并附加额外的 queue fd。
- 客户端 `VEthernet` 已存在 `SSMT + mq` 的并发读取链路。
- 服务端 `--mode=server` 下的 IPv6 transit tun 现在也已经接入了 `mq` worker 路径。

但当前实现仍然偏“隐式多队列”：

- 对外仍然只有一个 `ITap` 对象。
- 对内通过 `TapLinux` 持有多个 fd / stream_descriptor。
- 多队列状态分散在 `TapLinux`、`VEthernet`、`VirtualEthernetSwitcher` 中。
- 读写路径部分依赖 TLS 临时选择 fd。

这种实现可以继续工作，但如果后续要进一步优化吞吐、做更清晰的线程绑定、统计、CPU 亲和性和更严格的生命周期管理，当前模型会越来越难维护。

## 2. 目标

目标不是创建多个虚拟网卡，而是：

- 保持单个逻辑上的 tun/tap 虚拟网卡。
- 在用户态明确建模多个 queue 实例。
- 每个 worker 线程绑定一个 queue fd。
- 对同一条连接或同一条流，尽量保持读写侧的 queue 粘性。
- 提升并发读写吞吐能力。
- 统一客户端与服务端对 Linux 多队列 tun 的使用模型。

一句话描述：

> 单虚拟网卡，多队列实例，多线程绑定，并尽量保持 TUN_FD 亲和，而不是多个虚拟网卡。

## 3. 额外约束：TUN_FD 线程亲和性

这里需要明确一个关键约束：

- 多队列设计不能只考虑“读能并发”。
- 还必须考虑同一条连接或同一条流的 `TUN_FD` 亲和性。

原因是：

- 某个 queue fd 读入的 TCP 流量，如果后续继续由对应的 queue fd 写回，内核侧路径通常更容易保持局部性。
- 如果一个连接在用户态频繁跨 queue / 跨 fd 回写，即使逻辑正确，效率也可能下降。
- 因此“一个线程一个 queue”只是第一层；“尽量让同一条流保持 queue 粘性”才是第二层关键要求。

这意味着未来的设计不能只是：

- worker A 读到包
- 任意 worker B 都可以随意回写

而应该尽量做到：

- worker A / queue A 读到某条 TCP 连接的数据
- 该连接后续的回写优先仍落到 queue A

## 4. 为什么不是多个虚拟网卡

## 3. 为什么不是多个虚拟网卡

不建议把这个需求实现成多个虚拟网卡，原因如下：

1. 会明显增加地址、路由、DNS、MTU 配置复杂度。
2. 当前很多逻辑默认只有一个 tunnel interface。
3. 客户端路由、服务端 IPv6 transit、DNS 分流、防火墙和静态模式都会被迫大改。
4. 问题本质不是“多个设备”，而是“同一设备上的多个并行用户态收发通道”。

因此更合理的模型应是：

- 一个逻辑设备
- 多个 queue/instance
- 每个线程消费一个 queue

## 5. 当前代码里的问题

目前的 Linux 多队列能力主要存在这些问题：

1. 队列不是一等对象。
2. 生命周期和状态分散在多个类里。
3. server/client 两边容易各自补逻辑，逐渐分叉。
4. 很难对单个 queue 做统计、日志和故障隔离。
5. 后续如果要做 CPU 亲和、动态扩缩容、队列级调度，会很难继续维护。
6. 旧的 `SSMT-model` 主要是为了 client-vnet 性能引入的，不适合作为未来 server/client 的统一模型继续外扩。

当前具体表现包括：

- `TapLinux` 内部持有 `tun_ssmt_sds_`、`tun_ssmt_fds_size_`。
- `VEthernet` 通过 `ssmt_mq_to_take_effect_` 管理多队列生效状态。
- `TapLinux::Output()` 通过 TLS 里的 `tun_fd_` 决定写哪个 fd。
- 服务端 IPv6 transit tun 直到最近才显式接上 `mq` worker。

现有实现里其实已经隐含了一部分“fd 亲和”的意识：

- Linux 路径会把 `tun_fd_` 放进 TLS。
- 某些数据处理路径会尝试沿用当前读入时的 fd 回写。

但这部分目前仍然是隐式的，且没有上升为正式模型。

这些都说明：

- 功能基础已经存在
- 但抽象模型还不够清晰

## 6. 建议的模型

建议把 Linux tun/tap 抽象拆成两层。

### 5.1 逻辑设备层

保留一个逻辑上的 `ITap` / `TapLinux`，负责设备级能力：

- 创建和销毁设备
- 配置 IPv4 / IPv6 地址
- 配置路由、DNS、MTU
- 设备级生命周期管理

### 6.2 队列实例层

新增显式 queue 对象，例如：

- `TapLinuxQueue`
- 或 `ITapQueue`
- 或 `TapChannel`

每个实例代表同一设备上的一个 queue fd，负责：

- 持有 fd / `stream_descriptor`
- 持有绑定的 `io_context` 或 worker
- 启动单独读循环
- 单独关闭和回收
- 可选的 per-queue 统计
- 暴露一个稳定的 queue identity，供连接/流绑定使用

这样结构会更明确：

- `TapLinux` 是逻辑设备
- `TapLinuxQueue` 是设备上的并行读写队列实例

### 6.3 连接/流与 queue 的绑定层

建议显式增加一层“流到 queue 的绑定语义”，至少覆盖 TCP：

- 同一条 TCP 连接，如果由 queue A 读入
- 后续应优先继续由 queue A 回写

可选实现方式包括：

1. 连接对象显式记录 queue id
2. 连接对象显式记录 queue fd
3. 以 5 元组或连接主键映射到 queue id

这个绑定层并不一定要求“绝对禁止跨 queue”，但应当：

- 默认优先走原 queue
- 只有在连接迁移、queue 关闭或异常回退时才切换

否则，即使多队列并发读已经打通，也很难发挥最佳效率。

## 7. 好处

推进成“单设备，多显式队列实例”模型后，会有这些收益：

1. 语义更清晰
2. 生命周期更清晰
3. server/client 可以复用同一套队列模型
4. 更容易做统计、日志和问题隔离
5. 更容易支持 CPU 亲和、NUMA、动态队列数调整
6. 更容易正式表达连接到 queue 的粘性与亲和性
7. 更适合后续继续做性能优化而不破坏现有业务逻辑

## 8. 建议的演进步骤

建议分阶段推进，而不是一次重构所有调用方。

### 第一步：让 queue 对象显式化

目标：

- 不改变大部分外部调用方式
- 先把 `TapLinux` 里的隐式 fd 列表，整理为显式 queue 对象列表

建议变化：

- 从：
  - `tun_ssmt_sds_`
  - `tun_ssmt_fds_size_`
- 演进到：
  - `vector<shared_ptr<TapLinuxQueue>> queues_`

### 第二步：引入 queue 亲和语义

在 queue 对象显式化之后，不应立刻只停留在“多个 queue 能工作”，而应继续补上：

- 连接到 queue 的绑定关系
- 默认回写优先使用原 queue
- queue 关闭时的迁移策略

这一步是为了把当前隐式 TLS fd 亲和，演进成正式模型。

### 第三步：统一队列接口

把现在偏历史命名的：

- `Ssmt(context)`

逐步演进到更明确的接口，例如：

- `OpenQueue(context)`
- `OpenQueues(count, mq_mode)`
- `GetQueueCount()`
- `StopQueues()`

这样能减少上层对“SSMT”历史概念的误用。

### 第四步：统一 server/client 使用方式

目前客户端和服务端都已经在用 Linux 多队列能力，但入口不统一。

同时需要注意：

- 不建议继续让 server/client 直接“参考原本的 SSMT-model”去各自扩写。
- 原有 `SSMT-model` 是为 client-vnet 性能场景设计的。
- 未来应把它视为历史实现来源，而不是新的统一架构名称。

建议最终做到：

- 客户端主 tunnel
- 服务端 IPv6 transit tun

都走同一套 queue 管理接口。

## 9. 当前阶段建议

结合当前代码现状，最现实的下一步不是去创建多个虚拟网卡，而是：

1. 保持单 tun/tap 设备
2. 把多队列实现抽象成显式 queue 对象
3. 明确连接到 queue 的粘性/亲和策略
4. 统一 client/server 的 queue 生命周期和 worker 绑定方式
5. 再在此基础上追加更多性能优化

## 10. 总结

建议采用的方向是：

- 不是多个虚拟网卡
- 而是单个虚拟网卡的多队列实例模型

当前仓库已经具备实现这条路线的基础，后续工作重点应放在：

- 抽象清晰化
- queue 亲和语义清晰化
- 生命周期统一化
- server/client 复用化
- 多队列可观测性和可维护性提升

这条路线比“继续堆隐式 fd 列表”更稳，也比“重做成多个虚拟网卡”更符合项目当前架构。
