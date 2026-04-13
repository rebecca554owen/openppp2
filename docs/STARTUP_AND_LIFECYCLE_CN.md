# 启动与生命周期

[English Version](STARTUP_AND_LIFECYCLE.md)

## 入口

进程从 `main.cpp` 启动。

`PppApplication` 是顶层所有者，负责：

- 运行时配置
- 网络接口运行时覆盖参数
- 客户端或服务端运行对象
- 周期性 tick 行为
- 关闭与重启控制

## 启动序列

高层启动路径如下：

1. 进程入口
2. 权限检查
3. 单实例保护
4. 配置加载
5. 模式判定
6. 网络覆盖参数解析
7. 平台准备
8. 构造客户端或服务端运行时
9. 安排周期性 tick
10. 进入事件循环

## 配置加载

`LoadConfiguration(...)` 会从命令行和默认路径中寻找配置文件。

得到的 `AppConfiguration` 会成为运行时的中心策略对象。后续大量代码都是从这个对象取策略，而不是依赖零散全局变量。

## 网络覆盖参数

`GetNetworkInterface(...)` 收集如下运行时覆盖信息：

- DNS 服务器
- 物理网卡
- 首选网关
- TUN 名称、IP、掩码、网关
- static 模式
- vnet 模式
- 宿主网络优先策略
- bypass 列表与 DNS/防火墙规则文件
- mux 设置
- Linux 的 SSMT 与 protect 模式
- Windows 的租约时间和可选代理修改

这说明 OPENPPP2 既支持通过 JSON 保存稳定策略，也支持通过 CLI 做部署时适配。

## 模式选择

`IsModeClientOrServer(...)` 在没有显式指定时默认进入服务端模式。

这和代码结构一致：同一个可执行程序支持双角色，但服务端被视为默认运行身份。

## 客户端启动路径

客户端模式下，大致流程如下：

1. 创建 TUN/TAP 虚拟网卡
2. 创建 `VEthernetNetworkSwitcher`
3. 向 switcher 注入运行时参数
4. 加载 bypass 与 route 列表
5. 加载 DNS 规则
6. 在虚拟网卡上打开 switcher
7. 由 `VEthernetExchanger` 异步维护远端会话

这里的分工很明确：switcher 负责本地环境，exchanger 负责远端关系。

## 服务端启动路径

服务端模式下，大致流程如下：

1. 在适用场景下准备 Linux IPv6 环境
2. 创建 `VirtualEthernetSwitcher`
3. 加载防火墙规则
4. 打开监听器与辅助服务
5. 启动 accept 循环
6. 将接入的传输连接转换成隧道会话

因此服务端不只是一个监听器，而是整个覆盖网络节点的顶层会话交换机。

## 周期性 Tick 模型

`PppApplication::OnTick(...)` 是全局维护循环。

它负责：

- 状态打印
- 传输统计快照
- virr / 路由列表刷新
- vBGP 风格路由刷新
- 管理后端更新调用
- 重启与链路监督

这是一种典型基础设施模式：把维护逻辑放进一个可见的周期路径，而不是散落在大量零碎 timer 中。

## 关闭与释放

生命周期关闭是显式实现的：

- `PppApplication::Dispose()` 释放客户端或服务端运行时
- 客户端和服务端 switcher 释放其拥有的 exchanger 和连接
- transmission 关闭 socket 并停止待处理活动
- 平台支持的场景下，会恢复或清理路由和代理状态

这很重要，因为进程会修改宿主机网络状态。不能正确回收自身改动的网络进程，在运维上是不安全的。

## 重启模型

进程层本身就包含重启相关逻辑，而不是只把恢复能力放在客户端 exchanger 内部。这说明该系统把韧性看作系统级问题，而不是单纯 socket 级问题。

## 阅读提示

阅读启动代码时，建议始终记住这几层所有权边界：

- `PppApplication` 负责进程生命周期
- switcher 负责环境生命周期
- exchanger 负责会话生命周期
- transmission 负责连接生命周期

只要心里保持这层边界，后面代码会清晰很多。
