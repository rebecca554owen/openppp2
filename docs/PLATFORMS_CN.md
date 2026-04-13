# 平台集成

[English Version](PLATFORMS.md)

## 文档目的

OPENPPP2 采用一个共享协议核心，再配合多套操作系统特化网络集成实现。

这种拆分是必须的，因为虚拟网卡、路由 API、DNS 控制和 socket 保护机制在不同平台上并不相同。

## Windows

Windows 集成包括：

- Wintun 支持
- TAP-Windows 回退支持
- 基于 Win32 / IP Helper API 的路由管理
- 网卡 DNS 配置修改
- DNS 缓存刷新
- 可选本机代理集成
- Windows 特有的 PaperAirplane 支持

### 设计原因

Windows 必须显式接入宿主网络栈和网卡驱动。若强行用一个纯跨平台抽象，会掩盖大量真实行为。

## Linux

Linux 集成包括：

- 通过 `/dev/tun` 或 `/dev/net/tun` 打开 TUN
- 在条件允许时启用 multiqueue
- 路由增删行为
- protect 模式用于把 socket 锁定在底层网络
- 服务端 IPv6 transit 与 neighbor-proxy 支持

### 设计原因

Linux 是当前代码库里最完整的基础设施宿主平台，也是最能暴露底层网络能力的平台。

## macOS

macOS 集成使用：

- `utun`
- 基于平台工具和控制 socket 的路由及接口配置
- utun 特有分组处理

### 设计原因

macOS 的网络行为并不等同于 Linux TUN。因此工程保留独立的 Darwin 路径，而不是假装两者可以完全互换。

## Android

Android 集成不同于桌面 CLI 构建。

它采用：

- 共享库输出
- 由 Android VPN 集成提供的外部 TUN fd
- 基于 JNI 的 socket protect

### 设计原因

Android VPN 能力是应用宿主式的，因此 C++ 运行时在这里更像一个被 Android 代码调用的引擎，而不是独立 CLI 进程。

## 构建系统拆分

仓库支持：

- 根 CMake 驱动主 C++ 运行时
- Windows 下 Visual Studio / Ninja / vcpkg 工作流
- Linux 和类 Unix 下的 GCC/Clang 工作流
- Android 特化 CMake 构建
- Linux 多架构交叉构建脚本

这反映了很明确的基础设施意图：项目预期部署在多个目标平台，而不是只服务于单一桌面环境。

## 为什么平台代码不应被完全隐藏

平台特化代码保持可见，而且相对直接，是因为网络基础设施的行为最终取决于宿主机真实表现。

如果项目把所有平台差异都压成一个很小的抽象层，路由修改、网卡行为和 DNS 处理的真实含义反而会更难看清。

## 平台改动后应验证什么

- 虚拟网卡仍能正确创建和打开
- 路由能正确安装与回收
- DNS 修改能正确应用与回滚
- 受保护 socket 仍留在预期底层网络上
- IPv6 行为仍符合平台预期

## 相关文档

- [`OPERATIONS_CN.md`](OPERATIONS_CN.md)
- [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md)
- [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md)
