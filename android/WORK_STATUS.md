# OpenPPP2 Mobile Flutter Android 工作状态总结

## 项目概述

**项目路径**: `e:\Desktop\openppp2-next\openppp2_mobile`

**项目类型**: Flutter Android MVP VPN 应用

**架构**:
- Dart UI (Flutter)
- Kotlin Android VPN Service
- JNI 桥接到 C++ native VPN 库 (libopenppp2.so)
- MethodChannel/EventChannel 跨进程通信

**构建环境**:
- Flutter SDK: `E:\Dev\flutter-new`
- JDK: `E:\Dev\jdk-17`
- Android SDK: `E:\Dev\Android\Sdk`
- Android NDK: `E:\Dev\Android\Sdk\ndk\25.1.8937393`
- 代理: `http://127.0.0.1:2081`

---

## 已完成工作

### 1. 构建问题修复

#### 1.1 Kotlin 增量编译错误
- **问题**: Kotlin 增量编译导致构建失败
- **解决**: 在 `android/gradle.properties` 中禁用增量编译:
  ```properties
  kotlin.incremental=false
  ```

#### 1.2 Gradle 构建挂起
- **问题**: Gradle 构建挂起，下载 Flutter 引擎耗时过长
- **解决**: 在 `android/app/build.gradle` 中限制 ABI 为 arm64-v8a:
  ```gradle
  ndk {
      abiFilters "arm64-v8a"
  }
  ```

#### 1.3 Flutter 测试修复
- **问题**: 测试引用不存在的 `MyApp`
- **解决**: 更新 `test/widget_test.dart` 使用实际 app widget

#### 1.4 Flutter lint 警告修复
- **问题**: `withOpacity` 已弃用
- **解决**: 更新为 `withValues(alpha: ...)`

---

### 2. UI 布局修复

#### 2.1 主页布局
- **问题**: 内容左对齐，按钮未居中
- **解决**: 
  - 主布局改为 `ListView` 支持滚动
  - 添加 `crossAxisAlignment: CrossAxisAlignment.stretch`
  - 连接按钮使用 `Center` 包裹

#### 2.2 设置页增强
- **实现**: 详细的 VPN 参数表单（TUN IP、Gateway、mark 等）
- **功能**: 替换之前的纯 JSON 编辑，提供更好的用户体验

---

### 3. 调试功能增强

#### 3.1 主页调试面板
- **位置**: 首页底部，可滚动查看
- **功能**:
  - 实时显示 VPN 状态
  - 实时显示日志路径
  - 实时显示日志内容（每 2 秒自动刷新）
  - 操作按钮:
    - 刷新日志
    - 复制日志
    - 清空日志
    - 停止 VPN

#### 3.2 本地文件日志
- **文件**: `openppp2-vpn.log` (app 私有存储)
- **工具**: `PppLog.kt` 统一日志管理
- **功能**: 写入、读取、清空日志，带时间戳

#### 3.3 错误对话框
- **触发**: native 错误或连接超时
- **内容**: 错误信息 + 完整日志 + 复制按钮
- **目的**: 避免静默崩溃，提供可复制的错误信息

#### 3.4 连接超时看门狗
- **超时时间**: 8 秒
- **行为**: 超时后自动断开 VPN 并显示错误对话框

#### 3.5 状态轮询
- **频率**: 每 2 秒
- **目的**: 补偿跨进程 EventChannel 不可靠问题
- **实现**: Flutter 定期调用 native `getState`，通过日志推断状态

---

### 4. Android 侧增强

#### 4.1 VPN 服务隔离
- **修改**: `AndroidManifest.xml` 中添加 `android:process=":vpn"`
- **目的**: 隔离 VPN 服务进程，避免崩溃影响 UI

#### 4.2 阶段日志记录
- **日志点**:
  - `connect requested`
  - `PppVpnService created`
  - `onStartCommand action=...`
  - `startForeground done`
  - `vpn options ...`
  - `set_app_configuration result=...`
  - `builder.establish result=...`
  - `set_network_interface result=...`
  - `before libopenppp2.run(0)`
  - `libopenppp2.run returned=...`
  - `onStarted key=...`
  - `stopVpn requested, isRunning=...`
- **目的**: 精确定位连接失败点

#### 4.3 状态推断优化
- **已连接**: 日志包含 `VPN started with key`
- **连接中**: 日志包含 `set_network_interface result=0`、`before libopenppp2.run`、`builder.establish result=true`、`startForeground done`
- **未连接**: 日志包含 `failed`、`exception`、`error:`、`libopenppp2.run returned`、`stopVpn requested`
- **默认**: 未连接

#### 4.4 异常处理
- **位置**: MainActivity 和 PppVpnService
- **行为**: 捕获所有异常，记录日志，通过 EventChannel 通知 Flutter

---

### 5. 启动问题修复

#### 5.1 自动连接问题
- **问题**: App 启动时根据旧日志误判为连接中
- **解决**: 
  - 移除对旧日志中 `PppVpnService created`、`startForeground done`、`builder.establish result=true` 的连接中判断
  - 启动时调用 `_resetStartupState()` 清理残留连接中状态

#### 5.2 卡连接中无法中断
- **问题**: 连接中状态禁止点击按钮
- **解决**:
  - 连接中状态允许点击按钮
  - 按钮文案显示为 "点击强制停止"
  - 点击后调用 `_stopVpnForDebug()` 强制停止

---

## 当前问题

### 问题修复记录

#### 修复 1: C++ 层死锁（已完成 ✅）

**症状**：日志卡在 `vpnThread started, calling run(0)`，8秒后超时。

**根因**：`libopenppp2.run(0)` 中 `Invoke()` 等待了一个没有线程运行的 io_context。

**修复**：直接在 lambda 中调用 `start(app)`，不通过 `Invoke()` 转发。

#### 修复 2: C++ 层 io_context 不匹配（已完成 ✅）

**症状**：`run(0)` 立即返回错误码 `304` (`LIBOPENPPP2_ERROR_OPEN_VETHERNET_FAIL`)。

**根因**：`libopenppp2_try_open_ethernet_switcher` 内部使用 `Executors::GetDefault()` 获取全局 io_context，但和 `run()` 创建并运行的 io_context 不是同一个，导致 `VEthernetNetworkSwitcher::Open(tap)` 失败。

**修复**：修改 `libopenppp2_try_open_ethernet_switcher` 签名，接收传入的 io_context 参数，确保使用 `run()` 中创建并运行的 io_context。

```cpp
// 修复前
static int libopenppp2_try_open_ethernet_switcher(std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) {
    ...
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();  // 全局 io_context，可能未运行
    ...
}

// 修复后
static int libopenppp2_try_open_ethernet_switcher(
    std::shared_ptr<boost::asio::io_context> context,
    std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) {
    ...
    std::shared_ptr<ITap> tap = libopenppp2_from_tuntap_driver_new(context, network_interface);
    ...
}
```

**错误码参考**：
| 错误码 | 常量 | 含义 |
|---|---|---|
| 0 | `LIBOPENPPP2_ERROR_SUCCESS` | 成功 |
| 301 | `LIBOPENPPP2_ERROR_IT_IS_RUNING` | 已在运行 |
| 302 | `LIBOPENPPP2_ERROR_NETWORK_INTERFACE_NOT_CONFIGURED` | 网络接口未配置 |
| 303 | `LIBOPENPPP2_ERROR_APP_CONFIGURATION_NOT_CONFIGURED` | 应用配置未设置 |
| 304 | `LIBOPENPPP2_ERROR_OPEN_VETHERNET_FAIL` | 虚拟以太网打开失败 |
| 305 | `LIBOPENPPP2_ERROR_OPEN_TUNTAP_FAIL` | TUN/TAP 打开失败 |

#### 最新日志示例（修复后待测试）
```
2026-05-04 02:41:45.719 connect requested
2026-05-04 02:41:45.965 PppVpnService created
2026-05-04 02:41:45.968 onStartCommand action=...
2026-05-04 02:41:45.973 startForeground done
2026-05-04 02:41:45.977 vpn options ...
2026-05-04 02:41:46.017 set_app_configuration result=0
2026-05-04 02:41:46.056 builder.establish result=true
2026-05-04 02:41:46.058 set_network_interface result=0
2026-05-04 02:41:46.059 before libopenppp2.run(0)
2026-05-04 02:41:46.061 vpnThread started, calling run(0)
2026-05-04 02:41:46.062 libopenppp2.run returned=304  ← 修复前（错误）
```

**验证状态**:
- ✅ Native 库编译成功
- ✅ APK 构建成功
- ⏳ 待用户测试确认连接正常

---

## 文件结构

### Flutter 层

```
lib/
├── main.dart                    # 应用入口
├── vpn_service.dart             # VPN 服务封装
└── pages/
    ├── home_page.dart           # 主页（调试面板）
    └── settings_page.dart       # 设置页（VPN 参数配置）
```

### Android 层

```
android/app/src/main/
├── AndroidManifest.xml          # 应用清单（VPN 服务隔离）
└── kotlin/supersocksr/ppp/android/
    ├── MainActivity.kt          # Flutter-Android 桥接
    ├── PppVpnService.kt         # VPN 服务实现
    ├── PppLog.kt                # 本地日志工具
    └── c/
        └── libopenppp2.kt       # JNI 桥接
```

### JNI 层

```
android/app/src/main/jniLibs/arm64-v8a/
└── libopenppp2.so               # C++ native VPN 库
```

---

## 关键配置

### Gradle 配置

**android/gradle.properties**:
```properties
org.gradle.jvm.args=-Xmx4G
android.useAndroidX=true
android.enableJetifier=true
kotlin.incremental=false
```

**android/app/build.gradle**:
```gradle
android {
    defaultConfig {
        ndk {
            abiFilters "arm64-v8a"
        }
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = '17'
    }
}
```

### VPN 配置

**默认参数** (SettingsPage):
```dart
{
  'tunIp': '10.0.0.2',
  'tunMask': '255.255.255.0',
  'tunPrefix': 24,
  'gateway': '10.0.0.1',
  'route': '0.0.0.0',
  'routePrefix': 0,
  'dns1': '8.8.8.8',
  'dns2': '8.8.4.4',
  'mtu': 1400,
  'mark': 0,
  'mux': 0,
  'vnet': false,
  'blockQuic': false,
  'staticMode': false,
}
```

**用户当前配置** (从日志):
```
tunIp=10.0.0.4 tunMask=255.255.255.0 tunPrefix=24 route=0.0.0.0/0 dns1=8.8.8.8 dns2=8.8.4.4 mtu=1400 mark=0 mux=0 vnet=false blockQuic=true staticMode=true
```

---

## 构建命令

### Flutter 分析
```powershell
$env:PATH = "E:\Dev\flutter-new\bin;$env:PATH"
flutter analyze
```

### APK 构建
```powershell
$env:JAVA_HOME = "E:\Dev\jdk-17"
$env:ANDROID_HOME = "E:\Dev\Android\Sdk"
$env:PATH = "E:\Dev\flutter-new\bin;E:\Dev\jdk-17\bin;$env:PATH"
$env:HTTP_PROXY = "http://127.0.0.1:2081"
$env:HTTPS_PROXY = "http://127.0.0.1:2081"

cd android
.\gradlew.bat :app:assembleDebug "-Ptarget-platform=android-arm64" "-Ptarget=lib/main.dart" "-Pbase-application-name=android.app.Application" --stacktrace --no-watch-fs
```

### APK 路径
```
build/app/outputs/apk/debug/app-debug.apk
build/app/outputs/flutter-apk/app-debug.apk
```

---

## 下一步计划

### 立即行动
1. **验证死锁修复**
   - 安装最新 APK（包含死锁修复后的 native 库）
   - 点击连接
   - 查看状态是否变为"已连接"
   - 检查日志中是否出现 `onStarted key=...`

### 如果仍有问题

**如果日志有 `vpnThread started, calling run(0)` 但没有后续**:
- 可能还有新的 native 层问题
- 需要查看 `adb logcat -s libopenppp2` 获取 C++ 层日志

**如果状态变为已连接但无法上网**:
- 检查 TUN 配置参数
- 检查路由配置
- 检查 DNS 配置

### 长期优化
1. **Kotlin 版本升级**: 当前 1.9.24，建议升级到 2.1.0+
2. **Android Gradle Plugin 升级**: 当前 8.3.2，建议升级到 8.6.0+
3. **stopForeground API 升级**: 当前使用已弃用的 Boolean 参数，建议使用 ServiceStopFlags
4. **状态管理优化**: 考虑使用更可靠的状态同步机制（如 SharedPreferences 标志位）
5. **Native 库构建自动化**: 集成到 Flutter build 流程中

---

## 技术栈总结

- **UI**: Flutter (Dart)
- **Android**: Kotlin + VpnService API
- **Native**: C++ (libopenppp2.so)
- **桥接**: JNI (Kotlin ↔ C++)
- **通信**: MethodChannel/EventChannel (Flutter ↔ Kotlin)
- **日志**: 本地文件 + Logcat
- **存储**: SharedPreferences
- **构建**: Gradle + Flutter build tools

---

## 联系与支持

**项目路径**: `e:\Desktop\openppp2-next\openppp2_mobile`

**日志路径**: `/data/user/0/supersocksr.ppp.android/files/openppp2-vpn.log`

**VPN 服务进程**: `:vpn` (独立进程)

**最后更新**: 2026-05-04 02:55

**关键修复**:
1. C++ 层死锁（`libopenppp2.run(0)` 中 `Invoke()` 等待没有线程运行的 io_context）
2. C++ 层 io_context 不匹配（`libopenppp2_try_open_ethernet_switcher` 使用全局 io_context 而非 `run()` 创建的 io_context，导致 `VEthernetNetworkSwitcher::Open(tap)` 返回错误码 304）
