# OpenPPP2 Mobile

这是一个 OpenPPP2 Android Flutter MVP 客户端，目标是先跑通“一键连接 / 断开 + JSON 配置输入 + VPN Service + JNI + libopenppp2.so”的最小链路。

## 当前状态

- 已创建 Flutter 项目结构。
- 已实现基础 Material 3 UI。
- 已实现 Dart `MethodChannel` / `EventChannel` 包装。
- 已实现 Kotlin `MainActivity`、`PppVpnService`、JNI 桥接类 `supersocksr.ppp.android.c.libopenppp2`。
- 已接入 `arm64-v8a/libopenppp2.so`。
- 当前只打包 `arm64-v8a`，优先用于现代 Android 真机测试。

## 你需要先安装的软件

1. Android Studio
2. Flutter SDK
3. Android SDK / Platform Tools
4. 一台 Android 真机

安装好 Flutter 后，在命令行确认：

```powershell
flutter doctor
```

## 第一次运行

如果这个项目不是通过 `flutter create` 生成的完整模板，先运行一次引导脚本：

```powershell
.\tools\bootstrap_flutter.ps1
```

这个脚本会让 Flutter 生成缺失的 Android wrapper/模板文件，并恢复本项目已写好的 Dart/Kotlin 代码。

在项目目录运行：

```powershell
flutter pub get
flutter run
```

如果 Android Studio 提示缺少 SDK、NDK 或 Gradle，按提示安装即可。

## 注意事项

- VPN/TUN 必须用真机测试，模拟器通常不适合作为最终验证环境。
- 目前只包含 `arm64-v8a` 的 `libopenppp2.so`，所以建议先用 64 位 ARM 真机测试。
- 配置页面里默认 JSON 只是模板，你需要把 `client.server` 等字段改成你的真实 PPP 服务端地址。
- 如果要支持 `armeabi-v7a`、`x86_64`、`x86`，需要先为这些 ABI 构建 `libopenppp2.so` 并放入 `android/app/src/main/jniLibs/` 对应目录，再修改 `android/app/build.gradle` 的 `abiFilters`。

## 目录说明

```text
lib/
  main.dart
  vpn_service.dart
  pages/home_page.dart
  pages/settings_page.dart
android/app/src/main/kotlin/supersocksr/ppp/android/
  MainActivity.kt
  PppVpnService.kt
android/app/src/main/kotlin/supersocksr/ppp/android/c/
  libopenppp2.kt
android/app/src/main/jniLibs/arm64-v8a/
  libopenppp2.so
```
