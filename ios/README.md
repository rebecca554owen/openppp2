# OpenPPP2 iOS Build

This directory contains the iOS-native build surface for the shared OpenPPP2
runtime.

## Current scope

- Builds a static `openppp2_ios` archive target.
- Treats iOS as `_IPHONE`, not `_MACOS`, so macOS `utun` code is not selected.
- Provides `TapIos`, a callback-based `ITap` facade intended to be driven by
  `NEPacketTunnelFlow` from a Network Extension.
- Provides a small C bridge in `OpenPPP2PacketTunnelBridge.h`.
- Packages an `OpenPPP2.xcframework` with a module map for Swift import.

## One-command build

```sh
ios/build-xcframework.sh
```

The script builds both SDKs and writes:

- `bin/ios/libopenppp2_ios.a`
- `bin/ios-simulator/libopenppp2_ios.a`
- `bin/OpenPPP2.xcframework`

The simulator architecture defaults to the host architecture. Override it when
needed:

```sh
IOS_SIMULATOR_ARCHS=x86_64 ios/build-xcframework.sh
IOS_SIMULATOR_ARCHS=arm64 ios/build-xcframework.sh
```

## Manual device build

```sh
cmake -S ios -B build/ios-device \
  -G Ninja \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_SYSROOT=iphoneos \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0
```

```sh
cmake --build build/ios-device
```

The archive is written to `bin/ios/libopenppp2_ios.a`.

## Manual simulator build

```sh
cmake -S ios -B build/ios-simulator \
  -G Ninja \
  -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_SYSROOT=iphonesimulator \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0

cmake --build build/ios-simulator
```

The simulator archive is written to `bin/ios-simulator/libopenppp2_ios.a`.

## Xcode integration

Add `bin/OpenPPP2.xcframework` to the Packet Tunnel Extension target and link
the target with `libc++`.

Swift can import the C bridge as:

```swift
import OpenPPP2
```

`Examples/PacketTunnelProvider` contains a minimal `NEPacketTunnelProvider`
adapter that connects `NEPacketTunnelFlow` to `TapIos`.

## IPK packaging

Normal iPad installation uses an `.ipa` signed with an Apple development or
distribution certificate. An `.ipk` package is only useful for jailbreak-style
package managers or other custom install environments, and it still needs a
real `.app` bundle as input.

After building an app bundle, package it as:

```sh
APP_BUNDLE=/path/to/OpenPPP2.app ios/package-ipk.sh
```

The IPK script does not perform Apple code signing. For jailbreak-style
environments that need a fake signature and have `ldid` installed:

```sh
FAKESIGN=1 APP_BUNDLE=/path/to/OpenPPP2.app ios/package-ipk.sh
```

With explicit entitlements:

```sh
FAKESIGN=1 \
ENTITLEMENTS=/path/to/entitlements.plist \
APP_BUNDLE=/path/to/OpenPPP2.app \
ios/package-ipk.sh
```

Useful overrides:

```sh
PACKAGE_ID=io.github.miaocchi.openppp2 \
PACKAGE_VERSION=0.1.0 \
PACKAGE_ARCH=iphoneos-arm64 \
INSTALL_PREFIX=/Applications \
APP_BUNDLE=/path/to/OpenPPP2.app \
ios/package-ipk.sh
```

The package is written to `bin/ipk/`.

## IPA packaging

An `.ipa` is a zip archive containing `Payload/<AppName>.app`. The helper below
packages an existing `.app` bundle without Apple signing:

```sh
APP_BUNDLE=/path/to/OpenPPP2.app ios/package-ipa.sh
```

The unsigned IPA is written to `bin/ipa/OpenPPP2.ipa`.

For jailbreak-style environments that need fake signing and have `ldid`
installed:

```sh
FAKESIGN=1 APP_BUNDLE=/path/to/OpenPPP2.app ios/package-ipa.sh
```

With explicit entitlements:

```sh
FAKESIGN=1 \
ENTITLEMENTS=/path/to/entitlements.plist \
APP_BUNDLE=/path/to/OpenPPP2.app \
ios/package-ipa.sh
```

## Self-signed IPA

Self-signing can package and install a normal app when the target device trusts
the provisioning profile. Packet Tunnel/VPN support additionally requires the
`com.apple.developer.networking.networkextension` entitlement in that profile;
without it the app may install but the tunnel extension will not start.

List local code signing identities:

```sh
security find-identity -v -p codesigning
```

Sign an existing `.app` bundle and package it as an IPA:

```sh
APP_BUNDLE=/path/to/OpenPPP2.app \
SIGNING_IDENTITY="Apple Development: Your Name (TEAMID)" \
PROVISIONING_PROFILE=/path/to/profile.mobileprovision \
ENTITLEMENTS=/path/to/entitlements.plist \
ios/sign-and-package-ipa.sh
```

The signed IPA is written to `bin/ipa/OpenPPP2.ipa`.

## Notes

The static archive build compiles objects without resolving final third-party
link dependencies. A complete app/extension link still needs iOS-built OpenSSL
and any non-header-only Boost libraries used by the selected runtime surface.
