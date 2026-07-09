# OpenPPP2 iOS App

This directory contains a minimal iOS host app plus a Packet Tunnel Extension target.

## Targets

- `OpenPPP2`: host app that embeds the extension.
- `OpenPPP2PacketTunnel`: `NEPacketTunnelProvider` extension that links `bin/OpenPPP2.xcframework`.

## Unsigned build

Build the OpenPPP2 XCFramework first:

```sh
ios/build-xcframework.sh
```

Build OpenSSL for iOS:

```sh
ios/build-openssl.sh
```

Then build the app and package an unsigned IPA:

```sh
SDK=iphoneos ios/App/build-unsigned.sh
```

For simulator builds:

```sh
SDK=iphonesimulator CONFIGURATION=Debug ios/App/build-unsigned.sh
```

By default, the app build script uses:

- `bin/openssl-ios/iphoneos-arm64` for device builds.
- `bin/openssl-ios/iphonesimulator-x86_64` for simulator builds.

You can override these with `OPENSSL_INCLUDE_DIR` and `OPENSSL_LIB_DIR`. The OpenSSL paths must point to iOS or iOS-simulator libraries. Homebrew's macOS OpenSSL dylibs cannot be linked into an iOS app extension.

## Signing note

The project keeps signing manual and allows `CODE_SIGNING_ALLOWED=NO` for unsigned package creation. A normal iPad still requires a valid Apple-signed IPA with the Network Extension entitlement. Unsigned or fake-signed IPAs are only useful for environments that explicitly allow them, such as TrollStore or jailbreak workflows.

## Apple Developer signed build

After signing in to Xcode with a paid Apple Developer account, create or verify an Apple Development certificate in Xcode Settings, then build with a unique bundle id:

```sh
DEVELOPMENT_TEAM=6YS5L5WRBR \
OPENPPP2_BUNDLE_ID=com.example.openppp2 \
SDK=iphoneos \
CONFIGURATION=Release \
ios/App/build-signed.sh
```

The extension bundle id is derived as `${OPENPPP2_BUNDLE_ID}.PacketTunnel`, and the signed IPA is written to `bin/ipa/OpenPPP2-iphoneos-signed.ipa`.
