# Operations And Troubleshooting

[中文版本](OPERATIONS_CN.md)

## Build Verification

### Windows

Preferred script:

```bat
build_windows.bat Release x64
```

Requirements:

- Visual Studio 2022
- Ninja
- vcpkg toolchain discoverable by the script

### Linux / WSL

```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j32
```

Requirements:

- CMake
- GCC or Clang with C++17 support
- third-party dependencies available under `/root/dev` unless overridden

## First Runtime Checks

Before debugging tunnel behavior, confirm:

- config file path is correct
- role is correct: `--mode=client` or `--mode=server`
- listener ports are not already occupied
- certificates and keys exist for WSS
- TUN/TAP adapter creation succeeds
- routes, DNS rules, and bypass files exist where configured

## Useful Runtime Commands

```bash
ppp --help
```

```bash
ppp --mode=server --config=./appsettings.json
```

```bash
ppp --mode=client --config=./appsettings.json
```

## What To Watch In Runtime Output

The application prints operational state such as:

- current mode
- remote URI or listener endpoints
- proxy state
- transport statistics
- session count on the server
- client network state
- DNS and IPv6 related state

This console output is the first place to look before deeper packet capture.

## Common Failure Classes

### 1. Build failure

Typical causes:

- missing vcpkg dependencies on Windows
- missing third-party libs under `/root/dev` on Linux
- compiler too old or wrong standard flags

### 2. Listener starts but clients cannot connect

Typical causes:

- wrong listen port
- local firewall or cloud security group blocking
- WSS certificate/key mismatch
- reverse proxy not forwarding WS/WSS correctly

### 3. Client connects but no traffic passes

Typical causes:

- TUN IP/gateway/mask mismatch
- routes not applied as expected
- split-tunnel bypass list too broad
- DNS rules steering traffic away from the tunnel
- server policy rejects or expires the session

### 4. Reverse mappings do not work

Typical causes:

- `server.mapping` disabled
- malformed `client.mappings`
- local service not listening on the configured `local-ip:local-port`

### 5. IPv6 works inconsistently

Typical causes:

- server IPv6 mode not enabled
- Linux-only server-side data-plane expectations applied to other platforms
- assigned prefix/gateway inconsistent with local routing state

## Logging And Evidence Collection

For serious faults, collect:

- full console output
- effective config file
- route tables before and after startup
- local firewall state
- packet capture on physical NIC and virtual adapter
- backend logs if `server.backend` is enabled

Avoid debugging with filtered fragments only. Preserve the full output path first.

## Change Verification Discipline

When code changes affect a platform-specific path, verify on that platform:

- Windows changes: build on Windows
- Linux changes: build on Linux/WSL
- macOS changes: verify in a macOS toolchain before release
- Android changes: verify in the Android/NDK toolchain before release

For documentation-only changes, no binary rebuild is required.

## Operational Baselines

- keep one known-good config per deployment role
- keep route lists and DNS rules under change control
- minimize simultaneous feature activation during initial rollout
- test one transport style first, then add mux, mappings, static mode, or IPv6 incrementally

## Escalation Path For Debugging

1. Check config and runtime output
2. Check listeners, routes, DNS, and firewall state
3. Check client/server session establishment
4. Check packet flow on virtual adapter and physical NIC
5. Check backend integration only after data-plane basics are confirmed

## Related Documents

- [`CONFIGURATION.md`](CONFIGURATION.md)
- [`DEPLOYMENT.md`](DEPLOYMENT.md)
- [`SECURITY.md`](SECURITY.md)
