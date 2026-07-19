# Testing
> Status: Active
> Type: Development
> Last verified: 63fc030

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and documentation links, 2026-07-18.
> **Parent index:** [Back to index](README.md)


OpenPPP2 has unit tests for C++, Guardian Go logic, Flutter UI helpers, and iOS shared logic. GitHub Actions workflow **Test - Unit** runs these suites on pull requests to `main`.

## RED/GREEN Policy

1. Write or preserve a failing regression test first.
2. Implement or fix until it passes.
3. Record the break recipe in `tests/red-manifest/` for new regression suites.

At least 40% of cases per suite should be negative, boundary, or regression tests when adding new coverage.

## C++

Top-level project tests:

```bash
cmake -B build-test -DENABLE_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-test
ctest --test-dir build-test --output-on-failure
```

Standalone regression tests:

```bash
scripts/run-cpp-tests.sh
scripts/run-cpp-coverage.sh
```

The standalone C++ suite includes focused security and protocol regression tests that do not require a full native dependency tree, including DNS buffer parsing, P2P replay-window checks, Base64 handling, and Linux IPv6 sysctl validation.

## Go Guardian

```bash
cd go/guardian
go test ./...
```

## Flutter

```bash
cd android
flutter test
```

## iOS Logic

```bash
cd ios/App
./run-tests.sh
```

## Coverage

Top-level LLVM coverage:

```bash
chmod +x scripts/coverage.sh
./scripts/coverage.sh
```

Standalone C++ coverage writes `build/coverage/summary.txt`:

```bash
scripts/run-cpp-coverage.sh
```

## Smoke Test

Requires a built `bin/ppp` binary and a reachable server in the config:

```bash
chmod +x tools/proxy_mode_smoke.sh
PPP_BIN=./bin/ppp CONFIG=./appsettings.json ./tools/proxy_mode_smoke.sh
```

## Test Layout

```text
tests/
  CMakeLists.txt
  unit/
    test_application_mode.cpp
    test_tap_stub.cpp
    test_proxy_defaults.cpp
  cpp/
    base64_test.cpp
    dns_buffer_test.cpp
    dns_message_test.cpp
    dns_server_validation_test.cpp
    dns_wire_validation_test.cpp
    p2p_replay_window_test.cpp
    sysctl_validation_test.cpp
  red-manifest/
```

Android Flutter tests also include native-service static regressions such as `android/test/vpn_ipv6_leak_protection_test.dart`, which verifies the Kotlin VPN builder keeps IPv6 leak protection fail-closed.

## Android Instrumentation

Instrumentation tests live in `android/android/app/src/androidTest/` and need an emulator or device.

`app/src/debug/AndroidManifest.xml` removes `android:process` from `PppVpnService`, so instrumentation always runs the service in the app process. Anything that depends on the release multi-process layout — cross-process state delivery in particular — cannot be reproduced there and is covered by the source checks in `tests/tooling/test_runtime_ui_wiring.py` instead. Keep that in mind before concluding a cross-process path is proven by a green device run.

## CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `ENABLE_TESTS` | OFF | Build top-level `openppp2_tests` and register CTest targets |
| `ENABLE_COVERAGE` | OFF | Add LLVM coverage flags where supported |

Do not combine `ENABLE_COVERAGE` with `ENABLE_ASAN` in the same build.

## Route and DNS Architecture Gates

```bash
python3 -m unittest tests.tooling.test_repository_layout -v
python3 tools/check_repository_layout.py
python3 tools/check_vcxproj_sources.py
cmake -S tests/cpp -B build/test -G Ninja
cmake --build build/test
ctest --test-dir build/test --output-on-failure
```

The layout check rejects concrete Switcher/Exchanger names in DNS and route public headers, legacy `RouteHostPorts`/`DnsHostPorts` service locators, mutable container ports, and new declaration-fragment `.inc` files.

## Documentation and Runtime Contract Gates

```bash
python3 -m unittest tests.tooling.test_check_docs -v
python3 tools/check_docs.py
bash scripts/test-runtime-contract.sh cpp
```

CI invokes the same runtime-contract script with `dart` and `swift` in the Flutter and macOS jobs. All three
loaders use `tests/contracts/runtime-snapshot` directly, and `SHA256SUMS` prevents fixture drift.

## Linux Namespace Route/DNS Rollback

The integration test requires root and `iproute2`:

```bash
sudo bash tests/integration/linux/route_dns_rollback.sh
```

It compares the namespace route table and namespace-local resolver file with their baselines after both a normal
stop and a partial apply failure. CI uploads the before/after snapshots for inspection.

## Lifecycle Sanitizers

```bash
bash scripts/run-lifecycle-sanitizers.sh
```

The sanitizer gate builds the runtime lifecycle, ordered stop pipeline, 100-cycle client lifecycle stress,
Route coordinator, and DNS controller tests with ASan/UBSan. The stress target covers every startup phase,
concurrent duplicate Stop ownership, stale-generation completion, rollback failure, and deterministic resource
release. Platform handle and namespace evidence remains the responsibility of the platform CI and device jobs.
