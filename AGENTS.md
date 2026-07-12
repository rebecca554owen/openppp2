# AGENTS.md

## Cursor Cloud specific instructions

OPENPPP2 is a cross-platform C++ VPN/tunnel engine (the `ppp` binary) plus
management tooling (Go Guardian daemon + Svelte Web UI), and mobile apps
(Android/iOS). The startup update script installs the C++ test toolchain
(`cmake ninja-build clang llvm libboost-all-dev libssl-dev libstdc++-14-dev`).
Go 1.22 and Node 22 are already in the base image.

### What the dev environment covers

| Service | Lint / Test / Build / Run | Notes |
|---------|---------------------------|-------|
| C++ standalone unit tests (`tests/cpp`) | lint: `bash tools/check_include_boundaries.sh`, `bash tools/check_vcxproj_sources.sh`; test/build: `scripts/run-cpp-tests.sh` (cmake+ninja+clang → `ctest`) | Does **not** need the full native dep tree. See `docs/TESTING.md`. |
| Go Guardian (`go/guardian`) | test: `go test ./...`; build: `go build .`; run: `./guardian --config=guardian.json` | HTTP API + embedded Web UI on `127.0.0.1:18080`. |

### Non-obvious caveats

- **clang needs `libstdc++-14-dev`.** clang-18 selects the GCC-14 toolchain, but
  the base image only ships `libstdc++-13-dev`, so linking fails with
  `cannot find -lstdc++` until `libstdc++-14-dev` is installed (in the update
  script).
- **Guardian Web UI is pre-built and checked in** at `go/guardian/webui/dist`
  and embedded via `go:embed`, so the Guardian binary builds/runs without Node.
  Only run `npm ci && npm run dev` (or `npm run build`) in `go/guardian/webui`
  if you are changing the frontend.
- **Guardian login password = `auth.jwtSecret`** in the guardian config JSON. On
  first run Guardian generates a random secret and persists it to the config
  file; set a known `jwtSecret` in a `guardian.json` to log into the Web UI. The
  REST API is under the `/api/v1` prefix (e.g. `POST /api/v1/auth/login` with
  body `{"password":"<jwtSecret>"}`).
- **Creating a profile via the Web UI "Add" button** posts empty JSON `{ }`,
  which the backend rejects (`profile.JSON does not contain a known ppp key`).
  Seed profiles with valid content via `PUT /api/v1/profiles/{name}`, then
  edit/validate/save them through the UI.

### Out of scope in this environment

- **The full `ppp` core binary** (top-level `CMakeLists.txt`) is **not** built
  here: it requires third-party libraries (Boost 1.86, OpenSSL 3.0.13, jemalloc)
  under `THIRD_PARTY_LIBRARY_DIR` (default `/root/dev`), which is not provisioned.
  The `tests/cpp` suite covers C++ logic without that tree.
- **Android / iOS** apps need Flutter + Android NDK / Xcode.
- **Go managed backend** (`go/ppp`) needs MySQL + Redis (sentinel).
