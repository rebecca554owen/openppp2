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
| C++ standalone unit tests (`tests/cpp`) | lint: `bash tools/check_include_boundaries.sh`, `bash tools/check_vcxproj_sources.sh`; test/build: `scripts/run-cpp-tests.sh` (cmake+ninja+clang → `ctest`); TSan: `scripts/run-cpp-tsan-tests.sh` (separate `build/test-tsan` dir, `ENABLE_TSAN=ON`, mutually exclusive with ASan/UBSan) | Does **not** need the full native dep tree. See `docs/TESTING.md`. |
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

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **openppp2** (44317 symbols, 88035 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in terminal first.

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `gitnexus_context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `gitnexus_rename` which understands the call graph.
- NEVER commit changes without running `gitnexus_detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/openppp2/context` | Codebase overview, check index freshness |
| `gitnexus://repo/openppp2/clusters` | All functional areas |
| `gitnexus://repo/openppp2/processes` | All execution flows |
| `gitnexus://repo/openppp2/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
