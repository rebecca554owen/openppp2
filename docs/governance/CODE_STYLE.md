# Code Style and Module Boundaries

> Status: Active
> Type: Governance
> Last verified: a9cfec7

Use C++17, four spaces, no tabs, and the surrounding include/order conventions. Formatting applies to new and
changed code; inherited files are not mass-formatted.

| Location | Ownership |
|---|---|
| `ppp/app/runtime` | Runtime contract and lifecycle publication |
| `ppp/app/client/dns` | DNS policy, session lifetime, and reachability projection |
| `ppp/app/client/route` | Route state, transaction coordinator, and immutable plan input |
| `ppp/app/mux` | VMUX protocol, scheduling, and runtime state |
| `ppp/p2p` | Authenticated direct-channel primitives |
| Platform directories | OS calls and concrete adapters |
| `android`, `ios` | Presentation and platform bridges |

Prohibited patterns are enforced by `tools/check_repository_layout.py`: new `.inc` fragments, concrete-host names
in route/DNS public headers, mutable container pointers, reverse protocol dependencies, legacy service locators,
and route managers retaining a Switcher owner.
