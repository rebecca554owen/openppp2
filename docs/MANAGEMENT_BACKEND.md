# Management Backend

[中文版本](MANAGEMENT_BACKEND_CN.md)

## Role

The Go service under `go/` is the management and persistence side of OPENPPP2, not the packet data plane.

Its job is to support the C++ server runtime with:

- node authentication
- user lookup
- quota and expiry state
- traffic accounting
- HTTP management APIs
- Redis and MySQL persistence

## Why The Backend Is Separate

The split is clear from code:

- C++ owns adapters, routes, sockets, tunnel sessions, and packet forwarding
- Go owns business state, storage, and management APIs

This is a healthy infrastructure separation. Data-plane code and persistence-heavy control-plane code evolve for different reasons.

## Connection Model

The Go backend exposes a WebSocket endpoint and HTTP endpoints.

The C++ server connects to the WebSocket side through `VirtualEthernetManagedServer`.

That control link is used for:

- backend connection handshake
- echo/health
- session authentication
- traffic upload

## Wire Format

The backend protocol is not plain JSON lines. From code, packets are framed as:

- 8 hex characters containing payload length
- followed by a JSON object

The JSON object includes fields such as:

- `Id`
- `Node`
- `Guid`
- `Cmd`
- `Data`

## Main Commands

Observed command values include:

- `1000`: echo
- `1001`: connect
- `1002`: authentication
- `1003`: traffic

This is a small, purpose-built management protocol between the C++ node and the Go backend.

## HTTP API Role

The Go backend also exposes HTTP endpoints for administrative actions such as:

- create or modify user state
- load or reload user records
- query server records
- reload server records

This keeps operational and provisioning work outside the packet engine itself.

## Persistence Model

The Go side uses:

- Redis for distributed/cache-like state
- MySQL through GORM for durable state

That again reinforces the split: the C++ process should forward packets, while the Go service should maintain business and storage records.

## Why This Matters To Readers Of The C++ Code

Because it explains why some policy objects appear incomplete in the local runtime until backend responses arrive.

The server runtime is prepared to cooperate with external policy, but it still keeps enough local structure to remain a functioning network node.

## Operational Meaning

If you deploy OPENPPP2 without the backend, the tunnel can still function in a reduced local mode.

If you deploy it with the backend, you gain:

- centralized authentication
- centralized traffic accounting
- centralized node and user management

That makes the system suitable for both standalone infrastructure nodes and managed service deployments.
