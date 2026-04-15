# Management Backend

[中文版本](MANAGEMENT_BACKEND_CN.md)

## Role

The Go service under `go/` is the management and persistence side of OPENPPP2, not the packet data plane.

## What It Does

The backend supports the C++ server runtime with:

- node authentication
- user lookup
- quota and expiry state
- traffic accounting
- HTTP management endpoints
- Redis and MySQL persistence

## Main Shape

The backend is built around `ManagedServer`.

It:

- loads managed configuration from OS args
- connects to Redis and MySQL
- exposes a WebSocket control link
- exposes HTTP admin endpoints
- runs a background tick loop
- syncs user and server state

## Wire Model

The control protocol is framed with an 8-hex-length prefix followed by JSON packets.

Observed commands include:

- `1000` ECHO
- `1001` CONNECT
- `1002` AUTHENTICATION
- `1003` TRAFFIC

## Why It Is Separate

C++ owns adapters, routes, sockets, sessions, and forwarding. Go owns business state, storage, and management APIs.

## Related Documents

- `DEPLOYMENT.md`
- `OPERATIONS.md`
- `SECURITY.md`
