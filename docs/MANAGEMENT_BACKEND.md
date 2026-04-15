# Management Backend

[中文版本](MANAGEMENT_BACKEND_CN.md)

## Role

The Go service under `go/` is the management and persistence side of OPENPPP2, not the packet data plane.

It supports the C++ server runtime with:

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

## System Architecture Overview

```mermaid
graph TB
    subgraph "C++ Data Plane"
        VE[VirtualEthernet<br/>Adapter]
        ROUTE[Routing Engine]
        SOCKET[Socket Management]
        TUNNEL[Tunnel Session]
        FORWARD[Packet Forwarding]
    end

    subgraph "Go Control Plane"
        WS[WebSocket Server]
        HTTP[HTTP API]
        AUTH[Authentication]
        TRAFFIC[Traffic Statistics]
        POLICY[Policy Distribution]
    end

    subgraph "Persistence Layer"
        REDIS[(Redis Cache)]
        MYSQL[(MySQL Database)]
    end

    VE --> ROUTE
    ROUTE --> SOCKET
    SOCKET --> TUNNEL
    TUNNEL --> FORWARD

    WS --> AUTH
    WS --> TRAFFIC
    WS --> POLICY
    HTTP --> AUTH

    AUTH --> REDIS
    TRAFFIC --> REDIS
    POLICY --> REDIS
    REDIS --> MYSQL
```

## Backend Architecture Details

### Core Component Structure

The management backend is built using Go, with the core structure defined in `ManagedServer`:

```go
type ManagedServer struct {
    sync.Mutex
    disposed      bool
    ppp           *io.WebSocketServer    // WebSocket server
    configuration *ManagedServerConfiguration  // Configuration
    redis         *io.RedisClient        // Redis client

    servers map[int]*tb_server       // Server node mapping
    nodes   map[int]*_vpn_server    // WebSocket connection mapping
    users   map[string]*_vpn_user    // User session mapping
    dirty   map[string]bool         // Dirty data flag

    db_master *io.DB               // MySQL master
    db_salves *list.List          // MySQL slave list
}
```

### Data Flow Architecture

```mermaid
flowchart LR
    subgraph "Entry Layer"
        WS[WebSocket<br/>Connection]
        HTTP[HTTP<br/>Request]
    end

    subgraph "Processing Layer"
        ECHO[Heartbeat Processing]
        AUTH[Authentication]
        TRAFFIC[Traffic Processing]
        CTRL[Control Processing]
    end

    subgraph "Storage Layer"
        REDIS[(Redis<br/>Cache)]
        MYSQL[(MySQL<br/>Persistence)]
    end

    WS --> ECHO
    WS --> AUTH
    WS --> TRAFFIC
    HTTP --> CTRL

    ECHO --> REDIS
    AUTH --> REDIS
    TRAFFIC --> REDIS
    CTRL --> MYSQL
```

### Thread Model Design

```mermaid
sequenceDiagram
    participant C as C++ Node
    participant G as Go Backend
    participant R as Redis
    participant M as MySQL

    C->>G: WebSocket Connection
    G->>G: Accept Connection
    loop Heartbeat Cycle
        C->>G: ECHO (1000)
        G->>C: ECHO Response
    end
    C->>G: AUTH (1002)
    G->>R: Query User Cache
    R-->>G: Cache Hit
    G->>C: User Policy Data
    Note over G,M: Fallback to MySQL on miss
    C->>G: TRAFFIC (1003)
    G->>R: Update Cache
    G->>M: Periodic Sync
```

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

### Packet Structure Definition

```go
type _Packet struct {
    Id   int    `json:"Id"`   // Packet sequence number
    Node int    `json:"Node"`  // Server node ID
    Guid string `json:"Guid"`  // User GUID
    Cmd  int    `json:"Cmd"`  // Command type
    Data string `json:"Data"` // Data payload
}
```

The JSON object includes fields such as:

- `Id` - Packet identifier
- `Node` - Server node number
- `Guid` - User global unique identifier
- `Cmd` - Command type
- `Data` - Data payload

### Protocol Header Format

```
┌────────────┬──────────────────────────────────────┐
│  8 Hex   │          JSON Payload               │
│(Length)   │         (JSON Data)             │
└────────────┴──────────────────────────────────────┘
```

## Main Commands

Observed command values include:

| Command Code | Name | Function Description | Flow Direction |
|-------------|------|-------------------|----------------|
| 1000 | ECHO | Heartbeat/Health check | Bidirectional |
| 1001 | CONNECT | Node connection handshake | Request->Response |
| 1002 | AUTHENTICATION | User authentication | Request->Response |
| 1003 | TRAFFIC | Traffic reporting | Request->Response |

### Command Processing Flow

```mermaid
flowchart TD
    A[Receive Packet] --> B{Parse Cmd}
    B -->|1000| C[ECHO Processing]
    B -->|1001| D[CONNECT Processing]
    B -->|1002| E[AUTH Processing]
    B -->|1003| F[TRAFFIC Processing]

    C --> C1[Update node active time]
    C --> C2[Return original packet]

    D --> D1[Validate Key]
    D --> D2[Lookup server]
    D --> D3[Add node mapping]

    E --> E1[Validate GUID format]
    E --> E2[Lookup server]
    E --> E3[Query user data]
    E --> E4[Assemble policy response]

    F --> F1[Parse traffic tasks]
    F --> F2[Update Redis cache]
    F --> F3[Update local memory]
    F --> F4[Return latest status]
```

This is a small, purpose-built management protocol between the C++ node and the Go backend.

## HTTP API Endpoints

The Go backend also exposes HTTP endpoints for administrative actions.

### API List

| Endpoint Path | Method | Function | Parameters |
|---------------|--------|----------|------------|
| `/consumer/set` | POST | Set/Update user | key, guid, tx, rx, seconds, qos |
| `/consumer/new` | POST | Create new user | key, guid, tx, rx, seconds, qos |
| `/consumer/load` | GET | Load user (no reload) | key, guid |
| `/consumer/reload` | GET | Reload user data | key, guid |
| `/server/get` | GET | Get server | node |
| `/server/all` | GET | All server list | - |
| `/server/load` | POST | Reload server | - |

### Error Codes

| Error Code | Meaning | Description |
|-----------|---------|-------------|
| 0 | Success | Operation successful |
| 1 | Too fast | Concurrency control rate limit |
| 2 | JSON error | Parse failed |
| 11 | Parameter error | Invalid parameter |
| 12 | GUID error | Invalid GUID format |
| 13 | Node error | Invalid node number |
| 14 | Key error | Invalid auth key |
| 15 | TX error | Invalid upload traffic parameter |
| 16 | RX error | Invalid download traffic parameter |
| 17 | QoS error | Invalid bandwidth parameter |
| 18 | Seconds error | Invalid validity period parameter |
| 101 | Database error | MySQL access failure |
| 151 | Redis error | Redis access failure |
| 152 | Redis conflict | Cache key conflict |
| 201 | User not exist | User record does not exist |
| 202 | User not logged in | User not loaded to memory |
| 203 | User already exists | User record duplicate |
| 301 | Server not exist | Server record does not exist |

### HTTP Response Format

```json
{
    "Code": 0,
    "Message": "ok",
    "Tag": "{\"Guid\":\"...\",\"IncomingTraffic\":...}"
}
```

### Detailed API Specifications

#### 1. Set User (consumer/set)

Set or update traffic quota and validity period for specified user.

**Request Example**
```
POST /consumer/set?key=configKey&guid=userGUID&tx=1073741824&rx=1073741824&seconds=86400&qos=100000
```

**Response Example**
```json
{
    "Code": 0,
    "Message": "ok",
    "Tag": "{\"Guid\":\"A1B2C3D4E5F6\",\"IncomingTraffic\":1073741824,\"OutgoingTraffic\":1073741824,\"ExpiredTime\":86400,\"BandwidthQoS\":100000}"
}
```

#### 2. Create User (consumer/new)

Create a brand new user record.

**Request Example**
```
POST /consumer/new?key=configKey&guid=newUserGUID&tx=1073741824&rx=1073741824&seconds=86400&qos=100000
```

**Response Example**
```json
{
    "Code": 0,
    "Message": "ok",
    "Tag": ""
}
```

#### 3. Load User (consumer/load)

Load user data to local cache.

**Request Example**
```
GET /consumer/load?key=configKey&guid=userGUID
```

**Response Example**
```json
{
    "Code": 0,
    "Message": "ok",
    "Tag": "{\"Guid\":\"A1B2C3D4E5F6\",\"IncomingTraffic\":536870912,\"OutgoingTraffic\":536870912,\"ExpiredTime\":43200,\"BandwidthQoS\":50000}"
}
```

#### 4. Reload User (consumer/reload)

Force reload user data from database.

**Request Example**
```
GET /consumer/reload?key=configKey&guid=userGUID
```

#### 5. Get Server (server/get)

Query specified server node configuration.

**Request Example**
```
GET /server/get?node=1
```

**Response Example**
```json
{
    "Code": 0,
    "Message": "",
    "Tag": "{\"Id\":1,\"Link\":\"tcp://0.0.0.0:443\",\"Name\":\"Main Server\",\"Protocol\":\"TCP\",\"Transport\":\"UDP\",\"Masked\":true,\"BandwidthQoS\":100000}"
}
```

#### 6. All Servers (server/all)

Get all loaded server node list.

**Request Example**
```
GET /server/all
```

**Response Example**
```json
{
    "Code": 0,
    "Message": "",
    "Tag": "{\"List\":[{\"Id\":1,...},{\"Id\":2,...}]}"
}
```

This keeps operational and provisioning work outside the packet engine itself.

## Authentication Flow

### User Authentication Sequence Diagram

```mermaid
sequenceDiagram
    participant Client as C++ Client
    participant WS as WebSocket
    participant Cache as Redis Cache
    participant DB as MySQL

    Client->>WS: AUTH packet<br/>Guid=UserID, Node=NodeID
    WS->>Cache: Check local memory cache
    alt Cache hit
        Cache-->>WS: User data
    else Cache miss
        WS->>Cache: Query Redis
        alt Redis hit
            Cache-->>WS: User data
        else Redis miss
            WS->>DB: Query MySQL
            DB-->>WS: User data
            WS->>Cache: Write to Redis cache
        end
    end
    WS->>WS: Calculate QoS policy
    WS->>Client: Return auth response<br/>with quota, expiry time, QoS
```

### Authentication Detailed Logic

```mermaid
flowchart TD
    Start([Start Auth]) --> G[Receive AUTH packet]
    G --> G1{Validate GUID format}
    G1 -->|Invalid| E1[Return -1]
    G1 -->|Valid| N[Lookup server]
    N --> N1{Server exists?}
    N1 -->|No| E2[Return -1]
    N1 -->|Yes| M[Query local cache]
    M --> M1{Cache hit?}
    M1 -->|Yes| Q[Calculate QoS]
    M1 -->|No| R[Query Redis]
    R --> R1{Redis hit?}
    R1 -->|Yes| Q
    R1 -->|No| D[Query MySQL]
    D --> D1{MySQL exists?}
    D1 -->|No| E3[Return user not exist]
    D1 -->|Yes| Q2[Calculate QoS]
    Q --> Response[Return policy data]
    Q2 --> Response
```

### Policy Data Structure

After successful authentication, the returned policy data:

```go
type _vpn_user struct {
    Guid             string `json:"Guid"`              // User GUID
    ArchiveTime      uint32 `json:"ArchiveTime"`      // Archive time
    IncomingTraffic int64  `json:"IncomingTraffic"` // Remaining download quota
    OutgoingTraffic int64  `json:"OutgoingTraffic"` // Remaining upload quota
    ExpiredTime      uint32 `json:"ExpiredTime"`      // Expiry timestamp
    BandwidthQoS    uint32 `json:"BandwidthQoS"`    // Bandwidth limit
}
```

## Policy Distribution Mechanism

### Policy Calculation Rules

```mermaid
flowchart LR
    subgraph Input
        U[User QoS config]
        S[Server QoS config]
    end

    subgraph Processing
        C{User QoS=0?}
    end

    subgraph Output
        R[Final QoS value]
    end

    U --> C
    C -->|Yes| S
    C -->|No| R
    S --> R
```

Policy priority:
1. If user has configured QoS, use user-configured QoS
2. Otherwise use server-configured default QoS

## Traffic Reporting and Statistics

### Traffic Reporting Flow

```mermaid
sequenceDiagram
    participant C as C++ Node
    participant G as Go Backend
    participant R as Redis
    participant M as MySQL

    C->>G: TRAFFIC packet<br/>Tasks=[{Guid,RX,TX},...]
    G->>R: Query cache
    R-->>G: User data
    G->>G: Calculate new quota
    G->>R: Mark dirty
    G->>R: Update cache
    G->>M: Periodic sync
```

### Traffic Task Format

**Request Data Format**
```json
{
    "Tasks": [
        {
            "Guid": "A1B2C3D4E5F6",
            "RX": "1048576",
            "TX": "524288"
        }
    ]
}
```

**Response Data Format**
```json
{
    "List": [
        {
            "Guid": "A1B2C3D4E5F6",
            "IncomingTraffic": 996710144,
            "OutgoingTraffic": 999475712,
            "ExpiredTime": 86400,
            "BandwidthQoS": 100000
        }
    ]
}
```

### Traffic Sync Mode

Traffic data uses a three-level sync mechanism:

```mermaid
flowchart TD
    A[Local Memory] -->|Periodic| B[Redis Cache]
    B -->|Periodic| C[MySQL Persistence]

    A -.->|Real-time query| B
    B -.->|Real-time query| C
```

| Storage Layer | Sync Frequency | Use |
|-------------|---------------|-----|
| Local memory | Real-time | Fast read/write |
| Redis | ~20 seconds | Distributed cache |
| MySQL | ~20 seconds | Persistence |

### Traffic Deduction Rules

```mermaid
flowchart LR
    R[Reported RX/TX] --> C[Add to current quota]

    C --> Q{Check result}
    Q -->|Negative| L[Correct to 0]
    Q -->|Non-negative| R2[Keep original]

    L --> D[Mark dirty]
    R2 --> D
```

Rule explanation:
- Reported traffic is added to user's current quota
- If deduction result is negative, correct to 0
- After modification, mark dirty for sync

## Node Status Management

### Node State Management

```mermaid
flowchart TD
    Start([Node Start]) --> Connect[CONNECT handshake]
    Connect --> V[Validate Key]
    V -->|Fail| E[Reject connection]
    V -->|Success| Add[Add to node mapping]

    Add --> Tick[Heartbeat tick]
    Tick --> A{Check timeout}
    A -->|Timeout| Close[Close connection]
    A -->|Normal| Resp[Respond to heartbeat]
```

### Timeout Configuration Parameters

| Parameter Name | Default Value | Description |
|----------------|---------------|-------------|
| node-websocket-timeout | 20 seconds | WebSocket timeout |
| node-mysql-query | 1 second | Server MySQL query lock timeout |
| user-mysql-query | 1 second | User MySQL query lock timeout |
| user-cache-timeout | 3600 seconds | Redis cache expiration time |
| user-archive-timeout | 20 seconds | Data archive cycle |

### Node Liveness Detection

```mermaid
sequenceDiagram
    participant N as C++ Node
    participant G as Go Backend

    loop 20 second cycle
        N->>G: ECHO (1000)
        G->>N: ECHO Response
        Note over G: Update timeout=now+20s
    end

    alt No message for 40 seconds
        G->>G: Trigger timeout cleanup
        G->>G: Close connection
    end
```

## Persistence Model

The Go side uses:

- Redis for distributed/cache-like state
- MySQL through GORM for durable state

That again reinforces the split: the C++ process should forward packets, while the Go service should maintain business and storage records.

### Storage Architecture

```mermaid
graph LR
    subgraph Clients
        WS[WebSocket]
        HTTP[HTTP API]
    end

    subgraph Redis
        RC[(User Cache)]
        SC[(Server Cache)]
        DM[(Dirty Mark)]
    end

    subgraph MySQL
        MU[User Table]
        MS[Server Table]
    end

    WS --> RC
    HTTP --> RC
    RC --> MU
    SC --> MS
    RC <--> DM
```

### Database Table Structure

**User Table (tb_user)**

| Field Name | Type | Description |
|------------|------|-------------|
| guid | Primary key | User unique identifier |
| incoming_traffic | int64 | Download traffic quota |
| outgoing_traffic | int64 | Upload traffic quota |
| expired_time | uint32 | Expiry timestamp |
| qos | uint32 | Bandwidth QoS configuration |

**Server Table (tb_server)**

| Field Name | Type | Description |
|------------|------|-------------|
| id | Primary key | Server ID |
| link | string | Connection address |
| name | string | Server name |
| kf/kx/kl/kh | int | Key parameters |
| protocol | string | Protocol type |
| protocol_key | string | Protocol key |
| transport | string | Transport type |
| transport_key | string | Transport key |
| masked | bool | Obfuscation enabled |
| plaintext | bool | Plain transmission |
| delta_encode | bool | Delta encoding |
| shuffle_data | bool | Data shuffling |
| qos | uint32 | Bandwidth limit |

## Why This Matters To Readers Of The C++ Code

Because it explains why some policy objects appear incomplete in the local runtime until backend responses arrive.

The server runtime is prepared to cooperate with external policy, but it still keeps enough local structure to remain a functioning network node.

## Deployment Configuration Example

```json
{
    "database": {
        "master": {
            "host": "localhost",
            "port": 3306,
            "user": "root",
            "password": "password",
            "db": "openppp2"
        },
        "max-open-conns": 100,
        "max-idle-conns": 10,
        "conn-max-life-time": 3600
    },
    "redis": {
        "addresses": ["localhost:6379"],
        "master": "mymaster",
        "db": 0,
        "password": "redis_password"
    },
    "key": "your_secret_key",
    "path": "/websocket",
    "prefixes": "localhost:8080",
    "interfaces": {
        "consumer-reload": "/consumer/reload",
        "consumer-load": "/consumer/load",
        "consumer-set": "/consumer/set",
        "consumer-new": "/consumer/new",
        "server-get": "/server/get",
        "server-all": "/server/all",
        "server-load": "/server/load"
    },
    "concurrency-control": {
        "node-websocket-timeout": 20,
        "node-mysql-query": 1,
        "user-mysql-query": 1,
        "user-cache-timeout": 3600,
        "user-archive-timeout": 20
    }
}
```

## High Availability Design

### Master-Slave Separation

```mermaid
graph TB
    subgraph "Read Request"
        R[HTTP/WS Request] --> LB[Load Balancer]
        LB --> RS[Redis]
        LB --> S[MySQL Slave]
    end

    subgraph "Write Request"
        W[Data Write] --> WM[Redis Master]
        WM --> MM[MySQL Master]
    end
```

### Connection Pool Configuration

| Configuration | Recommended Value | Description |
|---------------|-------------------|-------------|
| MaxOpenConns | 100 | Maximum open connections |
| MaxIdleConns | 10 | Maximum idle connections |
| ConnMaxLifetime | 3600 | Connection lifetime (seconds) |

## Monitoring and Logging

### Key Log Categories

| Log Type | Recorded Content |
|---------|------------------|
| User login | User GUID, node ID, auth result |
| Traffic reporting | User GUID, reported traffic, remaining quota |
| Data sync | Sync success/failure record |
| Connection status | Node connection/disconnection |

### Performance Metrics

| Metric | Description |
|--------|-------------|
| Online users | Current number of users in memory |
| Active connections | WebSocket connection count |
| QPS | Queries per second |
| Cache hit rate | Redis cache hit rate |
| Sync delay | Data sync delay time |

## Troubleshooting Guide

### Common Issues

| Symptom | Possible Cause | Solution |
|---------|----------------|----------|
| Connection rejected | Key validation failed | Check config Key |
| User not found | User not created | Use /consumer/new to create |
| Quota not updating | Sync delay | Wait 20 seconds or manually sync |
| Query timeout | Concurrency lock contention | Adjust concurrency control parameters |

### Diagnostic Commands

```bash
# View online connections
curl http://localhost:8080/server/all

# Query user status
curl "http://localhost:8080/consumer/load?key=xxx&guid=xxx"

# Reload user data
curl "http://localhost:8080/consumer/reload?key=xxx&guid=xxx"
```

## Operational Meaning

If you deploy OPENPPP2 without the backend, the tunnel can still function in a reduced local mode.

If you deploy it with the backend, you gain:

- centralized authentication
- centralized traffic accounting
- centralized node and user management

That makes the system suitable for both standalone infrastructure nodes and managed service deployments.