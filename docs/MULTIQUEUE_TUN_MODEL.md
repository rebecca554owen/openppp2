# OpenPPP2 Linux Single Virtual NIC Multi-Queue Model Design

[Chinese Version](MULTIQUEUE_TUN_MODEL_CN.md)

## 1. Background

The project already has some basic multi-threaded virtual NIC reading capabilities on Linux:

- `TapLinux::OpenDriver()` has attempted to open a same-name tun device using `IFF_MULTI_QUEUE`.
- `TapLinux::Ssmt(context)` can reopen the same device and attach additional queue fds.
- The client `VEthernet` already has a concurrent reading path for `SSMT + mq`.
- The server-side `--mode=server` IPv6 transit tun has also recently been connected to the `mq` worker path.

However, the current implementation is still somewhat "implicit multi-queue":

- Externally, there is still only one `ITap` object.
- Internally, `TapLinux` holds multiple fds / `stream_descriptor`s.
- Multi-queue state is scattered across `TapLinux`, `VEthernet`, and `VirtualEthernetSwitcher`.
- Read/write paths partially rely on TLS to temporarily select the fd.

This implementation can continue to work, but if we want to further optimize throughput, achieve clearer thread binding, statistics, CPU affinity, and stricter lifecycle management, the current model will become increasingly hard to maintain.

## 2. Goals

The goal is not to create multiple virtual NICs, but to:

- Keep a single logical tun/tap virtual NIC.
- Explicitly model multiple queue instances in user space.
- Bind each worker thread to one queue fd.
- For the same connection or flow, maintain queue stickiness on both read and write sides as much as possible.
- Improve concurrent read/write throughput.
- Unify the client and server usage models for Linux multi-queue tun.

In one sentence:

> Single virtual NIC, multiple queue instances, multi-threaded binding, and TUN_FD affinity as much as possible, rather than multiple virtual NICs.

## 3. Additional Constraint: TUN_FD Thread Affinity

An important constraint needs to be clarified here:

- Multi-queue design must not only consider "concurrent reads".
- It must also consider `TUN_FD` affinity for the same connection or flow.

The reason is:

- TCP traffic read from a certain queue fd, if subsequently written back by the corresponding queue fd, is more likely to maintain locality on the kernel side.
- If a connection frequently crosses queues / fds in user space when writing back, even if logically correct, efficiency may drop.
- Therefore, "one thread per queue" is only the first layer; "try to keep the same flow sticky to a queue" is the second key requirement.

This means the future design should not simply be:

- Worker A reads a packet
- Any worker B can write back arbitrarily

But should instead try to achieve:

- Worker A / queue A reads data for a certain TCP connection
- Subsequent write-backs for this connection should preferably still land on queue A

## 4. Why Not Multiple Virtual NICs

It is not recommended to implement this requirement as multiple virtual NICs, for the following reasons:

1. It would significantly increase address, routing, DNS, and MTU configuration complexity.
2. Much of the current logic assumes there is only one tunnel interface.
3. Client routing, server IPv6 transit, DNS splitting, firewall, and static mode would all be forced to change significantly.
4. The essence of the problem is not "multiple devices", but "multiple parallel user-space send/receive channels on the same device".

Therefore, a more reasonable model should be:

- One logical device
- Multiple queues/instances
- Each thread consumes one queue

## 5. Issues in Current Code

The current Linux multi-queue capabilities mainly have these problems:

1. Queues are not first-class objects.
2. Lifecycle and state are scattered across multiple classes.
3. Server/client sides are prone to diverge as they each add logic.
4. It is difficult to do statistics, logging, and fault isolation for a single queue.
5. If we later want to do CPU affinity, dynamic scaling, and queue-level scheduling, it will be very hard to maintain.
6. The old `SSMT-model` was introduced mainly for client-vnet performance and is not suitable to continue expanding as a unified model for future server/client.

Current specific manifestations include:

- `TapLinux` internally holds `tun_ssmt_sds_`, `tun_ssmt_fds_size_`.
- `VEthernet` manages multi-queue activation state via `ssmt_mq_to_take_effect_`.
- `TapLinux::Output()` decides which fd to write via `tun_fd_` in TLS.
- Server-side IPv6 transit tun only recently explicitly connected to the `mq` worker.

The existing implementation actually already implicitly contains some awareness of "fd affinity":

- The Linux path puts `tun_fd_` into TLS.
- Certain data processing paths try to reuse the fd from which the data was read for writing back.

But this part is still implicit and has not been elevated to a formal model.

All of this shows:

- The functional foundation already exists
- But the abstract model is not yet clear enough

## 6. Proposed Model

It is recommended to split the Linux tun/tap abstraction into two layers.

### 6.1 Logical Device Layer

Retain a logical `ITap` / `TapLinux` responsible for device-level capabilities:

- Create and destroy device
- Configure IPv4 / IPv6 address
- Configure routing, DNS, MTU
- Device-level lifecycle management

### 6.2 Queue Instance Layer

Add explicit queue objects, for example:

- `TapLinuxQueue`
- Or `ITapQueue`
- Or `TapChannel`

Each instance represents one queue fd on the same device, responsible for:

- Holding fd / `stream_descriptor`
- Holding bound `io_context` or worker
- Starting a separate read loop
- Separate shutdown and reclamation
- Optional per-queue statistics
- Exposing a stable queue identity for connection/flow binding

This way the structure is clearer:

- `TapLinux` is the logical device
- `TapLinuxQueue` is a parallel read/write queue instance on the device

### 6.3 Connection/Flow-to-Queue Binding Layer

It is recommended to explicitly add a layer of "flow-to-queue binding semantics", at least covering TCP:

- If the same TCP connection is read by queue A
- Subsequent writes should preferably continue to be handled by queue A

Optional implementation methods include:

1. Connection object explicitly records queue id
2. Connection object explicitly records queue fd
3. Map 5-tuple or connection primary key to queue id

This binding layer does not necessarily require "absolutely prohibiting cross-queue", but should:

- Default to preferring the original queue
- Only switch upon connection migration, queue shutdown, or abnormal fallback

Otherwise, even if multi-queue concurrent reading is already working, it will be difficult to achieve optimal efficiency.

## 7. Benefits

After moving to the "single device, multiple explicit queue instances" model, these gains will be realized:

1. Clearer semantics
2. Clearer lifecycle
3. Server/client can reuse the same queue model
4. Easier to do statistics, logging, and problem isolation
5. Easier to support CPU affinity, NUMA, dynamic queue count adjustment
6. Easier to formally express connection-to-queue stickiness and affinity
7. More suitable for subsequent performance optimization without breaking existing business logic

## 8. Recommended Evolution Steps

It is recommended to advance in phases, rather than refactoring all callers at once.

### Step 1: Make Queue Objects Explicit

Goal:

- Do not change most external call patterns
- First organize the implicit fd list inside `TapLinux` into an explicit queue object list

Recommended changes:

- From:
  - `tun_ssmt_sds_`
  - `tun_ssmt_fds_size_`
- To:
  - `vector<shared_ptr<TapLinuxQueue>> queues_`

### Step 2: Introduce Queue Affinity Semantics

After queue objects are made explicit, do not stop at "multiple queues can work", but continue to add:

- Connection-to-queue binding relationship
- Default write-back prefers the original queue
- Queue shutdown migration policy

This step is to evolve the current implicit TLS fd affinity into a formal model.

### Step 3: Unify Queue Interface

Gradually evolve the current historically-named:

- `Ssmt(context)`

To clearer interfaces, for example:

- `OpenQueue(context)`
- `OpenQueues(count, mq_mode)`
- `GetQueueCount()`
- `StopQueues()`

This reduces misuse of the "SSMT" historical concept by upper layers.

### Step 4: Unify Server/Client Usage

Currently both client and server are already using Linux multi-queue capabilities, but the entry points are not unified.

Also note:

- It is not recommended to continue letting server/client directly "refer to the original SSMT-model" to expand individually.
- The original `SSMT-model` was designed for the client-vnet performance scenario.
- In the future it should be treated as a historical implementation source, not as the name of a new unified architecture.

The final goal is to have:

- Client main tunnel
- Server IPv6 transit tun

Both go through the same queue management interface.

## 9. Recommendations for the Current Stage

Combined with the current code status, the most realistic next step is not to create multiple virtual NICs, but to:

1. Keep a single tun/tap device
2. Abstract the multi-queue implementation into explicit queue objects
3. Clarify the connection-to-queue stickiness/affinity policy
4. Unify client/server queue lifecycle and worker binding methods
5. Then build further performance optimizations on this basis

## 10. Summary

The recommended direction is:

- Not multiple virtual NICs
- But a single virtual NIC multi-queue instance model

The current repository already has the foundation to implement this route. Subsequent work should focus on:

- Abstraction clarity
- Queue affinity semantics clarity
- Lifecycle unification
- Server/client reuse
- Multi-queue observability and maintainability improvements

This route is more stable than "continuing to pile implicit fd lists", and more aligned with the project's current architecture than "rebuilding into multiple virtual NICs".
