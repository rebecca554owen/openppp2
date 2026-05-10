# openppp2 深度代码优化与安全审核报告

> 生成时间：2026-05-09（首版） / 2026-05-09（续审追加 §14）  
> 范围：`/mnt/e/Desktop/openppp2-next/openppp2`  
> 语言：中文  
> 类型：性能、安全、协议、构建依赖、可维护性综合审核  
> 修订：§14 聚焦近期 2 个未推送提交（`ed61d5b`、`d483885`）与 7 个未提交工作区文件的针对性审核，与 §1–§13 的项目全景审核互为补充

---

## 1. 审核范围

本次审核通过多个 subagent 并行完成，覆盖以下维度：

- **安全审计**：加密、TLS、密钥、认证、输入校验、日志泄露、命令注入、证书与配置风险。
- **性能与架构审计**：传输层、网络层、DNS、Firewall、内存池、异步写队列、锁竞争、可扩展性。
- **传输协议审计**：握手状态机、帧长度、base94/obfuscation、WebSocket、DoS、teardown 并发。
- **构建与供应链审计**：CMake、CI、vendored 依赖、Android 依赖、安全编译选项、artifact 发布。
- **代码质量审计**：`stdafx.h`、配置系统、错误码体系、跨平台条件编译、生命周期管理、测试缺失。

### 主要代码范围

- `ppp/transmissions/*`
- `ppp/cryptography/*`
- `ppp/ssl/*`
- `ppp/net/*`
- `ppp/io/*`
- `ppp/threading/*`
- `ppp/coroutines/*`
- `ppp/app/client/*`
- `ppp/app/server/*`
- `ppp/app/protocol/*`
- `ppp/configurations/*`
- `ppp/diagnostics/*`
- `ppp/stdafx.h`
- `linux/*`, `windows/*`, `darwin/*`, `android/*`
- `CMakeLists.txt`, `.github/workflows/*`, `build-*.sh`, `build_windows.bat`
- `common/*`, `go/*`, `go/guardian/webui/*`
- `appsettings.json`, `go/appsettings.json`, `starrylink.net.key`, `starrylink.net.pem`, `cacert.pem`

> 复核说明：维护者确认根目录部分配置文件、证书和私钥为示例文件。本文据此将 `starrylink.net.key` / `starrylink.net.pem` 从 P0「生产密钥泄露」中排除；但由于 CI/release 当前会打包这些示例资产，且程序默认搜索 `./appsettings.json`，仍保留为「示例私钥/证书与弱配置误用风险」。`cacert.pem` / `cacert.sha256` 为公共 CA bundle 及其校验值，不属于私钥或生产凭据泄露范围。

### 项目规模

- 核心源码总量约：`105,063` 行。
- 主要语言：C++17、Go、JavaScript/Svelte、CMake、Shell、PowerShell。
- 主要依赖：Boost.Asio/Beast、OpenSSL、jemalloc、lwIP、JsonCpp/nlohmann/json、Svelte/Vite、Android NDK。

---

## 2. 总体结论

openppp2 是一个复杂的跨平台网络隧道/代理/VPN 运行时，覆盖传输加密、虚拟网卡、DNS、路由、WebSocket、服务端交换器、客户端网络切换器等模块。

代码中已有一些工程化改进：

- 错误码体系使用 X-macro 管理。
- `ITransmission` 主状态已部分改为 atomics。
- 部分 Android DNS/timer 崩溃路径已有集中状态对象修复。
- 部分 DNS redirect buffer 已从共享改为 per-call。
- IPv4 broadcast 已有限制。
- IPv6 NDP proxy 已避免每 tick 直接 shell/sysctl。

但当前仍存在高优先级安全、性能、并发和供应链风险。

最高优先级问题：

1. 根目录包含示例 RSA 私钥/证书和示例配置；经维护者说明，这些文件应按示例资产处理，不再直接定性为生产密钥泄露。但当前 CI/release 仍会把示例私钥、证书和 `appsettings.json` 打包进部分 artifact，且程序默认会加载 `./appsettings.json`，存在用户误用、弱默认配置传播和安全边界不清风险。
2. 默认/示例加密设计偏弱：MD5 KDF、无 salt、RC4、AES-CFB 无认证、默认 key 可预测、默认 plaintext，示例配置也包含固定协议密钥，应明确禁止生产复用。
3. TLS/WSS 路径存在证书校验关闭和主机名校验缺失风险。
4. 异步写队列缺少背压，可能被慢连接或恶意连接拖到 OOM。
5. 传输帧长度缺少策略上限，存在内存/slowloris DoS。
6. 多个 Dispose/Finalize/Socket/Timer 路径存在并发竞态。
7. 构建系统依赖硬编码路径、静态第三方库、vendored 依赖和过期 Android OpenSSL/NDK。
8. 项目几乎没有 C++ 测试、lint、静态分析、安全扫描。

---

## 3. 安全漏洞

### 3.1 示例 RSA 私钥/证书被 CI 打包与用户误用风险

**位置：**

- `starrylink.net.key:1-27`
- `appsettings.json:14,16`（协议/传输示例密钥）
- `appsettings.json:100-103`（证书路径与示例密码）
- `appsettings.json:129`（backend-key 示例值）
- `go/appsettings.json`（开发环境占位数据库/服务配置）
- `.github/workflows/build-linux-amd64.yml`
- `.github/workflows/build-windows-x64.yml`
- `.github/workflows/build-windows-arm64.yml`

**严重性：高 / High，P1**

> 复核调整：维护者说明根目录 `starrylink.net.key`、`starrylink.net.pem` 属于示例文件。在缺少其用于当前生产服务的证据时，本项不再按 P0「生产密钥泄露」处理。但示例私钥仍是可公开获取的私钥，且当前 CI/release 会将其与 `appsettings.json` 一并打包，程序又默认搜索 `./appsettings.json`，因此仍构成示例资产误用和弱默认配置传播风险。

仓库中包含示例 RSA 私钥：

```text
-----BEGIN RSA PRIVATE KEY-----
```

同时示例配置文件引用：

```json
"certificate-key-file": "starrylink.net.key",
"certificate-key-password": "test"
```

CI 构建流程还可能把示例证书/私钥复制进 artifact，扩大误用面。

`cacert.pem` 是 Mozilla/curl 风格的 CA 根证书 bundle，`cacert.sha256` 是其校验值；二者不是秘密，不应归入私钥或生产凭据泄露范围。其治理重点是来源、完整性校验、更新机制和过期根证书维护。

**影响：**

- 若该私钥确为示例文件且未用于生产服务，则不应定性为当前生产密钥泄露。
- 但该私钥已经公开，任何使用该示例私钥/证书部署 WSS 服务的用户，都等同于使用公开私钥。
- CI 当前会把 `starrylink.net.key`、`starrylink.net.pem` 和 `appsettings.json` 打包进部分 artifact；release workflow 又会发布这些 artifact，扩大误用面。
- 程序默认会尝试加载 `./appsettings.json`，用户解压 artifact 后直接运行时可能误用示例配置。
- 示例配置中包含固定协议密钥、固定代理凭据、固定本地地址、`certificate-key-password: "test"` 等，不适合生产环境。
- 若后续发现该证书/私钥曾用于真实线上服务，才应升级为 P0 并执行吊销、轮换和历史清理。

**修复建议：**

1. 将 `starrylink.net.key`、`starrylink.net.pem` 明确标注为测试/示例资产，例如移动到 `examples/certs/`，并使用 README 或文件名标明 `DO-NOT-USE-IN-PRODUCTION`。
2. CI/release 默认不得打包 `*.key`、示例证书和含固定凭据的完整 `appsettings.json`。如确需提供示例，应改为打包 `appsettings.example.json`，并删除私钥引用或改为占位路径。
3. 在 artifact 中提供最小安全模板：不包含私钥、不包含真实域名、不包含固定协议密钥、不包含代理账号密码，并明确要求用户首次运行生成自己的密钥和证书。
4. 在程序启动时检测到示例证书、示例私钥、固定示例 key、`certificate-key-password: "test"` 等，应输出醒目 warning；生产模式可拒绝启动。
5. 文档中明确说明：仓库根目录配置、证书、私钥仅为示例，不是生产默认配置，不得直接部署。
6. 若未来确认该私钥曾用于真实生产服务，则升级为 P0，并执行吊销、轮换、历史清理和发布公告。
7. 继续启用 secret scanning，但为示例文件建立显式 allowlist/注释，避免误报掩盖真正泄露。

---

### 3.2 WSS/TLS 后端连接关闭证书校验

**位置：**

- `ppp/app/server/VirtualEthernetManagedServer.cpp:1003-1014`

**严重性：高 / High**

代码中显式设置：

```cpp
bool verify_peer = false;
```

这会导致 TLS 加密存在，但不验证服务端身份。

**影响：**

- WSS 后端连接容易被 MITM。
- 攻击者可伪造证书。
- 流量可能被篡改或劫持。
- 用户误以为 WSS 是安全通道。

**修复建议：**

1. 生产默认强制 `verify_peer = true`。
2. 私有证书应使用私有 CA。
3. 支持证书 pinning / 公钥 pinning。
4. 关闭校验只能在 debug/insecure 模式显式开启。
5. 关闭校验时输出高危告警。

---

### 3.3 TLS 客户端缺少统一主机名校验

**位置：**

- `ppp/net/asio/templates/SslSocket.h:89-116`
- `ppp/ssl/SSL.cpp:264`

**严重性：高 / High**

代码设置了 SNI：

```cpp
SSL_set_tlsext_host_name(GetSslHandle(), host_.data())
```

但通用 `SslSocket` 路径中未统一设置：

```cpp
boost::asio::ssl::host_name_verification(host_)
```

**修复建议：**

```cpp
if (verify_peer_ && !host_.empty()) {
    ssl_socket_->set_verify_callback(
        boost::asio::ssl::host_name_verification(host_)
    );
}
```

同时：

- `host_` 为空时不允许进入已验证 TLS。
- DNS DoH/DoT 中已有主机名校验实践，建议抽象复用。

---

### 3.4 弱密钥派生与自定义密码学设计

**位置：**

- `ppp/cryptography/EVP.cpp:272-315`

**严重性：高 / High**

问题代码：

```cpp
EVP_BytesToKey(
    _cipher,
    EVP_md5(),
    NULLPTR,
    (Byte*)password.data(),
    (int)password.length(),
    1,
    _key.get(),
    _iv.get()
)
```

后续还使用：

```cpp
ComputeMD5(...)
rc4_crypt(...)
```

当前 KDF 存在：

- MD5；
- 无 salt；
- 1 次迭代；
- IV 确定性派生；
- 自定义 RC4 混合；
- 无现代 AEAD 认证保护。

**修复建议：**

1. 新协议默认使用 AES-256-GCM 或 ChaCha20-Poly1305。
2. KDF 使用 Argon2id、scrypt 或 PBKDF2-HMAC-SHA256。
3. 每会话随机 salt。
4. 每包随机 nonce/IV。
5. RC4/MD5 仅保留 legacy 兼容模式，并默认禁用。

---

### 3.5 默认密钥可预测，默认 plaintext 开启

> **⚠️ 已实施非阻断安全提示（P0-2）— 2026-05-10**
>
> 用户明确要求：弱 key、示例 key、短 key 只能 warning，不得 fail-closed，不得阻断启动。
> plaintext=true 可以显式配置，显示醒目提示但不拒绝启动。
>
> 已实施：在 `AppConfiguration.cpp` 配置归一化完成后检测以下场景并设置
> `kWarning` 级别错误码（`ConfigWeakKeyDefault`、`ConfigWeakKeyShort`、
> `ConfigPlaintextEnabled`），不改变任何默认值，不阻断启动：
>
> - protocol_key 或 transport_key 等于已知默认值 `"ppp"` → `ConfigWeakKeyDefault`
> - protocol_key 或 transport_key 长度 < 8 字节 → `ConfigWeakKeyShort`
> - `key.plaintext == true` → `ConfigPlaintextEnabled`
>
> 后续生产模式可选择性地将这些 warning 升级为强制拒绝（通过新增配置项或 CLI 标志）。

**位置：**

- `ppp/configurations/AppConfiguration.cpp:262-267`
- `ppp/configurations/AppConfiguration.cpp:803-808`

**严重性：高 / High**

问题代码：

```cpp
config.key.protocol_key = BOOST_BEAST_VERSION_STRING;
config.key.transport_key = BOOST_BEAST_VERSION_STRING;
config.key.plaintext = true;
```

**影响：**

- 默认密钥公开可预测。
- 默认配置可能明文传输。
- 用户未配置 key 时系统仍启动，导致弱部署。

**修复建议：**

1. ~~禁止默认弱 key 启动。~~ → 已调整为：检测并高亮提示，不阻断启动。
2. 首次启动生成随机高熵 key。
3. `plaintext` 默认关闭。
4. ~~配置中出现 `"ppp"`、`"test"`、空 key 时拒绝启动。~~ → 已调整为：检测并高亮提示，不阻断启动。

---

### 3.6 默认 AES-CFB 缺少认证完整性

**位置：**

- `ppp/stdafx.h:368-369`

```cpp
PPP_DEFAULT_KEY_PROTOCOL  = "aes-128-cfb";
PPP_DEFAULT_KEY_TRANSPORT = "aes-256-cfb";
```

**严重性：中高 / Medium-High**

AES-CFB 只提供机密性，不提供认证完整性。如果协议层没有额外 HMAC 或 AEAD tag，攻击者可能对密文做可控篡改。

**修复建议：**

- 默认改为 AEAD：`aes-256-gcm` 或 `chacha20-poly1305`。
- CFB 仅 legacy 兼容。
- 所有包必须有 tag。
- tag 验证失败立即丢包并关闭连接。

---

### 3.7 仍支持 RC4 / RC4-MD5 / RC4-SHA1

**位置：**

- `ppp/cryptography/rc4.cpp:341-346`
- `ppp/cryptography/rc4.cpp:365-370`

**严重性：中高 / Medium-High**

RC4 已被废弃，RC4-MD5、RC4-SHA1 均不应再作为安全算法。

**修复建议：**

- 默认禁用全部 RC4。
- 配置加载时拒绝 RC4。
- 若必须兼容，使用 `legacy=true` 显式开关。
- 日志中输出高危告警。

---

### 3.8 macOS/Darwin 使用 `system()` 拼接 shell 命令

**位置：**

- `ppp/app/client/VEthernetNetworkSwitcher.cpp:1081-1085`
- `ppp/app/client/VEthernetNetworkSwitcher.cpp:1184-1188`
- `darwin/ppp/tun/utun.cpp:187-190`

**严重性：中 / Medium**

问题代码：

```cpp
snprintf(cmd, sizeof(cmd),
    "ifconfig %s inet %s %s netmask %s up",
    name.data(), ip.data(), gw.data(), mask.data());

system(cmd);
```

**修复建议：**

- 禁止 `system()`。
- 使用 `posix_spawn` / `execve` 参数数组。
- 或调用平台 API。
- 对接口名、IP、mask 做白名单校验。

---

## 4. 性能与稳定性问题

### 4.1 异步写队列无背压，可能 OOM

> **✅ 已实施背压（P0-3）— 2026-05-10；✅ 已修正三条缺陷 — 2026-05-11**
>
> 已添加 `pending_items_` / `pending_bytes_` 原子计数器和
> `max_pending_items_`（默认 4096）/ `max_pending_bytes_`（默认 16 MiB）
> 阈值。入队前检查阈值，超限时返回 `AsyncWriteQueueBackpressure`
> 错误并拒绝写入。计数器在写完成（evtf 回调）、写启动失败、
> 和 Finalize 清理三条路径上对称更新。
> 阈值可通过 `SetMaxPendingItems()` / `SetMaxPendingBytes()` 配置，
> 设为 0 表示 unlimited。`GetPendingItems()` / `GetPendingBytes()`
> 可用于运行时监控。
>
> **CodeReviewer 审查修正（2026-05-11）：**
> 1. **pending_bytes_ 扣减归零 bug**：立即派发失败路径先调用 `Clear()`
>    （将 `packet_length` 置零）再 `fetch_sub(packet_length)`，
>    导致永远扣减 0。修正为先保存 `packet_length` 再 `Clear()`，
>    使用保存值扣减。
> 2. **临界区穿透**：背压阈值检查在 `syncobj_` 锁外、计数递增在锁内，
>    并发 WriteBytes 可全部通过检查再全部递增，突破限制。修正为
>    检查 + 递增在同一 `syncobj_` 临界区内作为原子 accept/reservation。
> 3. **阈值 data race**：`max_pending_items_` / `max_pending_bytes_` 为
>    普通 int，setter 并发写、WriteBytes 并发读构成 data race。修正为
>    `std::atomic<int>`，setter 将负数 clamp 到 0（0 仍表示 unlimited）。
>
> 未实施：慢连接断开策略、上游暂停读取通知。这些需要与传输层
> 和 TAP 层协调，属于后续独立优化项。

**位置：**

- `ppp/net/asio/IAsynchronousWriteIoQueue.cpp:106-147`

**优先级：P0**

当前写队列在已有写操作进行时直接追加：

```cpp
q->queues_.emplace_back(context);
return true;
```

没有最大 pending item、最大 pending bytes、高水位、丢弃策略、暂停上游读取或慢连接断开策略。

**影响：**

- 队列无限增长。
- 内存暴涨。
- 延迟无限增加。
- 最终 OOM。

**修复建议：**

增加：

```text
max_pending_items
max_pending_bytes
pending_items_
pending_bytes_
```

超过阈值时：

- 返回失败；
- 丢弃低优先级包；
- 断开慢连接；
- 通知上游暂停读取。

---

### 4.2 写队列 `disposed_` 普通 bool 存在数据竞争

**位置：**

- `ppp/net/asio/IAsynchronousWriteIoQueue.cpp:37-43`
- `ppp/net/asio/IAsynchronousWriteIoQueue.cpp:82-84`
- `ppp/net/asio/IAsynchronousWriteIoQueue.cpp:106-109`

**优先级：P0**

`disposed_` 是普通 bool，但存在锁外读、锁内写。C++ 中这属于数据竞争，行为未定义。

**修复建议：**

```cpp
std::atomic_bool disposed_{false};
```

或所有读写都统一在同一把锁内。

---

### 4.3 DNS cache 命中时复用共享 response 并原地改 transaction id

> **✅ 已修复（P0-5，copy-on-read）— 2026-05-10**
>
> 修复方案：`Get()` 命中缓存时，在锁内取出 `cached_response` / `cached_length`，
> 锁外分配 `local_copy`（`make_shared_alloc<Byte>`），`memcpy` 后仅在 `local_copy`
> 上写 `usTransID`，最后返回 `local_copy`。原始缓存 buffer 不再被修改，彻底消除
> 并发 Get() 线程互相覆盖 transaction id 的数据竞争。本修复独立于其他 P0 项，
> 不改变函数签名，不改变 `Add`/`Update`/`Clear`。

**位置：**

- `ppp/app/server/VirtualEthernetNamespaceCache.cpp:156-194`

**优先级：P0**

cache 命中后直接修改共享 response：

```cpp
((dns_hdr*)response.get())->usTransID = trans_id;
```

多个线程/会话同时命中同一个 DNS cache 时，会互相覆盖 transaction id。

**修复建议：**

- cache 中保存 immutable payload。
- 每次 Get 复制一份 response。
- 或只缓存 body，不缓存前 2 字节 transaction id。

---

### 4.4 传输层每包多次分配与拷贝

**位置：**

- `ppp/transmissions/ITransmission.cpp:267-290`
- `ppp/transmissions/ITransmission.cpp:383-414`
- `ppp/transmissions/ITransmission.cpp:563-612`
- `ppp/transmissions/ITransmission.cpp:676-689`

典型写路径中，一个包可能经历：

1. 加密输出分配；
2. base94 输出分配；
3. header + payload 拼接分配；
4. 多次 `memcpy`；
5. `shared_ptr<Byte>` 控制块分配。

**修复建议：**

- 使用 scatter-gather write。
- per-session scratch buffer。
- MTU size slab。
- 减少 `shared_ptr<Byte>`。
- 握手后完全跳过 base94。

示例：

```cpp
std::array<boost::asio::const_buffer, 2> bufs = {
    boost::asio::buffer(header),
    boost::asio::buffer(payload)
};
```

---

### 4.5 DNS redirect 每个查询创建 socket/timer/buffer

**位置：**

- `ppp/app/server/VirtualEthernetExchanger.cpp:802-827`
- `ppp/app/server/VirtualEthernetExchanger.cpp:829-875`
- `ppp/app/server/VirtualEthernetExchanger.cpp:891-917`

每个 DNS redirect 请求都会创建 UDP socket、timer、buffer，并同步 `send_to`。

**修复建议：**

- per-exchanger/per-upstream socket 池；
- `async_send_to`；
- outstanding DNS 请求表；
- timer wheel；
- recv buffer 池；
- 限制 outstanding DNS 数。

---

### 4.6 Firewall 域名匹配每次复制完整规则表

**位置：**

- `ppp/net/Firewall.cpp:331-380`
- `ppp/net/Firewall.cpp:389-449`

每次 DNS/domain 查询都会复制规则表，然后进行字符串拆分、trim、后缀拼接和 hash lookup。

**修复建议：**

使用 RCU 规则快照：

```cpp
std::atomic<std::shared_ptr<const RuleSet>> rules_;
```

域名匹配改为反向 trie 或 `string_view` 后缀匹配。

---

### 4.7 内存池全局锁 + block 线性扫描

**位置：**

- `ppp/threading/BufferswapAllocator.cpp:120-156`
- `ppp/threading/BufferswapAllocator.cpp:163-180`
- `ppp/threading/BufferblockAllocator.cpp:327-347`

**修复建议：**

- per-thread cache；
- per-io_context cache；
- size-class slab；
- pointer -> block 地址区间索引；
- tcache / lock-free freelist；
- allocator telemetry。

---

## 5. 传输协议风险

### 5.1 传输帧长度缺少策略上限，存在 DoS

> **⚠️ 已实施长度上限（P0-4A），读取超时仍为后续独立项 — 2026-05-10**
>
> 已在三个解码路径的 payload length 确定后、分配/读取前添加 `PPP_BUFFER_SIZE`
> （65536 字节）上限检查：
>
> - `base94_decode()` — base94 解码后的 payload_length
> - `Transmission_Packet_Decrypt()` — EVP header 解密后的 payload_len（内存解密路径）
> - `Transmission_Packet_Read()` — EVP header 解密后的 payload_len（网络读取路径）
>
> 超限帧返回 `ProtocolFrameInvalid` 错误并拒绝处理。未实施 per-frame 读取超时，
> 该功能需单独规划（涉及 Boost.Asio async_read deadline_timer 集成）。
> ITcpipTransmission 和 WebSocket 路径的限制需后续评估。

**位置：**

- `ppp/transmissions/ITransmission.cpp:914-920`
- `ppp/transmissions/ITransmission.cpp:529-537`
- `ppp/transmissions/ITcpipTransmission.cpp:163-174`
- `ppp/transmissions/templates/WebSocket.h:238-258`

读包逻辑根据包头长度直接分配：

```cpp
auto payload = ReadBytes(transmission, y, payload_len);
```

底层：

```cpp
MakeByteArray(allocator, length);
async_read(... length ...);
```

缺少握手前最大长度、握手后最大数据帧、控制帧最大长度和 per-frame read timeout。

**修复建议：**

设置多级上限：

```text
pre-handshake max frame: 4KB
control frame max: 8KB
absolute max: configurable but capped
```

并添加 per-frame read deadline。

---

### 5.2 WebSocket 握手角色疑似反置

**位置：**

- `ppp/transmissions/templates/WebSocket.h:103-116`
- `ppp/transmissions/templates/WebSocket.h:204-208`
- `ppp/transmissions/IWebsocketTransmission.cpp:96`
- `ppp/transmissions/IWebsocketTransmission.cpp:206`

`HandshakeClient()` 传入 false，最终使用 `HandshakeType_Server`；`HandshakeServer()` 传入 true，最终使用 `HandshakeType_Client`。

**修复建议：**

明确两层语义：

- WebSocket 层：TCP 主动连接方是 client。
- PPP 层：session_id 交换方向是 client/server。

并增加 TCP、WS、WSS、mux、proxy、client/server 双端集成测试。

---

### 5.3 WebSocket / TCP socket 成员并发访问存在竞态

**位置：**

- `ppp/transmissions/templates/WebSocket.h:125-171`
- `ppp/transmissions/ITcpipTransmission.cpp:54-66`
- `ppp/transmissions/ITcpipTransmission.cpp:153-174`
- `ppp/transmissions/ITcpipTransmission.cpp:195-245`

`socket_` 是普通 `shared_ptr` 成员。读写路径复制，Finalize 路径 move，可能并发读写 shared_ptr 成员本身。

**修复建议：**

- socket 访问统一放 strand；
- 或 mutex/atomic shared_ptr；
- Finalize one-shot；
- ShiftToScheduler 期间禁止并发读写。

---

### 5.4 server `VirtualEthernetExchanger::Finalize()` 非原子 one-shot

**位置：**

- `ppp/app/server/VirtualEthernetExchanger.cpp:173-247`

问题代码：

```cpp
if (disposed_) return;
disposed_ = true;
```

`disposed_` 是普通 bool，且无锁。

**修复建议：**

```cpp
if (disposed_.exchange(true)) {
    return;
}
```

并将 map 资源 move 到局部后锁外释放。

---

### 5.5 endpoint wire format 1 字节 host 长度可能截断

**位置：**

- `ppp/app/protocol/VirtualEthernetLinklayer.cpp:372-383`
- `ppp/app/protocol/VirtualEthernetLinklayer.cpp:103-140`

问题代码：

```cpp
stream.WriteByte(static_cast<Byte>(address_string.size()));
stream.Write(address_string.data(), 0, address_string.size());
```

若 hostname 长度 > 255，长度字段截断，但完整字符串仍被写入，导致解码端错帧。

**修复建议：**

```cpp
if (address_string.size() > 255) {
    return ProtocolFrameInvalid;
}
```

更优方案是升级为 2 字节长度字段，但需要版本协商。

---

### 5.6 `VirtualEthernetPacket::UnpackBy()` 缺少 `header_length <= packet_length`

**位置：**

- `ppp/app/protocol/VirtualEthernetPacket.cpp:233-238`
- `ppp/app/protocol/VirtualEthernetPacket.cpp:272-291`

只检查：

```cpp
header_length >= sizeof(PACKET_HEADER)
```

未检查：

```cpp
header_length <= packet_length
```

**修复建议：**

```cpp
if (header_length > packet_length) {
    return ProtocolFrameInvalid;
}
```

同时 `MemoryStream::Write()` 对负 length 也应防御。

---

## 6. 架构与可维护性问题

### 6.1 `ppp/stdafx.h` 是超级头文件

**位置：**

- `ppp/stdafx.h:1-2228`

`stdafx.h` 混合了平台宏、编译器宏、Boost/Asio/Beast、默认配置、DNS 列表、类型工具、日志宏、第三方库 hack、自定义 STL traits。

**修复建议：**

拆分为：

```text
ppp/base/Platform.h
ppp/base/Compiler.h
ppp/base/Constants.h
ppp/base/Types.h
ppp/base/Log.h
ppp/third_party/BoostCompat.h
ppp/base/StringConvert.h
```

---

### 6.2 伪造 Boost.Beast 版本宏

**位置：**

- `ppp/stdafx.h:272-284`

问题代码：

```cpp
#ifndef BOOST_BEAST_VERSION_HPP
#define BOOST_BEAST_VERSION_HPP
#define BOOST_BEAST_VERSION 322
#define BOOST_BEAST_VERSION_STRING "ppp"
#endif
```

这会欺骗预处理器，阻止真实 Boost.Beast 版本头正常展开。同时 `BOOST_BEAST_VERSION_STRING` 又被用作默认密钥。

**修复建议：**

- 删除这段伪造宏。
- 使用项目自有版本宏：`PPP_BUILD_VERSION_STRING`。

---

### 6.3 默认 DNS 列表疑似缺逗号导致字符串拼接

**位置：**

- `ppp/stdafx.h:372-458`

存在类似：

```cpp
"120.53.53.53"

PPP_PREFERRED_DNS_SERVER_1,
```

C/C++ 相邻字符串会拼接，可能变成非法 IP。

**修复建议：**

- 补逗号。
- 对默认 DNS 列表增加单元测试。
- 每项校验必须是合法 IP。

---

### 6.4 `AppConfiguration` 职责过重

**位置：**

- `ppp/configurations/AppConfiguration.h`
- `ppp/configurations/AppConfiguration.cpp`

一个类同时负责默认值、JSON 解析、校验、平台能力判断、字段归一化、派生值计算、序列化。

**修复建议：**

拆分：

```cpp
AppConfigurationParser
AppConfigurationValidator
AppConfigurationNormalizer
AppConfigurationSerializer
PlatformCapabilities
```

---

### 6.5 平台条件编译严重内联在业务逻辑中

**位置：**

- `ppp/app/client/VEthernetNetworkSwitcher.cpp`
- `ppp/app/ApplicationInitialize.cpp`
- `ppp/configurations/AppConfiguration.cpp`

**修复建议：**

抽象平台策略接口：

```cpp
RouteManager
DnsConfigurator
TapAdapter
FirewallManager
NetworkProtectionBackend
```

按平台实现：

```text
platform/windows/WindowsRouteManager.cpp
platform/linux/LinuxRouteManager.cpp
platform/macos/MacOSRouteManager.cpp
platform/android/AndroidNetworkBackend.cpp
```

---

## 7. 构建、依赖与供应链风险

### 7.1 Android OpenSSL 1.1.1i 过旧

**位置：**

- `build-android-local.sh`
- `.github/workflows/build-android.yml`

OpenSSL 1.1.1 系列已停止常规支持，1.1.1i 更早。

**修复建议：**

- 升级 OpenSSL 3.0 LTS / 3.2 / 3.3。
- 或使用 BoringSSL / 系统 Conscrypt。
- 固定版本和 hash。

---

### 7.2 Android NDK r20b 过旧

**位置：**

- `build-android-local.sh`
- `.github/workflows/build-android.yml`

**修复建议：**

升级到当前受支持 NDK。

---

### 7.3 第三方依赖硬编码路径

**位置：**

- `CMakeLists.txt`
- `android/CMakeLists.txt`
- `build-openppp2-by-cross.sh`
- `build-android-local.sh`

默认路径如：

```text
/root/dev
/root/android
/tmp/ndk
E:\Dev\...
```

**风险：**

- 构建不可复现。
- 本机目录污染可引入恶意库。
- CI/开发环境不一致。

**修复建议：**

- CMake Presets。
- vcpkg manifest。
- FetchContent。
- 明确版本和 hash。
- 不允许默认 `/root`、`/tmp`。

---

### 7.4 编译警告大量被压制

**位置：**

- `CMakeLists.txt`
- `android/CMakeLists.txt`
- `ppp.vcxproj`

包括：

```text
-Wno-format
-Wno-implicit-function-declaration
-Wno-null-dereference
-Wno-deprecated-declarations
_CRT_SECURE_NO_WARNINGS
```

**修复建议：**

- 逐步打开 `-Wall -Wextra -Wformat=2`。
- 安全构建使用 `-Werror`。
- warning suppression 按文件局部化。

---

### 7.5 存在 `-fno-stack-protector` 路径

**位置：**

- `CMakeLists.txt`
- `android/CMakeLists.txt`

**修复建议：**

删除 `-fno-stack-protector`，Release 默认：

```text
-fstack-protector-strong
-D_FORTIFY_SOURCE=2/3
-fPIE -pie
-Wl,-z,relro,-z,now
```

---

### 7.6 CI 缺少测试、安全扫描和 hardening 验证

缺失：

- C++ 单元测试；
- ctest；
- clang-tidy；
- cppcheck；
- CodeQL；
- govulncheck；
- npm audit；
- OSV scanner；
- Dependabot；
- SBOM；
- checksec/readelf；
- release artifact 签名。

**修复建议：**

引入：

```text
CodeQL
Dependabot
OSV-Scanner
Syft SBOM
Trivy
govulncheck
npm audit
clang-tidy
cppcheck
checksec
cosign / minisign / GPG signing
```

---

## 8. 优先级修复建议

### P0：必须立即处理

1. TLS/WSS 开启证书链校验与主机名校验，禁止生产路径默认关闭校验。
2. ~~禁止生产默认弱 key、固定 key 和 plaintext。~~ → **已调整为：检测并高亮提示弱 key/plaintext；不阻断启动（见 §3.5 状态更新）。**
3. ~~写队列加背压。~~ → **✅ 已实施：pending_items/pending_bytes + 阈值拒绝（见 §4.1 状态更新）。**
4. ~~传输帧加最大长度与超时。~~ → **⚠️ 已实施长度上限（PPP_BUFFER_SIZE）；读取超时仍为后续独立项（见 §5.1）。**
5. ~~修复 DNS cache transaction id 并发覆盖。~~ → **✅ 已修复：copy-on-read（见 §4.3 状态更新）。**
6. 修复主要 Dispose/Finalize one-shot。

> 复核调整：`starrylink.net.key` / `starrylink.net.pem` 经维护者说明属于示例资产，在无证据表明其仍用于生产服务时，不列入 P0 生产密钥泄露。

### P1：短期重要优化

1. CI/release 禁止默认打包示例私钥、示例证书和含固定凭据的根目录 `appsettings.json`；改为发布 `appsettings.example.json` 或最小安全模板。
2. 为示例证书、示例私钥、示例配置增加 `DO-NOT-USE-IN-PRODUCTION` 标识；启动时检测到示例 key/cert/password 时输出高亮告警或拒绝生产模式启动。
3. AEAD 加密迁移。
4. 禁用 RC4/MD5 KDF。
5. DNS redirect socket/timer 池化。
6. Firewall 匹配优化。
7. Android 依赖升级。
8. 消除 `system()` shell 拼接。
9. 增加 CodeQL / govulncheck / npm audit / OSV。

### P2：中期架构改善

1. 拆 `stdafx.h`。
2. 重构 `AppConfiguration`。
3. 平台策略接口化。
4. 引入 Result/ErrorEvent。
5. 增加 C++ 单元测试/fuzz。
6. 建立 SBOM、artifact 签名和 hardening 检查。
7. 改造内存池为 per-thread/per-context cache。
8. 为 route / DNS / lease 建立索引和时间轮。

---

## 9. 实施示例

### 9.1 写队列背压示例

```cpp
struct QueueLimits {
    size_t max_items = 4096;
    size_t max_bytes = 16 * 1024 * 1024;
};

bool IAsynchronousWriteIoQueue::CanEnqueue(size_t bytes) const noexcept {
    return pending_items_ < limits_.max_items &&
           pending_bytes_ + bytes <= limits_.max_bytes;
}
```

写入时：

```cpp
if (!CanEnqueue(packet_length)) {
    diagnostics::SetLastErrorCode(ErrorCode::AsyncWriteQueueBackpressure);
    return false;
}

pending_items_++;
pending_bytes_ += packet_length;
```

完成后扣减：

```cpp
pending_items_--;
pending_bytes_ -= context->packet_length;
```

---

### 9.2 TLS 主机名校验示例

```cpp
if (verify_peer_) {
    if (host_.empty()) {
        diagnostics::SetLastErrorCode(ErrorCode::SslHostNameRequired);
        return false;
    }

    ssl_socket_->set_verify_mode(boost::asio::ssl::verify_peer);
    ssl_socket_->set_verify_callback(
        boost::asio::ssl::host_name_verification(host_)
    );
}
```

---

### 9.3 Dispose one-shot 示例

```cpp
class Disposable {
private:
    std::atomic_bool finalized_{false};

public:
    void Finalize() noexcept {
        if (finalized_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }

        auto socket = std::move(socket_);
        auto timer = std::move(timer_);

        Close(socket);
        Cancel(timer);
    }
};
```

---

### 9.4 传输帧长度限制示例

```cpp
static constexpr int MAX_HANDSHAKE_FRAME = 4 * 1024;
static constexpr int MAX_CONTROL_FRAME   = 8 * 1024;
static constexpr int MAX_DATA_FRAME      = PPP_BUFFER_SIZE;

bool ValidateFrameLength(int len, FramePhase phase) noexcept {
    if (len <= 0) return false;

    switch (phase) {
        case FramePhase::Handshake:
            return len <= MAX_HANDSHAKE_FRAME;
        case FramePhase::Control:
            return len <= MAX_CONTROL_FRAME;
        case FramePhase::Data:
            return len <= MAX_DATA_FRAME;
    }

    return false;
}
```

---

### 9.5 DNS cache 修复示例

```cpp
std::shared_ptr<Byte> CloneDnsResponseWithId(
    const std::shared_ptr<const Byte>& cached,
    int len,
    uint16_t trans_id,
    const AllocatorPtr& allocator)
{
    auto out = BufferswapAllocator::MakeByteArray(allocator, len);
    if (!out) return nullptr;

    memcpy(out.get(), cached.get(), len);
    reinterpret_cast<dns_hdr*>(out.get())->usTransID = trans_id;
    return out;
}
```

---

## 10. 建议新增测试矩阵

### P0：安全/协议边界测试

1. 传输帧 fuzz：
   - length = 0；
   - length = 1；
   - length = 65535；
   - header_length > packet_length；
   - base94 header 错位；
   - 握手前非法帧。

2. 握手状态机：
   - TCP；
   - WS；
   - WSS；
   - mux；
   - proxy；
   - client/server 角色校验。

3. DNS cache 并发：
   - 多线程命中同一 record；
   - transaction id 不串扰。

4. Dispose 幂等：
   - read fail + write fail + timer timeout 同时发生；
   - 多次 Dispose；
   - 析构时未显式 Dispose。

### P1：配置测试

1. 空配置。
2. 默认 key。
3. 弱密码。
4. 端口越界。
5. IPv6 mode。
6. DNS server object/array/string。
7. websocket path。
8. certificate key missing。
9. plaintext 默认值。
10. `key.kl/key.kh` 越界。

### P2：性能基准

1. 小 UDP 包 PPS。
2. TCP tunnel throughput。
3. DNS redirect QPS。
4. Firewall domain rule 大规则集。
5. memory allocator lock wait。
6. write queue depth under slow peer。
7. Android DNS/timer teardown 压测。

---

## 11. 预期收益

### 性能收益

- 写队列不再无限膨胀。
- 慢连接不会拖垮进程。
- DNS 高 QPS 成本显著下降。
- 小包高 PPS 场景分配/拷贝减少。
- Firewall 大规则集匹配延迟下降。
- IPv6/lease/session 扩展性提升。
- 尾延迟降低。

### 安全收益

- 消除示例私钥/证书被误用和继续随 artifact 传播的影响。
- TLS MITM 风险大幅降低。
- 默认配置从“不安全可启动”变成“安全失败”。
- 弱加密和无认证加密逐步退出。
- 命令注入面收窄。
- 供应链风险可观测、可追踪。

### 可维护性收益

- 平台代码隔离。
- 配置解析可测试。
- 错误信息更可定位。
- `stdafx.h` 不再成为全局耦合点。
- Dispose 生命周期更一致。
- CI 可防止回归。

### 用户体验收益

- 连接失败原因更明确。
- DNS 响应更稳定。
- Android teardown 崩溃概率降低。
- 高并发下更不容易卡死/OOM。
- TLS/WSS 安全预期更符合用户直觉。

---

## 12. 最终执行顺序建议

### 第一批：立即修

1. TLS/WSS 开启证书链校验与主机名校验。
2. ~~禁止生产默认弱 key、固定 key 和 plaintext。~~ → 已调整为：检测并高亮提示弱 key/plaintext；不阻断启动（见 §3.5）。
3. ~~写队列加背压。~~ → ✅ 已实施（见 §4.1）。
4. ~~传输帧加最大长度与超时。~~ → ⚠️ 已实施长度上限；读取超时仍为后续独立项（见 §5.1）。
5. ~~修复 DNS cache transaction id 并发覆盖。~~ → ✅ 已修复（见 §4.3）。
6. 修复主要 Dispose/Finalize one-shot。

### 第二批：短期修

1. CI/release 排除示例私钥、示例证书和含固定凭据的完整配置，改为发布安全模板。
2. 对示例 key/cert/password 增加 `DO-NOT-USE-IN-PRODUCTION` 标识和启动告警。
3. AEAD 加密迁移。
4. 禁用 RC4/MD5 KDF。
5. DNS redirect socket/timer 池化。
6. Firewall 匹配优化。
7. Android 依赖升级。
8. 消除 `system()` shell 拼接。
9. 增加 CodeQL / govulncheck / npm audit / OSV。

### 第三批：中期重构

1. 拆 `stdafx.h`。
2. 重构 `AppConfiguration`。
3. 平台策略接口化。
4. 引入 Result/ErrorEvent。
5. 增加 C++ 单元测试/fuzz。
6. 建立 SBOM、artifact 签名和 hardening 检查。

---

## 13. 附：本次 subagent 结果状态

- 安全审计：完成。
- 构建/依赖/供应链审计：完成。
- 性能与架构审计：补跑完成。
- 传输协议/握手/边界审计：补跑完成。
- 代码质量与可维护性审计：补跑完成。
- 原始并行中的一个高阶模型不可用，另一个返回为空，已用可用 subagent 补审。

---

## 14. 续审（2026-05-09）：未推送提交与工作区修改

> 本节专门审核 §1–§13 之后产生的增量修改，聚焦于 Android 稳定性修复、TLS 握手并发安全、传输层原子化、DNS 异步生命周期统一这四条主线。
> 与首版重叠的发现（如默认密钥、示例私钥/证书误用风险、写队列背压、`stdafx.h` 拆分）不再重复，仅在本节末以"与首版关联"小节做交叉指引。

### 14.1 续审范围

| 项目 | 内容 |
|---|---|
| **未推送提交** | `ed61d5b`（Timer SetTimeout 句柄局部移动）、`d483885`（DNS IPFrame 跨异步调用保活） |
| **未提交工作区** | 7 个文件 / 约 1500 行差异 |
| **核心模块** | `ppp/threading/Timer.cpp`、`ppp/dns/DnsResolver.cpp`、`ppp/ssl/SSL.cpp`、`ppp/transmissions/ITransmission.{h,cpp}`、`ppp/app/client/VEthernetNetworkSwitcher.cpp`、`android/CMakeLists.txt` |

### 14.2 已提交但未推送的修复

#### 14.2.1 `ed61d5b` — Timer SetTimeout 用户句柄局部移动

**位置：** `ppp/threading/Timer.cpp:366`

将 `t->TickEvent` 内部 lambda 改为 `mutable noexcept`，先 `sender->Dispose()`，再把 `handler` 移到栈局部 `local`，最后 `local(sender)`。本意是让用户 lambda 中的 `shared_ptr` capture 在 **当前栈帧** 析构，而不是被延迟到外层 `Callable<outer-lambda>` 的析构链中累积栈深度，触发 Android 内核栈守护页（`SI_KERNEL`）。

**评估：**

- 修复方向正确：把析构成本从延迟链摊到本帧。
- 但仍依赖"所有 capture 在本帧析构能成功"，若用户 lambda 自己又 capture 了多层 `shared_ptr<Timer>`，仍可能产生递归。
- 与 §14.3.1 的 `-DFUNCTION` 一起部署后，整体回溯路径已显著变浅。

#### 14.2.2 `d483885` — DnsResolver 异步链中保活 `IPFrame`

**位置：** `ppp/app/client/VEthernetNetworkSwitcher.cpp:3550-3733`

为四个 `ResolveAsync*` lambda 与 `YieldContext::Spawn` 的协程额外捕获 `packet`（`(void)packet` 抑制 `-Wunused-lambda-capture`），保证 `IPFrame` 生命周期跨越所有异步阶段。

**评估：**

- 之前仅捕获 `frame`/`messages` 的 `BufferSegment` 视图，但底层 `IPFrame` 已在 `PacketInput` 返回时释放，触发 `~IPFrame()` 与正在执行的 DnsResolver 异步操作竞争。
- 修复以最小代价（5 行 capture）解决 `SIGSEGV / SI_KERNEL` ~8 秒崩溃，是典型的 **upstream-minimal-fix**，符合 bug 修复纪律。

### 14.3 工作区未提交大改动综览

| 文件 | 行数变化 | 主题 |
|---|---|---|
| `ppp/dns/DnsResolver.cpp` | +650 / −340 | `CompletionState` / `StunCompletionState` 集中所有权重写 DoH/DoT/UDP/TCP/STUN 异步链 |
| `ppp/transmissions/ITransmission.h` | +160 / −180 | `unsigned int : N` bitfield → 4×`std::atomic_bool` |
| `ppp/transmissions/ITransmission.cpp` | +80 / −60 | 配套 `.load(acquire)` / `.store(release)`、`std::atomic_load/store` 包裹 cipher `shared_ptr` |
| `ppp/ssl/SSL.cpp` | +130 / −60 | 客户端 SSL 上下文创建加进程级互斥、Android 跳过 `set_default_verify_paths`、删除 `"DEFAULT"` cipher 调用、握手前预排序 X509_STORE |
| `ppp/threading/Timer.cpp` | +20 / −80 | 撤销旧的"两段式延迟析构"，依赖 Android `-DFUNCTION` 切换为 `std::function` |
| `ppp/app/client/VEthernetNetworkSwitcher.cpp` | +18 / −6 | 在 ICMP echo 处理前过滤掉非 `ICMP_ECHO/ICMP_ER` 类型 |
| `android/CMakeLists.txt` | +1 | `ADD_DEFINITIONS(-DFUNCTION)` |

### 14.4 关键性能问题

#### **P-1：Android 跳过 TLS 会话缓存**

**位置：** `ppp/dns/DnsResolver.cpp:669-697`

```cpp
ssl_session_st* DnsResolver::AcquireTlsSession(const ppp::string& host_key) noexcept {
#if defined(__ANDROID__)
    (void)host_key;
    return NULLPTR;
#endif
    // ...
}
void DnsResolver::StoreTlsSession(const ppp::string& host_key, ssl_session_st* session) noexcept {
#if defined(__ANDROID__)
    (void)host_key;
    if (session != NULLPTR) {
        SSL_SESSION_free(reinterpret_cast<SSL_SESSION*>(session));
    }
    return;
#endif
    // ...
}
```

**影响：** 每次 DoH/DoT 查询都做完整 TLS 握手（1.5–2 RTT + ECDHE）。移动端 CPU 弱、RTT 高，影响最大化。

**修复建议：**

1. 定位真正的根因（疑为 BoringSSL session cache 在并发握手时崩溃）。
2. 过渡期使用进程内 LRU + `std::mutex` 保护，而非整体禁用。

#### **P-2：客户端 SSL_CTX 创建被全局锁串行化**

**位置：** `ppp/ssl/SSL.cpp:233-239`

```cpp
static std::mutex s_ssl_ctx_init_mutex;
std::lock_guard<std::mutex> guard(s_ssl_ctx_init_mutex);

std::shared_ptr<boost::asio::ssl::context> ssl_context =
    make_shared_object<boost::asio::ssl::context>(...);
// ... CA 加载 / verify mode / cipher suites / X509 sort ...
```

**影响：** 高并发握手场景退化为串行；锁内还包含磁盘 I/O（`load_verify_file` / `load_root_certificates`）。

**修复建议：**

```cpp
static std::once_flag s_ssl_globals_once;
std::call_once(s_ssl_globals_once, []() {
    SSL_CTX* warmup = SSL_CTX_new(TLS_client_method());
    if (warmup) SSL_CTX_free(warmup);
});
// 此后 SSL_CTX_new 与 CA 加载可并发执行
```

### 14.5 关键安全问题

#### **S-1：Android 上禁用 `set_default_verify_paths()` 但缺少替代 CA 来源**

**位置：** `ppp/ssl/SSL.cpp:175-177`、`ppp/ssl/SSL.cpp:247-250`

```cpp
#if !defined(__ANDROID__)
    ssl_context->set_default_verify_paths();
#endif
```

**风险等级：高**（前提：`verify_peer == true`）

Android 上没有等价 CA 加载路径。若上游配置了 `verify_peer = true`：

- 严格情况下握手会因找不到根证书而失败；
- 宽松情况下可能被错误地静默通过。

**修复示例：**

```cpp
#if defined(__ANDROID__)
    const auto& ca = ppp::configurations::GetAndroidCaBundlePath();
    if (!ca.empty()) {
        boost::system::error_code ec;
        ssl_context->load_verify_file(ca, ec);
        if (ec) {
            ppp::diagnostics::SetLastErrorCode(
                ppp::diagnostics::ErrorCode::SslCaBundleLoadFailed);
            return NULLPTR;
        }
    }
#else
    ssl_context->set_default_verify_paths();
#endif
```

可通过 JNI 从 `AndroidCAStore` 导出系统根，或在 APK 内置 Mozilla CA bundle，启动时拷贝到 `filesDir` 并在配置中传入路径。

#### **S-2：`SSL_CTX_set_cipher_list(ctx, "DEFAULT")` 被彻底删除**

**位置：** `ppp/ssl/SSL.cpp:188-200`、`ppp/ssl/SSL.cpp:253-264`

**风险等级：低**

BoringSSL 不识别字符串 `"DEFAULT"`，会清空 cipher list 并触发 `ssl_cipher_ptr_id_cmp` 崩溃。删除是必要的；但 OpenSSL 用户可能希望显式排除弱套件。

**修复建议：** 按密码学库分支：

```cpp
#if defined(OPENSSL_IS_BORINGSSL)
    // BoringSSL 内置默认列表已足够安全
#else
    SSL_CTX_set_cipher_list(ssl_context->native_handle(),
        "HIGH:!aNULL:!eNULL:!MD5:!RC4:!DES:!3DES:!EXPORT");
#endif
```

### 14.6 加固建议

#### **S-3：`CompletionState::slot0..slot3` 类型擦除**

**位置：** `ppp/dns/DnsResolver.cpp:64-67`

```cpp
std::shared_ptr<void> slot0;
std::shared_ptr<void> slot1;
std::shared_ptr<void> slot2;
std::shared_ptr<void> slot3;
```

**隐患：** `std::static_pointer_cast<T>` 失去编译期类型校验。后续若调整槽位顺序，会无声地把指针解释为错误类型。

**建议：** 使用 `std::variant<...>` 或继承式专用结构（`DohState : CompletionState` / `DotState`），让类型在编译期固定。

#### **S-4：`std::atomic_load/store(shared_ptr*)` 在 C++20 已弃用**

**位置：** `ppp/transmissions/ITransmission.cpp:87-88`、`1695-1696`、`1715-1716`

C++17 标准下可用，C++20 起触发 deprecated 警告，C++26 移除。

**建议：** 包装一层兼容工具，便于以后切到 `std::atomic<std::shared_ptr<T>>`：

```cpp
template<class T>
std::shared_ptr<T> atomic_load_compat(const std::shared_ptr<T>* p) noexcept {
#if __cplusplus >= 202002L
    static_assert(false, "Use std::atomic<std::shared_ptr<T>> directly");
#else
    return std::atomic_load(p);
#endif
}
```

#### **S-5：`UnixSocketAcceptor` macOS 加速链已收敛但需保留遥测**

详见 §1–§13 与 `docs/TCP_NAT_AUDIT_REPORT.md`。结论：保持当前的"单 outstanding accept + 启动顺序保障"，不要再改回多并发 accept。

### 14.7 隐性缺陷

#### **B-1：Timer.cpp 极简化依赖 `-DFUNCTION` 编译开关**

**位置：** `android/CMakeLists.txt:14`、`ppp/threading/Timer.cpp:43-67`

若任一交叉编译目标（如老 NDK、Linux 静态打包）漏掉 `-DFUNCTION`，会回退到旧 `ppp::function` 析构路径，重新触发 Android `SI_KERNEL` 栈溢出崩溃。

**建议：** 在 `Timer.cpp` 顶部加守卫：

```cpp
#if defined(__ANDROID__) && !defined(FUNCTION)
#  error "Android Timer.cpp requires -DFUNCTION (std::function backend); \
          ppp::function backend has a deep destructor recursion known crash."
#endif
```

或在 `stdafx.h` 中对 `__ANDROID__` 自动 define `FUNCTION`。

#### **B-2：ICMP 非 `ECHO/ER` 类型直接丢弃**

**位置：** `ppp/app/client/VEthernetNetworkSwitcher.cpp:565-582`

```cpp
if (frame->Type != IcmpType::ICMP_ECHO && frame->Type != IcmpType::ICMP_ER) {
    return false;
}
elif (IPAddressIsGatewayServer(frame->Destination, ...)) {
    // 网关 echo 处理
}
```

**功能影响：**

- 隧道内 `traceroute` 失效（依赖 `TIME_EXCEEDED`）。
- 路径 MTU 发现（PMTUD）失效（依赖 `DEST_UNREACH / Frag-Needed`）。
- `PORT_UNREACH` 不再回送给应用，UDP 短连接不会快速失败。

**长期方案：** 让 `VEthernetExchanger` 走一条 **无定时器的无状态注入路径** 处理 ICMP 错误，从而既保留 `traceroute / PMTUD` 又规避旧的定时器崩溃。当前是为稳定性做的临时折衷，**必须备忘录化并定期回看**。

#### **B-3：DoH/DoT 异步链中 `state->slot0` 复用**

**位置：** `ppp/dns/DnsResolver.cpp:1748-1752`、`2023-2027`

length-prefix 阶段完成后用 `response` buffer 覆盖原 `request` buffer。期间假定 `request` 已完整发送、不再被 boost::asio 引用——这是对调用顺序的隐式契约。

**建议：** 用专用 `slot_response`，让 `slot0` 始终保留 request 直到 `~CompletionState`：

```cpp
struct CompletionState final {
    // ...
    std::shared_ptr<void> request;   // 始终保留至生命周期结束
    std::shared_ptr<void> response;  // 单独槽
    std::shared_ptr<void> auxbuf;    // 长度前缀等
};
```

#### **B-4：obfuscation 标志校验失败后的冗余写**

**位置：** `ppp/transmissions/ITransmission.cpp:1432`

```cpp
ppp::diagnostics::SetLastErrorCode(
    ppp::diagnostics::ErrorCode::ObfuscationFlagsMismatch);
handshaked_.store(false, std::memory_order_release);   // ← 冗余
return 0;
```

新逻辑只在末尾 `handshaked_.store(true)`，此处 `handshaked_` 还从未被置 true。

**建议：** 删除该行避免误导后续阅读者。

### 14.8 边界场景一览

| 场景 | 影响 | 处理方案 |
|---|---|---|
| `make_shared_object` 抛异常 vs 返回 NULL | 部分 Resolver 路径同时检查 NULL 并捕获 `std::exception` | `make_shared_object` 已封装 `(std::nothrow)` 语义返回 NULL，建议在工具头中固化为 `noexcept` 契约 |
| `io_context.stop()` 后 `timer.async_wait` 未 fired | `CompletionState` 析构时 timer 仍持有 raw 指针 | stop 后 lambda 不再 dispatch，shared_ptr 计数会在 io_context 销毁时归零，安全 |
| DNS 完成回调内重新发起解析 | 之前观察到旧流仍 in-flight | 新模型在 `Complete()` 内 `move(callback)` 后再调用，已规避重入问题 |
| `ITransmission::Dispose()` 与读协程并发 | 旧 bitfield 共享存储被并发写 | 新原子化已修复 |

### 14.9 架构与可维护性

#### **A-1：项目级 `elif` 宏滥用**

**位置：** `ppp/stdafx.h:197-199`

```cpp
#ifndef elif
#define elif else if
#endif
```

**影响：** 与 Python 关键字混淆；IDE 与静态分析器易误报；阅读成本增加。

**建议：** 长期内分批清理为 `else if`，新代码禁止使用。

#### **A-2：`CompletionState` / `StunCompletionState` 重复**

**位置：** `ppp/dns/DnsResolver.cpp:45-145` 与 `162-205`

**建议：** 模板化合并：

```cpp
template<class TResult, class TCallback>
struct AsyncCompletionState final {
    std::atomic<bool> completed{ false };
    TCallback callback;
    // 公共 timer / socket / stream 槽
    void Complete(TResult result) noexcept { /* ... */ }
};
```

可减少约 60 行重复。

#### **A-3：`DnsResolver.cpp` 单文件 4500+ 行**

**建议：** 拆为：

```text
ppp/dns/DnsResolverDoH.cpp
ppp/dns/DnsResolverDoT.cpp
ppp/dns/DnsResolverUdp.cpp
ppp/dns/DnsResolverStun.cpp
ppp/dns/DnsResolverCore.cpp
```

便于增量编译与 PR 评审。

#### **A-4：注释中的非 ASCII 替换字符 / BOM 残留**

**位置：** 多处 `ppp/transmissions/ITransmission.h` 注释中存在 `鈥?`（U+FFFD）。

**原因：** Windows CRLF 与 UTF-8 BOM 混合，git 自动转换出错。

**建议：** 添加 `.gitattributes`：

```text
*.h text eol=lf working-tree-encoding=UTF-8
*.cpp text eol=lf working-tree-encoding=UTF-8
```

并统一以 UTF-8（无 BOM）保存源码。

### 14.10 依赖与构建

| 项 | 现状 | 建议 |
|---|---|---|
| C++17 | 全平台一致 | 评估升级 C++20 以使用 `std::atomic<std::shared_ptr<T>>` 与 `<concepts>` |
| BoringSSL vs OpenSSL | 通过 `__ANDROID__` 分支区分 | 引入显式宏 `PPP_CRYPTO_BORINGSSL` / `PPP_CRYPTO_OPENSSL`，避免与平台宏耦合 |
| Boost 1.87+ | `docs/BOOST_187_COMPATIBILITY.md` 已记录 | 保持 |

### 14.11 优先级整理

#### 优先级 1（关键 / 必须修复）

1. **修复 Android TLS 信任链缺口（S-1）**：`set_default_verify_paths()` 关掉后，必须确保 `verify_peer` 路径仍有 CA 数据；与 §3.2、§3.3 形成端到端 TLS 加固闭环。
2. **强制 `-DFUNCTION` 在所有 Android 构建里出现（B-1）**：在 `ppp/threading/Timer.cpp` 顶部加 `#error` 守卫。
3. **缩小 `s_ssl_ctx_init_mutex` 临界区（P-2）**：仅守护一次性的全局初始化，CA 加载放外部并发执行。

#### 优先级 2（重要）

4. 类型安全的 `CompletionState`（S-3 / A-2）：`std::variant` 或继承结构替换 `shared_ptr<void>` 槽。
5. 删除冗余 `handshaked_.store(false)`（B-4）。
6. 保留 ICMP 错误回送的最小路径（B-2）：让 PMTUD/traceroute 在 Android 下也可用；至少增加开关 `enable_icmp_errors_passthrough`。
7. 恢复 Android TLS 会话缓存（P-1）：定位崩溃根因，恢复缓存以降低 DNS 查询延迟。

#### 优先级 3（锦上添花）

8. 拆分 `ppp/dns/DnsResolver.cpp`（A-3）。
9. 清理 `elif` 宏（A-1）；UTF-8 BOM 修复（A-4）。
10. 引入 `atomic_load_compat` 包装（S-4），便于 C++20 升级。

### 14.12 关键修复示例

#### 14.12.1 Android CA 加载兜底

```cpp
// ppp/ssl/SSL.cpp - CreateClientSslContext
#if defined(__ANDROID__)
    const auto& ca = ppp::configurations::GetAndroidCaBundlePath();
    if (!ca.empty()) {
        boost::system::error_code ec;
        ssl_context->load_verify_file(ca, ec);
        if (ec) {
            ppp::diagnostics::SetLastErrorCode(
                ppp::diagnostics::ErrorCode::SslCaBundleLoadFailed);
            return NULLPTR;
        }
    }
#else
    ssl_context->set_default_verify_paths();
#endif
```

#### 14.12.2 缩小 SSL 全局初始化锁

```cpp
// ppp/ssl/SSL.cpp - CreateClientSslContext
static std::once_flag s_ssl_globals_once;
std::call_once(s_ssl_globals_once, []() {
    SSL_CTX* warmup = SSL_CTX_new(TLS_client_method());
    if (warmup) SSL_CTX_free(warmup);
});
// 此后无需全局锁；CA 加载、cipher 配置可并发
```

#### 14.12.3 Android 必须有 `-DFUNCTION` 守卫

```cpp
// ppp/threading/Timer.cpp - 顶部
#if defined(__ANDROID__) && !defined(FUNCTION)
#  error "Android Timer.cpp requires -DFUNCTION (std::function backend); \
          ppp::function backend has a deep destructor recursion known crash."
#endif
```

### 14.13 与首版（§1–§13）的关联指引

| 续审条目 | 首版相关章节 | 关联性 |
|---|---|---|
| S-1 Android CA 加载 | §3.2 WSS/TLS 关闭证书校验、§3.3 主机名校验缺失 | 共同构成 TLS 端到端校验闭环 |
| P-2 SSL_CTX 全局锁 | §6.5 平台条件编译 | 跨平台互斥设计模式 |
| B-2 ICMP 丢弃 | §5.5 / §5.6 协议帧边界检查 | 同属"为安全/稳定性而牺牲功能"的折衷 |
| A-3 DnsResolver 拆分 | §6.1 拆 `stdafx.h` | 同属"超大单元拆分"治理思路 |
| S-4 `atomic_load(shared_ptr*)` | §6.1 / §6.2 stdafx 与 Beast 版本宏 | C++ 标准升级路径 |

### 14.14 总体结论

| 维度 | 评级 | 理由 |
|---|---|---|
| 正确性 | ⭐⭐⭐⭐ | 已修复 macOS TCP NAT 链、Android Timer/DNS/SSL 三类崩溃；ITransmission 原子化收敛旧的 strand-only 假设 |
| 性能 | ⭐⭐⭐ | 移动端 TLS 缓存关闭与全局 SSL 锁是当前主要瓶颈 |
| 安全 | ⭐⭐⭐ | Android CA 加载缺口需立刻补上；首版 §3 的示例密钥清理和默认弱 key 安全默认值仍待处理 |
| 可维护性 | ⭐⭐⭐ | 大文件 + `shared_ptr<void>` 槽 + 注释 BOM 是中期债务 |

**核心建议：** 先合入当前未提交修复（Timer.cpp / DnsResolver.cpp / SSL.cpp / ITransmission.{h,cpp} / VEthernetNetworkSwitcher.cpp / android/CMakeLists.txt），再按 §14.11 优先级 1 的三项依次落地，可在不破坏已有 macOS/Android 修复的前提下补齐安全与性能短板。同时持续推进首版 §8 的 P0/P1 项（示例密钥清理与 artifact 脱敏、写队列背压、传输帧上限）。
