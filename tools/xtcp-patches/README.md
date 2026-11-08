# tools/xtcp-patches — XTCP pin 与补丁目录

## 当前 pin

- revision：`c9dd5601384201b396b1b6599c6c868097da5dcf`
- 来源：`https://github.com/liulilittle/xtcp/archive/${REVISION}.tar.gz`（**纯上游** main）
- SHA256：`6a9988d5bf5a039bd9bd0d0c7162e33afc1c60013af10f73abc82d0dc82b2631`
- 补丁目录只剩 `0001-cross-compile-threads-quiet.patch`（8 行，见下）

## 2026-11-01 推进记录：从 fork `607d9be` 切到纯上游 `c9dd560`

上一版 pin 指向 `rebecca554owen/xtcp` 的 `sync-upstream`（`607d9be`）。
**该树并不是「上游 c9dd560」**：它的父提交是旧上游 `e79db8f`，
`607d9be` = `e79db8f` + openppp2 的 28 个补丁（`c8e6767`）+ 3 个已被上游吸收的
额外提交 + 1 个 cross-compile 修复。也就是说上一版**没有**吃到上游那 64 个提交
（KCC v2、AVX2/SSSE3 融合拷贝+校验和、RACK/D-SACK/PAWS 正确性修复、SACK 选项预算、
byte-based immediate ACK、per-shard 重传路由、buffer pool headroom、frontier reclaim）。

### 核验方法与结论

| 核验方式 | 结果 |
|---|---|
| `git merge-base(up/main, fork/sync-upstream)` | `e79db8f`（fork 基于**旧**上游，非 c9dd560） |
| `git log up/main..fork/sync-upstream` | fork 独有 6 个提交（28 补丁 + 3 个上游已吸收的 + cross 修复） |
| `git log fork/sync-upstream..up/main` | 上游独有 **64** 个提交 |
| 28 个补丁逐条 `patch --reverse/--forward --dry-run` | 5 个完全吸收、8 个部分吸收、15 个被上游重写取代 |
| 补丁新增符号在 `c9dd560` 中的存在性（三方矩阵：基线/fork/上游） | 15 个补丁的关键符号在纯上游**全部缺失** |
| 集成层编译探针（`c++ -fsyntax-only`） | 纯上游头文件下 **14 个错误**；当前 fork 头文件下 0 个 |

### 上游是「重写」而非「吸收」

上游把受影响区域整体重写了：

| 文件 | 上游 c9dd560 | fork 607d9be |
|---|---|---|
| `src/core/tcp_fsm.cpp` | 7089 行 | 5559 行 |
| `plugins/ref/kcc_core.c` | 1196 行 | 470 行 |
| `plugins/cc_kcc.cpp` | 1468 行 | 555 行 |
| `include/xtcp/core/tcp.h` | 1482 行 | 1399 行 |

我们的补丁引入的公开 API（`ResumeReceive` / `ReceiveResumeResult` /
`ReceiveStateSnapshot` / `AckReleaseTelemetrySnapshot` / `TsoGateTelemetrySnapshot` /
`SendAdmissionSnapshot` / `KccTelemetrySnapshot` / `NextTimerDeadlineUs` /
`kCapChecksumPartialTx`）在纯上游**一个都不存在**，而 openppp2 集成层有约 40 处调用，
直接切纯上游会编译失败。

### 处置（方案 C）

openppp2 侧改造以适配上游 API，不再向 XTCP 打功能性补丁：

- **接收背压**：删掉显式 resume 调用，改用上游的 RFC 1122 零窗口模型
  （应用拒绝 → 回滚 RCV.NXT + 通告窗口 0 → 对端 persist 探测 → 应用接受 → 窗口重开）。
  上游内部已有同构机制（`rcv_blocked_` / `ooo_bytes_` / `AdvertisedWindow()` /
  `TrimOooToFrontier()`），接收端 persist 探测取 `snd_una_` 的首字节，部分重叠分段会
  裁掉已收前缀只投递新鲜后缀 ⇒ **零窗口路径无损**。
- **telemetry**：ack-release / tso-gate / send-admission / kcc 四组快照全部移除
  （它们本来都由环境变量 `OPENPPP2_XTCP_*_JSON` 门控，默认不开启）。
- **定时器截止期**：`PPP_XTCP_HAS_TIMER_DEADLINE` 改为按上游头文件是否含
  `NextTimerDeadlineUs` 自动探测；纯上游没有 ⇒ 走 1 ms 固定轮询兜底路径。
- **partial checksum**：上游始终计算完整 RFC 1071 校验和（融合拷贝+校验和），
  `SegMeta::checksum_partial` 与 `kCapChecksumPartialTx` 均不存在 ⇒ 后端不再传播该标志，
  TAP 收到的始终是完整校验和。

### 唯一保留的补丁

`0001-cross-compile-threads-quiet.patch`（8 行，`CMakeLists.txt`）：
上游仍是 `find_package(Threads REQUIRED)`，交叉编译时 CMake 的 Threads 探测跑不起来会
直接失败；改成 `QUIET` + `if(Threads_FOUND)` 后交叉构建才能通过。
该上下文在 `c9dd560` 中逐字一致，可干净应用。

## 机制保留

`tools/prepare_xtcp.sh` 的补丁机制仍然保留（`PATCH_DIR` / `PATCH_MARKER` /
`patch_stamp()`），目录为空时 stamp 为 `none`，脚本照常工作。
⇒ 将来若上游又引入需要本地定制的地方，把新补丁放进本目录即可，脚本会自动按名排序重放。

## 已知代价

- 零窗口恢复延迟：上游 persist 基础间隔 **1 s**、退避上限 `kMaxRto` = **60 s**，
  且 `TcpConn::SetPersistInterval` 在 `XtcpStack` 层不可达（无法调参）。
  对比旧 fork 的「应用侧显式 resume、立即重开窗口」，这里最坏要等一个 persist 周期。
- 轮询兜底：没有 `NextTimerDeadlineUs` 时用 1 ms 固定轮询驱动 `PollAckTimers`，
  CPU 比原来的截止期驱动高。
