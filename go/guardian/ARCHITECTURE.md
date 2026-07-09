# OpenPPP2 Guardian — 技术架构文档

> 面向接手开发者的完整项目说明。

---

## 1. 项目定位

Guardian 是一个**独立于 ppp 的外挂守护程序**，用于管理 ppp 二进制文件和配置文件，提供 Web UI + TUI 管理界面。

**不修改 ppp C++ 代码**。Guardian 通过 `exec.Command` 启动 ppp 子进程，通过 PTY 伪终端捕获输出，解析 ppp TUI 帧中的结构化数据（Duration/Sessions/TX/RX/IN/OUT 等）。

---

## 2. 目录结构

```
go/guardian/                     # Go 后端（daemon + TUI）
├── main.go                      # 入口：解析 --config，创建 Guardian，启动 API server
├── guardian.go                  # Guardian 编排器：持有三个 Manager，启动/停止实例
├── config.go                    # 配置模型（GuardianConfig/InstanceConfig/...）
├── webui.go                     # embed.FS 嵌入 webui/dist/
├── appsettings.json             # 默认 guardian 配置（首次运行自动生成）
│
├── instance/                    # 多实例进程管理
│   ├── manager.go               # Manager：Add/Remove/Start/Stop/Restart/Status/Logs/Shutdown
│   ├── instance.go              # instance 内部结构：cmd、logs ringBuffer、runtimeStats
│   ├── health.go                # HealthChecker：TCP/HTTP 健康检查（goroutine）
│   ├── ansi.go                  # StripANSI：过滤 ANSI 转义码
│   ├── pty_linux.go             # Linux PTY（/dev/ptmx + ioctl）
│   ├── pty_other.go             # 非 Linux 回退（os.Pipe）
│   ├── procattr_linux.go        # SysProcAttr（Setpgid）
│   └── procattr_other.go        # 非 Linux SysProcAttr
│
├── profile/                     # 配置文件管理（ppp 的 appsettings.json）
│   ├── manager.go               # CRUD + validate + backup/restore
│   ├── profile.go               # file I/O helpers
│   ├── validator.go             # JSON 校验 + ppp 结构检查
│   └── backup.go                # 自动备份/恢复/清理
│
├── binary/                      # 二进制版本管理
│   ├── manager.go               # Register/Discover/AutoDiscover/Remove/List
│   └── binary.go                # SHA256、版本检测（strings 命令）、架构检测
│
├── api/                         # HTTP + SSE API 层
│   ├── server.go                # Server 结构体、NewServer、Start、Shutdown
│   ├── router.go                # 路由注册（Go 1.22+ 模式路由）
│   ├── middleware.go            # CORS + Auth + 日志中间件，statusWriter（Flush+Unwrap）
│   ├── response.go              # JSON/Error/Success 响应辅助
│   ├── ws.go                    # SSE 推送：logs stream + event stream + heartbeat
│   ├── handler_instance.go      # CRUD + start/stop/restart + logs
│   ├── handler_profile.go       # CRUD + validate + backup/restore
│   ├── handler_binary.go        # register + discover + remove
│   ├── handler_auth.go          # login + refresh + changePassword
│   ├── handler_guardian.go      # /status + /guardian/config
│   ├── handler_service.go       # systemd install/uninstall/status
│   └── handler_static.go        # 嵌入式 Web UI 静态文件服务
│
├── auth/                        # JWT 认证
│   ├── jwt.go                   # HMAC-SHA256 JWT 生成/验证（stdlib only）
│   └── store.go                 # 内存 token 存储（Add/Remove/Clear/Cleanup）
│
├── service/                     # 系统服务集成
│   ├── service.go               # 跨平台接口
│   ├── systemd.go               # Linux systemd install/uninstall/status
│   ├── systemd_stubs.go         # 非 Linux 桩
│   ├── windows.go               # Windows Service 桩
│   └── windows_stubs.go         # 非 Windows 桩
│
├── cmd/tui/                     # 独立 TUI 二进制（separate Go module）
│   ├── go.mod                   # module ppp/guardian/cmd/tui（依赖 bubbletea/bubbles/lipgloss）
│   ├── main.go                  # 入口：--api、--token 参数
│   ├── client.go                # HTTP 客户端（REST + SSE）
│   ├── model.go                 # bubbletea 模型、初始化、数据类型
│   ├── update.go                # Update 函数：键盘事件处理
│   └── views.go                 # View 函数：5 个 Tab 渲染
│
└── webui/                       # Svelte 前端
    ├── package.json             # Vite + Svelte
    ├── vite.config.js           # 构建配置 + dev proxy
    ├── svelte.config.js
    ├── index.html
    └── src/
        ├── main.js
        ├── App.svelte           # 布局：sidebar + topbar + 内容区 + 语言切换
        ├── lib/
        │   ├── api.js           # HTTP/SSE 客户端（fetch + EventSource）
        │   ├── stores.js        # Svelte stores（instances, selectedInstance, isConnected）
        │   └── i18n.js          # 中英文翻译（en + zh）
        ├── components/
        │   ├── StatusBadge.svelte
        │   ├── ConfirmDialog.svelte
        │   ├── Toast.svelte
        │   ├── Loading.svelte
        │   └── Empty.svelte
        └── routes/
            ├── Dashboard.svelte   # 仪表盘：状态卡片 + 实例列表 + 创建/编辑弹窗
            ├── Instances.svelte   # 实例详情：进程信息 + 运行状态 + 日志
            ├── Configs.svelte     # 配置编辑：表单模式 + Raw JSON 模式（双向同步）
            ├── Logs.svelte        # 日志查看：SSE 实时流 + 搜索 + 暂停
            ├── Binaries.svelte    # 二进制管理：注册 + 发现 + 版本
            └── Settings.svelte    # 设置：登录/改密码 + API 状态 + 关于
```

---

## 3. 核心架构

### 3.1 数据流

```
ppp 子进程
   │
   ▼ (PTY slave → PTY master)
capturePty goroutine
   │
   ├── 解析 ANSI → 去除转义码 → clean line
   ├── 解析 key:value → runtimeStats (Duration/Sessions/TX/RX/...)
   ├── 过滤 TUI 噪音（边框/ASCII art/提示文字）
   └── 写入 ringBuffer + 通知 logSubscribers
                                      │
                                      ▼
                          ┌───────────────────────┐
                          │   instance.logMu 锁    │
                          │   ringBuffer + stats   │
                          └───────┬───────┬───────┘
                                  │       │
                          GET /api/v1/    SSE /api/v1/sse/
                          instances/{n}   logs/{n}
                                  │       │
                                  ▼       ▼
                          Web UI / TUI  Web UI
                          (REST 轮询)   (实时流)
```

### 3.2 进程管理

```go
type instance struct {
    mu              sync.RWMutex        // 生命周期锁（running/pid/startAt/stopAt/lastExit/cmd）
    logMu           sync.RWMutex        // 日志锁（ringBuffer/runtimeStats/logSubscribers）
    cfg             Config
    cmd             *exec.Cmd
    running         bool
    pid             int
    startedAt       *time.Time
    stoppedAt       *time.Time
    lastExit        *ExitState
    restartCount    int
    logs            *ringBuffer
    logSubscribers  map[chan LogEntry]struct{}
    runtimeStats    map[string]string
    healthCheck     *HealthChecker
    ...
}
```

**关键设计**：
- `mu` 和 `logMu` 分离：避免日志采集和生命周期操作互相阻塞
- PTY 伪终端：ppp 看到的是 TTY，启用完整 TUI 输出
- `Setpgid: true`：子进程独立进程组，stop 时 `syscall.Kill(-pid, sig)` 杀整个进程组
- 版本检测异步：注册二进制时先返回，后台 goroutine 调 `strings` 命令检测版本

### 3.3 ppp TUI 输出解析

capturePty 逐行读取 PTY master 输出，执行以下处理：

1. `StripANSI()` — 去除 ANSI 转义码（CSI/OSC/DCS 序列）
2. 去重 — 连续相同行跳过（ppp 每帧重绘整个 TUI）
3. 解析 `key: value` — 匹配已知 key（duration/sessions/tx/rx/in/out/...），写入 `runtimeStats`
4. 过滤噪音 — 边框字符、ASCII art、提示文字不写入日志
5. 写入 `ringBuffer` + 通知 SSE 订阅者

**runtimeStats 更新频率**：跟随 ppp TUI 刷新频率（约每 1 秒）。

### 3.4 锁模型

| 锁 | 保护范围 | 持有时间 |
|---|---------|---------|
| `Manager.mu` | instances map, eventSubscribers | 极短（map 操作） |
| `instance.mu` | running, pid, cmd, startedAt, stoppedAt, lastExit, restartCount | 短（状态更新） |
| `instance.logMu` | ringBuffer, runtimeStats, logSubscribers | 极短（单条写入） |
| `auth.TokenStore.mu` | token map | 极短 |
| `profile.Manager.mu` | 文件写入 | 短（I/O） |
| `binary.Manager.mu` | items map | 短 |

### 3.5 配置持久化

- `guardian.json` — Guardian 自身配置（listen、auth、instances 列表、profilesDir、binariesDir）
- `profiles/*.json` — ppp 的 appsettings.json（一个 profile 一个文件）
- `backups/{profile}/{timestamp}.json` — profile 自动备份
- 实例增删改后自动调 `SaveConfig()` 写回 guardian.json

首次运行时 `guardian.json` 不存在，使用 `DefaultConfig()` 启动，不报错。

---

## 4. API 设计

### 4.1 REST API

| Method | Path | 描述 |
|--------|------|------|
| POST | /api/v1/auth/login | 登录（password → JWT token） |
| POST | /api/v1/auth/refresh | 刷新 token |
| PUT | /api/v1/auth/password | 修改密码（首次无需旧密码） |
| GET | /api/v1/status | Guardian 状态（版本/运行时间/实例数/二进制数） |
| GET | /api/v1/instances | 列出所有实例 |
| POST | /api/v1/instances | 创建实例（name/binary/configPath/args/...） |
| GET | /api/v1/instances/{name} | 实例详情 + runtimeStats |
| PUT | /api/v1/instances/{name} | 更新实例（停机→更新→重启） |
| DELETE | /api/v1/instances/{name} | 删除实例（自动停止） |
| POST | /api/v1/instances/{name}/start | 启动实例 |
| POST | /api/v1/instances/{name}/stop | 停止实例 |
| POST | /api/v1/instances/{name}/restart | 重启实例 |
| GET | /api/v1/instances/{name}/logs | 获取日志（?n=50&stream=stdout） |
| GET | /api/v1/profiles | 列出配置文件 |
| GET | /api/v1/profiles/{name} | 获取配置内容 |
| PUT | /api/v1/profiles/{name} | 保存配置（自动备份旧版） |
| DELETE | /api/v1/profiles/{name} | 删除配置 |
| POST | /api/v1/profiles/{name}/validate | 验证 JSON |
| GET | /api/v1/profiles/{name}/backups | 列出备份 |
| POST | /api/v1/profiles/{name}/restore/{id} | 恢复备份 |
| GET | /api/v1/binaries | 列出已注册二进制 |
| GET | /api/v1/binaries/discover?dir=. | 扫描目录发现 ppp 二进制 |
| POST | /api/v1/binaries | 注册二进制（异步检测版本） |
| DELETE | /api/v1/binaries/{id} | 删除二进制 |
| PUT | /api/v1/guardian/config | 保存 guardian 配置 |
| GET | /api/v1/service/status | systemd 服务状态 |
| POST | /api/v1/service/install | 安装 systemd 服务 |
| POST | /api/v1/service/uninstall | 卸载 systemd 服务 |

### 4.2 SSE (Server-Sent Events)

| Path | 描述 |
|------|------|
| GET /api/v1/sse/logs/{name}?token=... | 实例日志实时流 |
| GET /api/v1/sse/events?token=... | 全局事件流（started/stopped/crashed/unhealthy/...） |

SSE 实现：标准 `text/event-stream`，`data: {json}\n\n` 格式，heartbeat 每 30 秒。

---

## 5. 前端架构

### 5.1 技术栈

- Svelte 4（非 SvelteKit，纯 SPA）
- Vite 5 构建
- 无外部 CSS 框架（内联 CSS）
- 无路由库（自定义 Tab 切换）
- 无状态管理库（Svelte stores）

### 5.2 暗色主题色板

| 用途 | 颜色 |
|------|------|
| 背景 | `#0d1117` |
| 面板 | `#161b22` |
| 边框 | `#30363d` |
| 文字 | `#c9d1d9` |
| 暗字 | `#8b949e` |
| 强调 | `#58a6ff` |
| 成功 | `#3fb950` |
| 危险 | `#f85149` |
| 警告 | `#d29922` |
| 按钮 | `#21262d` |

### 5.3 国际化

`src/lib/i18n.js` 包含 `en` 和 `zh` 两个字典，`t(key)` 函数根据 localStorage `guardian.lang` 返回翻译。默认自动检测浏览器语言。

### 5.4 构建与嵌入

```bash
cd go/guardian/webui
npm install
npm run build          # → dist/
cd ..
go build -o guardian . # embed.FS 嵌入 webui/dist/
```

Web UI 通过 `api/handler_static.go` 的 `handleStatic` 从嵌入 FS 提供静态文件。

---

## 6. 构建与运行

### 6.1 依赖

**Go 后端**：stdlib only（Go 1.23+），无外部依赖。
**TUI**：bubbletea + bubbles + lipgloss（独立 module `cmd/tui/`）。
**Web UI**：Svelte 4 + Vite 5（npm）。

### 6.2 构建命令

```bash
# Guardian daemon
cd go/guardian
go mod tidy
go build -o guardian .
go vet ./...

# TUI
cd go/guardian/cmd/tui
go mod tidy
go build -o guardian-tui .

# Web UI
cd go/guardian/webui
npm install
npm run build
```

### 6.3 运行

```bash
# 守护进程（首次运行无需配置文件，自动使用默认配置）
./guardian

# 指定配置文件
./guardian --config=/path/to/guardian.json

# TUI 客户端（连接到守护进程）
./guardian-tui --api=http://127.0.0.1:18080

# Web UI
# 浏览器打开 http://127.0.0.1:18080
```

### 6.4 首次使用流程

1. 启动 guardian → API 可用，无实例
2. 打开 Web UI → Binaries 页 → 发现 ppp 二进制 → 注册
3. Configs 页 → 创建配置 profile（表单或 Raw JSON）
4. Dashboard → 添加实例 → 选二进制 + 配置 + 模式（client/server）+ 参数 → 创建
5. 点启动 → ppp 运行 → 实时显示 TX/RX/Duration/Sessions

---

## 7. 已知设计决策与约束

| 决策 | 原因 |
|------|------|
| Guardian 不修改 ppp 代码 | 外挂架构，ppp 是黑盒 |
| PTY 伪终端而非 pipe | ppp 检测 isatty 后启用 TUI 输出 |
| runtimeStats 从 PTY 输出解析 | ppp 无结构化 API，只有 TUI 文本输出 |
| 版本检测用 strings 命令 | ppp 无 --version flag，版本嵌入二进制 |
| TUI 是独立二进制 | 通过 HTTP/SSE API 连接，支持 SSH 远程 |
| Web UI 嵌入 Go 二进制 | 单文件部署 |
| 所有锁按作用域分离 | mu（生命周期）/ logMu（日志+统计）避免死锁 |
| 实例增删改自动持久化 | 用户不需要手动保存 guardian.json |

---

## 8. 后续开发建议

### 8.1 功能扩展

- [ ] 实例分组/标签管理
- [ ] 配置模板系统（client/server 预设）
- [ ] 多 guardian 集群管理
- [ ] 流量统计图表（Chart.js）
- [ ] WebSocket 替代 SSE（双向通信）
- [ ] Windows Wails GUI（复用 Svelte 前端）
- [ ] 二进制远程下载（GitHub releases）
- [ ] 配置文件对比/合并
- [ ] 实例日志导出
- [ ] Prometheus /metrics 端点

### 8.2 架构改进

- [ ] 引入 structured logging（slog）
- [ ] HTTP handler 测试覆盖
- [ ] 前端端到端测试
- [ ] TLS 支持（自签证书 + Let's Encrypt）
- [ ] 配置文件热重载
- [ ] 实例资源限制（cgroups）

### 8.3 ppp 输出适配

当前 runtimeStats 解析基于 ppp TUI 文本格式。如果 ppp 版本更新导致输出格式变化，需要修改 `capturePty` 中的 key 匹配逻辑。建议：

1. 在 `instance/manager.go` 中集中维护 `statsKeys` map
2. 新增 key 时只需添加到 map
3. 考虑支持正则匹配（当前是精确 key 匹配）

---

## 9. 文件大小参考

| 组件 | 文件数 | 代码量 |
|------|--------|--------|
| Go 后端（guardian） | ~20 .go 文件 | ~2500 行 |
| Go TUI | 6 .go 文件 | ~1200 行 |
| Svelte 前端 | 18 .svelte/.js 文件 | ~1500 行 |
| **合计** | **~44 文件** | **~5200 行** |
