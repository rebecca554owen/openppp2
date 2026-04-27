# go/daemon

`go/daemon` 是一个单机单实例的本地守护层，目标是先把下面三件事跑通：

1. 管理单个本地 `ppp` 进程的启停与重启。
2. 读写该实例的配置文件。
3. 以 HTTP 方式暴露本地管理接口，并代理接入现有 `go/ppp` 管理 API。

当前实现特点：

- 只管理一个 `ppp` 实例。
- 默认提供本地 Web UI 和一组 JSON API。
- `/api/managed/*` 会反代到配置中的 `managedApi.baseUrl`。
- 适合先做单机管理 MVP，不直接替代现有 `go/ppp` 远程控制面。

当前主要接口：

- `GET /api/status`
- `GET /api/config`
- `PUT /api/config`
- `POST /api/start`
- `POST /api/stop`
- `POST /api/restart`
- `GET /api/logs`
- `ALL /api/managed/*`

启动方式示例：

```bash
go run ./go/daemon --configuration=./go/daemon/appsettings.json
```

说明：

- 当前仓库环境未内置 Go toolchain，本实现按标准库自包含方式编写。
- 后续扩展方向包括：多实例、鉴权、结构化状态采集、前端拆分、持久化实例目录结构等。
