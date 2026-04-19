# 错误处理 API

[English Version](ERROR_HANDLING_API.md)

## 范围

本文定义启动/运行路径与运维展示面共同使用的诊断错误 API 契约。

## 核心 API 面

锚点：

- `ppp/diagnostics/Error.h`
- `ppp/diagnostics/ErrorHandler.h`

主要调用：

- `SetLastErrorCode(ErrorCode code)`
- `SetLastError(...)`（覆盖 `bool`、整数、指针、以及调用方自定义返回值）
- `GetLastErrorCode()`（当前线程局部值）
- `GetLastErrorCodeSnapshot()` 与 `GetLastErrorTimestamp()`（进程级最近一次观测快照）
- `FormatErrorString(ErrorCode code)`

## Handler 注册契约

`RegisterErrorHandler(const ppp::string& key, const ppp::function<void(int err)>& handler)` 为 key-based 设计。

行为约定：

- key 对应一个注册槽位；
- 使用已有 key 再次注册会替换旧 handler；
- 传入空 handler 会移除该 key；
- handler 接收当前 `ErrorCode` 的整数值。

## 注册阶段线程安全边界

注册变更定位为初始化/卸载阶段行为：

- 支持：多线程运行前完成注册、替换、移除；
- 支持：受控停机且 worker 静止时移除 handler；
- 不作为支持契约：worker 活跃派发期间频繁变更注册表。

派发路径会在锁内复制当前 handler 集合、在锁外回调。该实现可保证派发连续性，但注册变更仍应按生命周期管理，不应作为热路径控制手段。

## 诊断覆盖策略

失败路径在返回失败哨兵值（`false`、`-1`、`NULLPTR`）前应设置诊断。

覆盖要求：

- 启动与环境准备失败必须设置诊断；
- 打开/重连/释放失败必须设置诊断；
- 回滚失败即使继续 best-effort 也必须设置诊断；
- 新增失败分支不应只依赖泛化兜底消息。

## 错误传播期望

诊断链路应保持单一事实源：

- 后端写入 `ErrorCode`；
- Console UI 等展示层读取快照并格式化文本；
- 桥接层（含 Android JNI）尽量保持语义映射，避免引入无法对齐的并行错误体系。

这样可让 CLI、日志与平台集成共享一致的运维排障语义。
