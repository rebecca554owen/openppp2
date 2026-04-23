# TUI 设计 — PPP PRIVATE NETWORK™ 2 控制台界面

## 概述

ConsoleUI 子系统（`ppp/app/ConsoleUI.h` / `ppp/app/ConsoleUI.cpp`）实现了一个
单例全屏终端 UI，内部划分为三个可滚动区段（VPN 信息、命令输出、输入行），并通过
专用渲染线程和输入线程运行，不会阻塞 Boost.Asio 主事件循环。

详细英文版本请参见 [TUI_DESIGN.md](TUI_DESIGN.md)。本文档仅提供核心设计要点的
中文说明，并与英文版**严格对称**。任何一方的行为变更必须同步修改另一方。

---

## 布局

```
┌──────────────────────────────────────────────────────────────────────┐
│ PageUp/PageDown: 滚动命令输入/输出         PPP PRIVATE NETWORK™ 2 │
│ Home/End       : 滚动 openppp2 信息                                  │
│          [彩色 OPENPPP2 ASCII 艺术字，5 行]                          │
├──────────────────────────────────────────────────────────────────────┤
│  [信息区段 — VPN 状态快照，Home / End 滚动]                         │
├──────────────────────────────────────────────────────────────────────┤
│  [命令区段 — 命令历史 / 输出，PageUp / PageDown 滚动]               │
├──────────────────────────────────────────────────────────────────────┤
│  > [输入行或占位提示，反显字符块作为光标]                           │
├──────────────────────────────────────┬───────────────────────────────┤
│  错误: 描述 (Ns ago)                  │  VPN: 状态  ↑ tx/s  ↓ rx/s │
└──────────────────────────────────────┴───────────────────────────────┘
```

固定头部 10 行（顶部边框、两行提示、5 行 ASCII 艺术字、空行、分隔符），
固定底部 5 行（输入分隔符、输入行、状态分隔符、状态栏、底部边框）。
中间区段按 3:2 比例切分给信息区和命令区，并在总高度不足时自动退化。

---

## 刷新策略（无闪烁）

渲染管线围绕三条原则设计：**不在每一帧开关光标**、**不在每一帧清屏**、
**按需重绘**（脏标记驱动）。这些共同消除了早期版本中普遍存在的光标闪烁
和 stdout 抖动问题。

```
RenderLoop（condition_variable 节拍，最长 100 ms）
  ├─ render_cv_.wait_for(lock, 100ms)
  ├─ DrainStatusQueue()  — 短锁 swap 出队列，锁外处理，再短锁写回
  ├─ need_redraw = dirty_.exchange(false) || force_redraw_
  ├─ 若终端尺寸变化，force_redraw_ = true; need_redraw = true
  ├─ 若 need_redraw，则 RenderFrame()
  └─ （循环 — 由 MarkDirty() 立即唤醒，或最多等待 100 ms）
```

所有公共修改方法（`AppendLine`、`UpdateStatus`、`SetInfoLines`、全部
`Insert*` / `Move*` / `Erase*` / `Scroll*`、以及 `HandleEnter`）在释放锁
之后调用 `MarkDirty()`。`MarkDirty()` 同时调用 `render_cv_.notify_one()`，
渲染线程在 UI 状态变化后**微秒级**唤醒，而非固定 20 Hz 节拍。渲染线程将
多次脏标记合并为一次重绘，避免突发输入导致 I/O 抖动。

`DrainStatusQueue()` 采用两阶段锁模式：短暂持锁将队列 `swap` 到本地变量，
释放锁后在锁外执行字符串处理（`ToLower`、`find`、`substr` 等），最后再次
短暂持锁写回 `vpn_state_text_` 和 `speed_text_`，保证渲染线程持锁时间最短。

### 光标处理（无闪烁）

**真实终端光标在 TUI 会话的全生命周期内始终隐藏**，只有 `Stop()` 在退出
时才会将其恢复可见。输入行中的插入位置通过一个反显白色字符块来指示，
该字符块由 `BuildEditorLine()` 在字符串中按字节位置嵌入：

```
> Editor text with caret█here
             ^^^^^^^^^^^
             渲染为 "\x1b[7m h\x1b[0m"（反显的 'h'）
```

由于该字符块是渲染字符串的一部分，它与帧中的其他字符一起原子更新，永远
不会产生循环发送 `\x1b[?25h` / `\x1b[?25l` 导致的光标抖动。

### 最小清屏策略

| 条件                                 | 发送的转义序列 |
|--------------------------------------|------------------|
| `Start()` 之后的第一帧               | `\x1b[2J\x1b[H`（整屏清除 + 归位） |
| 终端尺寸发生变化                     | `\x1b[2J\x1b[H`（整屏清除 + 归位） |
| 其他所有帧                           | `\x1b[H`（仅光标归位）             |

由于每一行输出都会被 box 构建器右填充为精确的 `width` 列宽度，仅用
"光标归位 + 全高度覆盖"即可擦除上一帧的内容，避免了 `\x1b[2J`
带来的屏幕闪烁。

### 备用屏幕缓冲区

`Start()` 通过 `\x1b[?1049h` 进入终端的备用屏幕缓冲区，`Stop()` 通过
`\x1b[?1049l` 离开。备用缓冲区的内容由终端模拟器保存，TUI 退出后用户
原有的 shell 提示符、滚动历史、光标位置会**原样再现**，就像本进程从未
运行过一样。

Windows 平台上还会在 `Start()` 时额外快照以下状态并在 `Stop()` 恢复：

- `GetConsoleMode()` — 控制台输出模式标志
- `GetConsoleCursorInfo()` — 光标可见性

---

## 按键绑定

| 按键                 | 作用 |
|----------------------|------|
| PageUp / PageDown    | 向上 / 向下滚动命令区段 |
| Home / End           | 将信息区段滚动到顶部 / 底部 |
| ↑ / ↓                | 命令历史上 / 下 |
| ← / →                | 移动文本光标 |
| Ctrl+A / Ctrl+E      | 光标移至行首 / 行尾 |
| Backspace / Delete   | 删除光标前 / 光标处字符 |
| Enter                | 执行命令 |

---

## 内置命令

```
openppp2 help     显示帮助
openppp2 restart  重启应用
openppp2 reload   重新加载配置（等价于 restart）
openppp2 exit     退出应用
openppp2 info     将 VPN 信息快照打印到命令输出区
openppp2 clear    清空命令输出区
<shell 命令>      通过子进程执行系统 shell 命令
```

为兼容旧版本，裸命令 `help` / `restart` / `reload` / `exit` / `clear` / `status`
也被接受。

非内置命令通过**受追踪的 std::thread**执行，避免阻塞输入循环。Shell 线程通过
`pending_shell_threads_`（`std::atomic<int>`）计数：线程进入时递增，退出时递减并
通知 `render_cv_`。`Stop()` 等待（最多 5 秒）计数器归零后再销毁共享状态，
防止子进程存活期间对已析构对象的访问（use-after-free）。

---

## 无 TTY 降级

当 `ShouldEnable()`（对 stdout 执行 `isatty`）返回 `false` 时：

1. **不**启动 `ConsoleUI`。
2. `PppApplication::Main()` 向 stdout 打印一次性纯文本 banner（版本、模式、
   进程 ID、配置路径、工作目录）。
3. 进程正常提供完整的 VPN 功能，仅没有交互式界面。
4. 无渲染线程，无输入线程，无 ANSI 转义输出——保证
   `./ppp > log.txt` 或管道重定向完全不会被污染。

**注意**：光标的隐藏/显示**只**由 `ConsoleUI::Start/Stop` 管理。`PppApplication`
的构造/析构**绝不**触碰光标状态，以避免在 stdout 被重定向时将 ANSI 序列
写进日志文件或与 TUI 的保存/恢复逻辑发生竞争。

---

## 线程安全

所有可变状态由单个 `std::mutex lock_` 保护。渲染线程在持锁区内拷贝出一份快
照，然后在锁外构建帧字符串并写入 stdout；每个公共修改方法都在释放锁之后
再调用 `MarkDirty()`。

对于跨线程生命周期控制，使用 `std::atomic<bool>` + `compare_exchange_strong`
语义保证启停幂等。

`pending_shell_threads_`（`std::atomic<int>`）追踪活跃 Shell 子线程数。`Stop()`
等待（最多 5 秒）此计数器归零后再销毁共享状态。

`render_cv_`（`std::condition_variable`）由 `MarkDirty()` 和 Shell 线程用于无
自旋唤醒渲染线程，由独立的 `render_cv_mutex_` 保护（与 `lock_` 分离，避免竞争）。

---

## 平台差异

| 特性                     | Windows                                   | POSIX                              |
|--------------------------|-------------------------------------------|------------------------------------|
| 输入读取                 | `_kbhit` + `_getch`                       | `read(STDIN_FILENO)` 非阻塞        |
| 输入模式                 | `PrepareInputTerminal()` 清除 `ENABLE_ECHO_INPUT` 和 `ENABLE_LINE_INPUT`，`RestoreInputTerminal()` 恢复 | `tcsetattr` 关闭 `ICANON`/`ECHO`/`ISIG` |
| 终端状态保存             | `GetConsoleMode/CursorInfo` + stdin 模式  | `tcgetattr` + `fcntl` 标志         |
| 备用屏幕缓冲区           | `\x1b[?1049h/l`（需启用 VT）             | `\x1b[?1049h/l`                    |
| 虚拟终端启用             | `ENABLE_VIRTUAL_TERMINAL_PROCESSING`      | 默认支持                           |

**滚动边界：** 信息区和命令区的最大滚动偏移均限制为
`max(0, (int)content_lines - panel_height)`，防止过度滚动导致面板顶部出现空行。

---

## 相关源码

- `ppp/app/ConsoleUI.h` / `ppp/app/ConsoleUI.cpp` — TUI 主实现
- `ppp/app/ApplicationInitialize.cpp` — TUI 启停整合点（isatty 降级判断）
- `ppp/app/ApplicationMainLoop.cpp` — 通过 `UpdateStatus` / `SetInfoLines`
  向 TUI 推送数据
- `ppp/stdafx.cpp::HideConsoleCursor` — 跨平台光标可见性原语

---

## 参考

- VT100 / ANSI 转义序列：ECMA-48
- 备用屏幕缓冲区：xterm control sequences, DEC Private Mode 1049
- 最小清屏理念来源：ncurses 的 `wnoutrefresh` + `doupdate` 双缓冲思想
