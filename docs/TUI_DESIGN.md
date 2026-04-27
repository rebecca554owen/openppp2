# TUI Design — PPP PRIVATE NETWORK™ 2 Console Interface

[中文版本](TUI_DESIGN_CN.md)

## Overview

The ConsoleUI subsystem (`ppp/app/ConsoleUI.h`, `ppp/app/ConsoleUI.cpp`) implements a
singleton full-screen, box-drawing terminal UI that runs inside the existing application
process. It is divided into three independently scrollable sections (VPN info, command
output, and input line) and uses two dedicated threads (render and input) so that all
blocking I/O stays completely off the Boost.Asio event loop.

When stdout is not connected to a real terminal (e.g. output redirected to a file or
pipe), the TUI is skipped entirely and basic startup information is printed in plain-text
format instead.

```mermaid
graph TD
    PppApp["PppApplication::Main()"]
    ShouldEnable["ConsoleUI::ShouldEnable()"]
    TUIPath["TUI Mode\nStart render + input threads"]
    PlainPath["Plain-text Mode\nPrint banner, no threads"]
    VPN["VPN data plane\n(always runs)"]

    PppApp --> ShouldEnable
    ShouldEnable -->|"stdout is a tty"| TUIPath
    ShouldEnable -->|"stdout redirected"| PlainPath
    TUIPath --> VPN
    PlainPath --> VPN
```

---

## Layout

```
┌──────────────────────────────────────────────────────────────────────┐  row 0
│ PageUp/PageDown: Scroll command input/output   PPP PRIVATE NETWORK™ 2│  row 1
│ Home/End       : Scroll openppp2 info                                │  row 2
│          ___  ____  _____ _   _ ____  ____  ____ ____               │  row 3
│         / _ \|  _ \| ____| \ | |  _ \|  _ \|  _ \___ \             │  row 4
│        | | | | |_) |  _| |  \| | |_) | |_) | |_) |__) |            │  row 5
│        | |_| |  __/| |___| |\  |  __/|  __/|  __// __/             │  row 6
│         \___/|_|   |_____|_| \_|_|   |_|   |_|  |_____|            │  row 7
│                                                                      │  row 8
├──────────────────────────────────────────────────────────────────────┤  row 9
│  [Info section — scrollable with Home / End]                         │
│  VPN interface name, address, status, statistics ...                 │
├──────────────────────────────────────────────────────────────────────┤
│  [Cmd section — scrollable with PageUp / PageDown]                   │
│  command output, shell subprocess output, built-in command output... │
├──────────────────────────────────────────────────────────────────────┤
│  > [input line or dim placeholder, white-background block as caret]   │
├──────────────────────────────────────────────────────────────────────┤
│  Error: description (Ns ago) / No errors                             │
└──────────────────────────────────────────────────────────────────────┘
```

### Fixed rows

| Section              | Rows  |
|----------------------|-------|
| Top border           | 1     |
| Hint lines           | 2     |
| ASCII art            | 5     |
| Empty spacer         | 1     |
| Header separator     | 1     |
| **Total (header)**   | **10**|

| Section              | Rows  |
|----------------------|-------|
| Input separator      | 1     |
| Input row            | 1     |
| Status separator     | 1     |
| Status bar           | 1     |
| Bottom border        | 1     |
| **Total (footer)**   | **5** |

### Dynamic allocation

```
middle      = terminal_height - 10 - 5
info_height = max(2,  (middle - 1) * 3 / 5)
cmd_height  = max(1,  middle - 1 - info_height)   // -1 for info/cmd separator
```

Minimum supported terminal size: **40 × 20**.

---

## Thread Model

TUI uses two dedicated threads that are completely decoupled from the Boost.Asio IO threads:

```mermaid
graph TD
    IOThread["Boost.Asio IO Thread\n(never touches TUI state directly)"]
    RenderThread["RenderThread\n(dirty-flag driven repaint)"]
    InputThread["InputThread\n(key polling loop)"]
    ConsoleUIState["ConsoleUI State\n(std::mutex protected)"]
    Stdout["stdout\nfwrite frame"]

    IOThread -->|"AppendLine / UpdateStatus / SetInfoLines"| ConsoleUIState
    InputThread -->|"InsertChar / Scroll / HandleEnter"| ConsoleUIState
    RenderThread -->|"woken by MarkDirty, snapshots state"| ConsoleUIState
    RenderThread -->|"BuildFrame + fwrite"| Stdout
```

The IO thread (and any Asio-posted coroutine) calls `AppendLine`, `UpdateStatus`, or
`SetInfoLines` to push data into the TUI. These calls acquire `lock_`, mutate state, then
release `lock_` and call `MarkDirty()`. The render thread wakes, takes a snapshot while
holding `lock_` for the minimum time, then constructs the complete frame string while
holding no lock, and finally calls `fwrite` to emit the frame atomically.

---

## Box-Drawing Character Encoding

All border characters are encoded as UTF-8 3-byte sequences. Each character
occupies exactly **one display column** on any compliant terminal.

| Symbol | Unicode | UTF-8 bytes      |
|--------|---------|------------------|
| `┌`    | U+250C  | E2 94 8C         |
| `┐`    | U+2510  | E2 94 90         |
| `└`    | U+2514  | E2 94 94         |
| `┘`    | U+2518  | E2 94 98         |
| `├`    | U+251C  | E2 94 9C         |
| `┤`    | U+2524  | E2 94 A4         |
| `┬`    | U+252C  | E2 94 AC         |
| `┴`    | U+2534  | E2 94 B4         |
| `─`    | U+2500  | E2 94 80         |
| `│`    | U+2502  | E2 94 82         |

The frame builder (`BuildFrame()`) constructs the entire output as a single `ppp::string`
and emits it with a single `fwrite`. This eliminates the partial-write interleaving that
would occur if each line were written individually.

---

## ASCII Art Coloring

The five-line art for "OPENPPP2" is split at display column **24**:

- Columns `[0, 24)` → dark gray ANSI `\x1b[90m` (represents **OPEN**)
- Columns `[24, end)` → bold bright-white ANSI `\x1b[1;97m` (represents **PPP2**)

Colors are only applied when `vt_enabled_` is true (VT100 processing confirmed on the
current console handle).

The split is intentional: "OPEN" appears subdued to draw the eye toward "PPP2", which
renders in prominent bold white. This makes the brand mark immediately readable even in
terminal themes with low contrast.

---

## Key Bindings

| Key                | Action                                          |
|--------------------|-------------------------------------------------|
| `Home`             | Scroll info section to top (oldest content)     |
| `End`              | Scroll info section to bottom (newest)          |
| `PageUp`           | Scroll cmd section up (toward older output)     |
| `PageDown`         | Scroll cmd section down (toward newest)         |
| `Up Arrow`         | Recall previous command from history            |
| `Down Arrow`       | Recall next command / restore current input     |
| `Left Arrow`       | Move text cursor left                           |
| `Right Arrow`      | Move text cursor right                          |
| `Ctrl+A`           | Move cursor to beginning of line                |
| `Ctrl+E`           | Move cursor to end of line                      |
| `Backspace`        | Erase character before cursor                   |
| `Delete`           | Erase character at cursor                       |
| `Enter`            | Execute command                                 |

---

## Built-In Commands

| Command               | Action                                           |
|-----------------------|--------------------------------------------------|
| `openppp2 help`       | Print command list to cmd output section         |
| `openppp2 restart`    | Graceful restart via `ShutdownApplication(true)` |
| `openppp2 reload`     | Same action as restart                           |
| `openppp2 exit`       | Exit via `ShutdownApplication(false)`            |
| `openppp2 info`       | Pull and print full runtime environment snapshot |
| `openppp2 clear`      | Clear cmd output ring buffer                     |
| *(any other input)*   | Execute as shell command, capture output         |

Bare commands such as `help`, `restart`, `exit`, `clear`, and `status` are not mapped to
built-in handlers. They are executed as shell commands.

### System Command Execution

Non-built-in commands are executed in a **tracked `std::thread`** to avoid blocking the
input loop:

- **Windows**: `cmd /c <command> 2>&1`
- **Linux / macOS**: `<command> 2>&1`

Output lines from the subprocess are appended to `cmd_lines_` one at a time via
`AppendLine()`. The shell thread reads lines from the subprocess `FILE*` pipe in a loop
and calls `AppendLine()` for each line.

Thread lifecycle is tracked via a `pending_shell_threads_` (`std::atomic<int>`) counter:
the counter is incremented before the thread is launched and decremented (with
`render_cv_.notify_one()`) when it exits. `Stop()` performs a bounded wait (up to 5 s)
for the counter to reach zero before tearing down shared state, preventing use-after-free
on the ConsoleUI instance.

```mermaid
sequenceDiagram
    participant IT as InputThread
    participant CUI as ConsoleUI
    participant ST as ShellThread
    participant Proc as subprocess popen

    IT->>CUI: ExecuteCommand("ls -la")
    CUI->>CUI: pending_shell_threads_.fetch_add(1)
    CUI->>ST: std::thread launch
    ST->>Proc: popen("ls -la 2>&1", "r")
    loop read lines
        Proc-->>ST: line
        ST->>CUI: AppendLine(line)
        CUI->>CUI: MarkDirty()
    end
    ST->>Proc: pclose
    ST->>CUI: pending_shell_threads_.fetch_sub(1)
    ST->>CUI: render_cv_.notify_one()
```

---

## Refresh Strategy (Flicker-Free)

The render pipeline is designed around three principles: **no per-frame cursor
toggling**, **no per-frame full-screen clear**, and **repaint-on-demand** driven
by a dirty flag. Together these eliminate all cursor flicker and stdout churn
that plagued earlier revisions of this subsystem.

```
RenderLoop (condition_variable tick, max 100 ms)
  ├─ render_cv_.wait_for(lock, 100ms)
  ├─ DrainStatusQueue()     — short-lock swap of status_queue_, process outside lock
  ├─ need_redraw = dirty_.exchange(false) || force_redraw_
  ├─ if (terminal size changed) force_redraw_ = true; need_redraw = true
  ├─ if (need_redraw) RenderFrame()
  └─ (loop — woken immediately by MarkDirty() or up to 100 ms idle wait)
```

Every public mutator (`AppendLine`, `UpdateStatus`, `SetInfoLines`, every
`Insert*` / `Move*` / `Erase*` / `Scroll*` method, and `HandleEnter`) calls
`MarkDirty()` after releasing the lock. `MarkDirty()` also calls
`render_cv_.notify_one()`, so the render thread wakes within microseconds of
any UI state change rather than at a fixed 20 Hz cadence. The render thread
coalesces multiple dirty marks into a single frame draw, so bursty input does
not produce bursty I/O.

`DrainStatusQueue()` uses a two-phase lock pattern: acquire `lock_` for a
minimum-duration `std::swap` of the queue into a local variable, release
`lock_`, process the local variable (string parsing, `ToLower`, `find`,
`substr`, etc.), then acquire `lock_` again only for the final write-back of
`vpn_state_text_` and `speed_text_`. This keeps the render thread's lock hold
time minimal.

```mermaid
sequenceDiagram
    participant Mutator as Mutator (AppendLine etc.)
    participant Lock as std::mutex lock_
    participant DirtyFlag as dirty_ (atomic)
    participant RenderCV as render_cv_
    participant RenderThread as RenderThread

    Mutator->>Lock: acquire lock, mutate state
    Mutator->>Lock: release lock
    Mutator->>DirtyFlag: dirty_.store(true)
    Mutator->>RenderCV: notify_one()
    RenderCV-->>RenderThread: wake up
    RenderThread->>Lock: short-hold snapshot copy
    RenderThread->>RenderThread: build frame string (no lock held)
    RenderThread->>RenderThread: fwrite to stdout
```

### Cursor Handling (Flicker-Free)

The real terminal cursor is **hidden for the entire lifetime of the TUI
session** and is only made visible again by `Stop()` during shutdown. The
caret position inside the editor line is conveyed by a single white-background
block that `BuildEditorLine()` embeds at the appropriate byte offset:

```
> Editor text with caret█here
             ^^^^^^^^^^^
             rendered as "\x1b[47m h\x1b[0m"  (white-background 'h')
```

Because the block is part of the rendered string, it moves atomically with
every other character in the frame and never produces the cursor-jitter that
arises from cyclic `\x1b[?25h` / `\x1b[?25l` sequences.

### Minimal-Clear Strategy

`RenderFrame()` emits:

| Condition                        | Escape sequence emitted              |
|----------------------------------|--------------------------------------|
| First frame after `Start()`     | `\x1b[2J\x1b[H` (full clear + home) |
| Terminal size changed            | `\x1b[2J\x1b[H` (full clear + home) |
| All other frames                 | `\x1b[H` (cursor home only)          |

Each row in the frame string already occupies the full terminal width (the
box builders right-pad to exactly `width` columns), so a simple cursor-home
followed by a full-height overwrite is sufficient to erase the previous
frame without the screen flash produced by `\x1b[2J`.

### Alternate Screen Buffer

`Start()` enters the terminal's alternate screen buffer via `\x1b[?1049h`
and `Stop()` leaves it via `\x1b[?1049l`. The alt-screen buffer is
preserved by the terminal emulator, so when the TUI exits the user's
original shell prompt, scrollback, and cursor position re-appear exactly
as they were before the process launched.

On Windows the pre-session console output mode (`GetConsoleMode`) and cursor
visibility (`GetConsoleCursorInfo`) are additionally snapshotted at `Start()`
and restored in `Stop()`.

---

## No-TTY Fallback

```
ConsoleUI::ShouldEnable()
  ├─ Windows: _isatty(_fileno(stdout))
  └─ POSIX:   isatty(STDOUT_FILENO)
```

When `ShouldEnable()` returns `false`:

1. `ConsoleUI::Start()` is **not** called.
2. `PppApplication::Main()` prints a one-time plain-text banner to `stdout`:
   - Application version
   - Mode (client / server)
   - Process ID
   - Config file path
   - Working directory
3. The process continues with full VPN functionality.
4. No render thread, no input thread.

This ensures log capture via `./ppp > log.txt` or piped output works without interference.

```mermaid
flowchart TD
    A["PppApplication::Main()"] --> B["ConsoleUI::ShouldEnable()"]
    B -->|"stdout is a tty"| C["ConsoleUI::Start()"]
    B -->|"stdout redirected/piped"| D["Print plain-text banner to stdout"]
    C --> E["EnableVirtualTerminal()"]
    E --> F["PrepareInputTerminal()"]
    F --> G["Launch render_thread_ + input_thread_"]
    G --> H["TUI active"]
    D --> I["VPN runs normally, no TUI threads"]
```

---

## Thread Safety

All mutable ConsoleUI state is protected by a single `std::mutex lock_`. The render
thread and the input thread both acquire `lock_` for short critical sections (snapshot
copies) and then work on their local copies.

`running_` is a `std::atomic<bool>` used for lock-free thread lifecycle signaling with
`compare_exchange_strong(memory_order_acq_rel)`.

`pending_shell_threads_` (`std::atomic<int>`) tracks the count of live shell subprocess
threads. `Stop()` waits (bounded by 5 s) until this counter reaches zero before
destroying shared state.

`render_cv_` (`std::condition_variable`) is used by `MarkDirty()` and the shell threads
to wake the render thread without spinning. It is guarded by `render_cv_mutex_`
(separate from `lock_` to avoid contention).

```mermaid
graph TD
    Lock["std::mutex lock_\nProtects: info_lines_, cmd_lines_, input_, vpn_state_"]
    AtomicRunning["std::atomic<bool> running_\nThread lifecycle signal"]
    AtomicPending["std::atomic<int> pending_shell_threads_\nShell thread count"]
    RenderCV["std::condition_variable render_cv_\nRender thread wake signal"]
    RenderCVMutex["std::mutex render_cv_mutex_\nDedicated mutex for render_cv_"]

    Lock -->|"render / input threads hold briefly"| RenderCV
    AtomicRunning -->|"compare_exchange_strong"| RenderCV
    AtomicPending -->|"Stop() waits for zero"| RenderCV
    RenderCV --> RenderCVMutex
```

---

## Data Flow

```mermaid
sequenceDiagram
    participant App as PppApplication::OnTick
    participant CUI as ConsoleUI (lock protected)
    participant RT as RenderThread
    participant IT as InputThread
    participant User as User keyboard

    App->>CUI: UpdateStatus("vpn=up rx=... tx=...")
    App->>CUI: SetInfoLines([...])

    RT->>CUI: DrainStatusQueue()
    RT->>CUI: Snapshot (info_lines_, cmd_lines_, input_, vpn_state_)
    RT->>RT: BuildFrame() → full frame string
    RT-->>stdout: fwrite(frame)

    User->>IT: keypress
    IT->>CUI: InsertInputChar / HandleEnter / Scroll*
    IT->>CUI: ExecuteCommand → AppendLine(output)
```

---

## TUI Startup Sequence

```mermaid
sequenceDiagram
    participant M as Main()
    participant C as ConsoleUI

    M->>C: ShouldEnable()
    alt stdout is a tty
        C-->>M: true
        M->>C: Start()
        C->>C: EnableVirtualTerminal()
        C->>C: PrepareInputTerminal()
        C->>C: launch render_thread_ + input_thread_
        C->>C: emit \x1b[?1049h (enter alt screen)
        C->>C: emit \x1b[?25l (hide real cursor)
        C-->>M: true (success)
    else stdout redirected
        C-->>M: false
        M->>stdout: plain-text banner
        note over M: TUI skipped, VPN runs normally
    end
```

---

## TUI Shutdown Sequence

```mermaid
sequenceDiagram
    participant App as PppApplication
    participant CUI as ConsoleUI
    participant RT as RenderThread
    participant IT as InputThread
    participant Shell as ShellThread(s) if any

    App->>CUI: Stop()
    CUI->>CUI: running_.store(false)
    CUI->>CUI: render_cv_.notify_all()
    RT-->>CUI: detects running_=false, exits loop
    IT-->>CUI: detects running_=false, exits loop
    CUI->>Shell: wait up to 5s for pending_shell_threads_ == 0
    Shell-->>CUI: all shell threads exit
    CUI->>CUI: RestoreInputTerminal()
    CUI->>CUI: emit \x1b[?25h (restore cursor visibility)
    CUI->>CUI: emit \x1b[?1049l (leave alt screen buffer)
```

---

## Platform Differences

| Feature              | Windows                                         | POSIX                                 |
|----------------------|-------------------------------------------------|---------------------------------------|
| Input reading        | `_kbhit()` + `_getch()` polling                | `poll()` + `read(STDIN_FILENO)`        |
| Input mode           | `PrepareInputTerminal()` clears `ENABLE_ECHO_INPUT` and `ENABLE_LINE_INPUT`; `RestoreInputTerminal()` restores | `tcsetattr` disables `ICANON`/`ECHO`/`ISIG` |
| Terminal state save  | `GetConsoleMode` + stdin mode                  | `tcgetattr` + `fcntl` flags           |
| Alt screen buffer    | `\x1b[?1049h/l` (requires VT enabled)         | `\x1b[?1049h/l`                       |
| VT enable            | `ENABLE_VIRTUAL_TERMINAL_PROCESSING`           | Supported by default                  |

**Scroll bounds:** The maximum scroll offset for both the info and cmd panels is clamped
to `max(0, (int)content_lines - panel_height)`. This prevents over-scrolling past the
last content line and eliminates the blank rows that appeared at the top of the panel
in earlier revisions.

---

## Public API Reference

### `static bool ConsoleUI::ShouldEnable()`

**Brief:** Detects whether stdout is connected to a real terminal.

**Returns:** `true` if stdout is a tty; `false` if redirected or piped.

**Note:** Must be called before `Start()`. If this returns `false`, calling `Start()` is
a no-op and the TUI will not initialize.

---

### `bool ConsoleUI::Start()`

**Brief:** Initializes the TUI subsystem: enables VT processing, prepares raw input
terminal mode, enters the alternate screen buffer, hides the real cursor, and launches
the render and input threads.

**Returns:** `true` on success; `false` if initialization failed at any step.

**Note:** This method is not `noexcept`. Any exception during thread creation will
propagate to the caller. `Stop()` must be called even if `Start()` returned `false` to
clean up any partial initialization.

---

### `void ConsoleUI::Stop()`

**Brief:** Signals all threads to stop, waits for shell subprocess threads to finish
(bounded to 5 seconds), restores the terminal to its pre-TUI state, restores cursor
visibility, and leaves the alternate screen buffer.

**Note:** Safe to call multiple times. The second and subsequent calls are no-ops due to
`running_.compare_exchange_strong()` guard.

---

### `void ConsoleUI::AppendLine(ppp::string line)`

**Brief:** Appends one line to the command output ring buffer and wakes the render thread.

**Parameters:**
- `line` — The string to append. May contain ANSI escape sequences. Must not be empty.

**Thread safety:** Acquires `lock_`. Safe to call from any thread.

---

### `void ConsoleUI::SetInfoLines(ppp::vector<ppp::string> lines)`

**Brief:** Replaces the entire content of the info section with the provided lines.

**Parameters:**
- `lines` — Vector of strings. Each string represents one line in the info panel.

**Thread safety:** Acquires `lock_`. Safe to call from any thread.

---

### `void ConsoleUI::UpdateStatus(ppp::string status)`

**Brief:** Pushes a status string to the internal status queue. The render thread drains
the queue via `DrainStatusQueue()` and parses it to update runtime state/speed cache.

**Parameters:**
- `status` — Space-separated key=value pairs, e.g. `"vpn=up rx=1024 tx=2048"`.

**Thread safety:** Acquires `lock_` only for a queue push. Safe to call
from any thread including the IO thread at high frequency.

### Status bar semantics

The bottom status row displays only diagnostics snapshot text:

- `No errors` when `ErrorCode::Success` is active.
- `Error: <message> (<age>)` for the last non-success error.

VPN state and throughput are still maintained for other UI paths, but they are not shown
in the bottom status row.

---

## Ring Buffer Sizing

The command output section uses a ring buffer (`cmd_lines_`) with a configurable maximum
line count. When the buffer is full, the oldest lines are discarded. The default maximum
is chosen to hold several thousand lines, balancing memory use against the ability to
scroll back through command history.

The info section (`info_lines_`) is replaced wholesale on each `SetInfoLines()` call.
It is not a ring buffer; it reflects the current VPN state snapshot.

---

## Error Code Reference

TUI subsystem error codes (from `ppp/diagnostics/Error.h`):

| ErrorCode                | Description                                               |
|--------------------------|-----------------------------------------------------------|
| `TuiStartFailed`         | `ConsoleUI::Start()` initialization failed                |
| `TuiRenderThreadFailed`  | Render thread failed to launch                            |
| `TuiInputThreadFailed`   | Input thread failed to launch                             |
| `TuiTerminalSetupFailed` | Terminal raw mode configuration failed                    |
| `TuiVtProcessingFailed`  | VT100 processing enable failed (Windows only)             |

---

## Related Source Files

- `ppp/app/ConsoleUI.h` / `ppp/app/ConsoleUI.cpp` — TUI main implementation
- `ppp/app/ApplicationInitialize.cpp` — TUI start/stop integration point (isatty fallback)
- `ppp/app/ApplicationMainLoop.cpp` — Pushes data to TUI via `UpdateStatus` / `SetInfoLines`
- `ppp/stdafx.cpp::HideConsoleCursor` — Cross-platform cursor visibility primitive

---

## References

- VT100 / ANSI escape sequences: ECMA-48
- Alternate screen buffer: xterm control sequences, DEC Private Mode 1049
- Minimal-clear philosophy: inspired by ncurses `wnoutrefresh` + `doupdate` double-buffer
