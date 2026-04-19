/**
 * @file ConsoleUI.cpp
 * @brief Implements a non-blocking console TUI with dedicated render/input threads.
 */

#include <ppp/app/ConsoleUI.h>
#include <ppp/app/PppApplication.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/threading/Executors.h>

#if defined(_WIN32)
#include <conio.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace ppp::app {

ConsoleUI& ConsoleUI::GetInstance() noexcept {
    static ConsoleUI instance;
    return instance;
}

bool ConsoleUI::Start() noexcept {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return true;
    }

    vt_enabled_ = EnableVirtualTerminal();
    if (!PrepareInputTerminal()) {
        running_.store(false, std::memory_order_release);
        return false;
    }

    ppp::HideConsoleCursor(true);

    try {
        render_thread_ = std::thread([this]() noexcept { RenderLoop(); });
        input_thread_ = std::thread([this]() noexcept { InputLoop(); });
    } catch (...) {
        running_.store(false, std::memory_order_release);
        if (render_thread_.joinable()) {
            render_thread_.join();
        }
        if (input_thread_.joinable()) {
            input_thread_.join();
        }
        RestoreInputTerminal();
        ppp::HideConsoleCursor(false);
        return false;
    }

    AppendLine("Console UI initialized. Type 'help' for commands.");
    return true;
}

void ConsoleUI::Stop() noexcept {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    if (render_thread_.joinable()) {
        render_thread_.join();
    }

    if (input_thread_.joinable()) {
        input_thread_.join();
    }

    RestoreInputTerminal();
    ppp::HideConsoleCursor(false);
}

void ConsoleUI::UpdateStatus(const ppp::string& status_text) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    status_queue_.push(status_text);
}

void ConsoleUI::AppendLine(const ppp::string& line) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    lines_.push_back(line);
    while (1000 < lines_.size()) {
        lines_.pop_front();
    }
}

void ConsoleUI::DrainStatusQueue() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    while (!status_queue_.empty()) {
        status_text_ = status_queue_.front();
        status_queue_.pop();

        ppp::string lower = ppp::ToLower(status_text_);
        if (ppp::string::npos != lower.find("disconnect")) {
            vpn_state_text_ = "disconnected";
        } else if (ppp::string::npos != lower.find("reconnect")) {
            vpn_state_text_ = "reconnecting";
        } else if (ppp::string::npos != lower.find("established") || ppp::string::npos != lower.find("connected")) {
            vpn_state_text_ = "connected";
        } else if (ppp::string::npos != lower.find("connect")) {
            vpn_state_text_ = "connecting";
        } else {
            vpn_state_text_ = status_text_;
        }
    }
}

void ConsoleUI::RenderLoop() noexcept {
    while (running_.load(std::memory_order_acquire)) {
        DrainStatusQueue();
        RenderFrame();
        ppp::Sleep(100);
    }

    RenderFrame();
}

void ConsoleUI::HandleEnter() noexcept {
    ppp::string command_line;
    {
        std::lock_guard<std::mutex> scope(lock_);
        command_line = input_buffer_;
        input_buffer_.clear();
        input_cursor_ = 0;
        history_index_ = -1;
        history_edit_backup_.clear();

        if (!command_line.empty()) {
            if (history_.empty() || history_.back() != command_line) {
                history_.push_back(command_line);
                while (200 < history_.size()) {
                    history_.pop_front();
                }
            }
        }
    }

    ExecuteCommand(command_line);
}

void ConsoleUI::HandleHistoryUp() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (history_.empty()) {
        return;
    }

    if (-1 == history_index_) {
        history_edit_backup_ = input_buffer_;
        history_index_ = static_cast<int>(history_.size()) - 1;
    } else if (0 < history_index_) {
        --history_index_;
    }

    if (0 <= history_index_ && static_cast<int>(history_.size()) > history_index_) {
        input_buffer_ = history_[static_cast<std::size_t>(history_index_)];
        input_cursor_ = input_buffer_.size();
    }
}

void ConsoleUI::HandleHistoryDown() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (history_.empty() || -1 == history_index_) {
        return;
    }

    int last_index = static_cast<int>(history_.size()) - 1;
    if (history_index_ < last_index) {
        ++history_index_;
        input_buffer_ = history_[static_cast<std::size_t>(history_index_)];
    } else {
        history_index_ = -1;
        input_buffer_ = history_edit_backup_;
        history_edit_backup_.clear();
    }
    input_cursor_ = input_buffer_.size();
}

void ConsoleUI::InsertInputChar(char ch) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (input_cursor_ > input_buffer_.size()) {
        input_cursor_ = input_buffer_.size();
    }
    input_buffer_.insert(input_cursor_, 1, ch);
    ++input_cursor_;
}

void ConsoleUI::MoveCursorLeft() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (0 < input_cursor_) {
        --input_cursor_;
    }
}

void ConsoleUI::MoveCursorRight() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (input_buffer_.size() > input_cursor_) {
        ++input_cursor_;
    }
}

void ConsoleUI::MoveCursorHome() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    input_cursor_ = 0;
}

void ConsoleUI::MoveCursorEnd() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    input_cursor_ = input_buffer_.size();
}

void ConsoleUI::EraseBeforeCursor() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (0 < input_cursor_ && !input_buffer_.empty()) {
        input_buffer_.erase(input_cursor_ - 1, 1);
        --input_cursor_;
    }
}

void ConsoleUI::EraseAtCursor() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (input_buffer_.size() > input_cursor_) {
        input_buffer_.erase(input_cursor_, 1);
    }
}

void ConsoleUI::InputLoop() noexcept {
#if defined(_WIN32)
    while (running_.load(std::memory_order_acquire)) {
        if (0 == _kbhit()) {
            ppp::Sleep(15);
            continue;
        }

        int ch = _getch();
        if (0 == ch || 224 == ch) {
            int key = _getch();
            if (72 == key) {
                HandleHistoryUp();
            } else if (80 == key) {
                HandleHistoryDown();
            } else if (75 == key) {
                MoveCursorLeft();
            } else if (77 == key) {
                MoveCursorRight();
            } else if (71 == key) {
                MoveCursorHome();
            } else if (79 == key) {
                MoveCursorEnd();
            } else if (83 == key) {
                EraseAtCursor();
            } else if (73 == key) {
                ScrollPage(1);
            } else if (81 == key) {
                ScrollPage(-1);
            } else if (141 == key) {
                ScrollBy(1);
            } else if (145 == key) {
                ScrollBy(-1);
            }
            continue;
        }

        if (13 == ch) {
            HandleEnter();
            continue;
        }

        if (8 == ch) {
            EraseBeforeCursor();
            continue;
        }

        if (32 <= ch && 126 >= ch) {
            InsertInputChar(static_cast<char>(ch));
        }
    }
#else
    while (running_.load(std::memory_order_acquire)) {
        char ch = '\0';
        ssize_t n = ::read(STDIN_FILENO, &ch, 1);
        if (0 >= n) {
            if (EAGAIN == errno || EWOULDBLOCK == errno) {
                ppp::Sleep(15);
                continue;
            }
            ppp::Sleep(15);
            continue;
        }

        if ('\r' == ch || '\n' == ch) {
            HandleEnter();
            continue;
        }

        if (127 == static_cast<unsigned char>(ch) || 8 == ch) {
            EraseBeforeCursor();
            continue;
        }

        if (27 == static_cast<unsigned char>(ch)) {
            char seq[16] = {'\0'};
            int seq_len = 0;
            for (; seq_len < 15; ++seq_len) {
                ssize_t rn = ::read(STDIN_FILENO, &seq[seq_len], 1);
                if (0 >= rn) {
                    break;
                }
                char c = seq[seq_len];
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || '~' == c) {
                    ++seq_len;
                    break;
                }
            }

            ppp::string key(seq, static_cast<std::size_t>(std::max(0, seq_len)));
            if ("[A" == key || "OA" == key) {
                HandleHistoryUp();
            } else if ("[B" == key || "OB" == key) {
                HandleHistoryDown();
            } else if ("[C" == key || "OC" == key) {
                MoveCursorRight();
            } else if ("[D" == key || "OD" == key) {
                MoveCursorLeft();
            } else if ("[H" == key || "[1~" == key || "[7~" == key || "OH" == key) {
                MoveCursorHome();
            } else if ("[F" == key || "[4~" == key || "[8~" == key || "OF" == key) {
                MoveCursorEnd();
            } else if ("[3~" == key) {
                EraseAtCursor();
            } else if ("[5~" == key) {
                ScrollPage(1);
            } else if ("[6~" == key) {
                ScrollPage(-1);
            } else if ("[1;5A" == key) {
                ScrollBy(1);
            } else if ("[1;5B" == key) {
                ScrollBy(-1);
            }
            continue;
        }

        if (32 <= static_cast<unsigned char>(ch) && 126 >= static_cast<unsigned char>(ch)) {
            InsertInputChar(ch);
        }
    }
#endif
}

void ConsoleUI::ExecuteCommand(const ppp::string& command_line) noexcept {
    ppp::string command = ppp::RTrim(ppp::LTrim(command_line));
    if (command.empty()) {
        return;
    }

    AppendLine("> " + command);
    ppp::string lower = ppp::ToLower(command);

    if ("help" == lower) {
        AppendLine("Commands: help, restart, exit, clear, status");
        return;
    }

    if ("restart" == lower) {
        AppendLine("Restart requested.");
        PppApplication::ShutdownApplication(true);
        return;
    }

    if ("exit" == lower) {
        AppendLine("Exit requested.");
        PppApplication::ShutdownApplication(false);
        return;
    }

    if ("clear" == lower) {
        std::lock_guard<std::mutex> scope(lock_);
        lines_.clear();
        scroll_offset_ = 0;
        return;
    }

    if ("status" == lower) {
        AppendLine(BuildStatusBarText());
        return;
    }

    AppendLine("Unknown command. Type 'help' for available commands.");
}

void ConsoleUI::ScrollBy(int delta_lines) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    int next = scroll_offset_ + delta_lines;
    if (0 > next) {
        next = 0;
    }
    scroll_offset_ = next;
}

void ConsoleUI::ScrollPage(int direction) noexcept {
    int width = 120;
    int height = 46;
    if (!ppp::GetConsoleWindowSize(width, height)) {
        width = 120;
        height = 46;
    }

    int page = std::max<int>(1, height - 3);
    ScrollBy(direction * page);
}

bool ConsoleUI::EnableVirtualTerminal() noexcept {
#if defined(_WIN32)
    HANDLE h_console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (NULLPTR == h_console || INVALID_HANDLE_VALUE == h_console) {
        return false;
    }

    DWORD mode = 0;
    if (!GetConsoleMode(h_console, &mode)) {
        return false;
    }

    if (0 == (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        if (!SetConsoleMode(h_console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
            return false;
        }
    }

    return true;
#else
    return true;
#endif
}

bool ConsoleUI::PrepareInputTerminal() noexcept {
#if defined(_WIN32)
    return true;
#else
    if (terminal_ready_) {
        return true;
    }

    if (0 != ::tcgetattr(STDIN_FILENO, &terminal_original_)) {
        return false;
    }

    struct termios raw = terminal_original_;
    raw.c_iflag &= static_cast<tcflag_t>(~(IXON | ICRNL));
    raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON));
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;

    if (0 != ::tcsetattr(STDIN_FILENO, TCSANOW, &raw)) {
        return false;
    }

    terminal_flags_ = ::fcntl(STDIN_FILENO, F_GETFL, 0);
    if (0 <= terminal_flags_) {
        if (0 != ::fcntl(STDIN_FILENO, F_SETFL, terminal_flags_ | O_NONBLOCK)) {
            ::tcsetattr(STDIN_FILENO, TCSANOW, &terminal_original_);
            terminal_flags_ = -1;
            return false;
        }
    }

    terminal_ready_ = true;
    return true;
#endif
}

void ConsoleUI::RestoreInputTerminal() noexcept {
#if defined(_WIN32)
    return;
#else
    if (!terminal_ready_) {
        return;
    }

    if (0 <= terminal_flags_) {
        ::fcntl(STDIN_FILENO, F_SETFL, terminal_flags_);
    }

    ::tcsetattr(STDIN_FILENO, TCSANOW, &terminal_original_);
    terminal_ready_ = false;
    terminal_flags_ = -1;
#endif
}

ppp::string ConsoleUI::RelativeSecondsText(uint64_t now, uint64_t last) noexcept {
    if (0 == last || last > now) {
        return "n/a";
    }

    uint64_t delta_ms = now - last;
    uint64_t seconds = delta_ms / 1000;
    return stl::to_string<ppp::string>(seconds) + "s";
}

ppp::string ConsoleUI::BuildStatusBarText() noexcept {
    ppp::string status_copy;
    ppp::string vpn_state_copy;
    {
        std::lock_guard<std::mutex> scope(lock_);
        status_copy = status_text_;
        vpn_state_copy = vpn_state_text_;
    }

    if (vpn_state_copy.empty()) {
        vpn_state_copy = "unknown";
    }

    ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCodeSnapshot();
    const char* err = ppp::diagnostics::FormatErrorString(code);
    uint64_t err_ts = ppp::diagnostics::GetLastErrorTimestamp();
    uint64_t now = ppp::threading::Executors::GetTickCount();

    ppp::string result = "vpn:" + vpn_state_copy;
    if (!status_copy.empty()) {
        result += " | note:" + status_copy;
    }
    result += " | err:";
    result += (NULLPTR == err ? "Unknown error" : err);
    result += " | err_age:" + RelativeSecondsText(now, err_ts);
    result += " | diag_ts:" + stl::to_string<ppp::string>(err_ts);
    return result;
}

ppp::string ConsoleUI::TruncateForWidth(const ppp::string& text, int width) noexcept {
    if (0 >= width) {
        return ppp::string();
    }

    std::size_t w = static_cast<std::size_t>(width);
    if (w >= text.size()) {
        ppp::string line = text;
        line.append(w - line.size(), ' ');
        return line;
    }

    if (3 >= w) {
        return text.substr(0, w);
    }

    return text.substr(0, w - 3) + "...";
}

ppp::string ConsoleUI::BuildEditorLine(const ppp::string& prompt, const ppp::string& input, std::size_t cursor_pos, int width, int& cursor_column) noexcept {
    cursor_column = 0;
    if (0 >= width) {
        return ppp::string();
    }

    std::size_t max_width = static_cast<std::size_t>(width);
    ppp::string safe_prompt = prompt;
    if (safe_prompt.size() > max_width) {
        safe_prompt = safe_prompt.substr(0, max_width);
    }

    std::size_t prompt_size = safe_prompt.size();
    std::size_t available = max_width > prompt_size ? (max_width - prompt_size) : 0;

    std::size_t safe_cursor = std::min<std::size_t>(cursor_pos, input.size());
    std::size_t view_start = 0;
    if (0 < available && safe_cursor >= available) {
        view_start = safe_cursor - available + 1;
    }
    if (0 < available && view_start + available > input.size()) {
        view_start = input.size() > available ? (input.size() - available) : 0;
    }

    ppp::string view;
    if (0 < available && view_start < input.size()) {
        view = input.substr(view_start, available);
    }

    if (0 < available) {
        if (view.size() < available) {
            view.append(available - view.size(), ' ');
        }
        if (0 < view_start && !view.empty()) {
            view[0] = '<';
        }
        if (view_start + available < input.size() && !view.empty()) {
            view[available - 1] = '>';
        }
    }

    ppp::string line = safe_prompt + view;
    if (line.size() < max_width) {
        line.append(max_width - line.size(), ' ');
    }

    std::size_t local_cursor = 0;
    if (safe_cursor >= view_start) {
        local_cursor = safe_cursor - view_start;
    }
    if (available <= local_cursor && 0 < available) {
        local_cursor = available - 1;
    }

    std::size_t column = prompt_size + local_cursor;
    if (max_width <= column && 0 < max_width) {
        column = max_width - 1;
    }
    cursor_column = static_cast<int>(column);
    return line;
}

void ConsoleUI::RenderFrame() noexcept {
    std::deque<ppp::string> lines;
    ppp::string input;
    std::size_t cursor = 0;
    int scroll = 0;
    {
        std::lock_guard<std::mutex> scope(lock_);
        lines = lines_;
        input = input_buffer_;
        cursor = input_cursor_;
        scroll = scroll_offset_;
    }

    int width = 120;
    int height = 46;
    if (!ppp::GetConsoleWindowSize(width, height)) {
        width = 120;
        height = 46;
    }

    if (20 > width) {
        width = 20;
    }
    if (4 > height) {
        height = 4;
    }

    int body_height = std::max<int>(1, height - 2);
    int total_lines = static_cast<int>(lines.size());
    int max_scroll = std::max<int>(0, total_lines - body_height);
    if (max_scroll < scroll) {
        scroll = max_scroll;
    }

    {
        std::lock_guard<std::mutex> scope(lock_);
        if (scroll_offset_ != scroll) {
            scroll_offset_ = scroll;
        }
    }

    int start_index = std::max<int>(0, total_lines - body_height - scroll);
    ppp::vector<ppp::string> body_lines;
    body_lines.reserve(static_cast<std::size_t>(body_height));
    for (int i = 0; i < body_height; ++i) {
        int index = start_index + i;
        if (0 <= index && total_lines > index) {
            body_lines.emplace_back(TruncateForWidth(lines[static_cast<std::size_t>(index)], width));
        } else {
            body_lines.emplace_back(ppp::string(static_cast<std::size_t>(width), ' '));
        }
    }

    int cursor_column = 0;
    ppp::string editor = BuildEditorLine("cmd> ", input, cursor, width, cursor_column);
    ppp::string status = TruncateForWidth(BuildStatusBarText(), width);

    ppp::string output;
    output.reserve(static_cast<std::size_t>(width) * static_cast<std::size_t>(height + 2));

    if (vt_enabled_) {
        output += "\x1b[2J\x1b[H";
    }

    for (auto&& line : body_lines) {
        output += line;
        output += "\n";
    }

    output += editor;
    output += "\n";
    output += status;

    if (vt_enabled_) {
        int editor_row = body_height + 1;
        int editor_col = cursor_column + 1;
        output += "\x1b[" + stl::to_string<ppp::string>(editor_row) + ";" + stl::to_string<ppp::string>(editor_col) + "H";
        output += "\x1b[?25h";
    }

    if (!vt_enabled_) {
        ppp::ClearConsoleOutputCharacter();
    }

    std::fwrite(output.data(), 1, output.size(), stdout);
    std::fflush(stdout);
}

} // namespace ppp::app
