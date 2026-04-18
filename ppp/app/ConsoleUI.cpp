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
    }
}

void ConsoleUI::RenderLoop() noexcept {
    while (running_.load(std::memory_order_acquire)) {
        DrainStatusQueue();
        RenderFrame();
        ppp::Sleep(100);
    }
}

void ConsoleUI::InputLoop() noexcept {
#if defined(_WIN32)
    while (running_.load(std::memory_order_acquire)) {
        if (0 == _kbhit()) {
            ppp::Sleep(20);
            continue;
        }

        int ch = _getch();
        if (0 == ch || 224 == ch) {
            int key = _getch();
            if (72 == key) {
                ScrollBy(1);
            } elif (80 == key) {
                ScrollBy(-1);
            } elif (73 == key) {
                ScrollPage(1);
            } elif (81 == key) {
                ScrollPage(-1);
            }
            continue;
        }

        if (13 == ch) {
            ppp::string command_line;
            {
                std::lock_guard<std::mutex> scope(lock_);
                command_line = input_buffer_;
                input_buffer_.clear();
            }
            ExecuteCommand(command_line);
            continue;
        }

        if (8 == ch) {
            std::lock_guard<std::mutex> scope(lock_);
            if (!input_buffer_.empty()) {
                input_buffer_.pop_back();
            }
            continue;
        }

        if (32 <= ch && 126 >= ch) {
            std::lock_guard<std::mutex> scope(lock_);
            input_buffer_.push_back(static_cast<char>(ch));
        }
    }
#else
    while (running_.load(std::memory_order_acquire)) {
        ppp::Sleep(100);
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
        AppendLine("Commands: help, restart, exit, clear, status, setloglevel, pageup, pagedown, up, down");
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

    if (0 == lower.find("setloglevel")) {
        AppendLine("setloglevel is currently a stub in Stage-4.");
        return;
    }

    if ("pageup" == lower) {
        ScrollPage(1);
        return;
    }

    if ("pagedown" == lower) {
        ScrollPage(-1);
        return;
    }

    if ("up" == lower || "scrollup" == lower) {
        ScrollBy(1);
        return;
    }

    if ("down" == lower || "scrolldown" == lower) {
        ScrollBy(-1);
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

    int page = std::max<int>(1, height - 4);
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

ppp::string ConsoleUI::RelativeTimeText(uint64_t now, uint64_t last) noexcept {
    if (0 == last || last > now) {
        return "n/a";
    }

    uint64_t delta = now - last;
    if (1000 > delta) {
        return "just now";
    }

    uint64_t seconds = delta / 1000;
    if (60 > seconds) {
        return stl::to_string<ppp::string>(seconds) + "s ago";
    }

    uint64_t minutes = seconds / 60;
    if (60 > minutes) {
        return stl::to_string<ppp::string>(minutes) + "m ago";
    }

    uint64_t hours = minutes / 60;
    return stl::to_string<ppp::string>(hours) + "h ago";
}

ppp::string ConsoleUI::BuildStatusBarText() noexcept {
    ppp::string status_copy;
    {
        std::lock_guard<std::mutex> scope(lock_);
        status_copy = status_text_;
    }

    ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCodeSnapshot();
    const char* err = ppp::diagnostics::FormatErrorString(code);
    uint64_t err_ts = ppp::diagnostics::GetLastErrorTimestamp();
    uint64_t now = ppp::threading::Executors::GetTickCount();

    ppp::string result = status_copy;
    if (!result.empty()) {
        result += " | ";
    }
    result += "error: ";
    result += (NULLPTR == err ? "Unknown error" : err);
    result += " (";
    result += RelativeTimeText(now, err_ts);
    result += ")";
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

void ConsoleUI::RenderFrame() noexcept {
    std::deque<ppp::string> lines;
    ppp::string input;
    int scroll = 0;
    {
        std::lock_guard<std::mutex> scope(lock_);
        lines = lines_;
        input = input_buffer_;
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
    if (8 > height) {
        height = 8;
    }

    int body_height = std::max<int>(1, height - 4);
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

    ppp::string banner = " PPP PRIVATE NETWORK 2 - Stage-4 Console UI ";
    ppp::string status = BuildStatusBarText();
    ppp::string command = "command> " + input;
    ppp::string separator(static_cast<std::size_t>(width), '-');

    ppp::string output;
    output.reserve(static_cast<std::size_t>(width) * static_cast<std::size_t>(height + 2));

    if (vt_enabled_) {
        output += "\x1b[2J\x1b[H";
    }

    output += TruncateForWidth(banner, width) + "\n";
    output += separator + "\n";
    for (auto&& line : body_lines) {
        output += line + "\n";
    }
    output += TruncateForWidth(status, width) + "\n";
    output += TruncateForWidth(command, width) + "\n";

    if (!vt_enabled_) {
        ppp::ClearConsoleOutputCharacter();
    }

    std::fwrite(output.data(), 1, output.size(), stdout);
    std::fflush(stdout);
}

} // namespace ppp::app
