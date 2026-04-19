/**
 * @file ConsoleUI.h
 * @brief Declares a non-blocking console TUI runtime for PPP.
 */

#pragma once

#include <ppp/stdafx.h>

#if !defined(_WIN32)
#include <termios.h>
#endif

namespace ppp::app {

/**
 * @brief Provides singleton non-blocking console TUI rendering and input handling.
 */
class ConsoleUI final {
public:
    /** @brief Gets process-wide ConsoleUI singleton instance. */
    static ConsoleUI& GetInstance() noexcept;

public:
    /** @brief Starts render/input worker threads if not already running. */
    bool Start() noexcept;
    /** @brief Requests worker threads to stop and joins them. */
    void Stop() noexcept;

public:
    /** @brief Enqueues a status update to be consumed by render thread. */
    void UpdateStatus(const ppp::string& status_text) noexcept;
    /** @brief Appends a line to the ring buffer output. */
    void AppendLine(const ppp::string& line) noexcept;

private:
    ConsoleUI() = default;
    ~ConsoleUI() = default;
    ConsoleUI(const ConsoleUI&) = delete;
    ConsoleUI& operator=(const ConsoleUI&) = delete;

private:
    void RenderLoop() noexcept;
    void InputLoop() noexcept;
    void RenderFrame() noexcept;
    void DrainStatusQueue() noexcept;
    void HandleEnter() noexcept;
    void HandleHistoryUp() noexcept;
    void HandleHistoryDown() noexcept;
    void InsertInputChar(char ch) noexcept;
    void MoveCursorLeft() noexcept;
    void MoveCursorRight() noexcept;
    void MoveCursorHome() noexcept;
    void MoveCursorEnd() noexcept;
    void EraseBeforeCursor() noexcept;
    void EraseAtCursor() noexcept;

private:
    void ExecuteCommand(const ppp::string& command_line) noexcept;
    void ScrollBy(int delta_lines) noexcept;
    void ScrollPage(int direction) noexcept;

private:
    bool EnableVirtualTerminal() noexcept;
    bool PrepareInputTerminal() noexcept;
    void RestoreInputTerminal() noexcept;
    ppp::string BuildStatusBarText() noexcept;
    static ppp::string RelativeSecondsText(uint64_t now, uint64_t last) noexcept;
    static ppp::string TruncateForWidth(const ppp::string& text, int width) noexcept;
    static ppp::string BuildEditorLine(const ppp::string& prompt, const ppp::string& input, std::size_t cursor_pos, int width, int& cursor_column) noexcept;

private:
    std::atomic<bool> running_{false};
    std::thread render_thread_;
    std::thread input_thread_;

    std::mutex lock_;
    std::deque<ppp::string> lines_;
    std::queue<ppp::string> status_queue_;
    ppp::string status_text_;
    ppp::string vpn_state_text_;
    ppp::string input_buffer_;
    std::size_t input_cursor_ = 0;
    std::deque<ppp::string> history_;
    int history_index_ = -1;
    ppp::string history_edit_backup_;
    int scroll_offset_ = 0;

    bool vt_enabled_ = false;

#if !defined(_WIN32)
    bool terminal_ready_ = false;
    struct termios terminal_original_ {};
    int terminal_flags_ = -1;
#endif
};

} // namespace ppp::app
