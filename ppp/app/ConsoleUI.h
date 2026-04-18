/**
 * @file ConsoleUI.h
 * @brief Declares a non-blocking console TUI runtime for PPP.
 */

#pragma once

#include <ppp/stdafx.h>

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

private:
    void ExecuteCommand(const ppp::string& command_line) noexcept;
    void ScrollBy(int delta_lines) noexcept;
    void ScrollPage(int direction) noexcept;

private:
    bool EnableVirtualTerminal() noexcept;
    ppp::string BuildStatusBarText() noexcept;
    static ppp::string RelativeTimeText(uint64_t now, uint64_t last) noexcept;
    static ppp::string TruncateForWidth(const ppp::string& text, int width) noexcept;

private:
    std::atomic<bool> running_{false};
    std::thread render_thread_;
    std::thread input_thread_;

    std::mutex lock_;
    std::deque<ppp::string> lines_;
    std::queue<ppp::string> status_queue_;
    ppp::string status_text_;
    ppp::string input_buffer_;
    int scroll_offset_ = 0;

    bool vt_enabled_ = false;
};

} // namespace ppp::app
