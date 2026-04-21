/**
 * @file ConsoleUI.cpp
 * @brief Full-screen box-drawing TUI for PPP PRIVATE NETWORK(TM) 2.
 *
 * @details
 * Implements a double-buffered, box-drawing terminal UI with three scrollable
 * sections (info, command output, and a single-line editor), rendered at up
 * to 10 Hz by a dedicated render thread.  A separate input thread handles
 * keyboard events without blocking the Boost.ASIO event loop.
 *
 * Key bindings:
 *   PageUp / PageDown  — scroll the command output section
 *   Home / End         — scroll the VPN info section
 *   Up / Down arrow    — navigate command history
 *   Left / Right arrow — move text cursor
 *   Ctrl+A             — move cursor to start of line
 *   Ctrl+E             — move cursor to end of line
 *   Backspace / Del    — erase character
 *   Enter              — execute command
 */

#include <ppp/app/ConsoleUI.h>
#include <ppp/app/PppApplication.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/threading/Executors.h>

#if defined(_WIN32)
#   include <conio.h>
#   include <io.h>
#else
#   include <cerrno>
#   include <fcntl.h>
#   include <unistd.h>
#endif

namespace ppp::app {

// ---------------------------------------------------------------------------
// UTF-8 box-drawing character constants (each is 3 bytes, 1 display column)
// ---------------------------------------------------------------------------

/** @brief Top-left corner:   ┌ (U+250C) */
static constexpr const char kBL[]   = "\xe2\x94\x8c";
/** @brief Top-right corner:  ┐ (U+2510) */
static constexpr const char kBR[]   = "\xe2\x94\x90";
/** @brief Bottom-left:       └ (U+2514) */
static constexpr const char kBBL[]  = "\xe2\x94\x94";
/** @brief Bottom-right:      ┘ (U+2518) */
static constexpr const char kBBR[]  = "\xe2\x94\x98";
/** @brief Left-T junction:   ├ (U+251C) */
static constexpr const char kLT[]   = "\xe2\x94\x9c";
/** @brief Right-T junction:  ┤ (U+2524) */
static constexpr const char kRT[]   = "\xe2\x94\xa4";
/** @brief Top-T junction:    ┬ (U+252C) */
static constexpr const char kTT[]   = "\xe2\x94\xac";
/** @brief Bottom-T junction: ┴ (U+2534) */
static constexpr const char kBT[]   = "\xe2\x94\xb4";
/** @brief Horizontal line:   ─ (U+2500) */
static constexpr const char kHH[]   = "\xe2\x94\x80";
/** @brief Vertical line:     │ (U+2502) */
static constexpr const char kVV[]   = "\xe2\x94\x82";

// ---------------------------------------------------------------------------
// ANSI escape sequences
// ---------------------------------------------------------------------------

/** @brief Hide the terminal cursor. */
static constexpr const char kHideCursor[]  = "\x1b[?25l";
/** @brief Show the terminal cursor. */
static constexpr const char kShowCursor[]  = "\x1b[?25h";
/** @brief Clear entire screen and move cursor to (1,1). */
static constexpr const char kClearScreen[] = "\x1b[2J\x1b[H";
/** @brief ANSI dark-gray foreground (for OPEN in art). */
static constexpr const char kColorGray[]   = "\x1b[90m";
/** @brief ANSI bold bright-white foreground (for PPP2 in art). */
static constexpr const char kColorWhite[]  = "\x1b[1;97m";
/** @brief ANSI attribute reset. */
static constexpr const char kColorReset[]  = "\x1b[0m";
/** @brief ANSI dim/dark gray (for placeholder text). */
static constexpr const char kColorDim[]    = "\x1b[2;37m";

// ---------------------------------------------------------------------------
// ASCII art definition (5 lines, ~50 columns wide)
// ---------------------------------------------------------------------------

/**
 * @brief Five-line ASCII art for "OPENPPP2".
 *
 * Characters in display columns [0, kArtSplitCol) represent "OPEN" and are
 * rendered in dark gray.  The remainder represents "PPP2" in bright white.
 */
static constexpr const char* kArtLines[5] = {
    "  ___  ____  _____ _   _ ____  ____  ____ ____  ",
    " / _ \\|  _ \\| ____| \\ | |  _ \\|  _ \\|  _ \\___ \\ ",
    "| | | | |_) |  _| |  \\| | |_) | |_) | |_) |__) |",
    "| |_| |  __/| |___| |\\  |  __/|  __/|  __// __/ ",
    " \\___/|_|   |_____|_| \\_|_|   |_|   |_|  |_____|",
};

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

ConsoleUI& ConsoleUI::GetInstance() noexcept {
    static ConsoleUI instance;
    return instance;
}

// ---------------------------------------------------------------------------
// Static helpers — box row builders
// ---------------------------------------------------------------------------

ppp::string ConsoleUI::RepeatHoriz(int count) noexcept {
    if (0 >= count) {
        return ppp::string();
    }

    ppp::string s;
    s.reserve(static_cast<std::size_t>(count) * 3u);
    for (int i = 0; i < count; ++i) {
        s += kHH;
    }
    return s;
}

ppp::string ConsoleUI::FitWidth(const ppp::string& s, int display_width) noexcept {
    if (0 >= display_width) {
        return ppp::string();
    }

    std::size_t w = static_cast<std::size_t>(display_width);
    if (s.size() <= w) {
        ppp::string out = s;
        out.append(w - s.size(), ' ');
        return out;
    }

    if (4u > w) {
        return s.substr(0u, w);
    }

    return s.substr(0u, w - 3u) + "...";
}

ppp::string ConsoleUI::BoxContentRow(const ppp::string& content, int width) noexcept {
    if (2 > width) {
        return ppp::string();
    }

    int inner = width - 2;
    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(inner) + 3u + 1u);
    row += kVV;
    row += FitWidth(content, inner);
    row += kVV;
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxSplitRow(
    const ppp::string& left,
    const ppp::string& right,
    int width,
    int split) noexcept {

    if (3 > width || 1 > split || split >= width - 1) {
        return BoxContentRow(left + " " + right, width);
    }

    // Left panel: split-1 columns (between left │ and center │)
    // Right panel: width - split - 1 columns (between center │ and right │)
    int left_inner  = split - 1;
    int right_inner = width - split - 1;

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(left_inner)
              + 3u + static_cast<std::size_t>(right_inner)
              + 3u + 1u);
    row += kVV;
    row += FitWidth(left, left_inner);
    row += kVV;
    row += FitWidth(right, right_inner);
    row += kVV;
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxSepRow(int width) noexcept {
    if (2 > width) {
        return ppp::string();
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(width - 2) * 3u + 3u + 1u);
    row += kLT;
    row += RepeatHoriz(width - 2);
    row += kRT;
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxSplitSepRow(int width, int split) noexcept {
    if (3 > width || 1 > split || split >= width - 1) {
        return BoxSepRow(width);
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(split - 1) * 3u
              + 3u + static_cast<std::size_t>(width - split - 1) * 3u
              + 3u + 1u);
    row += kLT;
    row += RepeatHoriz(split - 1);
    row += kTT;
    row += RepeatHoriz(width - split - 1);
    row += kRT;
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxBotRow(int width) noexcept {
    if (2 > width) {
        return ppp::string();
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(width - 2) * 3u + 3u + 1u);
    row += kBBL;
    row += RepeatHoriz(width - 2);
    row += kBBR;
    row += "\n";
    return row;
}

ppp::string ConsoleUI::BoxBotSplitRow(int width, int split) noexcept {
    if (3 > width || 1 > split || split >= width - 1) {
        return BoxBotRow(width);
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(split - 1) * 3u
              + 3u + static_cast<std::size_t>(width - split - 1) * 3u
              + 3u + 1u);
    row += kBBL;
    row += RepeatHoriz(split - 1);
    row += kBT;
    row += RepeatHoriz(width - split - 1);
    row += kBBR;
    row += "\n";
    return row;
}

// ---------------------------------------------------------------------------
// Art line renderer
// ---------------------------------------------------------------------------

ppp::string ConsoleUI::RenderArtLine(
    const ppp::string& raw,
    int inner_width,
    bool use_color) noexcept {

    int art_len = static_cast<int>(raw.size());

    // Determine centering padding
    int padding = 0;
    if (art_len < inner_width) {
        padding = (inner_width - art_len) / 2;
    }

    ppp::string row;
    row.reserve(3u + static_cast<std::size_t>(inner_width + 1) * 8u);
    row += kVV;  // left border

    // Left padding
    if (0 < padding) {
        row.append(static_cast<std::size_t>(padding), ' ');
    }

    if (!use_color) {
        // Plain text — just copy the art line (clipped to available width)
        int avail = inner_width - padding;
        if (0 < avail) {
            int take = std::min(avail, art_len);
            row.append(raw.data(), static_cast<std::size_t>(take));
            int fill = avail - take;
            if (0 < fill) {
                row.append(static_cast<std::size_t>(fill), ' ');
            }
        }
    } else {
        // Colored art: OPEN (dark gray) / PPP2 (bright white)
        int avail     = inner_width - padding;
        int split_col = ConsoleUI::kArtSplitCol;

        // OPEN part (dark gray)
        int open_end  = std::min(split_col, art_len);
        int open_take = std::min(open_end, avail);
        if (0 < open_take) {
            row += kColorGray;
            row.append(raw.data(), static_cast<std::size_t>(open_take));
        }

        // PPP2 part (bright white)
        int ppp2_start = open_end;
        int ppp2_end   = art_len;
        int ppp2_avail = avail - open_take;
        int ppp2_take  = std::min(ppp2_end - ppp2_start, ppp2_avail);
        if (0 < ppp2_take && ppp2_start < art_len) {
            row += kColorWhite;
            row.append(raw.data() + ppp2_start, static_cast<std::size_t>(ppp2_take));
        }

        if (0 < open_take || 0 < ppp2_take) {
            row += kColorReset;
        }

        // Right padding within art area
        int used = open_take + ppp2_take;
        int fill = avail - used;
        if (0 < fill) {
            row.append(static_cast<std::size_t>(fill), ' ');
        }
    }

    row += kVV;  // right border
    row += "\n";
    return row;
}

// ---------------------------------------------------------------------------
// Editor-line builder
// ---------------------------------------------------------------------------

ppp::string ConsoleUI::BuildEditorLine(
    const ppp::string& prompt,
    const ppp::string& input,
    std::size_t cursor_pos,
    int width,
    int& cursor_column) noexcept {

    cursor_column = 0;
    if (0 >= width) {
        return ppp::string();
    }

    std::size_t max_w = static_cast<std::size_t>(width);

    // Clip prompt to max_w
    ppp::string safe_prompt = prompt;
    if (safe_prompt.size() > max_w) {
        safe_prompt = safe_prompt.substr(0u, max_w);
    }

    std::size_t prompt_len = safe_prompt.size();
    std::size_t avail = (max_w > prompt_len) ? (max_w - prompt_len) : 0u;

    // Compute view window
    std::size_t safe_cursor = std::min(cursor_pos, input.size());
    std::size_t view_start = 0u;
    if (0u < avail && safe_cursor >= avail) {
        view_start = safe_cursor - avail + 1u;
    }

    if (0u < avail && view_start + avail > input.size() && input.size() > avail) {
        view_start = input.size() - avail;
    }

    // Extract visible portion
    ppp::string view;
    if (0u < avail && view_start < input.size()) {
        std::size_t take = std::min(avail, input.size() - view_start);
        view = input.substr(view_start, take);
    }

    // Pad to exactly avail columns
    if (view.size() < avail) {
        view.append(avail - view.size(), ' ');
    }

    // Overflow indicators
    if (0u < view_start && !view.empty()) {
        view[0u] = '<';
    }
    if (view_start + avail < input.size() && !view.empty()) {
        view[avail - 1u] = '>';
    }

    ppp::string line = safe_prompt + view;
    if (line.size() < max_w) {
        line.append(max_w - line.size(), ' ');
    }

    // Compute cursor column
    std::size_t local_cursor = (safe_cursor >= view_start) ? (safe_cursor - view_start) : 0u;
    if (0u < avail && avail <= local_cursor) {
        local_cursor = avail - 1u;
    }

    std::size_t col = prompt_len + local_cursor;
    if (0u < max_w && max_w <= col) {
        col = max_w - 1u;
    }

    cursor_column = static_cast<int>(col);
    return line;
}

// ---------------------------------------------------------------------------
// Age formatter
// ---------------------------------------------------------------------------

ppp::string ConsoleUI::FormatAge(uint64_t now_ms, uint64_t then_ms) noexcept {
    if (0u == then_ms || then_ms > now_ms) {
        return "n/a";
    }

    uint64_t delta_s = (now_ms - then_ms) / 1000u;
    return stl::to_string<ppp::string>(delta_s) + "s ago";
}

// ---------------------------------------------------------------------------
// ShouldEnable
// ---------------------------------------------------------------------------

bool ConsoleUI::ShouldEnable() noexcept {
#if defined(_WIN32)
    return 0 != ::_isatty(::_fileno(stdout));
#else
    return 0 != ::isatty(STDOUT_FILENO);
#endif
}

// ---------------------------------------------------------------------------
// Start / Stop
// ---------------------------------------------------------------------------

bool ConsoleUI::Start() noexcept {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return true;  // already running
    }

    vt_enabled_ = EnableVirtualTerminal();

    if (!PrepareInputTerminal()) {
        running_.store(false, std::memory_order_release);
        return false;
    }

    ppp::HideConsoleCursor(true);

    try {
        render_thread_ = std::thread([this]() noexcept { RenderLoop(); });
        input_thread_  = std::thread([this]() noexcept { InputLoop(); });
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

    AppendLine("Console UI started. Type 'openppp2 help' for commands.");
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

// ---------------------------------------------------------------------------
// Public data-update methods
// ---------------------------------------------------------------------------

void ConsoleUI::UpdateStatus(const ppp::string& status_text) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    status_queue_.push(status_text);
}

void ConsoleUI::AppendLine(const ppp::string& line) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    cmd_lines_.push_back(line);
    while (kMaxCmdLines < static_cast<int>(cmd_lines_.size())) {
        cmd_lines_.pop_front();
    }
}

void ConsoleUI::SetInfoLines(const ppp::vector<ppp::string>& lines) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    // Preserve the current scroll position so that periodic tick updates
    // (which call SetInfoLines every ~1 s) do not discard the user's scroll
    // position achieved via Home / End.  The scroll offset is clamped against
    // the new content size inside RenderFrame().
    bool was_empty = info_lines_.empty();
    info_lines_    = lines;

    // Only jump to the top when content is being populated for the first time;
    // subsequent updates keep whatever scroll position the user has set.
    if (was_empty) {
        info_scroll_ = 0;
    }
}

// ---------------------------------------------------------------------------
// Internal: drain status queue
// ---------------------------------------------------------------------------

void ConsoleUI::DrainStatusQueue() noexcept {
    std::lock_guard<std::mutex> scope(lock_);

    while (false == status_queue_.empty())
    {
        ppp::string txt = status_queue_.front();
        status_queue_.pop();

        ppp::string lower = ppp::ToLower(txt);

        if (ppp::string::npos != lower.find("disconnect"))
        {
            vpn_state_text_ = "Disconnected";
        }
        else if (ppp::string::npos != lower.find("reconnect"))
        {
            vpn_state_text_ = "Reconnecting";
        }
        else if (ppp::string::npos != lower.find("established") ||
                 ppp::string::npos != lower.find("connected"))
        {
            vpn_state_text_ = "Established";
        }
        else if (ppp::string::npos != lower.find("connect"))
        {
            vpn_state_text_ = "Connecting";
        }
        else
        {
            vpn_state_text_ = txt;
        }

        speed_text_.clear();

        std::size_t rx_pos = lower.find("rx=");
        std::size_t tx_pos = lower.find("tx=");

        if (ppp::string::npos != rx_pos)
        {
            std::size_t end_pos = lower.find(' ', rx_pos);
            ppp::string rx_val = (ppp::string::npos == end_pos)
                ? txt.substr(rx_pos + 3u)
                : txt.substr(rx_pos + 3u, end_pos - rx_pos - 3u);
            speed_text_ += "\xe2\x86\x93 ";
            speed_text_ += rx_val;
        }

        if (ppp::string::npos != tx_pos)
        {
            std::size_t end_pos = lower.find(' ', tx_pos);
            ppp::string tx_val = (ppp::string::npos == end_pos)
                ? txt.substr(tx_pos + 3u)
                : txt.substr(tx_pos + 3u, end_pos - tx_pos - 3u);

            if (false == speed_text_.empty())
            {
                speed_text_ += "  ";
            }

            speed_text_ += "\xe2\x86\x91 ";
            speed_text_ += tx_val;
        }
    }
}

// ---------------------------------------------------------------------------
// Render loop
// ---------------------------------------------------------------------------

void ConsoleUI::RenderLoop() noexcept {
    while (running_.load(std::memory_order_acquire)) {
        DrainStatusQueue();
        RenderFrame();
        ppp::Sleep(100);
    }

    // Final frame on exit
    RenderFrame();
}

// ---------------------------------------------------------------------------
// Core frame renderer
// ---------------------------------------------------------------------------

void ConsoleUI::RenderFrame() noexcept {
    // -----------------------------------------------------------------------
    // 1.  Snapshot terminal dimensions
    // -----------------------------------------------------------------------
    int width  = 120;
    int height = 46;
    if (!ppp::GetConsoleWindowSize(width, height)) {
        width  = 120;
        height = 46;
    }
    if (40 > width) {
        width = 40;
    }
    if (20 > height) {
        height = 20;
    }

    // -----------------------------------------------------------------------
    // 2.  Compute layout
    //
    //  Fixed header rows (top to bottom):
    //    0:  top border
    //    1:  hint row 1 (PageUp/Down + title)
    //    2:  hint row 2 (Home/End)
    //    3-7: ASCII art (5 rows)
    //    8:  empty row
    //    9:  header separator
    //  => kHeaderRows = 10
    //
    //  Fixed footer rows (bottom to top):
    //    -1: bottom border
    //    -2: status bar
    //    -3: status separator
    //    -4: input row
    //    -5: input separator
    //  => kFooterRows = 5
    //
    //  Middle = height - 10 - 5 = height - 15
    //  Split:  info_h + 1 (separator) + cmd_h = middle
    // -----------------------------------------------------------------------
    static constexpr int kHeaderRows = 10;
    static constexpr int kFooterRows = 5;

    int middle = height - kHeaderRows - kFooterRows;
    if (0 > middle) {
        middle = 0;
    }

    int info_h, cmd_h;
    if (3 > middle) {
        info_h = middle > 0 ? 1 : 0;
        cmd_h  = middle > 1 ? 1 : 0;
    } else {
        info_h = std::max(2, (middle - 1) * 3 / 5);
        cmd_h  = std::max(1, middle - 1 - info_h);
    }

    // -----------------------------------------------------------------------
    // 3.  Snapshot guarded state
    // -----------------------------------------------------------------------
    ppp::vector<ppp::string> info_snap;
    int                      info_scroll;
    std::deque<ppp::string>  cmd_snap;
    int                      cmd_scroll;
    ppp::string              input_snap;
    std::size_t              cursor_snap;
    ppp::string              vpn_state_snap;
    ppp::string              speed_snap;

    {
        std::lock_guard<std::mutex> scope(lock_);
        info_snap     = info_lines_;
        info_scroll   = info_scroll_;
        cmd_snap      = cmd_lines_;
        cmd_scroll    = cmd_scroll_;
        input_snap    = input_buffer_;
        cursor_snap   = input_cursor_;
        vpn_state_snap = vpn_state_text_;
        speed_snap    = speed_text_;
    }

    // -----------------------------------------------------------------------
    // 4.  Clamp scroll offsets
    // -----------------------------------------------------------------------
    {
        int total       = static_cast<int>(info_snap.size());
        int max_scroll  = std::max(0, total - info_h);
        if (info_scroll > max_scroll) {
            info_scroll = max_scroll;
            std::lock_guard<std::mutex> s(lock_);
            info_scroll_ = info_scroll;
        }
    }

    {
        int total       = static_cast<int>(cmd_snap.size());
        int max_scroll  = std::max(0, total - cmd_h);
        if (cmd_scroll > max_scroll) {
            cmd_scroll = max_scroll;
            std::lock_guard<std::mutex> s(lock_);
            cmd_scroll_ = cmd_scroll;
        }
    }

    // -----------------------------------------------------------------------
    // 5.  Build frame string
    // -----------------------------------------------------------------------
    ppp::string frame;
    frame.reserve(static_cast<std::size_t>(width * height) * 8u);

    if (vt_enabled_) {
        frame += kHideCursor;
        frame += kClearScreen;
    }

    int inner = width - 2;  // display columns inside borders

    // --- Row 0: top border ┌─────┐ ---
    {
        frame += kBL;
        frame += RepeatHoriz(width - 2);
        frame += kBR;
        frame += "\n";
    }

    // --- Row 1: hint 1 + right-aligned title ---
    {
        static constexpr const char kLeftHint1[]   = " PageUp/PageDown: Scroll command input/output";
        static constexpr const char kRightTitle[]  = "PPP PRIVATE NETWORK\xe2\x84\xa2 2 ";
        // kRightTitle display width: P-P-P- -P-R-I-V-A-T-E- -N-E-T-W-O-R-K-TM- -2-space = 23 cols
        static constexpr int kRightTitleDisplayW   = 23;

        int left_avail  = inner - kRightTitleDisplayW;
        if (0 > left_avail) {
            left_avail = 0;
        }

        frame += kVV;
        frame += FitWidth(kLeftHint1, left_avail);
        frame += kRightTitle;
        frame += kVV;
        frame += "\n";
    }

    // --- Row 2: hint 2 ---
    {
        static constexpr const char kLeftHint2[] = " Home/End       : Scroll openppp2 info";
        frame += BoxContentRow(kLeftHint2, width);
    }

    // --- Rows 3-7: ASCII art (5 lines) ---
    for (int i = 0; i < 5; ++i) {
        frame += RenderArtLine(ppp::string(kArtLines[i]), inner, vt_enabled_);
    }

    // --- Row 8: empty row ---
    frame += BoxContentRow("", width);

    // --- Row 9: header separator ---
    frame += BoxSepRow(width);

    // --- Info section (info_h rows) ---
    {
        int total  = static_cast<int>(info_snap.size());
        int start  = info_scroll;  // 0 = top of info content

        for (int i = 0; i < info_h; ++i) {
            int idx = start + i;
            if (0 <= idx && idx < total) {
                frame += BoxContentRow(" " + info_snap[static_cast<std::size_t>(idx)], width);
            } else {
                frame += BoxContentRow("", width);
            }
        }
    }

    // --- Separator between info and cmd ---
    frame += BoxSepRow(width);

    // --- Cmd section (cmd_h rows) ---
    {
        int total = static_cast<int>(cmd_snap.size());
        // cmd_scroll = 0 → show newest (bottom); > 0 → scrolled up
        int start = total - cmd_h - cmd_scroll;
        if (0 > start) {
            start = 0;
        }

        for (int i = 0; i < cmd_h; ++i) {
            int idx = start + i;
            if (0 <= idx && idx < total) {
                frame += BoxContentRow(" " + cmd_snap[static_cast<std::size_t>(idx)], width);
            } else {
                frame += BoxContentRow("", width);
            }
        }
    }

    // --- Input separator ---
    frame += BoxSepRow(width);

    // --- Input row ---
    int cursor_col = 0;
    {
        frame += kVV;

        if (input_snap.empty()) {
            // Placeholder text (dim/gray)
            static constexpr const char kPlaceholder[] =
                " > Exec openppp command or system commands.";
            if (vt_enabled_) {
                frame += kColorDim;
                frame += FitWidth(kPlaceholder, inner);
                frame += kColorReset;
            } else {
                frame += FitWidth(kPlaceholder, inner);
            }
            cursor_col = 2;  // after "> "
        } else {
            ppp::string editor_content =
                BuildEditorLine("> ", input_snap, cursor_snap, inner, cursor_col);
            frame += editor_content;
        }

        frame += kVV;
        frame += "\n";
    }

    // --- Status separator (split at width/2) ---
    int split = width / 2;
    frame += BoxSplitSepRow(width, split);

    // --- Status bar ---
    {
        // Left panel: error from diagnostics subsystem
        ppp::string left_text;
        {
            ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCodeSnapshot();
            const char* err_str = ppp::diagnostics::FormatErrorString(code);
            uint64_t err_ts     = ppp::diagnostics::GetLastErrorTimestamp();
            uint64_t now_ms     = ppp::threading::Executors::GetTickCount();

            if (ppp::diagnostics::ErrorCode::Success == code) {
                left_text = " No errors";
            } else {
                left_text  = " Error: ";
                left_text += (NULLPTR == err_str) ? "Unknown" : err_str;
                if (0u < err_ts) {
                    left_text += " (" + FormatAge(now_ms, err_ts) + ")";
                }
            }
        }

        // Right panel: VPN state + speeds
        ppp::string right_text = " VPN: ";
        right_text += vpn_state_snap.empty() ? ppp::string("Unknown") : vpn_state_snap;
        if (!speed_snap.empty()) {
            right_text += "  " + speed_snap;
        }

        frame += BoxSplitRow(left_text, right_text, width, split);
    }

    // --- Bottom border ---
    frame += BoxBotSplitRow(width, split);

    // --- Cursor positioning (VT100) ---
    if (vt_enabled_) {
        // 1-indexed row of the input line:
        //   1 (top border) + 9 (hint1, hint2, 5 art, empty, sep) + info_h + 1 (info-cmd sep)
        //   + cmd_h + 1 (cmd-input sep) + 1 (input row itself)
        int input_row = 1 + 9 + info_h + 1 + cmd_h + 1 + 1;  // = 13 + info_h + cmd_h
        // 1-indexed column: 1 (│ border) + cursor_col + 1 (1-indexed offset)
        int input_col = cursor_col + 2;

        frame += "\x1b[";
        frame += stl::to_string<ppp::string>(input_row);
        frame += ";";
        frame += stl::to_string<ppp::string>(input_col);
        frame += "H";
        frame += kShowCursor;
    }

    // -----------------------------------------------------------------------
    // 6.  Write frame to stdout in one atomic write
    // -----------------------------------------------------------------------
    std::fwrite(frame.data(), 1u, frame.size(), stdout);
    std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// Input editing handlers
// ---------------------------------------------------------------------------

void ConsoleUI::HandleEnter() noexcept {
    ppp::string command_line;
    {
        std::lock_guard<std::mutex> scope(lock_);
        command_line = input_buffer_;
        input_buffer_.clear();
        input_cursor_          = 0u;
        history_index_         = -1;
        history_edit_backup_.clear();

        if (!command_line.empty()) {
            if (history_.empty() || history_.back() != command_line) {
                history_.push_back(command_line);
                while (kMaxHistoryEntries < static_cast<int>(history_.size())) {
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
        history_index_       = static_cast<int>(history_.size()) - 1;
    } elif (0 < history_index_) {
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
        input_buffer_  = history_edit_backup_;
        history_edit_backup_.clear();
    }

    input_cursor_ = input_buffer_.size();
}

void ConsoleUI::InsertInputChar(char ch) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (input_cursor_ > input_buffer_.size()) {
        input_cursor_ = input_buffer_.size();
    }
    input_buffer_.insert(input_cursor_, 1u, ch);
    ++input_cursor_;
}

void ConsoleUI::MoveCursorLeft() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (0u < input_cursor_) {
        --input_cursor_;
    }
}

void ConsoleUI::MoveCursorRight() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (input_buffer_.size() > input_cursor_) {
        ++input_cursor_;
    }
}

void ConsoleUI::MoveCursorLineStart() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    input_cursor_ = 0u;
}

void ConsoleUI::MoveCursorLineEnd() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    input_cursor_ = input_buffer_.size();
}

void ConsoleUI::EraseBeforeCursor() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (0u < input_cursor_ && !input_buffer_.empty()) {
        input_buffer_.erase(input_cursor_ - 1u, 1u);
        --input_cursor_;
    }
}

void ConsoleUI::EraseAtCursor() noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    if (input_buffer_.size() > input_cursor_) {
        input_buffer_.erase(input_cursor_, 1u);
    }
}

// ---------------------------------------------------------------------------
// Scroll handlers
// ---------------------------------------------------------------------------

void ConsoleUI::ScrollInfoBy(int delta) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    int next = info_scroll_ + delta;
    if (0 > next) {
        next = 0;
    }

    int max_scroll = std::max(0, static_cast<int>(info_lines_.size()) - 1);
    if (next > max_scroll) {
        next = max_scroll;
    }

    info_scroll_ = next;
}

void ConsoleUI::ScrollInfoPage(int direction) noexcept {
    int w = 120;
    int h = 46;
    ppp::GetConsoleWindowSize(w, h);

    static constexpr int kHeaderRows = 10;
    static constexpr int kFooterRows = 5;
    int middle = h - kHeaderRows - kFooterRows;
    if (3 > middle) {
        middle = 3;
    }
    int info_h = std::max(2, (middle - 1) * 3 / 5);
    int page   = std::max(1, info_h - 1);
    ScrollInfoBy(direction * page);
}

void ConsoleUI::ScrollCmdBy(int delta) noexcept {
    std::lock_guard<std::mutex> scope(lock_);
    int next = cmd_scroll_ + delta;
    if (0 > next) {
        next = 0;
    }

    int max_scroll = std::max(0, static_cast<int>(cmd_lines_.size()) - 1);
    if (next > max_scroll) {
        next = max_scroll;
    }

    cmd_scroll_ = next;
}

void ConsoleUI::ScrollCmdPage(int direction) noexcept {
    int w = 120;
    int h = 46;
    ppp::GetConsoleWindowSize(w, h);

    static constexpr int kHeaderRows = 10;
    static constexpr int kFooterRows = 5;
    int middle = h - kHeaderRows - kFooterRows;
    if (3 > middle) {
        middle = 3;
    }
    int info_h = std::max(2, (middle - 1) * 3 / 5);
    int cmd_h  = std::max(1, middle - 1 - info_h);
    int page   = std::max(1, cmd_h - 1);
    ScrollCmdBy(direction * page);
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

void ConsoleUI::ExecuteCommand(const ppp::string& command_line) noexcept {
    ppp::string cmd = ppp::LTrim(ppp::RTrim(command_line));
    if (cmd.empty()) {
        return;
    }

    AppendLine("> " + cmd);

    ppp::string lower = ppp::ToLower(cmd);

    // -----------------------------------------------------------------------
    // Resolve "openppp2 <sub>" namespace
    // -----------------------------------------------------------------------
    ppp::string openppp2_sub;
    static constexpr const char kNS[] = "openppp2";
    static constexpr std::size_t kNSLen = sizeof(kNS) - 1u;

    if (0u == lower.find(kNS)) {
        if (lower.size() == kNSLen) {
            openppp2_sub = "help";
        } elif (lower.size() > kNSLen && ' ' == lower[kNSLen]) {
            openppp2_sub = ppp::LTrim(lower.substr(kNSLen + 1u));
        }
    }

    // Legacy bare commands (backwards compatibility)
    if (openppp2_sub.empty()) {
        if ("help"    == lower) { openppp2_sub = "help";    }
        elif ("restart" == lower) { openppp2_sub = "restart"; }
        elif ("exit"    == lower) { openppp2_sub = "exit";    }
        elif ("clear"   == lower) { openppp2_sub = "clear";   }
        elif ("status"  == lower) { openppp2_sub = "info";    }
        elif ("reload"  == lower) { openppp2_sub = "reload";  }
    }

    if (!openppp2_sub.empty()) {
        if ("help" == openppp2_sub) {
            AppendLine("Available commands:");
            AppendLine("  openppp2 help    - Show this help information");
            AppendLine("  openppp2 restart - Restart the application");
            AppendLine("  openppp2 reload  - Reload configuration (restart)");
            AppendLine("  openppp2 exit    - Exit the application");
            AppendLine("  openppp2 info    - Print VPN info snapshot to cmd output");
            AppendLine("  openppp2 clear   - Clear command output section");
            AppendLine("  <shell command>  - Execute a system shell command");
            return;
        }

        if ("restart" == openppp2_sub || "reload" == openppp2_sub) {
            AppendLine("Requesting application restart...");
            PppApplication::ShutdownApplication(true);
            return;
        }

        if ("exit" == openppp2_sub) {
            AppendLine("Requesting application exit...");
            PppApplication::ShutdownApplication(false);
            return;
        }

        if ("clear" == openppp2_sub) {
            std::lock_guard<std::mutex> scope(lock_);
            cmd_lines_.clear();
            cmd_scroll_ = 0;
            return;
        }

        if ("info" == openppp2_sub) {
            ppp::vector<ppp::string> info_copy;
            {
                std::lock_guard<std::mutex> scope(lock_);
                info_copy = info_lines_;
            }
            if (info_copy.empty()) {
                AppendLine("[No VPN info available yet]");
            } else {
                for (const ppp::string& line : info_copy) {
                    AppendLine(line);
                }
            }
            return;
        }

        AppendLine("Unknown openppp2 sub-command: '" + openppp2_sub + "'");
        AppendLine("Type 'openppp2 help' for available commands.");
        return;
    }

    // -----------------------------------------------------------------------
    // System command: run in a detached thread to avoid blocking input
    // -----------------------------------------------------------------------
    ExecuteSystemCommand(cmd);
}

void ConsoleUI::ExecuteSystemCommand(const ppp::string& cmd) noexcept {
    AppendLine("[Executing: " + cmd + "]");

    // Capture a raw pointer — the singleton outlives any detached thread.
    ConsoleUI* self = this;
    ppp::string cmd_copy = cmd;

    std::thread([self, cmd_copy]() noexcept {
        try {
#if defined(_WIN32)
            ppp::string shell_cmd = "cmd /c " + cmd_copy + " 2>&1";
            FILE* fp = ::_popen(shell_cmd.data(), "r");
#else
            ppp::string shell_cmd = cmd_copy + " 2>&1";
            FILE* fp = ::popen(shell_cmd.data(), "r");
#endif
            if (NULLPTR == fp) {
                self->AppendLine("[Error: failed to open process pipe]");
                return;
            }

            char buf[4096];
            while (NULLPTR != std::fgets(buf, sizeof(buf), fp)) {
                ppp::string line = buf;
                // Strip trailing newline / carriage-return
                while (!line.empty() &&
                       ('\n' == line.back() || '\r' == line.back())) {
                    line.pop_back();
                }
                self->AppendLine(line);
            }

#if defined(_WIN32)
            ::_pclose(fp);
#else
            ::pclose(fp);
#endif
            self->AppendLine("[Command finished]");
        } catch (...) {
            self->AppendLine("[Error: exception during system command]");
        }
    }).detach();
}

// ---------------------------------------------------------------------------
// Input loop
// ---------------------------------------------------------------------------

void ConsoleUI::InputLoop() noexcept {
#if defined(_WIN32)
    while (running_.load(std::memory_order_acquire)) {
        if (0 == ::_kbhit()) {
            ppp::Sleep(15);
            continue;
        }

        int ch = ::_getch();
        if (0 == ch || 224 == ch) {
            // Extended / function key
            int key = ::_getch();
            if (72 == key) {            // Up arrow
                HandleHistoryUp();
            } elif (80 == key) {        // Down arrow
                HandleHistoryDown();
            } elif (75 == key) {        // Left arrow
                MoveCursorLeft();
            } elif (77 == key) {        // Right arrow
                MoveCursorRight();
            } elif (71 == key) {        // Home — scroll info to top
                ScrollInfoBy(-999999);
            } elif (79 == key) {        // End — scroll info to bottom
                ScrollInfoBy(999999);
            } elif (83 == key) {        // Delete
                EraseAtCursor();
            } elif (73 == key) {        // PageUp — scroll cmd up
                ScrollCmdPage(1);
            } elif (81 == key) {        // PageDown — scroll cmd down
                ScrollCmdPage(-1);
            }
            continue;
        }

        if (13 == ch) {             // Enter
            HandleEnter();
            continue;
        }

        if (8 == ch) {              // Backspace
            EraseBeforeCursor();
            continue;
        }

        if (1 == ch) {              // Ctrl+A
            MoveCursorLineStart();
            continue;
        }

        if (5 == ch) {              // Ctrl+E
            MoveCursorLineEnd();
            continue;
        }

        if (32 <= ch && 126 >= ch) {
            InsertInputChar(static_cast<char>(ch));
        }
    }

#else  // POSIX

    while (running_.load(std::memory_order_acquire)) {
        char ch = '\0';
        ssize_t n = ::read(STDIN_FILENO, &ch, 1u);
        if (0 >= n) {
            if (EAGAIN == errno || EWOULDBLOCK == errno) {
                ppp::Sleep(15);
            } else {
                ppp::Sleep(15);
            }
            continue;
        }

        // Ctrl+A / Ctrl+E
        if ('\x01' == ch) { MoveCursorLineStart(); continue; }
        if ('\x05' == ch) { MoveCursorLineEnd();   continue; }

        if ('\r' == ch || '\n' == ch) {
            HandleEnter();
            continue;
        }

        if (127 == static_cast<unsigned char>(ch) || 8 == static_cast<unsigned char>(ch)) {
            EraseBeforeCursor();
            continue;
        }

        if (27 == static_cast<unsigned char>(ch)) {
            // ESC sequence reader
            char seq[16] = {'\0'};
            int  seq_len = 0;

            for (; seq_len < 15; ++seq_len) {
                ssize_t rn = ::read(STDIN_FILENO, &seq[seq_len], 1u);
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

            if ("[A" == key || "OA" == key) {       // Up
                HandleHistoryUp();
            } elif ("[B" == key || "OB" == key) {   // Down
                HandleHistoryDown();
            } elif ("[C" == key || "OC" == key) {   // Right
                MoveCursorRight();
            } elif ("[D" == key || "OD" == key) {   // Left
                MoveCursorLeft();
            } elif ("[H" == key || "[1~" == key ||  // Home — scroll info to top
                    "[7~" == key || "OH" == key) {
                ScrollInfoBy(-999999);
            } elif ("[F" == key || "[4~" == key ||  // End — scroll info to bottom
                    "[8~" == key || "OF" == key) {
                ScrollInfoBy(999999);
            } elif ("[3~" == key) {                 // Delete
                EraseAtCursor();
            } elif ("[5~" == key) {                 // PageUp — scroll cmd up
                ScrollCmdPage(1);
            } elif ("[6~" == key) {                 // PageDown — scroll cmd down
                ScrollCmdPage(-1);
            }
            continue;
        }

        if (32 <= static_cast<unsigned char>(ch) && 126 >= static_cast<unsigned char>(ch)) {
            InsertInputChar(ch);
        }
    }

#endif  // POSIX
}

// ---------------------------------------------------------------------------
// Terminal helpers
// ---------------------------------------------------------------------------

bool ConsoleUI::EnableVirtualTerminal() noexcept {
#if defined(_WIN32)
    HANDLE h = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (NULLPTR == h || INVALID_HANDLE_VALUE == h) {
        return false;
    }

    DWORD mode = 0;
    if (!::GetConsoleMode(h, &mode)) {
        return false;
    }

    if (0u == (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        if (!::SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
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
    raw.c_cc[VMIN]  = 0;
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
    terminal_ready_  = false;
    terminal_flags_  = -1;
#endif
}

} // namespace ppp::app
