#include <ppp/DateTime.h>
#include <ppp/diagnostics/Error.h>

#include <stdio.h>
#include <time.h>

/**
 * @file DateTime.cpp
 * @brief Implements DateTime timezone, parsing, and formatting utilities.
 */

#if defined(_WIN32)
#include <Windows.h>

#define localtime_r(t, res) localtime_s(res, t)
#define gmtime_r(t, res) gmtime_s(res, t)
#endif

namespace ppp 
{
    /** @brief Converts this local value to UTC by subtracting GMT offset. */
    DateTime DateTime::ToUtc() noexcept 
    {
        return AddSeconds(-GetGMTOffset());
    }

    /** @brief Converts this UTC value to local time by adding GMT offset. */
    DateTime DateTime::ToLocal() noexcept 
    {
        return AddSeconds(+GetGMTOffset());
    }

    /** @brief Gets current local wall clock time. */
    DateTime DateTime::Now() noexcept 
    {
        auto now = std::chrono::system_clock::now();
        auto ts  = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        return Local().AddSeconds(ts);
    }

    /** @brief Gets current UTC wall clock time. */
    DateTime DateTime::UtcNow() noexcept 
    {
        auto now = std::chrono::system_clock::now();
        auto ts  = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        return Utc().AddSeconds(ts);
    }

    /**
     * @brief Returns timezone offset from UTC in seconds.
     * @param abs When true, recomputes immediately; otherwise uses cached value.
     * @return Local minus UTC offset in seconds.
     */
    int DateTime::GetGMTOffset(bool abs) noexcept 
    {
        static constexpr auto gmtOffset = 
            []() noexcept 
            {
                time_t t = time(NULLPTR);

                struct tm local_tm;
                struct tm gmt_tm;

                localtime_r(&t, &local_tm);
                gmtime_r(&t, &gmt_tm);

                struct tm* local = &local_tm;
                struct tm* gmt = &gmt_tm;

                int hour_diff = local->tm_hour - gmt->tm_hour;
                int min_diff  = local->tm_min - gmt->tm_min;

                /** @details Corrects cross-day wrap-around between local and UTC. */
                if (local->tm_yday > gmt->tm_yday) 
                {
                    hour_diff += 24;
                }
                elif (local->tm_yday < gmt->tm_yday) 
                {
                    hour_diff -= 24;
                }
            
                return hour_diff * 3600 + min_diff * 60;
            };

        if (abs) {
            return gmtOffset();
        }

        static const int offset = gmtOffset();

        return offset;
    }

    /**
     * @brief Parses numeric date-time segments from free-form text.
     * @param s Input character buffer.
     * @param len Input length, or negative to auto-detect via C-string terminator.
     * @param out Receives parsed result.
     * @return True when at least one numeric segment is parsed.
     */
    bool DateTime::TryParse(const char* s, int len, DateTime& out) noexcept 
    {
        out = MinValue();
        if (NULLPTR == s && len != 0) 
        {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::DateTimeTryParseNullInputWithNonZeroLength);
        }

        if (NULLPTR != s && len == 0) 
        {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::DateTimeTryParseNonNullInputWithZeroLength);
        }

        if (len < 0) 
        {
            len = (int)strlen(s);
        }

        if (len < 1) 
        {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::DateTimeTryParseInputLengthInvalid);
        }

        static constexpr int max_segments_length = 7;
        ppp::string segments[max_segments_length + 1];

        const char* p = s;
        unsigned int length = 0;

        while (p < (s + len) && *p != '\x0') 
        {
            char ch = *p;
            if (ch >= '0' && ch <= '9') 
            {
                char buf[2] = { ch, '\x0' };
                segments[length] += buf;
            }
            else 
            {
                if (!segments[length].empty()) 
                {
                    length++;
                    /** @details Stops once all supported date-time segments are collected. */
                    if (length >= max_segments_length) 
                    {
                        break;
                    }
                    else {
                        segments[length].clear();
                    }
                }
            }

            p++;
        }

        struct 
        {
            int y;
            int M;
            int d;
            int H;
            int m;
            int s;
            int f;
        } tm;

        if (0 == length) 
        {
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::DateTimeTryParseNoNumericSegments);
        }
        else 
        {
            int* t = (int*)&tm;
            for (unsigned int i = 1; i <= max_segments_length; i++) 
            {
                if (i > (length + 1)) 
                {
                    t[i - 1] = 0;
                }
                else 
                {
                    ppp::string& sx = segments[i - 1];
                    if (sx.empty())
                    {
                        t[i - 1] = 0;
                    }
                    else
                    {
                        char* endptr = NULLPTR;
                        long val = strtol(sx.c_str(), &endptr, 10);
                        if (NULLPTR == endptr || endptr == sx.c_str() || *endptr != '\x0') {
                            t[i - 1] = 0;
                        } 
                        else {
                            t[i - 1] = static_cast<int>(val);
                        }
                    }
                }
            }

            out = DateTime(tm.y, tm.M, tm.d, tm.H, tm.m, tm.s, tm.f);
        }

        return length > 0;
    }

    /**
     * @brief Formats the current value with token-based pattern expansion.
     * @param format Token pattern (y, M, d, H, m, s, f, u, T).
     * @param fixed Enables truncation when generated segments exceed token width.
     * @return Formatted string.
     */
    ppp::string DateTime::ToString(const char* format, bool fixed) noexcept 
    {
        ppp::string result;
        if (NULLPTR == format || *format == '\x0') 
        {
            return result;
        }

        char symbol = 0;
        int symbol_size = 0;
        auto symbol_exec = 
            [&](int ch) noexcept 
            {
                ppp::string seg;
                switch (symbol) 
                {
                case 'y':
                    seg = stl::to_string<ppp::string>(Year());
                    break;
                case 'M':
                    seg = stl::to_string<ppp::string>(Month());
                    break;
                case 'd':
                    seg = stl::to_string<ppp::string>(Day());
                    break;
                case 'H':
                    seg = stl::to_string<ppp::string>(Hour());
                    break;
                case 'm':
                    seg = stl::to_string<ppp::string>(Minute());
                    break;
                case 's':
                    seg = stl::to_string<ppp::string>(Second());
                    break;
                case 'f':
                    seg = stl::to_string<ppp::string>(Millisecond());
                    break;
                case 'u':
                    seg = stl::to_string<ppp::string>(Microseconds());
                    break;
                case 'T':
                    seg = stl::to_string<ppp::string>((int64_t)TotalHours());
                    break;
                };

                int64_t seg_size = seg.size();
                /** @details Token width controls left padding or truncation. */
                if (fixed && seg_size > symbol_size) 
                {
                    seg = seg.substr(seg_size - symbol_size);
                }
                elif(seg_size < symbol_size) 
                {
                    seg = PaddingLeft(seg, symbol_size, '0');
                }

                if (ch != 0) 
                {
                    seg.append(1, ch);
                }

                result += seg;
                symbol = 0;
                symbol_size = 0;
            };

        const char* p = format;
        for (;;) 
        {
            char ch = *p++;
            if (ch != 0) /* yMdHmsfuT */ 
            { 
                bool fb = 
                    ch == 'y' || 
                    ch == 'M' || 
                    ch == 'd' || 
                    ch == 'H' || 
                    ch == 'm' || 
                    ch == 's' || 
                    ch == 'f' || 
                    ch == 'u' ||
                    ch == 'T';
                if (fb) 
                {
                    if (symbol != 0 && symbol != ch) 
                    {
                        symbol_exec(ch);
                    }

                    symbol = ch;
                    symbol_size++;
                    continue;
                }
            }

            symbol_exec(ch);
            if (ch == 0) 
            {
                break;
            }
        }

        return result;
    }
}
