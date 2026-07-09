#pragma once

#include <ppp/stdafx.h>

/**
 * @file DateTime.h
 * @brief Declares a lightweight tick-based date-time utility type.
 */

namespace ppp 
{
    //////////////////////////////////////////////////////////////////////////
    /**
     * @brief Time unit is 100-nanosecond intervals (10-millionths of a second per tick).
     */
    /**
     * @brief Day-of-week enumeration.
     */
    enum DayOfWeek 
    {
        DayOfWeek_Sunday,
        DayOfWeek_Monday,
        DayOfWeek_Tuesday,
        DayOfWeek_Wednesday,
        DayOfWeek_Thursday,
        DayOfWeek_Friday,
        DayOfWeek_Saturday
    };

    /**
     * @brief Tick-based date-time value type.
     *
     * One tick equals 100 nanoseconds.
     */
    struct DateTime final
    {
    private:
        int64_t                 m_ticks = 0;

    public:
        /** @brief Constructs the minimum representable value (tick 0). */
        DateTime() noexcept 
        {
            m_ticks = 0;
        }
        /** @brief Constructs from raw ticks. */
        DateTime(int64_t ticks) noexcept 
        {
            m_ticks = ticks;
        };
        /**
         * @brief Constructs from date-time components.
         * @param year Year component.
         * @param month Month component in range [1, 12].
         * @param day Day component.
         * @param hour Hour component.
         * @param minutes Minute component.
         * @param seconds Second component.
         * @param millisecond Millisecond component.
         */
        DateTime(int year, int month, int day = 0, int hour = 0, int minutes = 0, int seconds = 0, int millisecond = 0) noexcept 
        {
            this->m_ticks = 0;
            DateTime& dateTime = *this;
            dateTime = dateTime.AddYears(year - 1);
            dateTime = dateTime.AddMonths(month - 1);
            dateTime = dateTime.AddDays(day - 1);
            dateTime = dateTime.AddHours(hour);
            dateTime = dateTime.AddMinutes(minutes);
            dateTime = dateTime.AddSeconds(seconds);
            dateTime = dateTime.AddMilliseconds(millisecond);
        }

    public:
        /** @brief Gets normalized internal ticks. */
        int64_t                 Ticks() noexcept 
        {
            return m_ticks & 0x3FFFFFFFFFFFFFFF;
        }
        /** @brief Gets millisecond part in range [0, 999]. */
        int                     Millisecond() noexcept 
        {
            return (int)(Ticks() / 10000 % 1000);
        }
        /** @brief Gets second part in range [0, 59]. */
        int                     Second() noexcept 
        {
            return (int)(Ticks() / 10000000 % 60);
        }
        /** @brief Gets minute part in range [0, 59]. */
        int                     Minute() noexcept 
        {
            return (int)(Ticks() / 600000000 % 60);
        }
        /** @brief Gets hour part in range [0, 23]. */
        int                     Hour() noexcept 
        {
            return (int)(Ticks() / 36000000000LL % 24);
        }
        /** @brief Gets microsecond sub-millisecond part in range [0, 999]. */
        int                     Microseconds() noexcept 
        {
            return (int)(Ticks() / 10LL % 1000);
        }

    private:
        /** @brief Cumulative month-day table for leap years. */
        static int*             DaysToMonth366() noexcept 
        {
            static int buf[] = 
            {
                0,
                31,
                60,
                91,
                121,
                152,
                182,
                213,
                244,
                274,
                305,
                335,
                366
            };
            return buf;
        }
        /** @brief Cumulative month-day table for common years. */
        static int*             DaysToMonth365() noexcept 
        {
            static int buf[] = 
            {
                0,
                31,
                59,
                90,
                120,
                151,
                181,
                212,
                243,
                273,
                304,
                334,
                365
            };
            return buf;
        }
        /**
         * @brief Extracts a specific date part from ticks.
         * @param part 0-year, 1-day-of-year, 2-month, 3-day.
         * @return Requested date part.
         */
        int                     GetDatePart(int part) noexcept 
        {
            int64_t internalTicks = Ticks();
            int num = (int)(internalTicks / 864000000000LL);
            /** @details Breaks absolute days into 400/100/4/1-year cycles. */
            int num2 = num / 146097;
            num -= num2 * 146097;

            int num3 = num / 36524;
            if (num3 == 4)
            {
                num3 = 3;
            }

            num -= num3 * 36524;
            int num4 = num / 1461;

            num -= num4 * 1461;
            int num5 = num / 365;
            if (num5 == 4)
            {
                num5 = 3;
            }

            if (part == 0)
            {
                return num2 * 400 + num3 * 100 + num4 * 4 + num5 + 1;
            }

            num -= num5 * 365;
            if (part == 1)
            {
                return num + 1;
            }

            int* array = (num5 == 3 && (num4 != 24 || num3 == 3)) ? DaysToMonth366() : DaysToMonth365();
            int i = 0;
            for (i = num >> 6; num >= array[i]; i++);

            if (part == 2)
            {
                return i;
            }

            return num - array[i - 1] + 1;
        }

    public:
        /** @brief Gets day of month in range [1, 31]. */
        int                     Day() noexcept 
        {
            return GetDatePart(3);
        }
        /** @brief Gets day of year in range [1, 366]. */
        int                     DayOfYear() noexcept 
        {
            return GetDatePart(1);
        }
        /** @brief Gets day of week. */
        DayOfWeek               DayOfWeeks() noexcept 
        {
            return (DayOfWeek)((Ticks() / 864000000000LL + 1) % 7);
        }
        /** @brief Gets month in range [1, 12]. */
        int                     Month() noexcept 
        {
            return GetDatePart(2);
        }
        /** @brief Gets year in range [1, 9999]. */
        int                     Year() noexcept 
        {
            return GetDatePart(0);
        }

    public:
        /** @brief Returns the date part with time truncated to midnight. */
        DateTime                Date() noexcept 
        {
            int64_t internalTicks = Ticks();
            return DateTime((uint64_t)(internalTicks - internalTicks % 864000000000LL));
        }
        /** @brief Converts local time to UTC using current GMT offset. */
        DateTime                ToUtc() noexcept;
        /** @brief Converts UTC time to local time using current GMT offset. */
        DateTime                ToLocal() noexcept;

    public:
        /** @brief Compares two values by ticks. */
        static int              Compare(DateTime t1, DateTime t2) noexcept 
        {
            int64_t internalTicks = t1.Ticks();
            int64_t internalTicks2 = t2.Ticks();
            if (internalTicks > internalTicks2) 
            {
                return 1;
            }

            if (internalTicks < internalTicks2)
            {
                return -1;
            }

            return 0;
        }
        /** @brief Compares this value with another value by ticks. */
        int                     CompareTo(DateTime value) noexcept 
        {
            return Compare(*this, value);
        }
        /** @brief Tests whether two values have identical ticks. */
        bool                    Equals(DateTime value) noexcept 
        {
            return Ticks() == value.Ticks();
        }
        /** @brief Tests whether two values have identical ticks. */
        static bool             Equals(DateTime t1, DateTime t2) noexcept 
        {
            return t1.Ticks() == t2.Ticks();
        }
                                
    public:                     
        /** @brief Determines whether a year is a leap year in the Gregorian calendar. */
        static bool             IsLeapYear(int year) noexcept 
        {
            if (year < 1 || year > 9999) 
            {
                return false;
            }

            if (year % 4 == 0)
            {
                if (year % 100 == 0) 
                {
                    return year % 400 == 0;
                }

                return true;
            }
            
            return false;
        }
        /** @brief Gets the number of days in the specified year/month. */
        static int              DaysInMonth(int year, int month) noexcept 
        {
            if (month < 1 || month > 12) 
            {
                return -1;
            }

            int* array = IsLeapYear(year) ? DaysToMonth366() : DaysToMonth365();
            return array[month] - array[month - 1];
        }
                                
    public:                     
        /** @brief Adds raw ticks with clamping to valid range. */
        DateTime                AddTicks(int64_t value) noexcept 
        {
            int64_t internalTicks = Ticks();
            if (value > 3155378975999999999LL - internalTicks) 
            {
                value = 3155378975999999999LL - internalTicks;
            }

            if (value < -internalTicks) 
            {
                value = -internalTicks;
            }

            return DateTime(internalTicks + value);
        }
        /** @brief Adds time units by scale in milliseconds with rounding. */
        DateTime                Add(long double value, int scale) noexcept 
        {
            int64_t num = (int64_t)(value * (long double)scale + ((value >= 0.0) ? 0.5 : (-0.5)));
            if (num <= -315537897600000LL) 
            {
                num = -315537897600000LL;
            }

            if (num >= 315537897600000LL) 
            {
                num = 315537897600000LL;
            }

            return AddTicks(num * 10000);
        }
        /** @brief Adds days. */
        DateTime                AddDays(long double value) noexcept 
        {
            return Add(value, 86400000);
        }
        /** @brief Adds hours. */
        DateTime                AddHours(long double value) noexcept 
        {
            return Add(value, 3600000);
        }
        /** @brief Adds seconds. */
        DateTime                AddSeconds(long double value) noexcept 
        {
            return Add(value, 1000);
        }
        /** @brief Adds minutes. */
        DateTime                AddMinutes(long double value) noexcept 
        {
            return Add(value, 60000);
        }
        /** @brief Adds milliseconds. */
        DateTime                AddMilliseconds(long double value) noexcept 
        {
            return Add(value, 1);
        }

    private:
        /** @brief Converts a calendar date to ticks at midnight. */
        int64_t                 DateToTicks(int year, int month, int day) noexcept 
        {
            if (year >= 1 && year <= 9999 && month >= 1 && month <= 12) 
            {
                int* array = IsLeapYear(year) ? DaysToMonth366() : DaysToMonth365();
                if (day >= 1 && day <= array[month] - array[month - 1]) 
                {
                    int num = year - 1;
                    int num2 = num * 365 + num / 4 - num / 100 + num / 400 + array[month - 1] + day - 1;

                    int64_t ticks = (int64_t)num2 * 864000000000LL;
                    return ticks;
                }
            }

            return 0;
        }
        /** @brief Decomposes ticks into year/month/day components. */
        void                    GetDatePart(int& year, int& month, int& day) noexcept 
        {
            int64_t internalTicks = Ticks();
            int num = (int)(internalTicks / 864000000000LL);
            /** @details Uses Gregorian cycle decomposition for conversion speed. */
            int num2 = num / 146097;
            num -= num2 * 146097;

            int num3 = num / 36524;
            if (num3 == 4) {
                num3 = 3;
            }

            num -= num3 * 36524;
            int num4 = num / 1461;

            num -= num4 * 1461;
            int num5 = num / 365;
            if (num5 == 4) {
                num5 = 3;
            }

            year = num2 * 400 + num3 * 100 + num4 * 4 + num5 + 1;
            num -= num5 * 365;

            int* array = (num5 == 3 && (num4 != 24 || num3 == 3)) ? DaysToMonth366() : DaysToMonth365();
            int i = 0;
            for (i = (num >> 5) + 1; num >= array[i]; i++);

            month = i;
            day = num - array[i - 1] + 1;
        }

    public:
        /** @brief Adds months while clamping the resulting day to month length. */
        DateTime                AddMonths(int months) noexcept 
        {
            if (months < -120000 || months > 120000) 
            {
                return *this;
            }

            int year;
            int month;
            int day;
            GetDatePart(year, month, day);

            int num = month - 1 + months;
            if (num >= 0) 
            {
                month = num % 12 + 1;
                year += num / 12;
            }
            else 
            {
                month = 12 + (num + 1) % 12;
                year += (num - 11) / 12;
            }

            if (year < 1 || year > 9999) 
            {
                return *this;
            }

            int num2 = DaysInMonth(year, month);
            if (day > num2) 
            {
                day = num2;
            }

            int64_t ticks = DateToTicks(year, month, day);
            ticks += Ticks() % 864000000000LL;

            return DateTime(ticks);
        }
        /** @brief Subtracts another DateTime value in ticks. */
        DateTime                Subtract(DateTime value) noexcept 
        {
            return DateTime(Ticks() - value.Ticks());
        }
        /** @brief Adds years. */
        DateTime                AddYears(int year) noexcept 
        {
            if (year < -10000 || year > 10000)
            {
                return *this;
            }

            return AddMonths(year * 12);
        }

    public:
        /** @brief Gets total elapsed days represented by ticks. */
        long double             TotalDays() noexcept 
        {
            return (long double)Ticks() * 1.1574074074074074E-12;
        }
        /** @brief Gets total elapsed hours represented by ticks. */
        long double             TotalHours() noexcept 
        {
            return (long double)Ticks() * 2.7777777777777777E-11;
        }
        /** @brief Gets total elapsed milliseconds represented by ticks. */
        long double             TotalMilliseconds() noexcept 
        {
            long double num = (long double)Ticks() * 0.0001;
            if (num > 922337203685477.0) 
            {
                return 922337203685477.0;
            }

            if (num < -922337203685477.0) 
            {
                return -922337203685477.0;
            }

            return num;
        }
        /** @brief Gets total elapsed minutes represented by ticks. */
        long double             TotalMinutes() noexcept 
        {
            return (long double)Ticks() * 1.6666666666666667E-09;
        }
        /** @brief Gets total elapsed seconds represented by ticks. */
        long double             TotalSeconds() noexcept 
        {
            return (long double)Ticks() * 1E-07;
        }

    public:
        /** @brief Gets current local time. */
        static DateTime         Now() noexcept;
        /** @brief Gets current UTC time. */
        static DateTime         UtcNow() noexcept;
        /** @brief Gets local GMT offset in seconds. */
        static int              GetGMTOffset(bool abs = false) noexcept;
        /** @brief Gets minimum representable value. */
        static DateTime         MinValue() noexcept 
        {
            return DateTime(0);
        }
        /** @brief Gets maximum representable value. */
        static DateTime         MaxValue() noexcept 
        {
            return DateTime(3155378975999999999LL);
        }

    public:
        /** @brief Attempts to parse a date-time string. */
        static bool             TryParse(const char* s, DateTime& dateTime) noexcept 
        {
            return TryParse(s, -1, dateTime);
        }
        /** @brief Attempts to parse a date-time string with explicit length. */
        static bool             TryParse(const char* s, int len, DateTime& dateTime) noexcept;
        /** @brief Attempts to parse from C++ string storage. */
        static bool             TryParse(const ppp::string& s, DateTime& dateTime) noexcept 
        {
            ppp::string& sx = constantof(s);
            return TryParse(sx.c_str(), (int)sx.length(), dateTime);
        }
        /** @brief Parses a date-time string; returns MinValue on failure. */
        static DateTime         Parse(const char* s) noexcept 
        {
            return Parse(s, -1);
        }
        /** @brief Parses a date-time string with explicit length. */
        static DateTime         Parse(const char* s, int len) noexcept 
        {
            DateTime dateTime;
            TryParse(s, len, dateTime);
            return dateTime;
        }
        /** @brief Parses from C++ string storage. */
        static DateTime         Parse(const ppp::string& s) noexcept 
        {
            DateTime dateTime;
            TryParse(s, dateTime);
            return dateTime;
        }
        /** @brief Returns Unix epoch interpreted as UTC. */
        static DateTime         Utc() noexcept 
        {
            return DateTime(1970, 1, 1);
        }
        /** @brief Returns Unix epoch shifted to local timezone. */
        static DateTime         Local() noexcept 
        {
            return DateTime(1970, 1, 1).AddSeconds(GetGMTOffset());
        }

    public:
        /** @brief Formats this value with a custom token pattern. */
        ppp::string             ToString(const char* format) noexcept { return ToString(format, true); }
        /** @brief Formats this value with optional fixed-width token behavior. */
        ppp::string             ToString(const char* format, bool fixed) noexcept;

    public:
        /** @brief Equality comparison by ticks. */
        bool                    operator==(const DateTime& right) noexcept 
        {
            return Ticks() == constantof(right).Ticks();
        }
        /** @brief Inequality comparison by ticks. */
        bool                    operator!=(const DateTime& right) noexcept 
        {
            return Ticks() != constantof(right).Ticks();
        }
        /** @brief Greater-than comparison by ticks. */
        bool                    operator>(const DateTime& right) noexcept 
        {
            return Ticks() > constantof(right).Ticks();
        }
        /** @brief Less-than comparison by ticks. */
        bool                    operator<(const DateTime& right) noexcept 
        {
            return Ticks() < constantof(right).Ticks();
        }
        /** @brief Greater-than-or-equal comparison by ticks. */
        bool                    operator>=(const DateTime& right) noexcept 
        {
            return Ticks() >= constantof(right).Ticks();
        }
        /** @brief Less-than-or-equal comparison by ticks. */
        bool                    operator<=(const DateTime& right) noexcept 
        {
            return Ticks() <= constantof(right).Ticks();
        }
        /** @brief Adds ticks from another DateTime value. */
        DateTime                operator+(const DateTime& right) noexcept 
        {
            int64_t ticks = constantof(right).Ticks();
            return this->AddTicks(ticks);
        }
        /** @brief Subtracts ticks of another DateTime value. */
        DateTime                operator-(const DateTime& right) noexcept 
        {
            return this->Subtract(right);
        }
    };
}
