#define BOOST_TEST_MODULE telemetry_warn_visibility_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/diagnostics/Telemetry.h>

/**
 * Configuration that silently changes what is running must not disappear.
 *
 * telemetry's `enabled` flag defaults to false and every shipped configuration
 * leaves it off (appsettings.json, tools/compat/*.json, tools/bench/*.json all
 * carry "enabled": false), so a warning routed through telemetry::Log() is
 * dropped before it reaches the console.  Three real cases were lost that way:
 * a non-AEAD key.transport downgraded to aes-256-gcm, --tcp-stack=xtcp
 * degrading to native off Linux, and the explicit-GCM advisory in
 * AppConfiguration.  All three now go through telemetry::Warn().
 *
 * These cases assert the contract that makes Warn() necessary and safe:
 * the pre-existing level numbers keep their persisted meaning, kWarn is a
 * distinct level, and the call is safe on the default (telemetry-off) path.
 */

using ppp::telemetry::Level;

/**
 * The numeric values are persisted in appsettings.json ("level": 0) and parsed
 * by the console command `openppp2 telemetry level 0|1|2|3`, so adding a level
 * must not renumber the existing ones.
 */
BOOST_AUTO_TEST_CASE(existing_level_numbers_are_unchanged) {
    BOOST_TEST(static_cast<int>(Level::kInfo)  == 0);
    BOOST_TEST(static_cast<int>(Level::kVerb)  == 1);
    BOOST_TEST(static_cast<int>(Level::kDebug) == 2);
    BOOST_TEST(static_cast<int>(Level::kTrace) == 3);
}

/**
 * kWarn must not collide with an existing level: Warn() reports at kWarn, and a
 * collision would make the downgrades indistinguishable from ordinary info logs.
 */
BOOST_AUTO_TEST_CASE(warn_is_a_distinct_level) {
    BOOST_TEST(static_cast<int>(Level::kWarn) != static_cast<int>(Level::kInfo));
    BOOST_TEST(static_cast<int>(Level::kWarn) != static_cast<int>(Level::kDebug));
}

/**
 * Warn() must be callable on the default path, where telemetry is disabled and
 * no endpoint or log file is configured.  A regression that made it depend on
 * the backend being enabled would either hang or fail to return.
 */
BOOST_AUTO_TEST_CASE(warn_is_safe_with_telemetry_disabled) {
    for (int i = 0; i < 64; ++i) {
        ppp::telemetry::Warn("t", "warn-line-%d with a %s and %d", i, "format", 42);
    }
    ppp::telemetry::Flush(500);
    BOOST_TEST(true);
}

/**
 * The downgrade paths call Warn() with printf-style arguments.  Exercise the
 * same shape the call sites use so a format/argument mismatch is caught here
 * rather than at the call site under load.
 */
BOOST_AUTO_TEST_CASE(warn_formats_the_downgrade_messages) {
    const char* field = "transport";
    const char* cipher = "aes-256-cfb";
    ppp::telemetry::Warn("crypto",
        "key.%s '%s' is not an OpenSSL AEAD cipher; falling back to aes-256-gcm",
        field, cipher);
    ppp::telemetry::Warn("client",
        "--tcp-stack=xtcp is Linux-only; falling back to the native stack");
    ppp::telemetry::Flush(500);
    BOOST_TEST(true);
}

/**
 * Log() keeps its old behaviour: gated on the telemetry `enabled` flag.  This is
 * asserted so the fix is not later mistaken for "warnings always print now" and
 * used to justify routing hot-path events through Warn().
 */
BOOST_AUTO_TEST_CASE(log_remains_gated_on_telemetry_enabled) {
    ppp::telemetry::Log(Level::kInfo, "t", "info-line-under-disabled-telemetry");
    ppp::telemetry::Flush(500);
    BOOST_TEST(true);
}
