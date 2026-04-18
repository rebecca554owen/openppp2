/**
 * @file ApplicationHelp.cpp
 * @brief Version formatting and command-line help text rendering.
 */

#include <ppp/app/PppApplicationInternal.h>

namespace ppp::app {

/**
 * @brief Formats semantic version components into printable string.
 * @param major Major version number.
 * @param minor Minor version number.
 * @param patch Patch version number; omitted when zero.
 * @return Human-readable version string.
 */
static ppp::string GetVersionString(int major, int minor, int patch = 0) noexcept {
    char buf[100];
    *buf = '\x0';

    if (patch != 0) {
        snprintf(buf, sizeof(buf), "%d.%d.%d", major, minor, patch);
    } else {
        snprintf(buf, sizeof(buf), "%d.%d", major, minor);
    }

    return buf;
}

/**
 * @brief Converts Boost compile-time numeric version macro to dotted string.
 * @return Boost library version string.
 */
static ppp::string GetBoostVersionString() noexcept {
    constexpr int version = BOOST_VERSION;

    int minor = (version / 100) % 100;
    int major = version / 100000;
    int patch = version % 100;

    return GetVersionString(major, minor, patch);
}

/**
 * @brief Prints full command-line help, platform options, and dependency versions.
 */
void PppApplication::PrintHelpInformation() noexcept {
    ppp::string execution_file_name = ppp::GetExecutionFileName();
    ppp::string cwd = ppp::GetCurrentDirectoryPath();

    static constexpr int col_option_width = 40;
    static constexpr int col_description_width = 48;
    static constexpr int col_default_width = 23;
    static constexpr int col_command_width = 38;
    static constexpr int col_command_width_utlity = col_command_width + 2;

    fputs("┌──────────────────────────────────────────────────────────────────────┐\n", stdout);
    fputs("│                       PPP PRIVATE NETWORK™ 2                         │\n", stdout);
    fputs("│  Next-generation security network access technology, providing high- │\n", stdout);
    fputs("│  performance Virtual Ethernet tunneling service.                     │\n", stdout);
    fputs("└──────────────────────────────────────────────────────────────────────┘\n\n", stdout);

    fprintf(stdout, "Version:      %s\n", PPP_APPLICATION_VERSION);
    fputs("Copyright:    (C) 2017 ~ 2055 SupersocksR ORG. All rights reserved.\n", stdout);
    fprintf(stdout, "Current Dir:  %s\n\n", cwd.data());

    fputs("USAGE:\n", stdout);
    fprintf(stdout, "    %s [OPTIONS]\n\n", execution_file_name.data());

    fputs("GENERAL OPTIONS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "OPTION", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--rt=[yes|no]", col_description_width, "Enable real-time mode", col_default_width, "yes");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--mode=[client|server]", col_description_width, "Set running mode", col_default_width, "server");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--config=<path>", col_description_width, "Configuration file path", col_default_width, "./appsettings.json");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--dns=<ip-list>", col_description_width, "DNS server addresses", col_default_width, "8.8.8.8,8.8.4.4");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-flash=[yes|no]", col_description_width, "Enable advanced QoS policy", col_default_width, "no");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--auto-restart=<seconds>", col_description_width, "Auto restart interval", col_default_width, "0 (disabled)");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--link-restart=<count>", col_description_width, "Link reconnection attempts", col_default_width, "0");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--block-quic=[yes|no]", col_description_width, "Block QUIC protocol traffic", col_default_width, "no");
    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    fputs("SERVER-SPECIFIC OPTIONS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "OPTION", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--firewall-rules=<file>", col_description_width, "Firewall rules file", col_default_width, "./firewall-rules.txt");
    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    fputs("CLIENT-SPECIFIC OPTIONS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "OPTION", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--lwip=[yes|no]", col_description_width, "Network protocol stack selection", col_default_width,
#if defined(_WIN32)
        ppp::tap::TapWindows::IsWintun() ? "no" : "yes"
#else
        "no"
#endif
    );

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--vbgp=[yes|no]", col_description_width, "Enable virtual BGP routing", col_default_width, "yes");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--nic=<interface>", col_description_width, "Specify physical network interface", col_default_width, "auto-select");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--ngw=<ip>", col_description_width, "Force gateway address", col_default_width, "auto-detect");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun=<name>", col_description_width, "Virtual adapter name", col_default_width, NetworkInterface::GetDefaultTun().c_str());
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-ip=<ip>", col_description_width, "Virtual adapter IP address", col_default_width, "10.0.0.2");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-ipv6=<ip>", col_description_width, "Requested virtual adapter IPv6", col_default_width, "server-assigned");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-gw=<ip>", col_description_width, "Virtual adapter gateway", col_default_width, "10.0.0.1");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-mask=<bits>", col_description_width, "Subnet mask bits", col_default_width, "30");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-vnet=[yes|no]", col_description_width, "Enable subnet forwarding", col_default_width, "yes");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-host=[yes|no]", col_description_width, "Prefer host network", col_default_width, "yes");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-static=[yes|no]", col_description_width, "Enable static tunnel", col_default_width, "no");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-mux=<connections>", col_description_width, "MUX connection count (0=disabled)", col_default_width, "0");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-mux-acceleration=<mode>", col_description_width, "MUX acceleration mode (0-3)", col_default_width, "0 (standard)");

#if defined(_LINUX) || defined(_MACOS)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-promisc=[yes|no]", col_description_width, "Enable promiscuous mode", col_default_width, "yes");
#endif

#if defined(_MACOS)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-ssmt=<threads>", col_description_width, "SSMT thread optimization", col_default_width, "0");
#elif defined(_LINUX)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-ssmt=<N>[/<mode>]", col_description_width, "SSMT threads (N), mode: st or mq; mq opens one Linux tun queue per worker", col_default_width, "0/st");
#endif

#if defined(_LINUX)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-route=[yes|no]", col_description_width, "Route compatibility", col_default_width, "no");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-protect=[yes|no]", col_description_width, "Route protection", col_default_width, "yes");
#endif

#if defined(_WIN32)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--tun-lease-time-in-seconds=<sec>", col_description_width, "DHCP lease time", col_default_width, "7200");
#endif

    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    fputs("ROUTING OPTIONS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "OPTION", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--bypass=<file1|file2>", col_description_width, "Bypass IP list file", col_default_width, "./ip.txt");

#if defined(_LINUX)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--bypass-nic=<interface>", col_description_width, "Interface for bypass list", col_default_width, "auto-select");
#endif

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--bypass-ngw=<ip>", col_description_width, "Gateway for bypass list", col_default_width, "auto-detect");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--virr=[file/country]", col_description_width, "Auto-update and take effect IP-list", col_default_width, "./ip.txt/CN");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--dns-rules=<file>", col_description_width, "DNS rules configuration", col_default_width, "./dns-rules.txt");
    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

#if defined(_WIN32)
    fputs("WINDOWS-SPECIFIC COMMANDS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │\n", col_command_width_utlity, "COMMAND", col_description_width, "DESCRIPTION");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┤\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │\n", col_command_width_utlity, "--system-network-reset", col_description_width, "Reset Windows network stack");
    fprintf(stdout, "│ %-*s │ %-*s │\n", col_command_width_utlity, "--system-network-optimization", col_description_width, "Optimize network performance");
    fprintf(stdout, "│ %-*s │ %-*s │\n", col_command_width_utlity, "--system-network-preferred-ipv4", col_description_width, "Set IPv4 as preferred protocol");
    fprintf(stdout, "│ %-*s │ %-*s │\n", col_command_width_utlity, "--system-network-preferred-ipv6", col_description_width, "Set IPv6 as preferred protocol");
    fprintf(stdout, "│ %-*s │ %-*s │\n", col_command_width_utlity, "--no-lsp <program>", col_description_width, "Disable LSP for specified program");
    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┘\n\n", stdout);
#endif

    fputs("UTILITY COMMANDS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "COMMAND", col_description_width, "DESCRIPTION", col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--help", col_description_width, "Display this help information", col_default_width, "none");
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n", col_option_width, "--pull-iplist [file/country]", col_description_width, "Download country IP list from APNIC", col_default_width, "./ip.txt/CN");
    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    fputs("CONTACT:\n", stdout);
    fputs("    Telegram: https://t.me/supersocksr_group\n\n", stdout);

    fputs("DEPENDENCIES:\n", stdout);
    fprintf(stdout, "    boost@%s", GetBoostVersionString().c_str());

#if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
    fprintf(stdout, ", libc@%s", GetVersionString(__GLIBC__, __GLIBC_MINOR__).c_str());
#if defined(__MUSL__)
    fputs("/musl", stdout);
#else
    fputs("/glibc", stdout);
#endif
#endif

#if defined(LIBCURL_VERSION_MAJOR)
    fprintf(stdout, ", curl@%s", GetVersionString(LIBCURL_VERSION_MAJOR, LIBCURL_VERSION_MINOR, LIBCURL_VERSION_PATCH).c_str());
#endif

#if defined(OPENSSL_VERSION_MAJOR)
    fprintf(stdout, ", openssl@%s", GetVersionString(OPENSSL_VERSION_MAJOR, OPENSSL_VERSION_MINOR, OPENSSL_VERSION_PATCH).c_str());
#else
    fputs(", openssl@1.1.1", stdout);
#endif

#if defined(JEMALLOC_VERSION_MAJOR)
    fprintf(stdout, ", jemalloc@%s", GetVersionString(JEMALLOC_VERSION_MAJOR, JEMALLOC_VERSION_MINOR, JEMALLOC_VERSION_BUGFIX).c_str());
#endif

    fputs("\n", stdout);
    fflush(stdout);
}

} // namespace ppp::app
