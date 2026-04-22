/**
 * @file ApplicationNetwork.cpp
 * @brief Network interface defaults and dynamic IP-list update helpers.
 */

#include <ppp/app/PppApplicationInternal.h>

namespace ppp::app {

/**
 * @brief Returns platform-specific default tunnel adapter identifier.
 * @return Default tunnel name for the active operating system.
 */
ppp::string NetworkInterface::GetDefaultTun() noexcept {
    const char* default_tun_name = NULLPTR;
#if defined(_WIN32)
    default_tun_name = PPP_APPLICATION_NAME;
#elif defined(_MACOS)
    default_tun_name = "utun0";
#else
    default_tun_name = BOOST_BEAST_VERSION_STRING;
#endif
    return default_tun_name;
}

/**
 * @brief Parses bypass list argument into normalized file-path entries.
 * @param s Raw bypass list expression.
 * @return Number of entries inserted into the bypass set.
 */
int NetworkInterface::BypassLoadList(const ppp::string& s) noexcept {
    BypassSet& set = *Bypass;
    set.clear();

    if (s.empty()) {
        return 0;
    }

    ppp::vector<ppp::string> segments;
    ppp::string work = s;
    for (char& ch : work) {
        if (ch == '*' || ch == '?' || ch == '<' || ch == '>') {
            ch = '|';
        }
    }
    ppp::Tokenize<ppp::string>(work, segments, "|");

    if (segments.size() == 1) {
        set.emplace(std::move(segments[0]));
        return 1;
    }

    int events = 0;
    for (const ppp::string& i : segments) {
        if (i.empty()) {
            continue;
        }

        ppp::string t = ppp::LTrim(ppp::RTrim(i));
        if (t.empty()) {
            continue;
        }

        t = File::GetFullPath(File::RewritePath(t.data()).data());
        if (t.empty()) {
            continue;
        }

        auto r = set.emplace(std::move(t));
        if (r.second) {
            events++;
        }
    }

    return events;
}

/**
 * @brief Pulls IP list from URL asynchronously and delivers parsed result.
 * @param url Source URL.
 * @param cb Completion callback receiving count and parsed set.
 * @return True when asynchronous task is successfully scheduled.
 */
bool PppApplication::PullIPList(const ppp::string& url, const ppp::function<void(int, const ppp::set<ppp::string>&)>& cb) noexcept {
    if (NULLPTR == cb || url.empty()) {
        return false;
    }

    auto self = shared_from_this();
    std::thread([self, url, cb]() noexcept {
        ppp::set<ppp::string> ips;
        ppp::SetThreadName("vbgp");
        int events = self->PullIPList(url, ips);
        cb(events, ips);
    }).detach();
    return true;
}

/**
 * @brief Downloads and parses an IP list from HTTP/HTTPS endpoint.
 * @param url Source URL.
 * @param ips Output set filled with parsed CIDR entries.
 * @return Number of parsed entries, or negative value on failure.
 */
int PppApplication::PullIPList(const ppp::string& url, ppp::set<ppp::string>& ips) noexcept {
    using HttpClient = ppp::net::http::HttpClient;

    ppp::string host;
    ppp::string path;
    int port = IPEndPoint::MinPort;
    bool https = false;

    if (!HttpClient::VerifyUri(url, ppp::addressof(host), &port, ppp::addressof(path), &https)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
        return -1;
    }

    HttpClient http_client((https ? "https://" : "http://") + host, chnroutes2_cacertpath_default());

    int http_status_code = -1;
    std::string http_response_body = http_client.Get(path, http_status_code);
    if (http_status_code < 200 || http_status_code >= 300) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
        return -1;
    }

    return chnroutes2_getiplist(ips, ppp::string(), stl::transform<ppp::string>(http_response_body));
}

/**
 * @brief Pulls and applies country route list according to command expression.
 * @param command Path/country expression for target file and nation filter.
 * @param virr True to run in asynchronous auto-update mode; false for one-shot pull.
 */
void PppApplication::PullIPList(const ppp::string& command, bool virr) noexcept {
    ppp::string path;
    ppp::string nation;
    for (ppp::string command_string = ppp::LTrim(ppp::RTrim(command)); command_string.size() > 0;) {
        std::size_t index = command_string.find('<');
        if (index == std::string::npos) {
            index = command_string.find('/');
            if (index == std::string::npos) {
                path = command_string;
                break;
            }
        }

        path = ppp::RTrim(command_string.substr(0, index));
        nation = ppp::LTrim(command_string.substr(index + 1));
        break;
    }

    if (path.empty()) {
        path = chnroutes2_filepath_default();
    }

    path = File::GetFullPath(File::RewritePath(path.data()).data());

    bool ok = false;
    if (virr) {
        chnroutes2_getiplist_async([path, nation, configuration = configuration_](const ppp::string& response_text) noexcept {

            /**
             * @brief Applies fetched route set and restarts app when effective routes change.
             * @return -1 on failure, 0 when no effective change, 1 when restart is requested.
             */
            auto process = [&]() noexcept {
                ppp::set<ppp::string> ips;
                if (chnroutes2_getiplist(ips, nation, response_text) < 1) {
                    return -1;
                }

                auto bypass = GLOBAL_.bypass;
                if (NULL == bypass || bypass->find(path) == bypass->end()) {
                    chnroutes2_saveiplist(path, ips);
                    return 0;
                }

                ppp::set<ppp::string> olds;
                ppp::string iplist = ppp::LTrim(ppp::RTrim(File::ReadAllText(path.data())));
                chnroutes2_getiplist(olds, ppp::string(), iplist);
                if (chnroutes2_equals(ips, olds)) {
                    return 0;
                }

                ppp::string news = chnroutes2_toiplist(ips);
                if (!File::WriteAllBytes(path.data(), news.data(), news.size())) {
                    return -1;
                }

                ShutdownApplication(true);
                return 1;
            };

            int return_code = process();
            if (return_code < 0) {
                uint64_t now = Executors::GetTickCount();
                GLOBAL_VIRR_NEXT.store(now + (configuration->virr.retry_interval * 1000), std::memory_order_relaxed);
            }

            return return_code;
        });
    } else {
        ppp::set<ppp::string> ips;
        if (chnroutes2_getiplist(ips, nation) > 0) {
            ok = chnroutes2_saveiplist(path, ips);
        }
    }

    if (!virr && !ok) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigRouteLoadFailed);
    }
}

} // namespace ppp::app
