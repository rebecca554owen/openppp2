cmake_minimum_required(VERSION 3.16)
project(openppp2_cpp_tests LANGUAGES CXX)

option(ENABLE_COVERAGE "Enable LLVM coverage instrumentation" OFF)

get_filename_component(OPENPPP2_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

find_package(OpenSSL REQUIRED)

set(OPENPPP2_TEST_INCLUDES
    "${OPENPPP2_ROOT}"
    "${OPENPPP2_ROOT}/common"
    "${OPENPPP2_ROOT}/common/dnslib"
    "${OPENPPP2_ROOT}/common/json/include"
)

foreach(_hint /usr/include /usr/local/include /opt/homebrew/include)
    if(EXISTS "${_hint}/boost/version.hpp")
        list(APPEND OPENPPP2_TEST_INCLUDES "${_hint}")
        break()
    endif()
endforeach()

enable_testing()

set(OPENPPP2_AGGREGATOR_LOADER_TEST_SUPPORT
    support/aggregator_loader_test_stubs.cpp
    support/fake_aggligator/common/aggligator/aggligator.cpp
    support/dns_host_wiring_switcher_stub.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/AggregatorLoader.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsResponseHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/SwitcherTimeoutRegistry.cpp")

function(openppp2_add_cpp_test target)
    cmake_parse_arguments(ARG "" "" "SOURCES" ${ARGN})
    add_executable(${target} ${ARG_SOURCES})
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_include_directories(${target} PRIVATE ${OPENPPP2_TEST_INCLUDES})
    target_compile_options(${target} PRIVATE
        -Wno-format
        -Wno-deprecated-declarations
        -Wno-tautological-constant-out-of-range-compare
    )
    target_compile_definitions(${target} PRIVATE FUNCTION)
    if(ENABLE_COVERAGE)
        target_compile_options(${target} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
        target_link_options(${target} PRIVATE -fprofile-instr-generate)
    endif()
    if(target STREQUAL "runtime_snapshot_test" OR target STREQUAL "p2p_replay_window_test" OR target STREQUAL "base64_test" OR target STREQUAL "dns_server_validation_test" OR target STREQUAL "dns_wire_validation_test" OR target STREQUAL "sysctl_validation_test" OR target STREQUAL "dns_redirect_plan_test" OR target STREQUAL "dns_reachability_test" OR target STREQUAL "dns_response_handler_test" OR target STREQUAL "dns_route_dispatcher_test" OR target STREQUAL "dns_udp_relay_test" OR target STREQUAL "dns_host_ports_test" OR target STREQUAL "dns_host_interface_test" OR target STREQUAL "dns_host_wiring_test" OR target STREQUAL "route_host_ports_test" OR target STREQUAL "route_host_interface_test" OR target STREQUAL "route_state_test" OR target STREQUAL "route_coordinator_test" OR target STREQUAL "linux_route_platform_contract_test" OR target STREQUAL "route_platform_adapters_test" OR target STREQUAL "aggregator_loader_test" OR target STREQUAL "fake_ip_pool_test" OR target STREQUAL "dns_fake_ip_response_test" OR target STREQUAL "quic_reject_rate_limit_test" OR target STREQUAL "client_bypass_route_loader_test" OR target STREQUAL "exchanger_static_echo_channel_test" OR target STREQUAL "route_table_manager_test" OR target STREQUAL "switcher_timeout_registry_test" OR target STREQUAL "peer_prefix_route_entry_test" OR target STREQUAL "peer_prefix_route_from_json_test" OR target STREQUAL "client_datagram_port_manager_test" OR target STREQUAL "server_datagram_port_manager_test" OR target STREQUAL "static_datagram_port_manager_test")
        target_link_libraries(${target} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    add_test(NAME ${target} COMMAND ${target})
endfunction()

openppp2_add_cpp_test(runtime_snapshot_test SOURCES
    runtime_snapshot_test.cpp
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_compile_definitions(runtime_snapshot_test PRIVATE
    OPENPPP2_RUNTIME_FIXTURE_DIR=\"${OPENPPP2_ROOT}/tests/contracts/runtime-snapshot\")
openppp2_add_cpp_test(runtime_stop_coordinator_test SOURCES
    runtime_stop_coordinator_test.cpp)
openppp2_add_cpp_test(p2p_replay_window_test SOURCES p2p_replay_window_test.cpp)
openppp2_add_cpp_test(dns_buffer_test SOURCES dns_buffer_test.cpp "${OPENPPP2_ROOT}/common/dnslib/buffer.cpp")
openppp2_add_cpp_test(dns_message_test SOURCES dns_message_test.cpp "${OPENPPP2_ROOT}/common/dnslib/buffer.cpp" "${OPENPPP2_ROOT}/common/dnslib/message.cpp" "${OPENPPP2_ROOT}/common/dnslib/qs.cpp" "${OPENPPP2_ROOT}/common/dnslib/rr.cpp")
openppp2_add_cpp_test(dns_server_validation_test SOURCES dns_server_validation_test.cpp)
openppp2_add_cpp_test(dns_wire_validation_test SOURCES dns_wire_validation_test.cpp)
openppp2_add_cpp_test(base64_test SOURCES base64_test.cpp "${OPENPPP2_ROOT}/common/base64/base64.cpp")
openppp2_add_cpp_test(sysctl_validation_test SOURCES sysctl_validation_test.cpp)
openppp2_add_cpp_test(dns_redirect_plan_test SOURCES
    dns_redirect_plan_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsRedirectPlan.cpp")
openppp2_add_cpp_test(dns_reachability_test SOURCES
    dns_reachability_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsReachabilityParse.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsReachability.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsProviderCatalog.cpp")
openppp2_add_cpp_test(dns_response_handler_test SOURCES
    dns_response_handler_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsResponseHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
openppp2_add_cpp_test(dns_route_dispatcher_test SOURCES
    dns_route_dispatcher_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsRouteDispatcher.cpp")
openppp2_add_cpp_test(dns_udp_relay_test SOURCES dns_udp_relay_test.cpp)
openppp2_add_cpp_test(dns_host_ports_test SOURCES dns_host_ports_test.cpp)
openppp2_add_cpp_test(dns_host_interface_test SOURCES dns_host_interface_test.cpp)
openppp2_add_cpp_test(route_host_ports_test SOURCES
    route_host_ports_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteHost.cpp")
openppp2_add_cpp_test(route_host_interface_test SOURCES route_host_interface_test.cpp)
openppp2_add_cpp_test(route_state_test SOURCES
    route_state_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteState.cpp")
openppp2_add_cpp_test(route_coordinator_test SOURCES
    route_coordinator_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteState.cpp")
openppp2_add_cpp_test(linux_route_platform_contract_test SOURCES
    linux_route_platform_contract_test.cpp
    support/linux_route_platform_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/LinuxRoutePlatform.cpp")
openppp2_add_cpp_test(route_platform_adapters_test SOURCES
    route_platform_adapters_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/DarwinRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/MobileRoutePlatform.cpp")
openppp2_add_cpp_test(dns_host_wiring_test SOURCES
    dns_host_wiring_test.cpp
    ${OPENPPP2_AGGREGATOR_LOADER_TEST_SUPPORT}
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsHost.cpp")
target_include_directories(dns_host_wiring_test BEFORE PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/support/fake_aggligator")
add_test(
    NAME client_packet_dispatch_compile_test
    COMMAND bash "${OPENPPP2_ROOT}/tools/check_dispatch_handler_compiles.sh"
        "${CMAKE_CURRENT_BINARY_DIR}/client_packet_dispatch_compile.o")
openppp2_add_cpp_test(aggregator_loader_test SOURCES
    aggregator_loader_test.cpp
    ${OPENPPP2_AGGREGATOR_LOADER_TEST_SUPPORT})
target_include_directories(aggregator_loader_test BEFORE PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/support/fake_aggligator")
openppp2_add_cpp_test(peer_prefix_route_entry_test SOURCES
    peer_prefix_route_entry_test.cpp
    support/peer_prefix_route_test_stubs.cpp)
openppp2_add_cpp_test(peer_prefix_route_from_json_test SOURCES
    peer_prefix_route_from_json_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
openppp2_add_cpp_test(switcher_timeout_registry_test SOURCES
    switcher_timeout_registry_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/SwitcherTimeoutRegistry.cpp")
openppp2_add_cpp_test(fake_ip_pool_test SOURCES
    fake_ip_pool_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/FakeIpPool.cpp")
openppp2_add_cpp_test(dns_fake_ip_response_test SOURCES
    dns_fake_ip_response_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsFakeIpResponse.cpp")
openppp2_add_cpp_test(quic_reject_rate_limit_test SOURCES
    quic_reject_rate_limit_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/QuicRejectRateLimiter.cpp")
openppp2_add_cpp_test(client_bypass_route_loader_test SOURCES
    client_bypass_route_loader_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp")
openppp2_add_cpp_test(exchanger_static_echo_channel_test SOURCES
    exchanger_static_echo_channel_test.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp")
openppp2_add_cpp_test(route_table_manager_test SOURCES route_table_manager_test.cpp)
openppp2_add_cpp_test(client_datagram_port_manager_test SOURCES
    client_datagram_port_manager_test.cpp
    support/datagram_manager_stubs.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/udp/ClientDatagramPortManager.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/udp/UdpRelayHost.cpp")
openppp2_add_cpp_test(server_datagram_port_manager_test SOURCES
    server_datagram_port_manager_test.cpp
    support/server_datagram_manager_stubs.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/udp/ServerDatagramPortManager.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/udp/ServerUdpRelayHost.cpp")
openppp2_add_cpp_test(static_datagram_port_manager_test SOURCES
    static_datagram_port_manager_test.cpp
    support/static_datagram_manager_stubs.cpp
    support/ppp_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/udp/StaticDatagramPortManager.cpp"
    "${OPENPPP2_ROOT}/ppp/app/server/udp/StaticUdpRelayHost.cpp")
