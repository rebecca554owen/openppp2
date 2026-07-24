cmake_minimum_required(VERSION 3.16)
project(openppp2_cpp_tests LANGUAGES CXX)

option(ENABLE_COVERAGE "Enable LLVM coverage instrumentation" OFF)
option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer (cannot be combined with ENABLE_SANITIZERS)" OFF)

get_filename_component(OPENPPP2_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

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
    if(ENABLE_SANITIZERS AND ENABLE_TSAN)
        message(FATAL_ERROR "ENABLE_SANITIZERS (ASan/UBSan) and ENABLE_TSAN cannot be combined")
    endif()
    if(ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${target} PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
    if(ENABLE_TSAN AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${target} PRIVATE
            -fsanitize=thread
            -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=thread)
    endif()
    if(target STREQUAL "runtime_snapshot_test" OR target STREQUAL "runtime_stats_json_test" OR target STREQUAL "p2p_replay_window_test" OR target STREQUAL "base64_test" OR target STREQUAL "dns_server_validation_test" OR target STREQUAL "dns_wire_validation_test" OR target STREQUAL "sysctl_validation_test" OR target STREQUAL "dns_redirect_plan_test" OR target STREQUAL "dns_reachability_test" OR target STREQUAL "dns_response_handler_test" OR target STREQUAL "dns_route_dispatcher_test" OR target STREQUAL "dns_udp_relay_test" OR target STREQUAL "dns_host_ports_test" OR target STREQUAL "dns_host_interface_test" OR target STREQUAL "dns_host_wiring_test" OR target STREQUAL "dns_session_context_test" OR target STREQUAL "dns_controller_test" OR target STREQUAL "route_host_ports_test" OR target STREQUAL "route_host_interface_test" OR target STREQUAL "route_state_test" OR target STREQUAL "route_coordinator_test" OR target STREQUAL "linux_route_platform_contract_test" OR target STREQUAL "route_platform_adapters_test" OR target STREQUAL "aggregator_loader_test" OR target STREQUAL "fake_ip_pool_test" OR target STREQUAL "dns_fake_ip_response_test" OR target STREQUAL "quic_reject_rate_limit_test" OR target STREQUAL "client_bypass_route_loader_test" OR target STREQUAL "exchanger_static_echo_channel_test" OR target STREQUAL "switcher_timeout_registry_test" OR target STREQUAL "peer_prefix_route_entry_test" OR target STREQUAL "peer_prefix_route_from_json_test" OR target STREQUAL "client_datagram_port_manager_test" OR target STREQUAL "server_datagram_port_manager_test" OR target STREQUAL "static_datagram_port_manager_test" OR target STREQUAL "peer_route_announce_policy_test" OR target STREQUAL "tcp_mss_clamp_test" OR target STREQUAL "icmp_path_mtu_test")
        target_link_libraries(${target} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    add_test(NAME ${target} COMMAND ${target})
    # Watchdog: coroutine/lifecycle deadlocks must fail the test instead of
    # hanging CI forever.
    set_tests_properties(${target} PROPERTIES TIMEOUT 120)
endfunction()

openppp2_add_cpp_test(runtime_snapshot_test SOURCES
    runtime_snapshot_test.cpp
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_compile_definitions(runtime_snapshot_test PRIVATE
    OPENPPP2_RUNTIME_FIXTURE_DIR=\"${OPENPPP2_ROOT}/tests/contracts/runtime-snapshot\")
openppp2_add_cpp_test(runtime_stats_json_test SOURCES
    runtime_stats_json_test.cpp
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
openppp2_add_cpp_test(runtime_stop_coordinator_test SOURCES
    runtime_stop_coordinator_test.cpp)
openppp2_add_cpp_test(runtime_stop_pipeline_test SOURCES
    runtime_stop_pipeline_test.cpp)
openppp2_add_cpp_test(client_lifecycle_stress_test SOURCES
    client_lifecycle_stress_test.cpp)
openppp2_add_cpp_test(client_keepalive_policy_test SOURCES
    client_keepalive_policy_test.cpp)
openppp2_add_cpp_test(client_reconnection_policy_test SOURCES
    client_reconnection_policy_test.cpp)
openppp2_add_cpp_test(session_recovery_state_test SOURCES
    session_recovery_state_test.cpp)
openppp2_add_cpp_test(session_resume_fallback_decision_test SOURCES
    session_resume_fallback_decision_test.cpp)
openppp2_add_cpp_test(session_resume_information_test SOURCES
    session_resume_information_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_link_libraries(session_resume_information_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_handshake_state_test SOURCES
    session_resume_handshake_state_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_link_libraries(session_resume_handshake_state_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_authenticator_test SOURCES
    session_resume_authenticator_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp")
target_link_libraries(session_resume_authenticator_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_wss_fault_injection_test SOURCES
    session_resume_wss_fault_injection_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/TlsSessionExporter.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_compile_definitions(session_resume_wss_fault_injection_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(session_resume_wss_fault_injection_test PRIVATE
    Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_production_wss_lifecycle_test SOURCES
    session_resume_production_wss_lifecycle_test.cpp
    support/session_resume_production_wss_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmission.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmissionQoS.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/IWebsocketTransmission.cpp"
    "${OPENPPP2_ROOT}/ppp/Random.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/ssea.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Socket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/IPEndPoint.cpp"
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/SSL.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/IAsynchronousWriteIoQueue.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_accept_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_read_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_write_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_close_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_read_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_write_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_close_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket_perform_ssl_handshake.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket_perform_websocket_handshake.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_accept_sslv_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/TlsSessionExporter.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_compile_definitions(session_resume_production_wss_lifecycle_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(session_resume_production_wss_lifecycle_test PRIVATE
    boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(session_resume_establish_transaction_wss_test SOURCES
    session_resume_establish_transaction_wss_test.cpp
    support/session_resume_production_wss_test_stubs.cpp
    support/session_resume_information_test_stubs.cpp
    support/peer_prefix_route_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/server/SessionResumeEstablishTransaction.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/app/protocol/SessionResumeAuthenticator.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmission.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmissionQoS.cpp"
    "${OPENPPP2_ROOT}/ppp/transmissions/IWebsocketTransmission.cpp"
    "${OPENPPP2_ROOT}/ppp/Random.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/ssea.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp"
    "${OPENPPP2_ROOT}/ppp/net/Socket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/IPEndPoint.cpp"
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/SSL.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/IAsynchronousWriteIoQueue.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_accept_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_read_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_write_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_close_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_read_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_write_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_ssl_close_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket_perform_ssl_handshake.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_async_sslv_websocket_perform_websocket_handshake.cpp"
    "${OPENPPP2_ROOT}/ppp/net/asio/websocket/websocket_accept_sslv_websocket.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/ssl/TlsSessionExporter.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_compile_definitions(session_resume_establish_transaction_wss_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(session_resume_establish_transaction_wss_test PRIVATE
    boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(runtime_snapshot_publisher_test SOURCES
    runtime_snapshot_publisher_test.cpp)
openppp2_add_cpp_test(vmux_runtime_state_test SOURCES
    vmux_runtime_state_test.cpp)
openppp2_add_cpp_test(vmux_negotiation_test SOURCES
    vmux_negotiation_test.cpp)
openppp2_add_cpp_test(vmux_reliability_negotiation_test SOURCES
    vmux_reliability_negotiation_test.cpp)
openppp2_add_cpp_test(vmux_ack_tracker_test SOURCES
    vmux_ack_tracker_test.cpp)
openppp2_add_cpp_test(vmux_retransmit_buffer_test SOURCES
    vmux_retransmit_buffer_test.cpp)
openppp2_add_cpp_test(vmux_fec_codec_test SOURCES
    vmux_fec_codec_test.cpp)
openppp2_add_cpp_test(vmux_flow_reorder_test SOURCES
    vmux_flow_reorder_test.cpp)
openppp2_add_cpp_test(vmux_flow_context_admission_test SOURCES
    vmux_flow_context_admission_test.cpp)
openppp2_add_cpp_test(peer_route_announce_policy_test SOURCES
    peer_route_announce_policy_test.cpp)
openppp2_add_cpp_test(vmux_link_churn_test SOURCES
    vmux_link_churn_test.cpp)
openppp2_add_cpp_test(mux_transport_adapter_test SOURCES
    mux_transport_adapter_test.cpp)
target_link_libraries(mux_transport_adapter_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(runtime_readiness_test SOURCES
    runtime_readiness_test.cpp)
openppp2_add_cpp_test(runtime_lifecycle_test SOURCES
    runtime_lifecycle_test.cpp)
openppp2_add_cpp_test(tui_runtime_adapter_test SOURCES
    tui_runtime_adapter_test.cpp)
openppp2_add_cpp_test(p2p_replay_window_test SOURCES p2p_replay_window_test.cpp)
openppp2_add_cpp_test(p2p_control_packet_test SOURCES p2p_control_packet_test.cpp)
openppp2_add_cpp_test(p2p_key_derivation_test SOURCES
    p2p_key_derivation_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PKeyDerivation.cpp")
target_link_libraries(p2p_key_derivation_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_relay_offer_test SOURCES
    p2p_relay_offer_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp")
target_link_libraries(p2p_relay_offer_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_relay_offer_coordinator_test SOURCES
    p2p_relay_offer_coordinator_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/P2PCandidateAdapter.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp")
target_link_libraries(p2p_relay_offer_coordinator_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_relay_offer_consumer_test SOURCES
    p2p_relay_offer_consumer_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferConsumer.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp")
target_link_libraries(p2p_relay_offer_consumer_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_client_offer_session_test SOURCES
    p2p_client_offer_session_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PClientOfferSession.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PControlDatagram.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDataDatagram.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDirectActivationCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDirectDataPath.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferConsumer.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOfferCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PRelayOffer.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PKeyDerivation.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2POfferToken.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PCrypto.cpp")
target_link_libraries(p2p_client_offer_session_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_information_message_test SOURCES
    p2p_information_message_test.cpp
    support/peer_prefix_route_test_stubs.cpp
    support/peer_prefix_json_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/protocol/VirtualEthernetInformation.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/JsonAuxiliary.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_reader.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_value.cpp"
    "${OPENPPP2_ROOT}/common/json/src/json_writer.cpp")
target_link_libraries(p2p_information_message_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_offer_token_test SOURCES
    p2p_offer_token_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDirectActivationCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2POfferToken.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PCrypto.cpp")
target_link_libraries(p2p_offer_token_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_control_state_machine_test SOURCES
    p2p_control_state_machine_test.cpp)
openppp2_add_cpp_test(p2p_data_datagram_test SOURCES
    p2p_data_datagram_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDataDatagram.cpp")
target_link_libraries(p2p_data_datagram_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_channel_lifecycle_test SOURCES
    p2p_channel_lifecycle_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PChannel.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PDatagramTransport.cpp"
    "${OPENPPP2_ROOT}/ppp/p2p/P2PCrypto.cpp")
target_link_libraries(p2p_channel_lifecycle_test PRIVATE OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_datagram_transport_test SOURCES
    p2p_datagram_transport_test.cpp)
openppp2_add_cpp_test(ios_p2p_datagram_transport_test SOURCES
    ios_p2p_datagram_transport_test.cpp
    "${OPENPPP2_ROOT}/ios/IosP2PDatagramTransport.cpp")
openppp2_add_cpp_test(p2p_nat_classifier_test SOURCES
    p2p_nat_classifier_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PNatClassifier.cpp")
target_link_libraries(p2p_nat_classifier_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_capability_gate_test SOURCES
    p2p_capability_gate_test.cpp)
target_link_libraries(p2p_capability_gate_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_zero_rtt_cache_test SOURCES
    p2p_zero_rtt_cache_test.cpp)
target_link_libraries(p2p_zero_rtt_cache_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_stun_client_test SOURCES
    p2p_stun_client_test.cpp
    "${OPENPPP2_ROOT}/ppp/p2p/P2PStunClient.cpp")
target_link_libraries(p2p_stun_client_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(p2p_coalesce_frames_test SOURCES
    p2p_coalesce_frames_test.cpp)
target_link_libraries(p2p_coalesce_frames_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(tls_session_exporter_test SOURCES
    tls_session_exporter_test.cpp
    "${OPENPPP2_ROOT}/ppp/ssl/TlsSessionExporter.cpp")
target_compile_definitions(tls_session_exporter_test PRIVATE
    OPENPPP2_TEST_CERTIFICATE="${OPENPPP2_ROOT}/starrylink.net.pem"
    OPENPPP2_TEST_PRIVATE_KEY="${OPENPPP2_ROOT}/starrylink.net.key")
target_link_libraries(tls_session_exporter_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
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
openppp2_add_cpp_test(dns_udp_flow_registry_test SOURCES
    dns_udp_flow_registry_test.cpp
    "${OPENPPP2_ROOT}/ppp/dns/DnsUdpFlowRegistry.cpp")
target_link_libraries(dns_udp_flow_registry_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(dns_response_handler_test SOURCES
    dns_response_handler_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsResponseHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
openppp2_add_cpp_test(dns_route_dispatcher_test SOURCES
    dns_route_dispatcher_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsRouteDispatcher.cpp")
openppp2_add_cpp_test(dns_udp_relay_test SOURCES
    dns_udp_relay_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsSessionContext.cpp")
openppp2_add_cpp_test(dns_session_context_test SOURCES
    dns_session_context_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsSessionContext.cpp")
openppp2_add_cpp_test(dns_controller_test SOURCES
    dns_controller_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsController.cpp"
    "${OPENPPP2_ROOT}/ppp/dns/DnsUdpFlowRegistry.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsSessionContext.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/dns/DnsResponseHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(dns_controller_test PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(route_state_test SOURCES
    route_state_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteState.cpp")
openppp2_add_cpp_test(client_connection_teardown_state_test SOURCES
    client_connection_teardown_state_test.cpp)
openppp2_add_cpp_test(route_coordinator_test SOURCES
    route_coordinator_test.cpp
    support/ppp_test_stubs.cpp
    support/route_coordinator_platform_stub.cpp
    "${OPENPPP2_ROOT}/ppp/hash/hash_bytes.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteCoordinator.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteCoordinator_mobile.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/MobileRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteSpecs.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteState.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_compile_definitions(route_coordinator_test PRIVATE
    OPENPPP2_ROUTE_TEST_MOBILE)
openppp2_add_cpp_test(linux_route_platform_contract_test SOURCES
    linux_route_platform_contract_test.cpp
    support/linux_route_platform_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/LinuxRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/RouteSpecs.cpp")
openppp2_add_cpp_test(route_platform_adapters_test SOURCES
    route_platform_adapters_test.cpp
    "${OPENPPP2_ROOT}/ppp/app/client/route/WindowsRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/DarwinRoutePlatform.cpp"
    "${OPENPPP2_ROOT}/ppp/app/client/route/MobileRoutePlatform.cpp")
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
openppp2_add_cpp_test(tcp_mss_clamp_test SOURCES
    tcp_mss_clamp_test.cpp
    support/socket_default_ttl_stub.cpp
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
openppp2_add_cpp_test(icmp_path_mtu_test SOURCES
    icmp_path_mtu_test.cpp
    support/socket_default_ttl_stub.cpp
    "${OPENPPP2_ROOT}/ppp/net/native/checksum.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
openppp2_add_cpp_test(yield_context_test SOURCES
    yield_context_test.cpp
    support/yield_context_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(yield_context_test PRIVATE boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(spinlock_test SOURCES
    spinlock_test.cpp
    support/spinlock_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/threading/SpinLock.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(spinlock_test PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(asynchronous_write_io_queue_test SOURCES
    asynchronous_write_io_queue_test.cpp
    support/yield_context_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/net/asio/IAsynchronousWriteIoQueue.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(asynchronous_write_io_queue_test PRIVATE boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(protector_network_request_test SOURCES
    protector_network_request_test.cpp)
target_link_libraries(protector_network_request_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(transmission_qos_concurrency_test SOURCES
    transmission_qos_concurrency_test.cpp
    support/yield_context_test_stubs.cpp
    "${OPENPPP2_ROOT}/ppp/transmissions/ITransmissionQoS.cpp"
    "${OPENPPP2_ROOT}/ppp/coroutines/YieldContext.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Error.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/ErrorHandler.cpp"
    "${OPENPPP2_ROOT}/ppp/diagnostics/Telemetry.cpp")
target_link_libraries(transmission_qos_concurrency_test PRIVATE boost_context Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
openppp2_add_cpp_test(vdns_request_lifecycle_test SOURCES
    vdns_request_lifecycle_test.cpp)
target_link_libraries(vdns_request_lifecycle_test PRIVATE Threads::Threads)
openppp2_add_cpp_test(mapping_port_connect_reentrancy_test SOURCES
    mapping_port_connect_reentrancy_test.cpp)
target_link_libraries(mapping_port_connect_reentrancy_test PRIVATE Threads::Threads)
