#pragma once

/**
 * @file server_datagram_manager_stubs.h
 * @brief Spy surface shared by server_datagram_manager_stubs.cpp and the manager unit test (P2-e).
 */

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {
                namespace test {

                    /** @brief Records VirtualEthernetDatagramPort method invocations for assertions. */
                    struct ServerDatagramPortSpy final {
                        int construct = 0;
                        int destruct = 0;
                        int dispose = 0;
                        int open = 0;
                        int sendto = 0;

                        void Reset() noexcept;
                    };

                    /** @brief Process-wide spy instance backing the stubbed port. */
                    ServerDatagramPortSpy& ServerDatagramPortSpyInstance() noexcept;

                }
            }
        }
    }
}
