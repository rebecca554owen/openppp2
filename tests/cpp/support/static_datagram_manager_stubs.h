#pragma once

/**
 * @file static_datagram_manager_stubs.h
 * @brief Spy surface shared by static_datagram_manager_stubs.cpp and the manager unit test (P2-f).
 */

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {
                namespace test {

                    /** @brief Records VirtualEthernetDatagramPortStatic method invocations for assertions. */
                    struct StaticDatagramPortSpy final {
                        int construct = 0;
                        int destruct = 0;
                        int dispose = 0;
                        int open = 0;
                        int sendto = 0;

                        void Reset() noexcept;
                    };

                    /** @brief Process-wide spy instance backing the stubbed static port. */
                    StaticDatagramPortSpy& StaticDatagramPortSpyInstance() noexcept;

                }
            }
        }
    }
}
