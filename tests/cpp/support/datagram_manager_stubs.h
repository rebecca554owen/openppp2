#pragma once

/**
 * @file datagram_manager_stubs.h
 * @brief Spy surface shared by datagram_manager_stubs.cpp and the manager unit test (P2-c).
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {
                namespace test {

                    /** @brief Records VEthernetDatagramPort method invocations for assertions. */
                    struct DatagramPortSpy final {
                        int construct = 0;
                        int destruct = 0;
                        int dispose = 0;
                        int sendto = 0;
                        int onmessage = 0;
                        int finalize = 0;

                        void Reset() noexcept;
                    };

                    /** @brief Process-wide spy instance backing the stubbed port. */
                    DatagramPortSpy& DatagramPortSpyInstance() noexcept;

                }
            }
        }
    }
}
