#pragma once

/**
 * @file MappingConfiguration.h
 * @brief Static port mapping rule for FRP tunnel forwarding.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {

        /**
         * @brief Port mapping rule configuration.
         *
         * Describes one static port-forwarding entry that maps a local
         * service port to a remote port exposed through the virtual Ethernet
         * tunnel. Both TCP and UDP mappings are supported.
         */
        struct MappingConfiguration final {
            bool protocol_tcp_or_udp = false; ///< True selects TCP mapping; false selects UDP mapping.
            ppp::string local_ip;             ///< Local bind address for the forwarded service (empty = any).
            int local_port = 0;               ///< Local port of the service being forwarded.
            ppp::string remote_ip;            ///< Remote peer address to reach through the tunnel (may be empty).
            int remote_port = 0;              ///< Remote port exposed on the tunnel peer side.
        };

    }
}
