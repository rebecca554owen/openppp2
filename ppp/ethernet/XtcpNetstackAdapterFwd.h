/**
 * @file XtcpNetstackAdapterFwd.h
 * @brief Forward declaration of XtcpNetstackAdapter for VEthernet.h.
 */

#pragma once

#include <memory>

namespace ppp {
    namespace ethernet {
        class XtcpNetstackAdapter;
    }
}

namespace ppp {
    namespace ethernet {
        using XtcpNetstackAdapterPtr = std::shared_ptr<XtcpNetstackAdapter>;
    }
}
