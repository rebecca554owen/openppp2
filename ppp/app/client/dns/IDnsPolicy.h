#pragma once

namespace ppp::app::client::dns {

class IDnsPolicy {
public:
    virtual ~IDnsPolicy() noexcept = default;
    virtual void Close() noexcept = 0;
};

}
