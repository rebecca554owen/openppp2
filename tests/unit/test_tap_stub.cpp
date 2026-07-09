#include <gtest/gtest.h>

#include <ppp/tap/TapStub.h>

namespace {

TEST(TapStub, CreateRequiresContext) {
    auto stub = ppp::tap::TapStub::Create(nullptr);
    EXPECT_EQ(nullptr, stub);
}

TEST(TapStub, OpenAndOutputNoop) {
    auto context = ppp::make_shared_object<boost::asio::io_context>();
    auto stub = ppp::tap::TapStub::Create(context);
    ASSERT_NE(nullptr, stub);

    EXPECT_TRUE(stub->IsReady());
    EXPECT_FALSE(stub->IsOpen());

    EXPECT_TRUE(stub->Open());
    EXPECT_TRUE(stub->IsOpen());
    EXPECT_TRUE(stub->SetInterfaceMtu(1400));

    uint8_t packet[64] = {};
    EXPECT_TRUE(stub->Output(packet, static_cast<int>(sizeof(packet))));
    EXPECT_TRUE(stub->Output(ppp::make_shared_object<ppp::Byte>(64), 64));
}

} // namespace
