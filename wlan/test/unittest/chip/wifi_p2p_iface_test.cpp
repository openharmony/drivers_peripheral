/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <hdf_log.h>
#include "../../../chip/hdi_service/wifi_p2p_iface.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiP2pIfaceTest {
class WifiP2pIfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        std::string ifname = "p2p";
        std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn;
        std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
        p2pIface = new (std::nothrow) WifiP2pIface(ifname, vendorHal);
        if (p2pIface == nullptr) {
            return;
        }
    }
    void TearDown()
    {
        delete p2pIface;
        if (p2pIface != nullptr) {
            p2pIface = nullptr;
        }
    }

public:
    sptr<WifiP2pIface> p2pIface;
};

/**
 * @tc.name: WifiP2pIfaceTest
 * @tc.desc: WifiP2pIface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiP2pIfaceTest, WifiP2pIfaceTest, TestSize.Level1)
{
    HDF_LOGI("WifiP2pIfaceTest start");
    if (p2pIface == nullptr) {
        return;
    }
    p2pIface->Invalidate();
    EXPECT_FALSE(p2pIface->IsValid());
    EXPECT_TRUE(p2pIface->GetName() == "p2p");
    IfaceType type = IfaceType::STA;
    EXPECT_TRUE(p2pIface->GetIfaceType(type) == HDF_SUCCESS);
    EXPECT_TRUE(type == IfaceType::P2P);
    std::string name = "test";
    EXPECT_TRUE(p2pIface->GetIfaceName(name) == HDF_SUCCESS);
    EXPECT_TRUE(name == "p2p");
    std::vector<uint32_t> frequencies;
    BandType band = BandType::TYPE_5GHZ;
    EXPECT_TRUE(p2pIface->GetSupportFreqs(band, frequencies) == HDF_SUCCESS);
}
}