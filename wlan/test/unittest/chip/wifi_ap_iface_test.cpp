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
#include "../../../chip/hdi_service/wifi_ap_iface.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiApIfaceTest {
class WifiApIfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        std::string ifname = "ap";
        std::vector<std::string> instances;
        std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn;
        std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
        apIface = new (std::nothrow) WifiApIface(ifname, instances, vendorHal);
        if (apIface == nullptr) {
            return;
        }
    }
    void TearDown()
    {
        delete apIface;
        if (apIface != nullptr) {
            apIface = nullptr;
        }
    }

public:
    sptr<WifiApIface> apIface;
};

/**
 * @tc.name: wifiApIfaceTest
 * @tc.desc: wifiApIface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiApIfaceTest, wifiApIfaceTest001, TestSize.Level1)
{
    HDF_LOGI("wifiApIfaceTest001 start");
    if (apIface == nullptr) {
        return;
    }
    apIface->Invalidate();
    EXPECT_FALSE(apIface->IsValid());
    EXPECT_TRUE(apIface->GetName() == "ap");
    apIface->RemoveInstance("ap");
    IfaceType type = IfaceType::STA;
    EXPECT_TRUE(apIface->GetIfaceType(type) == HDF_SUCCESS);
    EXPECT_TRUE(type == IfaceType::AP);
    std::string name = "test";
    EXPECT_TRUE(apIface->GetIfaceName(name) == HDF_SUCCESS);
    EXPECT_TRUE(name == "ap");
}

/**
 * @tc.name: GetSupportFreqsTest
 * @tc.desc: GetSupportFreqs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiApIfaceTest, GetSupportFreqsTest, TestSize.Level1)
{
    HDF_LOGI("GetSupportFreqsTest start");
    if (apIface == nullptr) {
        return;
    }
    BandType band = BandType::TYPE_5GHZ;
    std::vector<uint32_t>frequencies;
    EXPECT_TRUE(apIface->GetSupportFreqs(band, frequencies) == HDF_SUCCESS);
    band = BandType::UNSPECIFIED;
    EXPECT_TRUE(apIface->GetSupportFreqs(band, frequencies) == HDF_FAILURE);
}
}