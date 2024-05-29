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
#include "../../../chip/hdi_service/wifi_sta_iface.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiStaIfaceTest {
const std::string WLAN_IFNAME = "wlan0";

class WifiStaIfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        std::shared_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn;
        std::shared_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
        staIface = new (std::nothrow) WifiStaIface(WLAN_IFNAME, vendorHal,
            std::make_shared<IfaceUtil>(ifaceTool));
    }
    void TearDown()
    {
        delete staIface;
        if (staIface != nullptr) {
            staIface = nullptr;
        }
    }

public:
    sptr<WifiStaIface> staIface;
};

/**
 * @tc.name: WifiStaIfaceTest001
 * @tc.desc: wifiStaIface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiStaIfaceTest, WifiStaIfaceTest001, TestSize.Level1)
{
    HDF_LOGI("WifiStaIfaceTest001 started");
    if (staIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    staIface->Invalidate();
    EXPECT_FALSE(staIface->IsValid());
    staIface->IsValid();
    EXPECT_TRUE(staIface->GetName() == WLAN_IFNAME);
    IfaceType type = IfaceType::AP;
    EXPECT_TRUE(staIface->GetIfaceType(type) == HDF_SUCCESS);
    EXPECT_TRUE(type == IfaceType::STA);
    std::string name;
    EXPECT_TRUE(staIface->GetIfaceName(name) == HDF_SUCCESS);
    EXPECT_TRUE(name == WLAN_IFNAME);
}
}