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
#include "../../../chip/hdi_service/wifi_chip.h"
#include "../../../chip/hdi_service/wifi_chip_modes.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiChipModesTest {
class WifiChipModesTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn;
        InitWifiHalFuncTable(&fn);
        wifiVendorHalTest = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
        wifiChipModes = std::make_shared<WifiChipModes>(wifiVendorHalTest);
    }
    void TearDown()
    {
        wifiVendorHalTest.reset();
        wifiChipModes.reset();
        ifaceTool.reset();
    }

public:
    std::shared_ptr<WifiVendorHal> wifiVendorHalTest;
    std::shared_ptr<WifiChipModes> wifiChipModes;
    std::shared_ptr<IfaceTool> ifaceTool;
};

/**
 * @tc.name: GetChipModesTest
 * @tc.desc: GetChipModes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiChipModesTest, GetChipModesTest, TestSize.Level1)
{
    HDF_LOGI("GetChipModesTest started.");
    if (wifiChipModes == nullptr) {
        return;
    }
    std::vector<UsableMode> modes;
    modes = wifiChipModes->GetChipModes(true);
    EXPECT_TRUE(modes.size() != 0);
}
}