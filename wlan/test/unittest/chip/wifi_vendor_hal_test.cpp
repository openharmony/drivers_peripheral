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
#include "../../../chip/hdi_service/wifi_vendor_hal.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiVendorHalTest {
class WifiVendorHalTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
        const WifiHalFn fn = {};
        wifiVendorHalTest = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
    }
    void TearDown()
    {
        wifiVendorHalTest.reset();
    }

    static void OnSubsystemRestartCallbackMock(const std::string& test)
    {
        HDF_LOGI("OnSubsystemRestartCallbackMock enter");
    }

    static void OnStopCompleteCallbackMock(const std::string& test)
    {
        HDF_LOGI("OnStopCompleteCallbackMock enter");
    }
public:
    std::shared_ptr<WifiVendorHal> wifiVendorHalTest;
};

/**
 * @tc.name: StartTest
 * @tc.desc: Start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiVendorHalTest, StartTest, TestSize.Level1)
{
    HDF_LOGI("StartTest started");
    if (wifiVendorHalTest == nullptr) {
        HDF_LOGE("wifiVendorHalTest is null");
        return;
    }
    EXPECT_TRUE(wifiVendorHalTest->Start() != HAL_SUCCESS);
    wifiVendorHalTest->Start();
}
}