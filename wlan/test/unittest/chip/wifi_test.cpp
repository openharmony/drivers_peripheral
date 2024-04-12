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
#include "v1_0/chip/hdi_service/chip_controller_service.h"
#include "../../../chip/hdi_service/wifi.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiTest {
class WifiTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        wifiTest = std::make_shared<Wifi>();
    }
    void TearDown()
    {
        wifiTest.reset();
    }

    static void handlerMock(const std::string& ifName)
    {
        HDF_LOGI("handlerMock enter");
    }
public:
    std::shared_ptr<Wifi> wifiTest;
};

/**
 * @tc.name: RegisterWifiEventCallbackTest
 * @tc.desc: RegisterWifiEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiTest, RegisterWifiEventCallbackTest, TestSize.Level1)
{
    HDF_LOGI("RegisterWifiEventCallbackTest start");
    if (wifiTest == nullptr) {
        return;
    }
    EXPECT_TRUE(wifiTest->RegisterWifiEventCallback(nullptr) == HDF_FAILURE);
}

/**
 * @tc.name: IsInitTest
 * @tc.desc: IsInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiTest, IsInitTest, TestSize.Level1)
{
    HDF_LOGI("IsInitTest start");
    if (wifiTest == nullptr) {
        return;
    }
    bool inited = true;
    wifiTest->IsInit(inited);
    EXPECT_FALSE(inited);
    wifiTest->Init();
    wifiTest->IsInit(inited);
    EXPECT_TRUE(inited);
}

/**
 * @tc.name: GetAvailableChipsTest
 * @tc.desc: GetAvailableChips
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiTest, GetAvailableChipsTest, TestSize.Level1)
{
    HDF_LOGI("GetAvailableChipsTest start");
    if (wifiTest == nullptr) {
        return;
    }
    std::vector<uint32_t> chipIds;
    EXPECT_TRUE(wifiTest->GetAvailableChips(chipIds) == HDF_SUCCESS);
}

/**
 * @tc.name: IsInitTest
 * @tc.desc: IsInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiTest, ReleaseTest, TestSize.Level1)
{
    HDF_LOGI("ReleaseTest start");
    if (wifiTest == nullptr) {
        return;
    }
    EXPECT_TRUE(wifiTest->Release() == HDF_SUCCESS);
}
}