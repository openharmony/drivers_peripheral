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

public:
    std::shared_ptr<Wifi> wifiTest;
};

/**
 * @tc.name: IsInitTest
 * @tc.desc: IsInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiTest, IsInitTest, TestSize.Level1)
{
    HDF_LOGI("IsInitTest started");
    if (wifiTest == nullptr) {
        HDF_LOGE("wifiTest is null");
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
    HDF_LOGI("GetAvailableChipsTest started");
    if (wifiTest == nullptr) {
        HDF_LOGE("wifiTest is null");
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
    HDF_LOGI("ReleaseTest started");
    if (wifiTest == nullptr) {
        HDF_LOGE("wifiTest is null");
        return;
    }
    EXPECT_TRUE(wifiTest->Release() == HDF_SUCCESS);
}
}