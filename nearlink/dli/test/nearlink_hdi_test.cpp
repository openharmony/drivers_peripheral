/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <gtest/gtest.h>
#include <hdf_log.h>
#include <vector>
#include "v1_1/isle_hci_interface.h"
#include "v1_0/isle_hci_callback.h"

using namespace testing::ext;

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Hci {
namespace V1_1 {

sptr<ISleHciInterface> nearlinkDliInterface = nullptr;

class NearlinkDliHdiTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};


class NearlinkDliCallbacksForTest : public ISleHciCallback {
public:
    NearlinkDliCallbacksForTest()
    {}
    ~NearlinkDliCallbacksForTest()
    {}

    int32_t initializationComplete(SleStatus status)
    {
        GTEST_LOG_(INFO) << "NeearlinkDliCallbacksForTest::initializationComplete called";
        return 0;
    }

    int32_t hciPacketReceived(uint32_t type, const std::vector<uint8_t> &data)
    {
        GTEST_LOG_(INFO) << "NeearlinkDliCallbacksForTest::hciPacketReceived called";
        return 0;
    }
};

void NearlinkDliHdiTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
    nearlinkDliInterface = OHOS::HDI::Nearlink::Hci::V1_1::ISleHciInterface::Get(true);
    if (nearlinkDliInterface == nullptr) {
        HDF_LOGE("nearlinkDliHdiTest nearlinkDliInterface is nullptr\n");
    }
}

void NearlinkDliHdiTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void NearlinkDliHdiTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void NearlinkDliHdiTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 * @tc.name: HDI_nearlinkDliInterface_001_SleHalInitTest
 * @tc.desc: Test nearlinkDliInterface SleHalInit.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkDliHdiTest, HDI_nearlinkDliInterface_001_SleHalInitTest, TestSize.Level1)
{
    sptr<NearlinkDliCallbacksForTest> callback_ = new NearlinkDliCallbacksForTest();
    int ret = nearlinkDliInterface->SleHalInit(callback_);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: HDI_nearlinkDliInterface_002_SleSendHciPacketTest
 * @tc.desc: Test nearlinkDliInterface SleSendHciPacket.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkDliHdiTest, HDI_nearlinkDliInterface_002_SleSendHciPacketTest, TestSize.Level1)
{
    sptr<NearlinkDliCallbacksForTest> callback_ = new NearlinkDliCallbacksForTest();
    int ret = nearlinkDliInterface->SleHalInit(callback_);
    EXPECT_EQ(-1, ret);
    std::vector<uint8_t> sleHciTestData = {0xA1, 0x07, 0x10, 0x02, 0x00, 0x00, 0x00};
    ret = nearlinkDliInterface->SleSendHciPacket(sleHciTestData);
    EXPECT_EQ(-1, ret);
}

/**
 * @tc.name: HDI_nearlinkDliInterface_003_SleCloseTest
 * @tc.desc: Test nearlinkDliInterface SleClose.
 * @tc.type: FUNC
 */
HWTEST_F(NearlinkDliHdiTest, HDI_nearlinkDliInterface_003_SleCloseTest, TestSize.Level1)
{
    sptr<NearlinkDliCallbacksForTest> callback_ = new NearlinkDliCallbacksForTest();
    int ret = nearlinkDliInterface->SleHalInit(callback_);
    EXPECT_EQ(-1, ret);
    ret = nearlinkDliInterface->Close();
    EXPECT_EQ(0, ret);
}

} // V1_1
} // Hci
} // Nearlink
} // HDI
} // OHOS
