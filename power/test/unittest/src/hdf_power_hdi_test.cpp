/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>
#include <securec.h>

#include "v1_2/ipower_interface.h"
#include "v1_2/power_types.h"
#include "v1_2/running_lock_types.h"

using namespace OHOS::HDI;
using namespace OHOS::HDI::Power::V1_2;
using namespace testing::ext;

namespace {
sptr<IPowerInterface> g_powerInterface = nullptr;
std::mutex g_mutex;
const uint32_t MAX_PATH = 256;
const uint32_t WAIT_TIME = 1;
const std::string SUSPEND_STATE = "mem";
const std::string SUSPEND_STATE_PATH = "/sys/power/state";
const std::string LOCK_PATH = "/sys/power/wake_lock";
const std::string UNLOCK_PATH = "/sys/power/wake_unlock";
class HdfPowerHdiTest : public testing::Test {
public:
    static void SetUpTestCase();
    std::string ReadFile(const std::string& file);
};

void HdfPowerHdiTest::SetUpTestCase()
{
    g_powerInterface = IPowerInterface::Get(true);
}

std::string HdfPowerHdiTest::ReadFile(const std::string& file)
{
    std::ifstream ifs;
    ifs.open(file);
    if (!ifs.is_open()) {
        return "";
    }
    std::string line;
    std::getline(ifs, line);

    ifs.close();
    return line;
}
}

namespace {
/**
  * @tc.name: HdfPowerHdiTest001
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: FUNC
  */
HWTEST_F(HdfPowerHdiTest, HdfPowerHdiTest001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_powerInterface);
}

/**
  * @tc.name: HdfPowerHdiTest002
  * @tc.desc: check startsuspend
  * @tc.type: FUNC
  */
HWTEST_F(HdfPowerHdiTest, HdfPowerHdiTest002, TestSize.Level1)
{
    int32_t ret = g_powerInterface->StartSuspend();
    EXPECT_EQ(0, ret);

    char stateBuf[MAX_PATH] = {0};
    std::string stateValue;

    ret = snprintf_s(stateBuf, MAX_PATH, sizeof(stateBuf) - 1, SUSPEND_STATE_PATH.c_str());
    EXPECT_FALSE(ret < EOK);
    sleep(WAIT_TIME);
    stateValue = HdfPowerHdiTest::ReadFile(stateBuf);
    std::string state = stateValue;
    auto it = state.find(SUSPEND_STATE);
    EXPECT_TRUE(it != std::string::npos);
}

/**
  * @tc.name: HdfPowerHdiTest003
  * @tc.desc: check StopSuspend
  * @tc.type: FUNC
  */
HWTEST_F(HdfPowerHdiTest, HdfPowerHdiTest003, TestSize.Level1)
{
    int32_t ret = g_powerInterface->StopSuspend();
    EXPECT_EQ(0, ret) << "HdfPowerHdiTest003 failed";
}

/**
  * @tc.name: HdfPowerHdiTest005
  * @tc.desc: check SuspendBlock
  * @tc.type: FUNC
  */
HWTEST_F(HdfPowerHdiTest, HdfPowerHdiTest005, TestSize.Level1)
{
    std::string testName = "HdfPowerHdiTest005";
    int32_t ret = g_powerInterface->SuspendBlock(testName);
    EXPECT_EQ(0, ret);

    char lockBuf[MAX_PATH] = {0};
    std::string lockValue;

    ret = snprintf_s(lockBuf, MAX_PATH, sizeof(lockBuf) - 1, LOCK_PATH.c_str());
    EXPECT_FALSE(ret < EOK);

    sleep(WAIT_TIME);
    lockValue = HdfPowerHdiTest::ReadFile(lockBuf);
    std::string lock = lockValue;
    auto it = lock.find(testName);
    EXPECT_TRUE(it != std::string::npos);
    g_powerInterface->SuspendUnblock(testName);
}

/**
  * @tc.name: HdfPowerHdiTest006
  * @tc.desc: check SuspendUnblock
  * @tc.type: FUNC
  */
HWTEST_F(HdfPowerHdiTest, HdfPowerHdiTest006, TestSize.Level1)
{
    std::string testName = "HdfPowerHdiTest006";
    g_powerInterface->SuspendBlock(testName);
    sleep(WAIT_TIME);
    int32_t ret = g_powerInterface->SuspendUnblock(testName);
    EXPECT_EQ(0, ret);

    char unLockBuf[MAX_PATH] = {0};
    std::string unLockValue;

    ret = snprintf_s(unLockBuf, MAX_PATH, sizeof(unLockBuf) - 1, UNLOCK_PATH.c_str());
    EXPECT_FALSE(ret < EOK);

    sleep(WAIT_TIME);
    unLockValue = HdfPowerHdiTest::ReadFile(unLockBuf);
    std::string unLock = unLockValue;
    auto it = unLock.find(testName);
    EXPECT_TRUE(it != std::string::npos);
}

/**
  * @tc.name: HdfPowerHdiTest007
  * @tc.desc: check GetWakeupReason
  * @tc.type: FUNC
  */
HWTEST_F(HdfPowerHdiTest, HdfPowerHdiTest007, TestSize.Level1)
{
    std::string testName = "HdfPowerHdiTest007";
    int32_t ret = g_powerInterface->GetWakeupReason(testName);
#ifdef DRIVER_PERIPHERAL_POWER_WAKEUP_CAUSE_PATH
    EXPECT_EQ(0, ret);
#else
    EXPECT_NE(0, ret);
#endif
}

/**
  * @tc.name: HdfPowerHdiTest008
  * @tc.desc: check GetWakeupReason
  * @tc.type: FUNC
  */
HWTEST_F(HdfPowerHdiTest, HdfPowerHdiTest008, TestSize.Level1)
{
    std::string testName = "HdfPowerHdiTest008";
    RunningLockInfo filledInfo;
    filledInfo.name = testName;
    filledInfo.type = RUNNINGLOCK_BUTT;
    filledInfo.uid = 0;
    filledInfo.pid = 0;
    int32_t ret = g_powerInterface->HoldRunningLockExt(filledInfo, 0, testName);
    EXPECT_NE(0, ret);
    ret = g_powerInterface->UnholdRunningLockExt(filledInfo, 0, testName);
    EXPECT_NE(0, ret);
}
}