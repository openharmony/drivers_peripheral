/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hdf_base.h"
#include "mock_wakelock_name.h"
#include "running_lock_impl.h"

using namespace OHOS::HDI;
using namespace OHOS::HDI::Power::V1_2;
using namespace testing::ext;

namespace {
constexpr int32_t DEFAULT_TIMEOUT_FOR_TEST_MS = 100;
constexpr int32_t DEFAULT_RUNNINGLOCK_INVALID_TYPE = 100;
constexpr int32_t RUNNINGLOCK_TIMEOUT_NONE = -1;
constexpr int32_t RUNNINGLOCK_TIMEOUT_DEFAULT = 0;
constexpr int32_t RUNNINGLOCK_TIMEOUT_SET_BASE_MS = 50;
const std::string runnninglockNameLabel = "runninglock.test.";
constexpr int32_t US_PER_MS = 1000;
class HdfPowerRunningLockTest : public testing::Test {
public:
    static void SetUpTestCase();
};

void HdfPowerRunningLockTest::SetUpTestCase()
{
    RunningLockImpl::SetDefaultTimeOutMs(DEFAULT_TIMEOUT_FOR_TEST_MS);
}
}

namespace {
/**
  * @tc.name: HdfPowerRunningLockTest001
  * @tc.desc: test Hold, running lock name is null
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest001, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = "";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, RunningLockImpl::Hold(runinglockInfo, powerState));
}

/**
  * @tc.name: HdfPowerRunningLockTest002
  * @tc.desc: test Hold, running lock type is invalid
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest002, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = runnninglockNameLabel + "normal.2";
    runinglockInfo.type = static_cast<RunningLockType>(DEFAULT_RUNNINGLOCK_INVALID_TYPE);
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, RunningLockImpl::Hold(runinglockInfo, powerState));
}

/**
  * @tc.name: HdfPowerRunningLockTest003
  * @tc.desc: test Unhold, running lock name is null
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest003, TestSize.Level1)
{
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = "";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, RunningLockImpl::Unhold(runinglockInfo));
}

/**
  * @tc.name: HdfPowerRunningLockTest004
  * @tc.desc: test Unhold, running lock type is invalid
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest004, TestSize.Level1)
{
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = runnninglockNameLabel + "normal.4";
    runinglockInfo.type = static_cast<RunningLockType>(DEFAULT_RUNNINGLOCK_INVALID_TYPE);
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;

    EXPECT_EQ(HDF_ERR_INVALID_PARAM, RunningLockImpl::Unhold(runinglockInfo));
}

/**
  * @tc.name: HdfPowerRunningLockTest005
  * @tc.desc: test Hold and UnHold, running lock type is phone
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest005, TestSize.Level1)
{
    RunningLockType setLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    std::string setLockNameOne = runnninglockNameLabel + "phone.5";
    std::string setLockNameTwo = runnninglockNameLabel + "phone2.5";
    RunningLockType errorLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    std::string errorLockName = runnninglockNameLabel + "phone.error.5";

    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockNameOne;
    runinglockInfo.type = setLockType;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    // runninglock type and same & timeoutMs < 0, hold lock failed
    EXPECT_EQ(HDF_FAILURE, RunningLockImpl::Hold(runinglockInfo, powerState));

    runinglockInfo.name = setLockNameTwo;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    // unhold a non-existent lock, return success
    runinglockInfo.type = errorLockType;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    runinglockInfo.type = setLockType;
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = errorLockName;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));
    runinglockInfo.name = setLockNameTwo;

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = setLockNameOne;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
}

/**
  * @tc.name: HdfPowerRunningLockTest006
  * @tc.desc: test Hold and UnHold, running lock type is notification
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest006, TestSize.Level1)
{
    RunningLockType setLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION;
    std::string setLockNameOne = runnninglockNameLabel + "notify.6";
    std::string setLockNameTwo = runnninglockNameLabel + "notify2.6";
    RunningLockType errorLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    std::string errorLockName = runnninglockNameLabel + "notify.error.6";

    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockNameOne;
    runinglockInfo.type = setLockType;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    // runninglock type and same & timeoutMs < 0, hold lock failed
    EXPECT_EQ(HDF_FAILURE, RunningLockImpl::Hold(runinglockInfo, powerState));

    runinglockInfo.name = setLockNameTwo;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    // unhold a non-existent lock, return success
    runinglockInfo.type = errorLockType;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    runinglockInfo.type = setLockType;
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = errorLockName;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));
    runinglockInfo.name = setLockNameTwo;

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = setLockNameOne;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
}

/**
  * @tc.name: HdfPowerRunningLockTest007
  * @tc.desc: test Hold and UnHold, running lock type is audio
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest007, TestSize.Level1)
{
    RunningLockType setLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO;
    std::string setLockNameOne = runnninglockNameLabel + "audio.7";
    std::string setLockNameTwo = runnninglockNameLabel + "audio2.7";
    RunningLockType errorLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    std::string errorLockName = runnninglockNameLabel + "audio.error.7";

    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockNameOne;
    runinglockInfo.type = setLockType;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    // runninglock type and same & timeoutMs < 0, hold lock failed
    EXPECT_EQ(HDF_FAILURE, RunningLockImpl::Hold(runinglockInfo, powerState));

    runinglockInfo.name = setLockNameTwo;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    // unhold a non-existent lock, return success
    runinglockInfo.type = errorLockType;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    runinglockInfo.type = setLockType;
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = errorLockName;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));
    runinglockInfo.name = setLockNameTwo;

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = setLockNameOne;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
}

/**
  * @tc.name: HdfPowerRunningLockTest008
  * @tc.desc: test Hold and UnHold, running lock type is sport
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest008, TestSize.Level1)
{
    RunningLockType setLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT;
    std::string setLockNameOne = runnninglockNameLabel + "sport.8";
    std::string setLockNameTwo = runnninglockNameLabel + "sport2.8";
    RunningLockType errorLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    std::string errorLockName = runnninglockNameLabel + "sport.error.8";

    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockNameOne;
    runinglockInfo.type = setLockType;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    // runninglock type and same & timeoutMs < 0, hold lock failed
    EXPECT_EQ(HDF_FAILURE, RunningLockImpl::Hold(runinglockInfo, powerState));

    runinglockInfo.name = setLockNameTwo;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    // unhold a non-existent lock, return success
    runinglockInfo.type = errorLockType;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    runinglockInfo.type = setLockType;
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = errorLockName;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));
    runinglockInfo.name = setLockNameTwo;

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = setLockNameOne;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
}

/**
  * @tc.name: HdfPowerRunningLockTest009
  * @tc.desc: test Hold and UnHold, running lock type is navigation
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest009, TestSize.Level1)
{
    RunningLockType setLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION;
    std::string setLockNameOne = runnninglockNameLabel + "navi.9";
    std::string setLockNameTwo = runnninglockNameLabel + "navi.sec.9";
    RunningLockType errorLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    std::string errorLockName = runnninglockNameLabel + "navi.error.0";

    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockNameOne;
    runinglockInfo.type = setLockType;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    // runninglock type and same & timeoutMs < 0, hold lock failed
    EXPECT_EQ(HDF_FAILURE, RunningLockImpl::Hold(runinglockInfo, powerState));

    runinglockInfo.name = setLockNameTwo;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    // unhold a non-existent lock, return success
    runinglockInfo.type = errorLockType;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    runinglockInfo.type = setLockType;
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = errorLockName;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));
    runinglockInfo.name = setLockNameTwo;

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = setLockNameOne;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
}

/**
  * @tc.name: HdfPowerRunningLockTest010
  * @tc.desc: test Hold and UnHold, running lock type is task
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest010, TestSize.Level1)
{
    RunningLockType setLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    std::string setLockNameOne = runnninglockNameLabel + "task.10";
    std::string setLockNameTwo = runnninglockNameLabel + "task.sec.10";
    RunningLockType errorLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    std::string errorLockName = runnninglockNameLabel + "task.error.10";

    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockNameOne;
    runinglockInfo.type = setLockType;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    // runninglock type and same & timeoutMs < 0, hold lock failed
    EXPECT_EQ(HDF_FAILURE, RunningLockImpl::Hold(runinglockInfo, powerState));

    runinglockInfo.name = setLockNameTwo;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    // unhold a non-existent lock, return success
    runinglockInfo.type = errorLockType;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    runinglockInfo.type = setLockType;
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = errorLockName;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 2, RunningLockImpl::GetCount(runinglockInfo.type));
    runinglockInfo.name = setLockNameTwo;

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = setLockNameOne;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
}

/**
  * @tc.name: HdfPowerRunningLockTest011
  * @tc.desc: test Hold and UnHold, running lock type is 0, use default type Task
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest011, TestSize.Level1)
{
    RunningLockType setLockType = static_cast<RunningLockType>(0);
    std::string setLockName = runnninglockNameLabel + "zero.11";
    RunningLockType defaultLockType = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;

    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockName;
    runinglockInfo.type = setLockType;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t originCount = RunningLockImpl::GetCount(defaultLockType);

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(defaultLockType));

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(defaultLockType));
}

/**
  * @tc.name: HdfPowerRunningLockTest012
  * @tc.desc: test Hold and UnHold, running lock type and power state(sleep) are mutually exclusive
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest012, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::SLEEP;
    std::string setLockName = runnninglockNameLabel + "sleep.12";

    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockName;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;

    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));

    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));

    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, RunningLockImpl::Hold(runinglockInfo, powerState));

    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, RunningLockImpl::Hold(runinglockInfo, powerState));

    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
}

/**
  * @tc.name: HdfPowerRunningLockTest013
  * @tc.desc: test Hold and UnHold, running lock type and power state(sleep) are mutually exclusive
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest013, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::INACTIVE;
    std::string setLockName = runnninglockNameLabel + "inactive.13";

    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = setLockName;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;

    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT;
    runinglockInfo.name = setLockName + "sport.13";
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));

    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION;
    runinglockInfo.name = setLockName + "navigation.13";
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));

    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    runinglockInfo.name = setLockName + "task.13";
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));

    runinglockInfo.name = setLockName + "phone.13";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = setLockName + "notification.13";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION;
    originCount = RunningLockImpl::GetCount(runinglockInfo.type);
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = setLockName + "audio.13";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO;
    originCount = RunningLockImpl::GetCount(runinglockInfo.type);
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
}

/**
  * @tc.name: HdfPowerRunningLockTest014
  * @tc.desc: test Hold and UnHold, timeout is None
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest014, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t waitTimeOutMs = DEFAULT_TIMEOUT_FOR_TEST_MS + 10;

    uint32_t oriPhoneCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE);
    uint32_t oriNotifyCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION);
    uint32_t oriAudioCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO);

    runinglockInfo.name = runnninglockNameLabel + "phone.14";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriPhoneCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    runinglockInfo.name = runnninglockNameLabel + "notify.14";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION;
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriNotifyCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
  
    runinglockInfo.name = runnninglockNameLabel + "audio.14";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO;
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriAudioCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    usleep(waitTimeOutMs * US_PER_MS);

    EXPECT_EQ(oriPhoneCount + 1, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE));
    EXPECT_EQ(oriNotifyCount + 1, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION));
    EXPECT_EQ(oriAudioCount + 1, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO));

    runinglockInfo.name = runnninglockNameLabel + "phone.14";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(oriPhoneCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    runinglockInfo.name = runnninglockNameLabel + "notify.14";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(oriNotifyCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
  
    runinglockInfo.name = runnninglockNameLabel + "audio.14";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(oriAudioCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
}

/**
  * @tc.name: HdfPowerRunningLockTest015
  * @tc.desc: test Hold and UnHold, timeout is None
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest015, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t waitTimeOutMs = DEFAULT_TIMEOUT_FOR_TEST_MS + 10;

    uint32_t oriSportCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT);
    uint32_t oriNaviCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION);
    uint32_t oriTaskCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK);

    runinglockInfo.name = runnninglockNameLabel + "sport.15";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT;
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriSportCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    runinglockInfo.name = runnninglockNameLabel + "navi.15";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION;
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriNaviCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    runinglockInfo.name = runnninglockNameLabel + "task.15";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriTaskCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    usleep(waitTimeOutMs * US_PER_MS);

    EXPECT_EQ(oriSportCount + 1, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT));
    EXPECT_EQ(oriNaviCount + 1, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION));
    EXPECT_EQ(oriTaskCount + 1, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK));

    runinglockInfo.name = runnninglockNameLabel + "sport.15";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(oriSportCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    runinglockInfo.name = runnninglockNameLabel + "navi.15";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(oriNaviCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));

    runinglockInfo.name = runnninglockNameLabel + "task.15";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(oriTaskCount, RunningLockImpl::GetCount(runinglockInfo.type));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(RunningLockImpl::GetRunningLockTag(runinglockInfo.type)));
}

/**
  * @tc.name: HdfPowerRunningLockTest016
  * @tc.desc: test Hold and UnHold, timeout is default
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest016, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_DEFAULT;
    uint32_t waitTimeOutMs = DEFAULT_TIMEOUT_FOR_TEST_MS + 10;

    uint32_t oriPhoneCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE);
    uint32_t oriNotifyCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION);
    uint32_t oriAudioCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO);
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE)));
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION)));
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO)));

    runinglockInfo.name = runnninglockNameLabel + "phone.16";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriPhoneCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = runnninglockNameLabel + "notify.16";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriNotifyCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
  
    runinglockInfo.name = runnninglockNameLabel + "audio.16";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriAudioCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE)));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION)));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO)));

    usleep(waitTimeOutMs * US_PER_MS);

    EXPECT_EQ(oriPhoneCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE));
    EXPECT_EQ(oriNotifyCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION));
    EXPECT_EQ(oriAudioCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE)));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION)));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO)));
}

/**
  * @tc.name: HdfPowerRunningLockTest017
  * @tc.desc: test Hold and UnHold, timeout is default
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest017, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_DEFAULT;
    uint32_t waitTimeOutMs = DEFAULT_TIMEOUT_FOR_TEST_MS + 10;

    uint32_t oriSportCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT);
    uint32_t oriNaviCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION);
    uint32_t oriTaskCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK);
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT)));
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION)));
    ASSERT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK)));

    runinglockInfo.name = runnninglockNameLabel + "sport.16";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriSportCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = runnninglockNameLabel + "navi.16";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriNaviCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = runnninglockNameLabel + "task.16";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriTaskCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT)));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION)));
    EXPECT_EQ(true, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK)));

    usleep(waitTimeOutMs * US_PER_MS);

    EXPECT_EQ(oriSportCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT));
    EXPECT_EQ(oriNaviCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION));
    EXPECT_EQ(oriTaskCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT)));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION)));
    EXPECT_EQ(false, MockWakeLockName::FindWakeLockName(
        RunningLockImpl::GetRunningLockTag(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK)));
}

/**
  * @tc.name: HdfPowerRunningLockTest018
  * @tc.desc: test Hold and UnHold, timeout is set
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest018, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_SET_BASE_MS;
    uint32_t timeoutIntervalMs = 10;
    uint32_t waitTimeOutMs = 200;

    uint32_t oriPhoneCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE);
    uint32_t oriNotifyCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION);
    uint32_t oriAudioCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO);
    uint32_t oriSportCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT);
    uint32_t oriNaviCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION);
    uint32_t oriTaskCount = RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK);

    runinglockInfo.name = runnninglockNameLabel + "phone.17";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    runinglockInfo.timeoutMs += timeoutIntervalMs;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriPhoneCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = runnninglockNameLabel + "notify.17";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION;
    runinglockInfo.timeoutMs += timeoutIntervalMs;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriNotifyCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
  
    runinglockInfo.name = runnninglockNameLabel + "audio.17";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO;
    runinglockInfo.timeoutMs += timeoutIntervalMs;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriAudioCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = runnninglockNameLabel + "sport.17";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT;
    runinglockInfo.timeoutMs += timeoutIntervalMs;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriSportCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = runnninglockNameLabel + "navi.17";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION;
    runinglockInfo.timeoutMs += timeoutIntervalMs;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriNaviCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.name = runnninglockNameLabel + "task.17";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    runinglockInfo.timeoutMs += timeoutIntervalMs;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(oriTaskCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    usleep(waitTimeOutMs * US_PER_MS);

    EXPECT_EQ(oriPhoneCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE));
    EXPECT_EQ(oriNotifyCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION));
    EXPECT_EQ(oriAudioCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO));
    EXPECT_EQ(oriSportCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT));
    EXPECT_EQ(oriNaviCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION));
    EXPECT_EQ(oriTaskCount, RunningLockImpl::GetCount(RunningLockType::RUNNINGLOCK_BACKGROUND_TASK));
}

/**
  * @tc.name: HdfPowerRunningLockTest019
  * @tc.desc: test Hold and UnHold, runninglock type and same & timeoutMs > 0, running lock updated
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest019, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = runnninglockNameLabel + "phone.18";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    uint32_t waitTimeOutMs = DEFAULT_TIMEOUT_FOR_TEST_MS + 10;

    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    usleep(waitTimeOutMs * US_PER_MS);
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));
 
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_DEFAULT;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    usleep(waitTimeOutMs * US_PER_MS);
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
}

/**
  * @tc.name: HdfPowerRunningLockTest020
  * @tc.desc: test Hold and UnHold, runninglock type and same & timeoutMs > 0, running lock updated
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest020, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = runnninglockNameLabel + "audio.19";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO;
    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_DEFAULT;
    uint32_t updateTimeOutMs = 50;
    uint32_t waitTimeOutMs = 70;

    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.timeoutMs = updateTimeOutMs;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    usleep(waitTimeOutMs * US_PER_MS);
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
}

/**
  * @tc.name: HdfPowerRunningLockTest021
  * @tc.desc: test Hold and UnHold, manual unhold and timeout unhold
  * @tc.type: FUNC
  * @tc.require: issueI6IU18
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest021, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo {};
    runinglockInfo.name = runnninglockNameLabel + "sport.20";
    runinglockInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT;
    runinglockInfo.timeoutMs = 100;
    uint32_t manualUnholdTimeMs = 50;
    uint32_t waitTimeOutMs = 120;

    uint32_t originCount = RunningLockImpl::GetCount(runinglockInfo.type);

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    usleep(manualUnholdTimeMs * US_PER_MS);

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));

    runinglockInfo.timeoutMs = RUNNINGLOCK_TIMEOUT_NONE;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Hold(runinglockInfo, powerState));
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    usleep(waitTimeOutMs * US_PER_MS);
    EXPECT_EQ(originCount + 1, RunningLockImpl::GetCount(runinglockInfo.type));

    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::Unhold(runinglockInfo));
    EXPECT_EQ(originCount, RunningLockImpl::GetCount(runinglockInfo.type));
}

/**
  * @tc.name: HdfPowerRunningLockTest022
  * @tc.desc: test HoldLock and UnholdLock
  * @tc.type: FUNC
  * @tc.require: issueI9C4GG
  */
HWTEST_F(HdfPowerRunningLockTest, HdfPowerRunningLockTest022, TestSize.Level1)
{
    PowerHdfState powerState = PowerHdfState::AWAKE;
    RunningLockInfo runinglockInfo1 {};
    runinglockInfo1.name = runnninglockNameLabel + "task.22";
    runinglockInfo1.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::HoldLock(runinglockInfo1, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::UnholdLock(runinglockInfo1));

    RunningLockInfo runinglockInfo2 {};
    runinglockInfo2.name = "";
    runinglockInfo2.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::HoldLock(runinglockInfo2, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::UnholdLock(runinglockInfo2));

    powerState = PowerHdfState::SLEEP;
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::HoldLock(runinglockInfo1, powerState));
    EXPECT_EQ(HDF_SUCCESS, RunningLockImpl::UnholdLock(runinglockInfo1));
}
}