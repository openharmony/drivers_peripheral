/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <cmath>
#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include "hdf_base.h"
#include "osal_time.h"
#include "vibrator_if.h"
#include "vibrator_type.h"

using namespace testing::ext;

namespace {
    uint32_t g_duration = 1000;
    uint32_t g_noDuration = 0;
    uint32_t g_sleepTime1 = 2000;
    uint32_t g_sleepTime2 = 5000;
    const char *g_timeSequence = "haptic.clock.timer";
    const char *g_builtIn = "haptic.default.effect";
    const char *g_arbitraryStr = "arbitraryString";
    const struct VibratorInterface *g_vibratorDev = nullptr;
}

class HdfVibratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfVibratorTest::SetUpTestCase()
{
    g_vibratorDev = NewVibratorInterfaceInstance();
}

void HdfVibratorTest::TearDownTestCase()
{
    if(g_vibratorDev != nullptr){
        FreeVibratorInterfaceInstance();
        g_vibratorDev = nullptr;
    }
}

void HdfVibratorTest::SetUp()
{
}

void HdfVibratorTest::TearDown()
{
}

/**
  *@tc.name: CheckVibratorInstanceIsEmpty
  *@tc.desc: Create a vibrator instance. The instance is not empty.
  *@tc.type: FUNC
  *@tc.require: SR000FK1JM,AR000FK1J0,AR000FK1JP
  */
HWTEST_F(HdfVibratorTest, CheckVibratorInstanceIsEmpty, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);
}

/**
  *@tc.name: PerformOneShotVibratorDuration_001
  *@tc.desc: Controls this vibrator to perform a one-shot vibrator at a given duration.
    Controls this vibrator to stop the vibrator
  *@tc.type: FUNC
  *@tc.require: AR000FK1JN,AR000FK1J0
  */
HWTEST_F(HdfVibratorTest, PerformOneShotVibratorDuration_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->StartOnce(g_duration);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    OsalMSleep(g_sleepTime1);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  *@tc.name: PerformOneShotVibratorDuration_002
  *@tc.desc: Controls this vibrator to perform a one-shot vibrator at 0 millisecond.
    Controls this vibrator to stop the vibrator
  *@tc.type: FUNC
  *@tc.require: AR000FK1JN,AR000FK1JP
  */
HWTEST_F(HdfVibratorTest, PerformOneShotVibratorDuration_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->StartOnce(g_noDuration);
    EXPECT_EQ(startRet, HDF_ERR_INVALID_PARAM);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  *@tc.name: ExecuteVibratorEffect_001
  *@tc.desc: Controls this Performing Time Series Vibrator Effects.
    Controls this vibrator to stop the vibrator
  *@tc.type: FUNC
  *@tc.require: AR000FK1JN,AR000FK1J0
  */
HWTEST_F(HdfVibratorTest, ExecuteVibratorEffect_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->Start(g_timeSequence);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    OsalMSleep(g_sleepTime2);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  *@tc.name: ExecuteVibratorEffect_002
  *@tc.desc: Controls this Performing built-in Vibrator Effects.
    Controls this vibrator to stop the vibrator.
  *@tc.type: FUNC
  *@tc.require: AR000FK1J0,AR000FK1JP
  */
HWTEST_F(HdfVibratorTest, ExecuteVibratorEffect_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->Start(g_builtIn);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    OsalMSleep(g_sleepTime1);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  *@tc.name: ExecuteVibratorEffect_003
  *@tc.desc: Controls this Perform a Empty vibrator effect.
    Controls this vibrator to stop the vibrator.
  *@tc.type: FUNC
  *@tc.require: AR000FK1J0,AR000FK1JP
  */
HWTEST_F(HdfVibratorTest, ExecuteVibratorEffect_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->Start(nullptr);
    EXPECT_EQ(startRet, HDF_ERR_INVALID_PARAM);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  *@tc.name: ExecuteVibratorEffect_004
  *@tc.desc: Controls this Performing Time Series Vibrator Effects.
    Controls this vibrator to stop the vibrator.
  *@tc.type: FUNC
  *@tc.require: AR000FK1JN,AR000FK1JP
  */
HWTEST_F(HdfVibratorTest, ExecuteVibratorEffect_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->Start(g_timeSequence);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    OsalMSleep(g_sleepTime2);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_BUTT);
    EXPECT_EQ(endRet, HDF_FAILURE);

    endRet = g_vibratorDev->Stop(VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  *@tc.name: ExecuteVibratorEffect_005
  *@tc.desc: Controls this vibrator to stop the vibrator.
    Controls this Performing Time Series Vibrator Effects.
    Controls this vibrator to stop the vibrator.
  *@tc.type: FUNC
  *@tc.require: AR000FK1JN,AR000FK1JP
  */
HWTEST_F(HdfVibratorTest, ExecuteVibratorEffect_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->Start(g_timeSequence);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    OsalMSleep(g_sleepTime2);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  *@tc.name: ExecuteVibratorEffect_006
  *@tc.desc: Controls this vibrator to stop the vibrator.
    Controls this Perform built-in Vibrator Effects.
    Controls this vibrator to stop the vibrator.
  *@tc.type: FUNC
  *@tc.require: AR000FK1JN,AR000FK1JP
  */
HWTEST_F(HdfVibratorTest, ExecuteVibratorEffect_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->Start(g_builtIn);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    OsalMSleep(g_sleepTime2);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  *@tc.name: ExecuteVibratorEffect_007
  *@tc.desc: Controls this Perform a one-shot vibrator with an arbitrary string.
    Controls this vibrator to stop the vibrator.
  *@tc.type: FUNC
  *@tc.require: AR000FK1JN,AR000FK1J0,AR000FK1JP
  */
HWTEST_F(HdfVibratorTest, ExecuteVibratorEffect_007, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorDev);

    int32_t startRet = g_vibratorDev->Start(g_arbitraryStr);
    EXPECT_EQ(startRet, HDF_ERR_INVALID_PARAM);

    int32_t endRet = g_vibratorDev->Stop(VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}