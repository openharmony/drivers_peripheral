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

#include <cmath>
#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include "hdf_base.h"
#include "osal_time.h"
#include "v1_2/ivibrator_interface.h"
#include "vibrator_type.h"

using namespace OHOS::HDI::Vibrator::V1_2;
using namespace testing::ext;

namespace {
    uint32_t g_duration = 1000;
    uint32_t g_noDuration = 0;
    uint32_t g_sleepTime1 = 2000;
    uint32_t g_sleepTime2 = 5000;
    int32_t g_intensity1 = 30;
    int32_t g_intensity2 = -30;
    int32_t g_frequency1 = 200;
    int32_t g_frequency2 = -200;
    int32_t g_pkgTime = 434;
    int32_t g_pkgEventNum = 1;
    enum OHOS::HDI::Vibrator::V1_2::EVENT_TYPE g_eventType = OHOS::HDI::Vibrator::V1_2::CONTINUOUS;
    int32_t g_eventDuration = 149;
    int32_t g_eventTime = 0;
    int32_t g_eventIntensity = 100;
    int32_t g_eventFrequency = 50;
    int32_t g_eventIndex = 0;
    int32_t g_eventPointNum = 4;
    int32_t g_pointTime0 = 0;
    int32_t g_pointIntensity0 = 0;
    int32_t g_pointFrequency0 = 0;
    int32_t g_pointTime1 = 1;
    int32_t g_pointIntensity1 = 1;
    int32_t g_pointFrequency1 = 0;
    int32_t g_pointTime2 = 32;
    int32_t g_pointIntensity2 = 1;
    int32_t g_pointFrequency2 = -39;
    int32_t g_pointTime3 = 149;
    int32_t g_pointIntensity3 = 0;
    int32_t g_pointFrequency3 = -39;
    constexpr int32_t MIN_DURATION = 0;
    constexpr int32_t MAX_DURATION = 3600000;
    std::vector<std::string> g_effect_list = {"haptic.clock.timer", "haptic.long_press.light", \
        "haptic.long_press.medium", "haptic.long_press.light", "haptic.fail", "haptic.charging", \
        "haptic.slide.light", "haptic.threshold"};
    std::string g_builtIn = "haptic.default.effect";
    std::string g_arbitraryStr = "arbitraryString";
    sptr<OHOS::HDI::Vibrator::V1_2::IVibratorInterface> g_vibratorInterface = nullptr;
}

class HdfVibratorHdiTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfVibratorHdiTest::SetUpTestCase()
{
    g_vibratorInterface = OHOS::HDI::Vibrator::V1_2::IVibratorInterface::Get();
}

void HdfVibratorHdiTest::TearDownTestCase()
{
}

void HdfVibratorHdiTest::SetUp()
{
}

void HdfVibratorHdiTest::TearDown()
{
}

/**
  * @tc.name: CheckVibratorInstanceIsEmpty
  * @tc.desc: Create a vibrator instance. The instance is not empty.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, CheckVibratorInstanceIsEmpty, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
}

/**
  * @tc.name: PerformOneShotVibratorDuration_001
  * @tc.desc: Controls this vibrator to perform a one-shot vibrator at a given duration.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, PerformOneShotVibratorDuration_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce(g_duration);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    OsalMSleep(g_sleepTime1);

    int32_t endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: PerformOneShotVibratorDuration_002
  * @tc.desc: Controls this vibrator to perform a one-shot vibrator at 0 millisecond.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, PerformOneShotVibratorDuration_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce(g_noDuration);
    EXPECT_EQ(startRet, HDF_ERR_INVALID_PARAM);

    int32_t endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: ExecuteVibratorEffect_001
  * @tc.desc: Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, ExecuteVibratorEffect_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    
    int32_t ret;
    for (auto iter : g_effect_list) {
        printf("VibratorEffect : %s\n", iter.c_str());
        ret = g_vibratorInterface->Start(iter);
        EXPECT_EQ(ret, HDF_SUCCESS);

        OsalMSleep(g_sleepTime2);

        ret = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_PRESET);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
  * @tc.name: ExecuteVibratorEffect_002
  * @tc.desc: Controls this Performing built-in Vibrator Effects.
  * Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, ExecuteVibratorEffect_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret;
    for (auto iter : g_effect_list) {
        printf("VibratorEffect : %s\n", iter.c_str());
        ret = g_vibratorInterface->Start(iter);
        EXPECT_EQ(ret, HDF_SUCCESS);

        OsalMSleep(g_sleepTime1);

        ret = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_PRESET);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
  * @tc.name: ExecuteVibratorEffect_004
  * @tc.desc: Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, ExecuteVibratorEffect_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret;
    for (auto iter : g_effect_list) {
        printf("VibratorEffect : %s\n", iter.c_str());
        ret = g_vibratorInterface->Start(iter);
        EXPECT_EQ(ret, HDF_SUCCESS);

        OsalMSleep(g_sleepTime2);

        ret = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_BUTT);
        EXPECT_EQ(ret, HDF_FAILURE);

        ret = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_PRESET);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
  * @tc.name: ExecuteVibratorEffect_005
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, ExecuteVibratorEffect_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret;
    for (auto iter : g_effect_list) {
        printf("VibratorEffect : %s\n", iter.c_str());
        ret = g_vibratorInterface->Start(iter);
        EXPECT_EQ(ret, HDF_SUCCESS);

        OsalMSleep(g_sleepTime2);

        ret = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_PRESET);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
  * @tc.name: ExecuteVibratorEffect_006
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * Controls this Perform built-in Vibrator Effects.
  * Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, ExecuteVibratorEffect_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret;
    for (auto iter : g_effect_list) {
        printf("VibratorEffect : %s\n", iter.c_str());
        ret = g_vibratorInterface->Start(iter);
        EXPECT_EQ(ret, HDF_SUCCESS);

        OsalMSleep(g_sleepTime2);

        ret = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_PRESET);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
  * @tc.name: ExecuteVibratorEffect_007
  * @tc.desc: Controls this Perform a one-shot vibrator with an arbitrary string.
  * Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, ExecuteVibratorEffect_007, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start(g_arbitraryStr);
    EXPECT_EQ(startRet, HDF_ERR_INVALID_PARAM);

    int32_t endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: GetVibratorInfo_001
  * @tc.desc: Obtain the vibrator setting strength, frequency capability and range in the system.
  * Validity check of input parameters.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, GetVibratorInfo_001, TestSize.Level1)
{
    uint32_t majorVer;
    uint32_t minorVer;
    if (g_vibratorInterface->GetVersion(majorVer, minorVer) != HDF_SUCCESS) {
        printf("get version failed!\n\t");
        return;
    }

    if (majorVer > 0 && minorVer <= 0) {
        printf("version not support!\n\t");
        return;
    }
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    printf("intensity = %d, intensityMaxValue = %d, intensityMinValue = %d\n\t",
    info[0].isSupportIntensity, info[0].intensityMaxValue, info[0].intensityMinValue);
    printf("frequency = %d, intensityMaxValue = %d, intensityMinValue = %d\n\t",
    info[0].isSupportFrequency, info[0].frequencyMaxValue, info[0].frequencyMinValue);
}

/**
  * @tc.name: EnableVibratorModulation_001
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, EnableVibratorModulation_001, TestSize.Level1)
{
    uint32_t majorVer;
    uint32_t minorVer;
    if (g_vibratorInterface->GetVersion(majorVer, minorVer) != HDF_SUCCESS) {
        printf("get version failed!\n\t");
        return;
    }

    if (majorVer > 0 && minorVer <= 0) {
        printf("version not support!\n\t");
        return;
    }
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        EXPECT_GT(g_duration, 0);
        EXPECT_GE(g_intensity1, info[0].intensityMinValue);
        EXPECT_LE(g_intensity1, info[0].intensityMaxValue);
        EXPECT_GE(g_frequency1, info[0].frequencyMinValue);
        EXPECT_LE(g_frequency1, info[0].frequencyMaxValue);

        startRet = g_vibratorInterface->EnableVibratorModulation(g_duration, g_intensity1, g_frequency1);
        EXPECT_EQ(startRet, HDF_SUCCESS);
        OsalMSleep(g_sleepTime1);
        startRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
        EXPECT_EQ(startRet, HDF_SUCCESS);
    }
}

/**
  * @tc.name: EnableVibratorModulation_002
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * Validity check of input parameters.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, EnableVibratorModulation_002, TestSize.Level1)
{
    uint32_t majorVer;
    uint32_t minorVer;
    if (g_vibratorInterface->GetVersion(majorVer, minorVer) != HDF_SUCCESS) {
        printf("get version failed!\n\t");
        return;
    }

    if (majorVer > 0 && minorVer <= 0) {
        printf("version not support!\n\t");
        return;
    }
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        startRet = g_vibratorInterface->EnableVibratorModulation(g_noDuration, g_intensity1, g_frequency1);
        EXPECT_EQ(startRet, VIBRATOR_NOT_PERIOD);
    }
}

/**
  * @tc.name: EnableVibratorModulation_003
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * Validity check of input parameters.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, EnableVibratorModulation_003, TestSize.Level1)
{
    uint32_t majorVer;
    uint32_t minorVer;
    if (g_vibratorInterface->GetVersion(majorVer, minorVer) != HDF_SUCCESS) {
        printf("get version failed!\n\t");
        return;
    }

    if (majorVer > 0 && minorVer <= 0) {
        printf("version not support!\n\t");
        return;
    }
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        startRet = g_vibratorInterface->EnableVibratorModulation(g_duration, g_intensity2, g_frequency1);
        EXPECT_EQ(startRet, VIBRATOR_NOT_INTENSITY);
    }
}

/**
  * @tc.name: EnableVibratorModulation_004
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * Validity check of input parameters.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, EnableVibratorModulation_004, TestSize.Level1)
{
    uint32_t majorVer;
    uint32_t minorVer;
    if (g_vibratorInterface->GetVersion(majorVer, minorVer) != HDF_SUCCESS) {
        printf("get version failed!\n\t");
        return;
    }

    if (majorVer > 0 && minorVer <= 0) {
        printf("version not support!\n\t");
        return;
    }
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        startRet = g_vibratorInterface->EnableVibratorModulation(g_duration, g_intensity1, g_frequency2);
        EXPECT_EQ(startRet, VIBRATOR_NOT_FREQUENCY);
    }
}

/**
  * @tc.name: GetEffectInfo_001
  * @tc.desc: Get effect information with the given effect type.
  * @tc.type: FUNC
  * @tc.require:I6FBDQ
  */
HWTEST_F(HdfVibratorHdiTest, GetEffectInfo_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    int32_t ret;
    for (auto iter : g_effect_list) {
        printf("VibratorEffect : %s\n", iter.c_str());
        ret = g_vibratorInterface->GetEffectInfo(iter, effectInfo);
        printf("isSupportEffect = [%d]\n\r", effectInfo.isSupportEffect);
        printf("duration = [%d]\n\r", effectInfo.duration);
        EXPECT_EQ(ret, HDF_SUCCESS);
        if (effectInfo.isSupportEffect) {
            EXPECT_GT(effectInfo.duration, MIN_DURATION);
            EXPECT_LE(effectInfo.duration, MAX_DURATION);
        }
    }
}

/**
  * @tc.name: GetEffectInfo_002
  * @tc.desc: Get effect information with the given effect type.
  * @tc.type: FUNC
  * @tc.require:#I6FBDQ
  */
HWTEST_F(HdfVibratorHdiTest, GetEffectInfo_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    int32_t ret = g_vibratorInterface->GetEffectInfo("invaild effect id", effectInfo);
    printf("isSupportEffect = [%d]\n\r", effectInfo.isSupportEffect);
    printf("duration = [%d]\n\r", effectInfo.duration);
    EXPECT_EQ(ret, HDF_SUCCESS);
    EXPECT_EQ(effectInfo.isSupportEffect, false);
    EXPECT_EQ(effectInfo.duration, 0);
}

/**
  * @tc.name: PlayHapticPattern
  * @tc.desc: HD vibration data packet delivery.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(HdfVibratorHdiTest, PlayHapticPattern, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    OHOS::HDI::Vibrator::V1_2::HapticPaket pkg;
    pkg.time = g_pkgTime;
    pkg.eventNum = g_pkgEventNum;

    OHOS::HDI::Vibrator::V1_2::HapticEvent hapticEvent;
    hapticEvent.type = g_eventType;
    hapticEvent.duration = g_eventDuration;
    hapticEvent.time = g_eventTime;
    hapticEvent.intensity = g_eventIntensity;
    hapticEvent.frequency = g_eventFrequency;
    hapticEvent.index = g_eventIndex;
    hapticEvent.pointNum = g_eventPointNum;

    OHOS::HDI::Vibrator::V1_2::CurvePoint curvePoint0;
    curvePoint0.time = g_pointTime0;
    curvePoint0.intensity = g_pointIntensity0;
    curvePoint0.frequency = g_pointFrequency0;
    hapticEvent.points.push_back(std::move(curvePoint0));

    OHOS::HDI::Vibrator::V1_2::CurvePoint curvePoint1;
    curvePoint1.time = g_pointTime1;
    curvePoint1.intensity = g_pointIntensity1;
    curvePoint1.frequency = g_pointFrequency1;
    hapticEvent.points.push_back(std::move(curvePoint1));

    OHOS::HDI::Vibrator::V1_2::CurvePoint curvePoint2;
    curvePoint2.time = g_pointTime2;
    curvePoint2.intensity = g_pointIntensity2;
    curvePoint2.frequency = g_pointFrequency2;
    hapticEvent.points.push_back(std::move(curvePoint2));

    OHOS::HDI::Vibrator::V1_2::CurvePoint curvePoint3;
    curvePoint3.time = g_pointTime3;
    curvePoint3.intensity = g_pointIntensity3;
    curvePoint3.frequency = g_pointFrequency3;
    hapticEvent.points.push_back(std::move(curvePoint3));

    pkg.events.push_back(std::move(hapticEvent));
    int32_t startRet = g_vibratorInterface->PlayHapticPattern(pkg);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: GetHapticCapacity
  * @tc.desc: Obtains the vibration capability of the motor.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(HdfVibratorHdiTest, GetHapticCapacity, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    OHOS::HDI::Vibrator::V1_2::HapticCapacity hapticCapacity;
    int32_t startRet = g_vibratorInterface->GetHapticCapacity(hapticCapacity);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    printf("hapticCapacity.isSupportHdHaptic = %d\n", hapticCapacity.isSupportHdHaptic);
    printf("hapticCapacity.isSupportPresetMapping = %d\n", hapticCapacity.isSupportPresetMapping);
    printf("hapticCapacity.isSupportTimeDelay = %d\n", hapticCapacity.isSupportTimeDelay);

    int32_t endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: GetHapticStartUpTime
  * @tc.desc: Indicates the time from command is issued to the time the motor starts.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(HdfVibratorHdiTest, GetHapticStartUpTime, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    
    int32_t startUpTime;
    int32_t mode = 0;
    int32_t startRet = g_vibratorInterface->GetHapticStartUpTime(mode, startUpTime);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    printf("startUpTime = %d\n", startUpTime);

    int32_t endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}