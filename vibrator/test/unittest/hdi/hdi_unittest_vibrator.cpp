/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include "hdf_base.h"
#include "hdf_log.h"
#include "osal_time.h"
#include "parameters.h"
#include "v1_3/ivibrator_interface.h"

#define HDF_LOG_TAG "hdi_unittest_vibrator"
#define TEST_FUNC_IN HDF_LOGI("%{public}s in", testing::UnitTest::GetInstance()->current_test_info()->name())

using namespace std;
using namespace testing::ext;
using namespace OHOS::HDI::Vibrator;
using namespace OHOS::HDI::Vibrator::V1_3;

namespace {
    uint32_t g_duration = 2000;
    std::string g_effect1 = "haptic.long_press.light";
    HapticPaket g_pkg = {434, 1, {{V1_2::CONTINUOUS, 0, 149, 100, 50, 0, 4,
        {{0, 0, 0}, {1, 1, 0}, {32, 1, -39}, {149, 0, -39}}}}};
    V1_2::HapticPaket g_pkg1 = {434, 1, {{V1_2::TRANSIENT, 0, 149, 100, 50, 0, 4,
        {{0, 0, 0}, {1, 1, 0}, {32, 1, -39}, {149, 0, -39}}}}};
    int32_t g_vibratorId = 0;
    int32_t g_intensity = 60;
    std::vector<HdfWaveInformation> g_info;
    const std::vector<std::string> g_effect{"haptic.long_press.light", "haptic.slide.light", \
        "haptic.threshold", "haptic.long_press.medium", "haptic.fail", "haptic.common.notice1", \
        "haptic.common.success", "haptic.charging", "haptic.long_press.heavy"};
    HapticCapacity g_hapticCapacity;-
    sptr<V1_3::IVibratorInterface> g_vibratorInterface = nullptr;
} // namespace

class HdiUnitTestVibrator : public testing::Test {
public:
    static void SetUpTestSuite();
    static void TearDownTestSuite();
    void SetUp();
    void TearDown();
};

void HdiUnitTestVibrator::SetUpTestSuite()
{
    g_vibratorInterface = V1_3::IVibratorInterface::Get();
}

void HdiUnitTestVibrator::TearDownTestSuite()
{
}

void HdiUnitTestVibrator::SetUp()
{
}

void HdiUnitTestVibrator::TearDown()
{
}

/**
  * @tc.name: CheckVibratorInstanceIsEmpty
  * @tc.desc: Create a Vibrator instance. The instance is not empty.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, CheckVibratorInstanceIsEmpty001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);
}

/**
  * @tc.name: VibratorStartOnceTest001
  * @tc.desc: Start one-shot vibration with given duration.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, VibratorStartOnceTest001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->StartOnce(2000);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(2000);
}

/**
  * @tc.name: VibratorStartTest001
  * @tc.desc: Start periodic vibration with preset effect.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, VibratorStartTest001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->Start("haptic.pattern.type1");
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(2000);
}

/**
  * @tc.name: GetHapticCapacity
  * @tc.desc: Obtains the vibration capability of the motor.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, GetHapticCapacity, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->GetHapticCapacity(g_hapticCapacity);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    printf("g_hapticCapacity.isSupportHdHaptic = %d\n", g_hapticCapacity.isSupportHdHaptic);
    printf("g_hapticCapacity.isSupportPresetMapping = %d\n", g_hapticCapacity.isSupportPresetMapping);
    printf("g_hapticCapacity.isSupportTimeDelay = %d\n", g_hapticCapacity.isSupportTimeDelay);
}

/**
  * @tc.name: EnableCompositeEffectTest001
  * @tc.desc: Start periodic vibration with custom composite effect.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, EnableCompositeEffectTest001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    if (g_hapticCapacity.isSupportPresetMapping) {
        HDF_LOGI("EnableCompositeEffectTest001 phone in");
        PrimitiveEffect primitiveEffect1 { 0, 60007, 0 };
        PrimitiveEffect primitiveEffect2 { 1000, 60007, 0 };
        PrimitiveEffect primitiveEffect3 { 1000, 60007, 0 };
        CompositeEffect effect1 = {
            .primitiveEffect = primitiveEffect1,
        };
        CompositeEffect effect2 = {
            .primitiveEffect = primitiveEffect2,
        };
        CompositeEffect effect3 = {
            .primitiveEffect = primitiveEffect3,
        };
        std::vector<CompositeEffect> vec;
        vec.push_back(effect1);
        vec.push_back(effect2);
        vec.push_back(effect3);
        HdfCompositeEffect effect;
        effect.type = HDF_EFFECT_TYPE_PRIMITIVE;
        effect.compositeEffects = vec;
        int32_t ret = g_vibratorInterface->EnableCompositeEffect(effect);
        HDF_LOGD("ret:%{public}d", ret);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalMSleep(2000);
    }
}

/**
  * @tc.name: EnableCompositeEffectTest002
  * @tc.desc: Start periodic vibration with custom composite effect.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, EnableCompositeEffectTest002, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    if (g_hapticCapacity.isSupportPresetMapping) {
        HDF_LOGI("EnableCompositeEffectTest002 phone in");
        PrimitiveEffect primitiveEffect1 { 0, 60007, 0 };
        PrimitiveEffect primitiveEffect2 { 1000, 60007, 0 };
        PrimitiveEffect primitiveEffect3 { 1000, 60007, 0 };
        CompositeEffect effect1 = {
            .primitiveEffect = primitiveEffect1,
        };
        CompositeEffect effect2 = {
            .primitiveEffect = primitiveEffect2,
        };
        CompositeEffect effect3 = {
            .primitiveEffect = primitiveEffect3,
        };
        std::vector<CompositeEffect> vec;
        vec.push_back(effect1);
        vec.push_back(effect2);
        vec.push_back(effect3);
        HdfCompositeEffect effect;
        effect.type = HDF_EFFECT_TYPE_PRIMITIVE;
        effect.compositeEffects = vec;
        int32_t ret = g_vibratorInterface->EnableCompositeEffect(effect);
        HDF_LOGD("ret:%{public}d", ret);
        EXPECT_EQ(HDF_SUCCESS, ret);

        OsalMSleep(1000);
        ret = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_PRESET);
        HDF_LOGD("ret:%{public}d", ret);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: GetEffectInfoTest001
  * @tc.desc: Get effect information with the given effect type.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, GetEffectInfoTest001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    int32_t ret = g_vibratorInterface->GetEffectInfo("haptic.pattern.type1", effectInfo);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(effectInfo.duration, 1900);
    EXPECT_EQ(effectInfo.isSupportEffect, true);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: GetEffectInfoTest002
  * @tc.desc: Get effect information with the given effect type.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, GetEffectInfoTest002, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    int32_t ret = g_vibratorInterface->GetEffectInfo("invalid.effect.id", effectInfo);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(effectInfo.duration, 0);
    EXPECT_EQ(effectInfo.isSupportEffect, false);
}

/**
  * @tc.name: VibratorStopTest001
  * @tc.desc: Stop vibration.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, VibratorStopTest001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->StartOnce(2000);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalMSleep(1000);
    ret = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: IsVibratorRunningTest001
  * @tc.desc: Get vibration status.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, IsVibratorRunningTest001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    PrimitiveEffect primitiveEffect1 { 0, 60007, 0 };
    PrimitiveEffect primitiveEffect2 { 1000, 60007, 0 };
    PrimitiveEffect primitiveEffect3 { 1000, 60007, 0 };
    CompositeEffect effect1 = {
        .primitiveEffect = primitiveEffect1,
    };
    CompositeEffect effect2 = {
        .primitiveEffect = primitiveEffect2,
    };
    CompositeEffect effect3 = {
        .primitiveEffect = primitiveEffect3,
    };
    std::vector<CompositeEffect> vec;
    vec.push_back(effect1);
    vec.push_back(effect2);
    vec.push_back(effect3);
    HdfCompositeEffect effect;
    effect.type = HDF_EFFECT_TYPE_PRIMITIVE;
    effect.compositeEffects = vec;
    int32_t ret = g_vibratorInterface->EnableCompositeEffect(effect);
    HDF_LOGD("ret:%{public}d", ret);
    if (g_hapticCapacity.isSupportPresetMapping) {
        EXPECT_EQ(HDF_SUCCESS, ret);
        bool state {false};
        g_vibratorInterface->IsVibratorRunning(state);
        HDF_LOGD("Vibrating state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
        EXPECT_EQ(state, true);

        OsalMSleep(3000);
        g_vibratorInterface->IsVibratorRunning(state);
        HDF_LOGD("Stoped state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
        EXPECT_EQ(state, false);
    } else {
        OsalMSleep(3000);
    }
}

/**
  * @tc.name: IsVibratorRunningTest002
  * @tc.desc: Get vibration status.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, IsVibratorRunningTest002, TestSize.Level1)
{
    TEST_FUNC_IN;
    bool state {false};
    g_vibratorInterface->IsVibratorRunning(state);
    HDF_LOGD("No vibrate state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
    EXPECT_EQ(state, false);
}

/**
  * @tc.name: GetVibratorInfo001
  * @tc.desc: Get vibrator information.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, GetVibratorInfo001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);
    std::vector<HdfVibratorInfo> info;
    int32_t ret = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(info.size(), 0);

    printf("isSupportIntensity = %d, intensityMaxValue = %d, intensityMinValue = %d\n\t",
        info[0].isSupportIntensity, info[0].intensityMaxValue, info[0].intensityMinValue);
    printf("isSupportFrequency = %d, intensityMaxValue = %d, intensityMinValue = %d\n\t",
        info[0].isSupportFrequency, info[0].frequencyMaxValue, info[0].frequencyMinValue);
}

/**
  * @tc.name: EnableVibratorModulation_001
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, EnableVibratorModulation_001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);
    std::vector<HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        uint32_t duration = 2000;
        int32_t intensity = 30;
        int32_t frequency = 200;
        uint32_t sleepTime = 2000;
        startRet = g_vibratorInterface->EnableVibratorModulation(duration, intensity, frequency);
        EXPECT_EQ(startRet, HDF_SUCCESS);
        OsalMSleep(sleepTime);
        startRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE);
        EXPECT_EQ(startRet, HDF_SUCCESS);
    }
}

/**
  * @tc.name: EnableVibratorModulation_002
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * Validity check of input parameters.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, EnableVibratorModulation_002, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);
    std::vector<HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        uint32_t noDuration = 0;
        int32_t intensity = 30;
        int32_t frequency = 200;
        startRet = g_vibratorInterface->EnableVibratorModulation(noDuration, intensity, frequency);
        EXPECT_EQ(startRet, -1);
    }
}

/**
  * @tc.name: VibratorStartTest011
  * @tc.desc: Start periodic vibration with preset effect.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, VibratorStartTest011, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    for (auto iter : g_effect) {
        g_vibratorInterface->GetEffectInfo(iter, effectInfo);
        if (effectInfo.isSupportEffect == true) {
            printf("VibratorStart : %s\n", iter.c_str());
            int32_t ret = g_vibratorInterface->Start(iter);
            HDF_LOGD("ret:%{public}d", ret);
            EXPECT_EQ(HDF_SUCCESS, ret);
            OsalMSleep(2000);
        }
    }
}

/**
  * @tc.name: PlayHapticPattern
  * @tc.desc: HD vibration data packet delivery.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, PlayHapticPattern, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->PlayHapticPattern(g_pkg);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: PlayHapticPattern_001
  * @tc.desc: HD vibration data packet delivery.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, PlayHapticPattern_001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->PlayHapticPattern(g_pkg1);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: GetHapticStartUpTime
  * @tc.desc: Indicates the time from command is issued to the time the motor starts.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, GetHapticStartUpTime, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startUpTime = 0;
    int32_t mode = 0;
    int32_t startRet = g_vibratorInterface->GetHapticStartUpTime(mode, startUpTime);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    printf("startUpTime = %d\n", startUpTime);

    int32_t endRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopV1_2Test_001
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, StopV1_2Test_001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce(g_duration);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopV1_2Test_002
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, StopV1_2Test_002, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start(g_effect1);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopV1_2Test_003
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, StopV1_2Test_003, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->PlayHapticPattern(g_pkg);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopV1_2Test_004
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, StopV1_2Test_004, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start(g_effect1);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_BUTT);
    EXPECT_EQ(endRet, HDF_ERR_INVALID_PARAM);
}

/**
  * @tc.name: StartByIntensityTest
  * @tc.desc: Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, StartByIntensityTest, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartByIntensity(g_effect1, g_intensity);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopTest
  * @tc.desc: Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, StopTest, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce(g_duration);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop(HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
    OsalMSleep(g_duration);

    startRet = g_vibratorInterface->StartByIntensity(g_effect1, g_intensity);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    endRet = g_vibratorInterface->StopV1_2(HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
    OsalMSleep(g_duration);


    startRet = g_vibratorInterface->Start(g_effect1);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    endRet = g_vibratorInterface->Stop(HdfVibratorMode::HDF_VIBRATOR_MODE_BUTT);
    EXPECT_EQ(endRet, HDF_ERR_INVALID_PARAM);
    OsalMSleep(g_duration);
}

/**
  * @tc.name: GetAllWaveInfoTest
  * @tc.desc: Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, GetAllWaveInfoTest, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->GetAllWaveInfo(g_vibratorId, g_info);

    if (g_hapticCapacity.isSupportPresetMapping) {
        EXPECT_EQ(startRet, HDF_SUCCESS);
    } else {
        HDF_LOGI("%{public}s device is not SupportPresetMapping", __func__ );
    }
}