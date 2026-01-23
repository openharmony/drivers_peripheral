/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "v2_0/ivibrator_interface.h"

#define HDF_LOG_TAG "vibrator_impl_test"

using namespace std;
using namespace testing::ext;
using namespace OHOS::HDI::Vibrator;
using namespace OHOS::HDI::Vibrator::V2_0;

namespace {
    uint32_t g_duration = 2000;
    uint32_t g_highInt = 110;
    std::string g_effect1 = "haptic.effect.soft";
    HapticPaket g_pkg = {434, 1, {{V2_0::CONTINUOUS, 0, 149, 100, 50, 0, 4,
        {{0, 0, 0}, {1, 1, 0}, {32, 1, -39}, {149, 0, -39}}}}};
    V2_0::HapticPaket g_pkg1 = {434, 1, {{V2_0::TRANSIENT, 0, 149, 100, 50, 0, 4,
        {{0, 0, 0}, {1, 1, 0}, {32, 1, -39}, {149, 0, -39}}}}};
    int32_t g_intensity = 60;
    std::vector<HdfWaveInformation> g_info;
    const std::vector<std::string> g_effect{"haptic.long_press.light", "haptic.slide.light", \
        "haptic.threshold", "haptic.long_press.medium", "haptic.fail", "haptic.common.notice1", \
        "haptic.common.success", "haptic.charging", "haptic.long_press.heavy"};
    HapticCapacity g_hapticCapacity;
    sptr<V2_0::IVibratorInterface> g_vibratorInterface = nullptr;
} // namespace

class VibratorImplTest : public testing::Test {
public:
    static void SetUpTestSuite();
    static void TearDownTestSuite();
    void SetUp();
    void TearDown();
};

void VibratorImplTest::SetUpTestSuite()
{
    g_vibratorInterface = V2_0::IVibratorInterface::Get();
}

void VibratorImplTest::TearDownTestSuite()
{
}

void VibratorImplTest::SetUp()
{
}

void VibratorImplTest::TearDown()
{
}

/**
  * @tc.name: CheckVibratorInstanceIsEmpty
  * @tc.desc: Create a Vibrator instance. The instance is not empty.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, CheckVibratorInstanceIsEmpty001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
}

/**
  * @tc.name: VibratorStartOnceTest001
  * @tc.desc: Start one-shot vibration with given duration.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, VibratorStartOnceTest001, TestSize.Level1)
{
    HDF_LOGI("VibratorStartOnceTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->StartOnce({0, 0}, 2000);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(2000);
}

/**
  * @tc.name: VibratorStartTest001
  * @tc.desc: Start periodic vibration with preset effect.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, VibratorStartTest001, TestSize.Level1)
{
    HDF_LOGI("VibratorStartTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->Start({0, 0}, "haptic.pattern.type1");
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(2000);
}

/**
  * @tc.name: GetHapticCapacity
  * @tc.desc: Obtains the vibration capability of the motor.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(VibratorImplTest, GetHapticCapacity, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->GetHapticCapacity({0, 0}, g_hapticCapacity);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    printf("g_hapticCapacity.isSupportHdHaptic = %d\n", g_hapticCapacity.isSupportHdHaptic);
    printf("g_hapticCapacity.isSupportPresetMapping = %d\n", g_hapticCapacity.isSupportPresetMapping);
    printf("g_hapticCapacity.isSupportTimeDelay = %d\n", g_hapticCapacity.isSupportTimeDelay);
}

/**
  * @tc.name: EnableCompositeEffectTest001
  * @tc.desc: Start periodic vibration with custom composite effect.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, EnableCompositeEffectTest001, TestSize.Level1)
{
    HDF_LOGI("EnableCompositeEffectTest001 in");
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
        int32_t ret = g_vibratorInterface->EnableCompositeEffect({0, 0}, effect);
        HDF_LOGD("ret:%{public}d", ret);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalMSleep(2000);
    }
}

/**
  * @tc.name: EnableCompositeEffectTest002
  * @tc.desc: Start periodic vibration with custom composite effect.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, EnableCompositeEffectTest002, TestSize.Level1)
{
    HDF_LOGI("EnableCompositeEffectTest002 in");
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
        int32_t ret = g_vibratorInterface->EnableCompositeEffect({0, 0}, effect);
        HDF_LOGD("ret:%{public}d", ret);
        EXPECT_EQ(HDF_SUCCESS, ret);

        OsalMSleep(1000);
        ret = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
        HDF_LOGD("ret:%{public}d", ret);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: GetEffectInfoTest001
  * @tc.desc: Get effect information with the given effect type.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, GetEffectInfoTest001, TestSize.Level1)
{
    HDF_LOGI("GetEffectInfoTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    int32_t ret = g_vibratorInterface->GetEffectInfo({0, 0}, "haptic.pattern.type1", effectInfo);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(effectInfo.duration, 1900);
    EXPECT_EQ(effectInfo.isSupportEffect, true);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: GetEffectInfoTest002
  * @tc.desc: Get effect information with the given effect type.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, GetEffectInfoTest002, TestSize.Level1)
{
    HDF_LOGI("GetEffectInfoTest002 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    int32_t ret = g_vibratorInterface->GetEffectInfo({0, 0}, "invalid.effect.id", effectInfo);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(effectInfo.duration, 0);
    EXPECT_EQ(effectInfo.isSupportEffect, false);
}

/**
  * @tc.name: VibratorStopTest001
  * @tc.desc: Stop vibration.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, VibratorStopTest001, TestSize.Level1)
{
    HDF_LOGI("VibratorStopTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->StartOnce({0, 0}, 2000);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalMSleep(1000);
    ret = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: IsVibratorRunningTest001
  * @tc.desc: Get vibration status.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, IsVibratorRunningTest001, TestSize.Level1)
{
    HDF_LOGI("IsVibratorRunningTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    if (g_hapticCapacity.isSupportPresetMapping) {
        HDF_LOGI("IsVibratorRunningTest001 phone in");
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
        int32_t ret = g_vibratorInterface->EnableCompositeEffect({0, 0}, effect);
        HDF_LOGD("ret:%{public}d", ret);
        EXPECT_EQ(HDF_SUCCESS, ret);

        bool state {false};
        g_vibratorInterface->IsVibratorRunning({0, 0}, state);
        HDF_LOGD("Vibrating state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
        EXPECT_EQ(state, true);

        OsalMSleep(3000);
        g_vibratorInterface->IsVibratorRunning({0, 0}, state);
        HDF_LOGD("Stoped state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
        EXPECT_EQ(state, false);
    }
}

/**
  * @tc.name: IsVibratorRunningTest002
  * @tc.desc: Get vibration status.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, IsVibratorRunningTest002, TestSize.Level1)
{
    HDF_LOGI("IsVibratorRunningTest002 in");
    bool state {false};
    g_vibratorInterface->IsVibratorRunning({0, 0}, state);
    HDF_LOGD("No vibrate state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
    EXPECT_EQ(state, false);
}

/**
  * @tc.name: GetVibratorInfo001
  * @tc.desc: Get vibrator information.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, GetVibratorInfo001, TestSize.Level1)
{
    HDF_LOGI("GetVibratorInfo001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);
    std::vector<V2_0::HdfVibratorInfo> info;
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
  * @tc.require: #I4NN4Z
  */
HWTEST_F(VibratorImplTest, EnableVibratorModulation_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    std::vector<V2_0::HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        uint32_t duration = 2000;
        int32_t intensity = 30;
        int32_t frequency = 200;
        uint32_t sleepTime = 2000;
        startRet = g_vibratorInterface->EnableVibratorModulation({0, 0}, duration, intensity, frequency);
        EXPECT_EQ(startRet, HDF_SUCCESS);
        OsalMSleep(sleepTime);
        startRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
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
HWTEST_F(VibratorImplTest, EnableVibratorModulation_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    std::vector<V2_0::HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        uint32_t noDuration = 0;
        int32_t intensity = 30;
        int32_t frequency = 200;
        startRet = g_vibratorInterface->EnableVibratorModulation({0, 0}, noDuration, intensity, frequency);
        EXPECT_EQ(startRet, -1);
    }
}

/**
  * @tc.name: VibratorStartTest011
  * @tc.desc: Start periodic vibration with preset effect.
  * @tc.type: FUNC
  * @tc.require: AR000HQ6N2
  */
HWTEST_F(VibratorImplTest, VibratorStartTest011, TestSize.Level1)
{
    HDF_LOGI("VibratorStartTest011 in");
    ASSERT_NE(nullptr, g_vibratorInterface);
    
    HdfEffectInfo effectInfo;
    for (auto iter : g_effect) {
        g_vibratorInterface->GetEffectInfo({0, 0}, iter, effectInfo);
        if (effectInfo.isSupportEffect == true) {
            printf("VibratorStart : %s\n", iter.c_str());
            int32_t ret = g_vibratorInterface->Start({0, 0}, iter);
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
  * @tc.require:#I8BZ5H
  */
HWTEST_F(VibratorImplTest, PlayHapticPattern, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->PlayHapticPattern({0, 0}, g_pkg);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: PlayHapticPattern_001
  * @tc.desc: HD vibration data packet delivery.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(VibratorImplTest, PlayHapticPattern_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
 
    int32_t startRet = g_vibratorInterface->PlayHapticPattern({0, 0}, g_pkg1);
    EXPECT_EQ(startRet, HDF_SUCCESS);
 
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: GetHapticStartUpTime
  * @tc.desc: Indicates the time from command is issued to the time the motor starts.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(VibratorImplTest, GetHapticStartUpTime, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startUpTime = 0;
    int32_t mode = 0;
    int32_t startRet = g_vibratorInterface->GetHapticStartUpTime({0, 0}, mode, startUpTime);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    printf("startUpTime = %d\n", startUpTime);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopV1_2Test_001
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(VibratorImplTest, StopV1_2Test_001, TestSize.Level1)
{
    HDF_LOGI("StopV1_2Test_001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce({0, 0}, g_duration);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopV1_2Test_002
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(VibratorImplTest, StopV1_2Test_002, TestSize.Level1)
{
    HDF_LOGI("StopV1_2Test_002 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, g_effect1);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopV1_2Test_003
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(VibratorImplTest, StopV1_2Test_003, TestSize.Level1)
{
    HDF_LOGI("StopV1_2Test_003 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->PlayHapticPattern({0, 0}, g_pkg);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: StopV1_2Test_004
  * @tc.desc: Controls this vibrator to stop the vibrator.
  * @tc.type: FUNC
  * @tc.require:#I8BZ5H
  */
HWTEST_F(VibratorImplTest, StopV1_2Test_004, TestSize.Level1)
{
    HDF_LOGI("StopV1_2Test_004 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, g_effect1);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_BUTT);
    EXPECT_EQ(endRet, HDF_ERR_INVALID_PARAM);
}

/**
  * @tc.name: StartByIntensityTest
  * @tc.desc: Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require:#I96NNZ
  */
HWTEST_F(VibratorImplTest, StartByIntensityTest, TestSize.Level1)
{
    HDF_LOGI("StartByIntensityTest in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartByIntensity({0, 0}, g_effect1, g_intensity);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}
 
/**
  * @tc.name: StopTest
  * @tc.desc: Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require:#I96NNZ
  */
HWTEST_F(VibratorImplTest, StopTest, TestSize.Level1)
{
    HDF_LOGI("StopTest in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce({0, 0}, g_duration);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
    OsalMSleep(g_duration);
 
    startRet = g_vibratorInterface->StartByIntensity({0, 0}, g_effect1, g_intensity);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
    OsalMSleep(g_duration);

    startRet = g_vibratorInterface->Start({0, 0}, g_effect1);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_BUTT);
    EXPECT_EQ(endRet, HDF_ERR_INVALID_PARAM);
    OsalMSleep(g_duration);
}
 
/**
  * @tc.name: GetAllWaveInfoTest
  * @tc.desc: Controls this Performing Time Series Vibrator Effects.
  * Controls this vibrator to stop the vibrator
  * @tc.type: FUNC
  * @tc.require:#I96NNZ
  */
HWTEST_F(VibratorImplTest, GetAllWaveInfoTest, TestSize.Level1)
{
    HDF_LOGI("StartByIntensityTest in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->GetAllWaveInfo({0, 0}, g_info);
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

/**
  * @tc.name: multi stop test
  * @tc.desc: test multi ways to stop the vibrator
  * @tc.type: FUNC
  */
HWTEST_F(VibratorImplTest, MultiStopTest_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartByIntensity({0, 0}, g_effect1, g_intensity);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: multi stop test
  * @tc.desc: test multi ways to stop the vibrator
  * @tc.type: FUNC
  */
HWTEST_F(VibratorImplTest, MultiStopTest_002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartByIntensity({0, 0}, g_effect1, g_intensity);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: multi stop test
  * @tc.desc: test multi ways to stop the vibrator
  * @tc.type: FUNC
  */
HWTEST_F(VibratorImplTest, MultiStopTest_003, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartByIntensity({0, 0}, g_effect1, g_intensity);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: multi stop test
  * @tc.desc: test multi ways to stop the vibrator
  * @tc.type: FUNC
  */
HWTEST_F(VibratorImplTest, StartOnce_MultiStopTest_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce({0, 0}, 2000);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: multi stop test
  * @tc.desc: test multi ways to stop the vibrator
  * @tc.type: FUNC
  */
HWTEST_F(VibratorImplTest, StartOnce_MultiStopTest_002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce({0, 0}, 2000);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: multi stop test
  * @tc.desc: test multi ways to stop the vibrator
  * @tc.type: FUNC
  */
HWTEST_F(VibratorImplTest, StartOnce_MultiStopTest_003, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->StartOnce({0, 0}, 2000);
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

/**
  * @tc.name: running status check
  * @tc.desc: test running status after vibrator on
  * @tc.type: FUNC
  */
HWTEST_F(VibratorImplTest, StartPreset_RunningStatus_001, TestSize.Level1)
{
    HDF_LOGI("StartPreset_RunningStatus_001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, g_effect1);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    bool state {false};
    g_vibratorInterface->IsVibratorRunning({0, 0}, state);
    HDF_LOGD("Vibrating state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
    EXPECT_EQ(state, true);
}

HWTEST_F(VibratorImplTest, StartPreset_hard_case_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.hard");
    EXPECT_EQ(startRet, HDF_SUCCESS);

    bool state {false};
    g_vibratorInterface->IsVibratorRunning({0, 0}, state);
    HDF_LOGD("Vibrating state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
    EXPECT_EQ(state, true);
}

HWTEST_F(VibratorImplTest, StartPreset_hard_stop_case_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.hard");
    EXPECT_EQ(startRet, HDF_SUCCESS);

    bool state {false};
    g_vibratorInterface->IsVibratorRunning({0, 0}, state);
    HDF_LOGD("Vibrating state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
    EXPECT_EQ(state, true);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_sharp_case_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);

    bool state {false};
    g_vibratorInterface->IsVibratorRunning({0, 0}, state);
    HDF_LOGD("Vibrating state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
    EXPECT_EQ(state, true);
}

HWTEST_F(VibratorImplTest, StartPreset_sharp_stop_case_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);

    bool state {false};
    g_vibratorInterface->IsVibratorRunning({0, 0}, state);
    HDF_LOGD("Vibrating state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
    EXPECT_EQ(state, true);

    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.common.long_press");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_003, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.max");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_004, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.min");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength1");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength2");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_007, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength3");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_008, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength4");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_009, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength5");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_010, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.focus");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_011, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.click");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_012, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.mode_switch");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_013, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.slide");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_014, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.AIbar");
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_case_015, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.common.long_press");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.common.long_press");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.max");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.min");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength1");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength2");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_007, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength3");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_008, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength4");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_009, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength5");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_010, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.focus");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_011, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.click");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_012, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.mode_switch");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_013, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.slide");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_info_stop_case_014, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.AIbar");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.common.long_press");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.max");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.min");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength1");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_006, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength2");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_007, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength3");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_008, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength4");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_009, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength5");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_010, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.focus");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_011, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.click");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_012, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.mode_switch");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_013, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.slide");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_xml_hdhaptic_stop_case_014, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.AIbar");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.common.long_press");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_003, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.max");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_004, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.min");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_005, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength1");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_006, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength2");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_007, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength3");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_008, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength4");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_009, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength5");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_010, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.focus");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_011, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.click");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_012, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.mode_switch");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_013, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.slide");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_once_stop_case_014, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.AIbar");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_ONCE);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.common.long_press");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_003, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.max");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_004, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.min");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_005, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength1");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_006, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength2");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_007, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength3");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_008, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength4");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_009, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength5");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_010, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.focus");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_011, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.click");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_012, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.mode_switch");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_013, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.slide");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_preset_stop_case_014, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.AIbar");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.common.long_press");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_003, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.max");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_004, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.volume.min");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_005, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength1");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_006, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength2");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_007, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength3");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_008, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength4");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_009, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.grade.normal.strength5");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_010, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.focus");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_011, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.click");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_012, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.camera.mode_switch");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_013, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__);
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.slide");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_mult_xml_hdhaptic_stop_case_014, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->Start({0, 0}, "haptic.AIbar");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    startRet = g_vibratorInterface->Start({0, 0}, "haptic.effect.sharp");
    EXPECT_EQ(startRet, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_HDHAPTIC);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartPreset_low_int_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->StartByIntensity({0, 0}, g_effect1, 0);
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.effect.sharp", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.common.long_press", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.volume.max", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.volume.min", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength1", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength2", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_007, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength3", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_008, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength4", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_009, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength5", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_010, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.camera.focus", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_011, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.camera.click", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_012, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.camera.mode_switch", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_013, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.slide", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_014, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.AIbar", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_low_int_case_015, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.common.long_press", 0);
    EXPECT_EQ(ret, HDF_SUCCESS);
    int32_t endRet = g_vibratorInterface->Stop({0, 0}, HdfVibratorMode::HDF_VIBRATOR_MODE_PRESET);
    EXPECT_EQ(endRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, VibratorStartOnceLowTimeTest001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartOnce({0, 0}, 50); // test 50ms time convert to preset
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(50);
}

HWTEST_F(VibratorImplTest, VibratorStartOnceLowTimeTest002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartOnce({0, 0}, 30); // test 30ms time convert to preset
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(30);
}

HWTEST_F(VibratorImplTest, VibratorStartOnceLowTimeTest003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartOnce({0, 0}, 10); // test 10ms time convert to preset
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(30);
}

HWTEST_F(VibratorImplTest, VibratorStartOnceLowTimeTest004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartOnce({0, 0}, 5); // test 5ms time convert to preset
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(30);
}

HWTEST_F(VibratorImplTest, StartPreset_high_int_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet = g_vibratorInterface->StartByIntensity({0, 0}, g_effect1, g_highInt);
    EXPECT_EQ(startRet, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.effect.sharp", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.common.long_press", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.volume.max", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.volume.min", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret =
        g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength1", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret =
        g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength2", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_007, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret =
        g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength3", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_008, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret =
        g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength4", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_009, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret =
        g_vibratorInterface->StartByIntensity({0, 0}, "haptic.grade.normal.strength5", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_010, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.camera.focus", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_011, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret =
        g_vibratorInterface->StartByIntensity({0, 0}, "haptic.camera.click", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_012, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret =
        g_vibratorInterface->StartByIntensity({0, 0}, "haptic.camera.mode_switch", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_013, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.slide", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(VibratorImplTest, StartByIntensityPreset_xml_high_int_case_014, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t ret = g_vibratorInterface->StartByIntensity({0, 0}, "haptic.AIbar", g_highInt);
    EXPECT_EQ(ret, HDF_SUCCESS);
}