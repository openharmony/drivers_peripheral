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

#include <cmath>
#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include "hdf_base.h"
#include "osal_time.h"
#include "v1_3/ivibrator_interface.h"
#include "vibrator_type.h"
#include "vibrator_uhdf_log.h"

using namespace OHOS::HDI::Vibrator;
using namespace OHOS::HDI::Vibrator::V1_3;
using namespace testing::ext;

namespace {
    const std::vector<std::string> g_effect{"haptic.long_press.light", "haptic.slide.light", \
        "haptic.threshold", "haptic.long_press.medium", "haptic.fail", "haptic.common.notice1", \
        "haptic.common.success", "haptic.charging", "haptic.long+press.heavy"};
    const std::string DEVICETYPE_KEY = "const.product.devicetype";
    const std::string PHONE_TYPE = "phone";
    uint32_t g_duration2 = 2000;
    uint32_t g_duration3 = 0;
    uint32_t g_sleepTime3 = 2000;
    uint32_t g_sleepTime4 = 1000;
    uint32_t g_sleepTime5 = 3000;
    int32_t g_intensity3 = 30;
    int32_t g_frequency3 = 200;
    std::string g_effectType1 = "haptic.pattern.type1";
    std::string g_effectType2 = "invalid.effect.id";
    V1_2::PrimitiveEffect g_primitiveEffect1 { 0, 60007, 0 };
    V1_2::PrimitiveEffect g_primitiveEffect2 { 1000, 60007, 0 };
    V1_2::PrimitiveEffect g_primitiveEffect3 { 1000, 60007, 0 };
    V1_2::PrimitiveEffect g_primitiveEffect4 { 0, 60007, 0 };
    V1_2::PrimitiveEffect g_primitiveEffect5 { 1000, 60007, 0 };
    V1_2::PrimitiveEffect g_primitiveEffect6 { 1000, 60007, 0 };
    sptr<OHOS::HDI::Vibrator::V1_3::IVibratorInterface> g_vibratorInterface = nullptr;
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
    g_vibratorInterface = OHOS::HDI::Vibrator::V1_3::IVibratorInterface::Get();
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
  * @tc.name: VibratorStartOnceTest001
  * @tc.desc: Start one-shot vibratation with given duration.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, VibratorStartOnceTest001, TestSize.Level1)
{
    HDF_LOGI("VibratorStartOnceTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->StartOnce(g_duration2);
    HDF_LOGI("ret:%{public}d", ret);
    EXPECT_EQ(ret, HDF_SUCCESS);
    OsalMSleep(g_sleepTime3);
}

/**
  * @tc.name: VibratorStartTest001
  * @tc.desc: Start periodic vibration with preset effect.
  * @tc.type: FUNC
  * @tc.require:#14NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, VibratorStartTest001, TestSize.Level1)
{
    HDF_LOGI("VibratorStartTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->Start(g_effectType1);
    HDF_LOGI("ret:%{public}d", ret);
    EXPECT_EQ(ret, HDF_SUCCESS);
    OsalMSleep(g_sleepTime3);
}

/**
  * @tc.name: EnableCompositeEffectTest001
  * @tc.desc: Start periodic vibration with custom composite effect.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, EnableCompositeEffectTest001, TestSize.Level1)
{
    HDF_LOGI("EnableCompositeEffectTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    if (OHOS::system::GetParameter(DEVICETYPE_KEY, "") == PHONE_TYPE) {
        HDF_LOGI("EnableCompositeEffectTest001 phone in");
        V1_2::CompositeEffect effect1 = {
            .primitiveEffect = g_primitiveEffect1,
        };
        V1_2::CompositeEffect effect2 = {
            .primitiveEffect = g_primitiveEffect2,
        };
        V1_2::CompositeEffect effect3 = {
            .primitiveEffect = g_primitiveEffect3,
        };
        std::vector<V1_2::CompositeEffect> vec;
        vec.push_back(effect1);
        vec.push_back(effect2);
        vec.push_back(effect3);
        V1_2::HdfCompositeEffect effect;
        effect.type = V1_2::HDF_EFFECT_TYPE_PRIMITIVE;
        effect.compositeEffects = vec;
        int32_t ret = g_vibratorInterface->EnableCompositeEffect(effect);
        HDF_LOGI("ret:%{public}d", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);
        OsalMSleep(2000);
    }
}

/**
  * @tc.name: EnableCompositeEffectTest002
  * @tc.desc: Start periodic vibration with custom composite effect.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, EnableCompositeEffectTest002, TestSize.Level1)
{
    HDF_LOGI("EnableCompositeEffectTest002 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    if (OHOS::system::GetParameter(DEVICETYPE_KEY, "") == PHONE_TYPE) {
        HDF_LOGI("EnableCompositeEffectTest002 phone in");
        V1_2::CompositeEffect effect1 = {
            .primitiveEffect = g_primitiveEffect4,
        };
        V1_2::CompositeEffect effect2 = {
            .primitiveEffect = g_primitiveEffect5,
        };
        V1_2::CompositeEffect effect3 = {
            .primitiveEffect = g_primitiveEffect6,
        };
        std::vector<V1_2::CompositeEffect> vec;
        vec.push_back(effect1);
        vec.push_back(effect2);
        vec.push_back(effect3);
        V1_2::HdfCompositeEffect effect;
        effect.type = V1_2::HDF_EFFECT_TYPE_PRIMITIVE;
        effect.compositeEffects = vec;
        int32_t ret = g_vibratorInterface->EnableCompositeEffect(effect);
        HDF_LOGI("ret:%{public}d", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        OsalMSleep(g_sleepTime4);
        ret = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_PRESET);
        HDF_LOGD("ret:%{public}d", ret);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: GetVibratorInfoTest001
  * @tc.desc: Get effect information with the given effect type.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, GetEffectInfoTest001, TestSize.Level1)
{
    HDF_LOGI("GetVibratorInfoTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    int32_t ret = g_vibratorInterface->GetEffectInfo(g_effectType1, effectInfo);
    HDF_LOGI("ret:%{public}d", ret);
    EXPECT_EQ(effectInfo.duration, 1900);
    EXPECT_EQ(effectInfo.isSupportEffect, true);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
  * @tc.name: GetVibratorInfoTest002
  * @tc.desc: Get effect information with the given effect type.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, GetEffectInfoTest002, TestSize.Level1)
{
    HDF_LOGI("GetVibratorInfoTest002 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    HdfEffectInfo effectInfo;
    int32_t ret = g_vibratorInterface->GetEffectInfo(g_effectType2, effectInfo);
    HDF_LOGI("ret:%{public}d", ret);
    EXPECT_EQ(effectInfo.duration, 0);
    EXPECT_EQ(effectInfo.isSupportEffect, false);
}

/**
  * @tc.name: VibratorStopTest001
  * @tc.desc: Stop vibration.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, VibratorStopTest001, TestSize.Level1)
{
    HDF_LOGI("VibratorStopTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->StartOnce(g_duration2);
    HDF_LOGI("ret:%{public}d", ret);
    EXPECT_EQ(ret, HDF_SUCCESS);

    OsalMSleep(g_sleepTime4);
    ret = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE);
    HDF_LOGI("ret:%{public}d", ret);
    EXPECT_EQ(ret, HDF_SUCCESS);
}

/**
  * @tc.name: IsVibratorRunningTest001
  * @tc.desc: Get vibration status.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, IsVibratorRunningTest001, TestSize.Level1)
{
    HDF_LOGI("IsVibratorRunningTest001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    if (OHOS::system::GetParameter(DEVICETYPE_KEY, "") == PHONE_TYPE) {
        HDF_LOGI("IsVibratorRunningTest001 phone in");
        V1_2::CompositeEffect effect1 = {
            .primitiveEffect = g_primitiveEffect4,
        };
        V1_2::CompositeEffect effect2 = {
            .primitiveEffect = g_primitiveEffect5,
        };
        V1_2::CompositeEffect effect3 = {
            .primitiveEffect = g_primitiveEffect6,
        };
        std::vector<V1_2::CompositeEffect> vec;
        vec.push_back(effect1);
        vec.push_back(effect2);
        vec.push_back(effect3);
        V1_2::HdfCompositeEffect effect;
        effect.type = V1_2::HDF_EFFECT_TYPE_PRIMITIVE;
        effect.compositeEffects = vec;
        int32_t ret = g_vibratorInterface->EnableCompositeEffect(effect);
        HDF_LOGI("ret:%{public}d", ret);
        EXPECT_EQ(ret, HDF_SUCCESS);

        bool state {false};
        g_vibratorInterface->IsVibratorRunning(state);
        HDF_LOGD("Vibrating state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
        EXPECT_EQ(state, true);

        OsalMSleep(g_sleepTime5);
        g_vibratorInterface->IsVibratorRunning(state);
        HDF_LOGD("Stoped state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
        EXPECT_EQ(state, false);
    }
}

/**
  * @tc.name: IsVibratorRunningTest002
  * @tc.desc: Get vibration status.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, IsVibratorRunningTest002, TestSize.Level1)
{
    HDF_LOGI("IsVibratorRunningTest002 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    bool state {false};
    g_vibratorInterface->IsVibratorRunning(state);
    HDF_LOGD("No vibrate state:%{public}s", state ? "is vibrating ..." : "vibrate stopped");
    EXPECT_EQ(state, false);
}

/**
  * @tc.name: GetVibratorInfo001
  * @tc.desc: Get vibration information.
  * @tc.type: FUNC
  * @tc.require:AR000HQ6N2
  */
HWTEST_F(HdfVibratorHdiTest, GetVibratorInfo001, TestSize.Level1)
{
    HDF_LOGI("GetVibratorInfo001 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;
    int32_t ret = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(ret, HDF_SUCCESS);
    EXPECT_GT(info.size(), 0);
    HDF_LOGI("isSupportIntensity = %{public}d, intensityMaxValue = %{public}d, intensityMinValue = %{public}d\n\t",
        info[0].isSupportIntensity, info[0].intensityMaxValue, info[0].intensityMinValue);
    HDF_LOGI("isSupportFrequency = %{public}d, frequencyMaxValue = %{public}d, frequencyMinValue = %{public}d\n\t",
        info[0].isSupportFrequency, info[0].frequencyMaxValue, info[0].frequencyMinValue);
}

/**
  * @tc.name: EnableVibratorModulation_005
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * @tc.type: FUNC
  * @tc.require:#14NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, EnableVibratorModulation_005, TestSize.Level1)
{
    HDF_LOGI("EnableVibratorModulation_005 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;
    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        startRet = g_vibratorInterface->EnableVibratorModulation(g_duration2, g_intensity3, g_frequency3);
        EXPECT_EQ(startRet, HDF_SUCCESS);
        OsalMSleep(g_sleepTime3);
        startRet = g_vibratorInterface->StopV1_2(HdfVibratorModeV1_2::HDF_VIBRATOR_MODE_ONCE);
        EXPECT_EQ(startRet, HDF_SUCCESS);
    }
}

/**
  * @tc.name: EnableVibratorModulation_006
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * @tc.type: FUNC
  * @tc.require:#14NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, EnableVibratorModulation_006, TestSize.Level1)
{
    HDF_LOGI("EnableVibratorModulation_006 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;
    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
        startRet = g_vibratorInterface->EnableVibratorModulation(g_duration3, g_intensity3, g_frequency3);
        EXPECT_EQ(startRet, -1);
    }
}

/**
  * @tc.name: VibratorStartTest011
  * @tc.desc: Start vibrator based on the setting vibration effect.
  * @tc.type: FUNC
  * @tc.require:#14NN4Z
  */
HWTEST_F(HdfVibratorHdiTest, VibratorStartTest011, TestSize.Level1)
{
    HDF_LOGI("VibratorStartTest011 in");
    ASSERT_NE(nullptr, g_vibratorInterface);

    for (auto iter : g_effect) {
        HdfEffectInfo effectInfo;
        g_vibratorInterface->GetEffectInfo(iter, effectInfo);
        if (effectInfo.isSupportEffect == true) {
            HDF_LOGI("vibratorStart : %{public}s\n", iter.c_str());
            int32_t ret = g_vibratorInterface->Start(iter);
            HDF_LOGD("ret:%{public}d", ret);
            EXPECT_EQ(HDF_SUCCESS, ret);
            OsalMSleep(2000);
        }
    }
}