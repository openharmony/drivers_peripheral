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
#include "v1_0/ilight_interface.h"
#include "light_if.h"

using namespace OHOS::HDI::Light::V1_0;
using namespace testing::ext;

namespace {
    constexpr uint32_t g_sleepTime = 3;
    constexpr int32_t MAX_VALUE = 255;
    constexpr int32_t MIN_VALUE = 0;
    constexpr int32_t ON_TIME = 500;
    constexpr int32_t OFF_TIME = 500;
    std::vector<HdfLightInfo> g_info;
    sptr<ILightInterface> g_lightInterface = nullptr;
}

class HdfLightHdiTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfLightHdiTest::SetUpTestCase()
{
    g_lightInterface = ILightInterface::Get();
}

void HdfLightHdiTest::TearDownTestCase()
{
}

void HdfLightHdiTest::SetUp()
{
}

void HdfLightHdiTest::TearDown()
{
}

static void InitConfig(HdfLightEffect &effect)
{
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_NONE;
}

static int32_t IsSupportedlightId(int32_t lightId)
{
    EXPECT_GT(g_info.size(), 0);

    bool result = std::any_of(g_info.begin(), g_info.end(),
        [lightId](const HdfLightInfo &info) {return info.lightId == lightId;});
    if (result) {
        return LIGHT_SUCCESS;
    }
    return NOT_SUPPORT;
}

static void LightTest(int32_t lightId, int32_t lightFlashMode, HdfLightEffect &effect)
{
    if (lightFlashMode != HDF_LIGHT_FLASH_NONE) {
        effect.flashEffect.onTime = ON_TIME;
        effect.flashEffect.offTime = OFF_TIME;
    }
    effect.flashEffect.flashMode = lightFlashMode;

    int32_t ans = IsSupportedlightId(lightId);
    int32_t ret = g_lightInterface->TurnOnLight(lightId, effect);
    printf("on--lightId: %d, ret: %d, ans: %d\n", lightId, ret, ans);
    EXPECT_EQ(ans, ret);

    OsalSleep(g_sleepTime);
    ret = g_lightInterface->TurnOffLight(lightId);
    printf("off--lightId: %d, ret: %d, ans: %d\n", lightId, ret, ans);
    EXPECT_EQ(ans, ret);
}
/**
  * @tc.name: TurnOnMultiLight001
  * @tc.desc: Turn on multiple lights.
  * @tc.type: FUNC
  * @tc.require: AR000HHMA4
  */
HWTEST_F(HdfLightHdiTest, TurnOnMultiLight001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    struct HdfLightColor color = {
        .colorValue.rgbColor.r = MAX_VALUE,
        .colorValue.rgbColor.g = MAX_VALUE,
        .colorValue.rgbColor.b = MAX_VALUE,
    };
    std::vector<HdfLightColor> lightColor;
    lightColor.push_back(color);

    int32_t ret = IsSupportedlightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnMultiLights(lightId, lightColor);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnMultiLight002
  * @tc.desc: Turn on multiple lights.
  * @tc.type: FUNC
  * @tc.require: AR000HHMA4
  */
HWTEST_F(HdfLightHdiTest, TurnOnMultiLight002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_BATTERY;
    struct HdfLightColor color1 = {
        .colorValue.rgbColor.r = MAX_VALUE,
        .colorValue.rgbColor.g = MAX_VALUE,
        .colorValue.rgbColor.b = MAX_VALUE,
    };
    struct HdfLightColor color2 = {
        .colorValue.rgbColor.r = MAX_VALUE,
        .colorValue.rgbColor.g = MAX_VALUE,
        .colorValue.rgbColor.b = 0,
    };
    std::vector<HdfLightColor> lightColor;
    lightColor.push_back(color1);
    lightColor.push_back(color2);

    int32_t ret = IsSupportedlightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnMultiLights(lightId, lightColor);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlinkException001
  * @tc.desc: The ontime setting is abnormal in blinking mode.
  * @tc.type: FUNC
  * @tc.require: AR000HHMA4
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightBlinkException001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = MAX_VALUE,
        .lightColor.colorValue.rgbColor.g = MAX_VALUE,
        .lightColor.colorValue.rgbColor.b = MAX_VALUE,
        .flashEffect.onTime = -1,
        .flashEffect.offTime = OFF_TIME,
        .flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK,
    };

    int32_t ret = IsSupportedlightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlinkException002
  * @tc.desc: The ontime setting is abnormal in blinking mode.
  * @tc.type: FUNC
  * @tc.require: AR000HHMA4
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightBlinkException002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = MAX_VALUE,
        .lightColor.colorValue.rgbColor.g = MAX_VALUE,
        .lightColor.colorValue.rgbColor.b = MAX_VALUE,
        .flashEffect.onTime = ON_TIME,
        .flashEffect.offTime = -1,
        .flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK,
    };

    int32_t ret = IsSupportedlightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGradientException001
  * @tc.desc: The ontime setting is abnormal in gradient mode.
  * @tc.type: FUNC
  * @tc.require: AR000HHMA4
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightGradientException001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = MAX_VALUE,
        .lightColor.colorValue.rgbColor.g = MAX_VALUE,
        .lightColor.colorValue.rgbColor.b = MAX_VALUE,
        .flashEffect.onTime = -1,
        .flashEffect.offTime = OFF_TIME,
        .flashEffect.flashMode = HDF_LIGHT_FLASH_GRADIENT,
    };

    int32_t ret = IsSupportedlightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGradientException002
  * @tc.desc: The ontime setting is abnormal in gradient mode.
  * @tc.type: FUNC
  * @tc.require: AR000HHMA4
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightGradientException002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = MAX_VALUE,
        .lightColor.colorValue.rgbColor.g = MAX_VALUE,
        .lightColor.colorValue.rgbColor.b = MAX_VALUE,
        .flashEffect.onTime = ON_TIME,
        .flashEffect.offTime = -1,
        .flashEffect.flashMode = HDF_LIGHT_FLASH_GRADIENT,
    };

    int32_t ret = IsSupportedlightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}