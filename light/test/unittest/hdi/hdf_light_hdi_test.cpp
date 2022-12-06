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
#include "light_type.h"

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

void InitConfig(HdfLightEffect &effect)
{
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_NONE;
}

/**
  * @tc.name: TurnOnLightRed001
  * @tc.desc: Turn on the battery light is steady on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightRed_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreen001
  * @tc.desc: Turn on the battery light is steady on green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightGreen_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlue001
  * @tc.desc: Turn on the battery light is steady on blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightBlue_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRed002
  * @tc.desc: Turn on the battery light blinking red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightRed_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK;
    effect.flashEffect.onTime = ON_TIME;
    effect.flashEffect.offTime = OFF_TIME;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreen002
  * @tc.desc: Turn on the battery light blinking green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightGreen_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK;
    effect.flashEffect.onTime = ON_TIME;
    effect.flashEffect.offTime = OFF_TIME;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlue002
  * @tc.desc: Turn on the battery light blinking blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightBlue_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK;
    effect.flashEffect.onTime = ON_TIME;
    effect.flashEffect.offTime = OFF_TIME;
    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightUnsupport001
  * @tc.desc: Unsupported flashmode(HDF_LIGHT_FLASH_GRADIENT).
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightUnsupport_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_GRADIENT;
    effect.flashEffect.onTime = ON_TIME;
    effect.flashEffect.offTime = OFF_TIME;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(LIGHT_NOT_FLASH, ret);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightUnsupport002
  * @tc.desc: Unsupported lightID(LIGHT_ID_NOTIFICATIONS).
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightUnsupport_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_NOTIFICATIONS, effect);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
}

/**
  * @tc.name: TurnOnLightUnsupport003
  * @tc.desc: Unsupported lightID(LIGHT_ID_ATTENTION).
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightUnsupport_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_ATTENTION, effect);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal001
  * @tc.desc: Abnormal onTime in gradient mode.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightAbnormal_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_GRADIENT;
    effect.flashEffect.onTime = 0;
    effect.flashEffect.offTime = OFF_TIME;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(LIGHT_NOT_FLASH, ret);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal002
  * @tc.desc: Abnormal offTime in gradient mode.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightAbnormal_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_GRADIENT;
    effect.flashEffect.onTime = ON_TIME;
    effect.flashEffect.offTime = 0;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(LIGHT_NOT_FLASH, ret);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal003
  * @tc.desc: Abnormal onTime in blinking mode.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightAbnormal_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK;
    effect.flashEffect.onTime = 0;
    effect.flashEffect.offTime = OFF_TIME;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(LIGHT_NOT_FLASH, ret);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal004
  * @tc.desc: Abnormal offTime in blinking mode.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLightAbnormal_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK;
    effect.flashEffect.onTime = ON_TIME;
    effect.flashEffect.offTime = 0;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BATTERY, effect);
    EXPECT_EQ(LIGHT_NOT_FLASH, ret);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnMultiLights001
  * @tc.desc: TurnOnMultiLights.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnMultiLights_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightColor> lightColor;
    struct HdfLightColor light;
    light.colorValue.rgbColor.r = MAX_VALUE;
    light.colorValue.rgbColor.g = MIN_VALUE;
    light.colorValue.rgbColor.b = MIN_VALUE;
    lightColor.push_back(light);

    int32_t ret = g_lightInterface->TurnOnMultiLights(LIGHT_ID_BATTERY, lightColor);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}