/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
    constexpr int32_t g_minLightId = HDF_LIGHT_ID_BATTERY;
    constexpr int32_t g_maxLightId = HDF_LIGHT_ID_ATTENTION;
    constexpr int32_t MAX_VALUE = 255;
    constexpr int32_t MIN_VALUE = 0;
    constexpr int32_t ON_TIME = 500;
    constexpr int32_t OFF_TIME = 500;
    std::vector<HdfLightInfo> g_info;
    sptr<ILightInterface> g_lightInterface = nullptr;

class HdfLightHdiServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfLightHdiServiceTest::SetUpTestCase()
{
    g_lightInterface = ILightInterface::Get();
}

void HdfLightHdiServiceTest::TearDownTestCase()
{
}

void HdfLightHdiServiceTest::SetUp()
{
}

void HdfLightHdiServiceTest::TearDown()
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
  * @tc.name: CheckLightInstanceIsEmpty
  * @tc.desc: Creat a light instance. The instance is not empty.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0100, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);
}

/**
  * @tc.name: GetLightInfo001
  * @tc.desc: Get light info.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0200, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, g_minLightId);
        EXPECT_LE(iter.lightId, g_maxLightId);
    }
}

/**
  * @tc.name: TurnOnLight001
  * @tc.desc: TurnOnLight.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0300, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(HDF_SUCCESS, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, g_minLightId);
        EXPECT_LE(iter.lightId, g_maxLightId);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = 255;
        effect.lightColor.colorValue.rgbColor.g = 0;
        effect.lightColor.colorValue.rgbColor.b = 0;
        effect.flashEffect.flashMode = LIGHT_FLASH_NONE;
        int32_t ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(g_sleepTime);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: TurnOnLight002
  * @tc.desc: TurnOnLight.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0400, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, g_minLightId);
        EXPECT_LE(iter.lightId, g_maxLightId);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = 255;
        effect.lightColor.colorValue.rgbColor.g = 0;
        effect.lightColor.colorValue.rgbColor.b = 0;
        effect.flashEffect.flashMode = LIGHT_FLASH_BUTT;
        int32_t ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(LIGHT_NOT_FLASH, ret);
    }
}

/**
  * @tc.name: TurnOnLight003
  * @tc.desc: TurnOnLight.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0500, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, g_minLightId);
        EXPECT_LE(iter.lightId, g_maxLightId);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = 255;
        effect.lightColor.colorValue.rgbColor.g = 0;
        effect.lightColor.colorValue.rgbColor.b = 0;
        effect.flashEffect.flashMode = LIGHT_FLASH_BLINK;
        effect.flashEffect.onTime = ON_TIME;
        effect.flashEffect.offTime = OFF_TIME;
        int32_t ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(g_sleepTime);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: TurnOnLight005
  * @tc.desc: TurnOnLight.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0600, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(HDF_SUCCESS, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, g_minLightId);
        EXPECT_LE(iter.lightId, g_maxLightId);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = 255;
        effect.lightColor.colorValue.rgbColor.g = 0;
        effect.lightColor.colorValue.rgbColor.b = 0;
        effect.flashEffect.flashMode = LIGHT_FLASH_GRADIENT;
        int32_t ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        OsalSleep(g_sleepTime);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: DisableLight001
  * @tc.desc: DisableLight.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0700, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    int32_t ret  = g_lightInterface->TurnOnLight(HDF_LIGHT_ID_BUTT, effect);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
    ret  = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_BUTT);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
}

/**
  * @tc.name: DisableLight002
  * @tc.desc: DisableLight.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0800, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    int32_t ret  = g_lightInterface->TurnOnLight(HDF_LIGHT_ID_NOTIFICATIONS, effect);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
    ret  = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_NOTIFICATIONS);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
}

/**
  * @tc.name: TurnOnMultiLights001
  * @tc.desc: DTurnOnMultiLights.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_0900, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface-> GetLightInfo(info);
    EXPECT_EQ(0, ret);
    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, g_minLightId);
        EXPECT_LE(iter.lightId, g_maxLightId);
        std::vector<HdfLightColor> lightColor;
        struct HdfLightColor light;
        light.colorValue.rgbColor.b = 0;
        lightColor.push_back(light);
        ret = g_lightInterface->TurnOnMultiLights(iter.lightId, lightColor);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: TurnOnLightRed001
  * @tc.desc: Turn on the battery light is steady on red.
  * @tc.type: FUNC
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1000, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1100, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1200, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1300, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1400, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1500, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1600, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1700, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1800, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_1900, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_2000, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_2100, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_2200, Function | MediumTest | Level1)
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
  */
HWTEST_F(HdfLightHdiServiceTest, SUB_Driver_Sensor_HdiLight_2300, Function | MediumTest | Level1)
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

/* *
 * @tc.number: SUB_Driver_Light_GetlightInfo_0200
 * @tc.name  : testhdiServiceGetLightInfoTimes001
 * @tc.desc  : Get light info 10times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceGetLightInfoTimes001, Function | MediumTest | Level1)
{
    int32_t ret;

    ASSERT_NE(nullptr, g_lightInterface);

    for (int i = 0; i < 10; i++) {
        ret = g_lightInterface->GetLightInfo(g_info);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(g_info.size(), 0);
        printf("get light list num[%zu]\n\r", g_info.size());

        for (auto iter : g_info) {
            printf("lightId[%d], lightName[%s], lightNumber[%d]\n\r", iter.lightId, iter.lightName.c_str(),
                   iter.lightNumber);
        }
    }
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_0500
 * @tc.name  : testhdiServiceTurnOnLightMAX001
 * @tc.desc  : Enter the minimum excess value to turn on the red light.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightMAX001, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_0600
 * @tc.name  : testhdiServiceTurnOnLightRedMAX001
 * @tc.desc  : Enter the maximum excess value to turn on the red light.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightRedMAX001, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_0700
 * @tc.name  : testhdiServiceTurnOnLightRedMAXTimes001
 * @tc.desc  : Turn on the light and it's always red 10 times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightRedMAXTimes001, Function | MediumTest | Level1)
{
    int32_t ret;

    ASSERT_NE(nullptr, g_lightInterface);

    for (int i = 0; i < 10; i++) {
        HdfLightEffect effect;
        InitConfig(effect);
        effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
        ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(SLEEPTIME);

        ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_0800
 * @tc.name  : testhdiServiceTurnOnLightGreenMAX001
 * @tc.desc  : Enter the maximum excess value to turn on the green light.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightGreenMAX001, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_0900
 * @tc.name  : testhdiServiceTurnOnLightGreenMAXTimes001
 * @tc.desc  : Turn on the light and it's always green 10 times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightGreenMAXTimes001, Function | MediumTest | Level1)
{
    int32_t ret;
    ASSERT_NE(nullptr, g_lightInterface);

    for (int i = 0; i < 10; i++) {
        HdfLightEffect effect;
        InitConfig(effect);
        effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
        ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(SLEEPTIME);

        ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_1000
 * @tc.name  : testhdiServiceTurnOnLightBlueMAX001
 * @tc.desc  : Enter the maximum excess value to turn on the blue light.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightBlueMAX001, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_1100
 * @tc.name  : testhdiServiceTurnOnLightBlueMAXTimes001
 * @tc.desc  : Turn on the light and it's always blue 10 times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightBlueMAXTimes001, Function | MediumTest | Level1)
{
    int32_t ret;
    ASSERT_NE(nullptr, g_lightInterface);

    for (int i = 0; i < 10; i++) {
        HdfLightEffect effect;
        InitConfig(effect);
        effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
        ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(SLEEPTIME);

        ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_1200
 * @tc.name  : testhdiServiceTurnOnLightFM001
 * @tc.desc  : The input is Abnormal flashmode.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightFM001, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.flashEffect.flashMode = 0;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_1300
 * @tc.name  : testhdiServiceTurnOnLightTime001
 * @tc.desc  : Turn on the light Abnormal times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightTime001, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.flashEffect.onTime = -1;
    effect.flashEffect.offTime = 10;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_1400
 * @tc.name  : testhdiServiceTurnOnLightTime002
 * @tc.desc  : Turn on the light Abnormal times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightTime002, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.flashEffect.onTime = 10;
    effect.flashEffect.offTime = -1;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_1500
 * @tc.name  : testhdiServiceTurnOnLightTime003
 * @tc.desc  : Turn on the light times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightTime003, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.flashEffect.onTime = 256;
    effect.flashEffect.offTime = 0;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnLight_1600
 * @tc.name  : testhdiServiceTurnOnLightTime004
 * @tc.desc  : Turn on the light times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnLightTime004, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.flashEffect.onTime = 0;
    effect.flashEffect.offTime = 256;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnMultiLights_0200
 * @tc.name  : testhdiServiceTurnOnMultiLightsRedMAX001
 * @tc.desc  : Turn on the light Abnormal lightid.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnMultiLightsRedMAX001, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightColor> lightColor;
    struct HdfLightColor light;
    light.colorValue.rgbColor.r = MAX_VALUE;
    lightColor.push_back(light);

    int32_t ret = g_lightInterface->TurnOnMultiLights(HDF_LIGHT_ID_BATTERY, lightColor);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_NOTIFICATIONS);
    EXPECT_EQ(HDF_FAILURE, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOnMultiLights_0300
 * @tc.name  : testhdiServiceTurnOnMultiLightsTimes001
 * @tc.desc  : Turn on the light lightid 10 times.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOnMultiLightsTimes001, Function | MediumTest | Level1)
{
    int32_t ret;

    ASSERT_NE(nullptr, g_lightInterface);
    for (int i = 0; i < 10; i++) {
        std::vector<HdfLightColor> lightColor;
        struct HdfLightColor light;
        light.colorValue.rgbColor.r = MAX_VALUE;
        light.colorValue.rgbColor.g = MIN_VALUE;
        light.colorValue.rgbColor.b = MIN_VALUE;
        lightColor.push_back(light);
        ret = g_lightInterface->TurnOnMultiLights(HDF_LIGHT_ID_BATTERY, lightColor);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(SLEEPTIME);

        ret = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_BATTERY);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOffLight_0100
 * @tc.name  : testhdiServiceTurnOffBattery001
 * @tc.desc  : Turn Off Light.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOffBattery001, Function | MediumTest | Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightColor> lightColor;
    struct HdfLightColor light;
    light.colorValue.rgbColor.r = MAX_VALUE;
    lightColor.push_back(light);

    int32_t ret = g_lightInterface->TurnOnMultiLights(HDF_LIGHT_ID_BATTERY, lightColor);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOffLight_0200
 * @tc.name  : testhdiServiceTurnOffNotifications001
 * @tc.desc  : Turn Off Light.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOffNotifications001, Function | MediumTest | Level2)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightColor> lightColor;
    struct HdfLightColor light;
    light.colorValue.rgbColor.r = MAX_VALUE;
    lightColor.push_back(light);

    int32_t ret = g_lightInterface->TurnOnMultiLights(HDF_LIGHT_ID_BATTERY, lightColor);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_NOTIFICATIONS);
    EXPECT_EQ(HDF_FAILURE, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOffLight_0300
 * @tc.name  : testhdiServiceTurnOffAttention001
 * @tc.desc  : Turn Off Light.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOffAttention001, Function | MediumTest | Level2)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightColor> lightColor;
    struct HdfLightColor light;
    light.colorValue.rgbColor.r = MAX_VALUE;
    lightColor.push_back(light);

    int32_t ret = g_lightInterface->TurnOnMultiLights(HDF_LIGHT_ID_BATTERY, lightColor);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_ATTENTION);
    EXPECT_EQ(HDF_FAILURE, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOffLight_0400
 * @tc.name  : testhdiServiceTurnOffButt001
 * @tc.desc  : Turn Off Light.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOffButt001, Function | MediumTest | Level2)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightColor> lightColor;
    struct HdfLightColor light;
    light.colorValue.rgbColor.r = MAX_VALUE;
    lightColor.push_back(light);

    int32_t ret = g_lightInterface->TurnOnMultiLights(HDF_LIGHT_ID_BUTT, lightColor);
    EXPECT_EQ(-2, ret);
    OsalSleep(SLEEPTIME);

    ret = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_BUTT);
    EXPECT_EQ(HDF_FAILURE, ret);
}

/* *
 * @tc.number: SUB_Driver_Light_TurnOffLight_0500
 * @tc.name  : testhdiServiceTurnOffNoOn001
 * @tc.desc  : Turn it off when it's not on.
 */
HWTEST_F(HatsHdfLightCommonTestAdditional, testhdiServiceTurnOffNoOn001, Function | MediumTest | Level2)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightColor> lightColor;
    struct HdfLightColor light;
    light.colorValue.rgbColor.r = MAX_VALUE;
    lightColor.push_back(light);

    int32_t ret = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_BUTT);
    EXPECT_EQ(HDF_FAILURE, ret);
}
} // namespace