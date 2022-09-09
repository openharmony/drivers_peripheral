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
    constexpr uint32_t g_sleepTime = 2;
    constexpr int32_t MIN_LIGHT_ID = HDF_LIGHT_ID_BATTERY;
    constexpr int32_t MAX_LIGHT_ID = HDF_LIGHT_ID_ATTENTION;
    constexpr int32_t ON_TIME = 500;
    constexpr int32_t OFF_TIME = 500;
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

/**
  * @tc.name: CheckLightInstanceIsEmpty
  * @tc.desc: Create a light instance. The instance is not empty.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, CheckLightInstanceIsEmpty, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);
}

/**
  * @tc.name: GetLightInfo001
  * @tc.desc: Get light info.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, GetLightInfo001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);
    }
}

/**
  * @tc.name: TurnOnLight001
  * @tc.desc: TurnOnLight.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLight001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(HDF_SUCCESS, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = 255;
        effect.lightColor.colorValue.rgbColor.g = 0;
        effect.lightColor.colorValue.rgbColor.b = 0;
        effect.flashEffect.flashMode = HDF_LIGHT_FLASH_NONE;
        ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(g_sleepTime);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);

        effect.lightColor.colorValue.rgbColor.r = 0;
        effect.lightColor.colorValue.rgbColor.g = 255;
        ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(g_sleepTime);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);

        effect.lightColor.colorValue.rgbColor.b = 255;
        effect.lightColor.colorValue.rgbColor.g = 0;
        ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
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
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLight002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = 255;
        effect.lightColor.colorValue.rgbColor.g = 0;
        effect.lightColor.colorValue.rgbColor.b = 0;
        effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK;
        effect.flashEffect.onTime = ON_TIME;
        effect.flashEffect.offTime = OFF_TIME;
        ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(g_sleepTime);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);

        effect.lightColor.colorValue.rgbColor.r = 0;
        effect.lightColor.colorValue.rgbColor.g = 255;
        ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(g_sleepTime);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);

        effect.lightColor.colorValue.rgbColor.b = 255;
        effect.lightColor.colorValue.rgbColor.r = 255;
        ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalSleep(g_sleepTime);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: TurnOnLight003
  * @tc.desc: TurnOnLight.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLight003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    uint32_t lightId = LIGHT_ID_BUTT;
    HdfLightEffect effect;
    effect.lightColor.colorValue.rgbColor.r = 255;
    effect.lightColor.colorValue.rgbColor.g = 0;
    effect.lightColor.colorValue.rgbColor.b = 0;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK;
    effect.flashEffect.onTime = ON_TIME;
    effect.flashEffect.offTime = OFF_TIME;

    int32_t ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
}

/**
  * @tc.name: TurnOnLight004
  * @tc.desc: TurnOnLight.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnLight004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = 255;
        effect.lightColor.colorValue.rgbColor.g = 0;
        effect.lightColor.colorValue.rgbColor.b = 0;
        effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BUTT;
        effect.flashEffect.onTime = ON_TIME;
        effect.flashEffect.offTime = OFF_TIME;
        ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(LIGHT_NOT_FLASH, ret);
    }
}

/**
  * @tc.name: TurnOnMultiLights001
  * @tc.desc: TurnOnMultiLights.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnMultiLights001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);
    printf("get light list num[%zu]\n\r", info.size());

    for (auto iter : info)
    {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);

        std::vector<HdfLightColor> lightColor;
        struct HdfLightColor light;
        light.colorValue.rgbColor.r = 255;
        light.colorValue.rgbColor.g = 0;
        light.colorValue.rgbColor.b = 0;
        lightColor.push_back(light);

        ret = g_lightInterface->TurnOnMultiLights(iter.lightId, lightColor);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
  * @tc.name: TurnOnMultiLights002
  * @tc.desc: TurnOnMultiLights.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, TurnOnMultiLights002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    uint32_t lightId = LIGHT_ID_BUTT;
    std::vector<HdfLightColor> lightColor;
    struct HdfLightColor light;
    light.colorValue.rgbColor.r = 255;
    light.colorValue.rgbColor.g = 0;
    light.colorValue.rgbColor.b = 0;
    std::vector<HdfLightInfo> info;
    lightColor.push_back(light);
    int32_t ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);
    printf("get light list num[%zu]\n\r", info.size());

    ret = g_lightInterface->TurnOnMultiLights(lightId, lightColor);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

/**
  * @tc.name: DisableLight001
  * @tc.desc: DisableLight.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiTest, DisableLight001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    int32_t ret  = g_lightInterface->TurnOnLight(HDF_LIGHT_ID_BUTT, effect);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
    ret  = g_lightInterface->TurnOffLight(HDF_LIGHT_ID_BUTT);
    EXPECT_EQ(LIGHT_NOT_SUPPORT, ret);
}
