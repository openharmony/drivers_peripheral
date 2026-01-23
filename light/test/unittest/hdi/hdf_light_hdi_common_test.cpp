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
    constexpr uint32_t g_sleepTime_s = 1;
    constexpr uint32_t g_sleepTime_l = 5;
    constexpr int32_t ON_TIME = 500;
    constexpr int32_t OFF_TIME = 100;
    constexpr int32_t MIN_VALUE = 0;
    constexpr int32_t MAX_VALUE = 255;
    std::vector<HdfLightInfo> g_info;
    sptr<ILightInterface> g_lightInterface = nullptr;
}

class HdfLightHdiCommonTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfLightHdiCommonTest::SetUpTestCase()
{
    g_lightInterface = ILightInterface::Get();
}

void HdfLightHdiCommonTest::TearDownTestCase()
{
}

void HdfLightHdiCommonTest::SetUp()
{
}

void HdfLightHdiCommonTest::TearDown()
{
}

static void InitConfig(HdfLightEffect &effect)
{
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_NONE;
}

/**
  * @tc.name: CheckLightInstanceIsEmpty
  * @tc.desc: Create a light instance. The instance is not empty.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, CheckLightInstanceIsEmpty, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);
}

/**
  * @tc.name: GetLightInfo001
  * @tc.desc: Get light info.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, GetLightInfo_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t ret = g_lightInterface->GetLightInfo(g_info);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(g_info.size(), 0);
    printf("get light list num[%zu]\n\r", g_info.size());

    for (auto iter : g_info) {
        printf("lightId[%d], lightName[%s], lightNumber[%d]\n\r",\
            iter.lightId, iter.lightName.c_str(), iter.lightNumber);
    }
}

/**
  * @tc.name: TurnOnLightRed001
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRed_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreen001
  * @tc.desc: Turn on the light always on green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreen_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
  * @tc.name: TurnOnLightBlue001
  * @tc.desc: Turn on the light always on blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBlue_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRed002
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRed_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreen002
  * @tc.desc: Turn on the light always on green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreen_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlue002
  * @tc.desc: Turn on the light always on blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBlue_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRed003
  * @tc.desc: Turn on the battery light blinking red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRed_003, TestSize.Level1)
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
  * @tc.name: TurnOnLightGreen003
  * @tc.desc: Turn on the battery light blinking green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreen_003, TestSize.Level1)
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
  * @tc.name: TurnOnLightBlue003
  * @tc.desc: Turn on the battery light blinking blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBlue_003, TestSize.Level1)
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
  * @tc.name: TurnOnLightRedshort001
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRedshort_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRedshort002
  * @tc.desc: Turn on the battery light blinking red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRedshort_002, TestSize.Level1)
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

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreenshort_003
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreenshort_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreenshort_004
  * @tc.desc: Turn on the battery light blinking red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreenshort_004, TestSize.Level1)
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

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlueshort_005
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBlueshort_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlueshort_006
  * @tc.desc: Turn on the battery light blinking red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBlueshort_006, TestSize.Level1)
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

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreenshort001
  * @tc.desc: Turn on the light always on green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreenshort_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreenshort002
  * @tc.desc: Turn on the light always on green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreenshort_002, TestSize.Level1)
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

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlueshort001
  * @tc.desc: Turn on the light always on blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBlueshort_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlueshort002
  * @tc.desc: Turn on the battery light blinking blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBlueshort_002, TestSize.Level1)
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

    OsalSleep(g_sleepTime_s);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRedlong001
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRedlong_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRedlong002
  * @tc.desc: Turn on the battery light blinking red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRedlong_002, TestSize.Level1)
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

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRedlong003
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRedlong_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRedlong004
  * @tc.desc: Turn on the battery light blinking red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRedlong_004, TestSize.Level1)
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

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRedlong005
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRedlong_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightRedlong006
  * @tc.desc: Turn on the battery light blinking red.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightRedlong_006, TestSize.Level1)
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

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreenlong001
  * @tc.desc: Turn on the light always on green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreenlong_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGreenlong002
  * @tc.desc: Turn on the light always on green.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightGreenlong_002, TestSize.Level1)
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

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBluelong001
  * @tc.desc: Turn on the light always on blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBluelong_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBluelong_002
  * @tc.desc: Turn on the battery light blinking blue.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightBluelong_002, TestSize.Level1)
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

    OsalSleep(g_sleepTime_l);

    ret = g_lightInterface->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal001
  * @tc.desc: Abnormal flashmode.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = -1;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal002
  * @tc.desc: Abnormal flashmode.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BUTT;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal003
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(-1, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal004
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_004, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BUTT, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal005
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_005, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BUTT, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal006
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BUTT, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal007
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_007, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BUTT, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}
/**
  * @tc.name: TurnOnLightAbnormal008
  * @tc.desc: Abnormal flashmode.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_008, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;
    effect.flashEffect.flashMode = -1;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal009
  * @tc.desc: Abnormal flashmode.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_009, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;
    effect.flashEffect.flashMode = HDF_LIGHT_FLASH_BUTT;

    int32_t ret = g_lightInterface->TurnOnLight(g_info[0].lightId, effect);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOffLight(g_info[0].lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal010
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_010, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(-1, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal011
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_011, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MAX_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BUTT, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal012
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_012, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BUTT, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal013
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_013, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MAX_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BUTT, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightAbnormal014
  * @tc.desc: Abnormal lightID.
  * @tc.type: FUNC
  * @tc.require: #I4NN4Z
  */
HWTEST_F(HdfLightHdiCommonTest, TurnOnLightAbnormal_014, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;

    int32_t ret = g_lightInterface->TurnOnLight(LIGHT_ID_BUTT, effect);
    EXPECT_NE(HDF_SUCCESS, ret);
}