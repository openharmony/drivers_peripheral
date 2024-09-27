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
#include "hdf_log.h"
#include "osal_time.h"
#include "v1_0/ilight_interface.h"
#include "light_type.h"

#define HDF_LOG_TAG "hdi_unittest_light"

using namespace OHOS::HDI::Light::V1_0;
using namespace testing::ext;

namespace {
    constexpr uint32_t g_sleepTime = 3;
    constexpr int32_t ON_TIME = 500;
    constexpr int32_t OFF_TIME = 100;
    std::vector<HdfLightInfo> g_info;
    sptr<ILightInterface> g_lightInterface = nullptr;
}

class HdiUnitTestLight : public testing::Test {
public:
    static void SetUpTestSuite();
    static void TearDownTestSuite();
    void SetUp();
    void TearDown();
};

void HdiUnitTestLight::SetUpTestSuite()
{
    g_lightInterface = ILightInterface::Get();
}

void HdiUnitTestLight::TearDownTestSuite()
{
}

void HdiUnitTestLight::SetUp()
{
}

void HdiUnitTestLight::TearDown()
{
}

static int32_t IsSupportedLightId(int32_t lightId)
{
    HDF_LOGI("%{public}s in", __func__ );
    EXPECT_GT(g_info.size(), 0);

    bool result = std::any_of(g_info.begin(), g_info.end(),
        [lightId](const HdfLightInfo &info) {return info.lightId == lightId;});
    if (result) {
        return HDF_SUCCESS;
    }

    return HDF_ERR_NOT_SUPPORT;
}

static void LightTest(int32_t lightId, int32_t lightFlashMode, HdfLightEffect &effect)
{
    HDF_LOGI("%{public}s in", __func__ );
    if (lightFlashMode != HDF_LIGHT_FLASH_NONE) {
        effect.flashEffect.onTime = ON_TIME;
        effect.flashEffect.offTime = OFF_TIME;
    }
    effect.flashEffect.flashMode = lightFlashMode;

    int32_t ans = IsSupportedLightId(lightId);
    int32_t ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(ans, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(ans, ret);
}

/**
  * @tc.name: CheckLightInstanceIsEmpty
  * @tc.desc: Create a light instance. The instance is not empty.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, CheckLightInstanceIsEmpty001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);
}

/**
  * @tc.name: GetLightInfo001
  * @tc.desc: Get light info.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, GetLightInfo001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t ret = g_lightInterface->GetLightInfo(g_info);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(g_info.size(), 0);

    printf("get light list num[%zu]\n\r", g_info.size());
    for (auto iter : g_info) {
        printf("lightId[%d], name[%s], number[%d], type[%d]\n\r", iter.lightId, iter.lightName.c_str(),
            iter.lightNumber, iter.lightType);
    }
}

/**
  * @tc.name: TurnOnLightBatteryAlwaysOnRed001
  * @tc.desc: The power indicator is steady red.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryAlwaysOnRed001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnLightBatteryAlwaysOnGreen001
  * @tc.desc: The power indicator is steady green.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryAlwaysOnGreen001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnLightBatteryAlwaysOnBlue001
  * @tc.desc: The power indicator is steady blue.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryAlwaysOnBlue001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnLightBatteryAlwaysOnWhite001
  * @tc.desc: The power indicator is steady white.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryAlwaysOnWhite001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnLightBatteryBlinkRed001
  * @tc.desc: The power indicator is blinking red.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryBlinkRed001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_BLINK, effect);
}

/**
  * @tc.name: TurnOnLightBatteryBlinkGreen001
  * @tc.desc: The power indicator is blinking green.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryBlinkGreen001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_BLINK, effect);
}

/**
  * @tc.name: TurnOnLightBatteryBlinkBlue001
  * @tc.desc: The power indicator is blinking blue.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryBlinkBlue001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_BLINK, effect);
}

/**
  * @tc.name: TurnOnLightBatteryBlinkWhite001
  * @tc.desc: The power indicator is blinking white.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryBlinkWhite001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_BLINK, effect);
}

/**
  * @tc.name: TurnOnLightBatteryGradientRed001
  * @tc.desc: The power indicator red light gradients.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryGradientRed001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_GRADIENT, effect);
}

/**
  * @tc.name: TurnOnLightBatteryGradientGreen001
  * @tc.desc: The power indicator green light gradients.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryGradientGreen001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_GRADIENT, effect);
}

/**
  * @tc.name: TurnOnLightBatteryGradientBlue001
  * @tc.desc: The power indicator blue light gradients.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryGradientBlue001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_GRADIENT, effect);
}

/**
  * @tc.name: TurnOnLightBatteryGradientWhite001
  * @tc.desc: The power indicator white light gradients.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBatteryGradientWhite001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_BATTERY, HDF_LIGHT_FLASH_GRADIENT, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsAlwaysOnRed001
  * @tc.desc: The notification light is steady red.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsAlwaysOnRed001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsAlwaysOnGreen001
  * @tc.desc: The notification light is steady green.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsAlwaysOnGreen001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsAlwaysOnBlue001
  * @tc.desc: The notification light is steady blue.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsAlwaysOnBlue001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsAlwaysOnWhite001
  * @tc.desc: The notification light is steady white.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsAlwaysOnWhite001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsBlinkRed001
  * @tc.desc: Notification light blinking red.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsBlinkRed001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_BLINK, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsBlinkGreen001
  * @tc.desc: Notification light blinking green.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsBlinkGreen001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_BLINK, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsBlinkBlue001
  * @tc.desc: Notification light blinking blue.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsBlinkBlue001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_BLINK, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsBlinkWhite001
  * @tc.desc: Notification light blinking white.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsBlinkWhite001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_BLINK, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsGradientRed001
  * @tc.desc: Notification light gradient red.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsGradientRed001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_GRADIENT, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsGradientGreen001
  * @tc.desc: Notification light gradient green.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsGradientGreen001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_GRADIENT, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsGradientBlue001
  * @tc.desc: Notification light gradient blue.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsGradientBlue001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 0,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_GRADIENT, effect);
}

/**
  * @tc.name: TurnOnLightNotificationsGradientWhite001
  * @tc.desc: Notification light gradient white.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightNotificationsGradientWhite001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
    };

    LightTest(HDF_LIGHT_ID_NOTIFICATIONS, HDF_LIGHT_FLASH_GRADIENT, effect);
}

/**
  * @tc.name: TurnOnLightAttention001
  * @tc.desc: The reserved indicator is not supported currently.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightAttention001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 0,
        .lightColor.colorValue.rgbColor.b = 0,
    };

    LightTest(HDF_LIGHT_ID_ATTENTION, HDF_LIGHT_FLASH_NONE, effect);
}

/**
  * @tc.name: TurnOnMultiLights001
  * @tc.desc: Turn on multiple lights.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnMultiLights001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    struct HdfLightColor color = {
        .colorValue.rgbColor.r = 255,
        .colorValue.rgbColor.g = 255,
        .colorValue.rgbColor.b = 255,
    };
    std::vector<HdfLightColor> lightColor;
    lightColor.push_back(color);

    int32_t ret = IsSupportedLightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnMultiLights(lightId, lightColor);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnMultiLights002
  * @tc.desc: Turn on multiple lights.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnMultiLights002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_BATTERY;
    struct HdfLightColor color1 = {
        .colorValue.rgbColor.r = 255,
        .colorValue.rgbColor.g = 255,
        .colorValue.rgbColor.b = 255,
    };
    struct HdfLightColor color2 = {
        .colorValue.rgbColor.r = 255,
        .colorValue.rgbColor.g = 255,
        .colorValue.rgbColor.b = 0,
    };
    std::vector<HdfLightColor> lightColor;
    lightColor.push_back(color1);
    lightColor.push_back(color2);

    int32_t ret = IsSupportedLightId(lightId);
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
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBlinkException001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
        .flashEffect.onTime = -1,
        .flashEffect.offTime = OFF_TIME,
        .flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK,
    };

    int32_t ret = IsSupportedLightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightBlinkException002
  * @tc.desc: The offtime setting is abnormal in blinking mode.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightBlinkException002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
        .flashEffect.onTime = ON_TIME,
        .flashEffect.offTime = -1,
        .flashEffect.flashMode = HDF_LIGHT_FLASH_BLINK,
    };

    int32_t ret = IsSupportedLightId(lightId);
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
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightGradientException001, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
        .flashEffect.onTime = -1,
        .flashEffect.offTime = OFF_TIME,
        .flashEffect.flashMode = HDF_LIGHT_FLASH_GRADIENT,
    };

    int32_t ret = IsSupportedLightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: TurnOnLightGradientException002
  * @tc.desc: The offtime setting is abnormal in gradient mode.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestLight, TurnOnLightGradientException002, TestSize.Level1)
{
    HDF_LOGI("%{public}s in", __func__ );
    ASSERT_NE(nullptr, g_lightInterface);

    int32_t lightId = HDF_LIGHT_ID_NOTIFICATIONS;
    HdfLightEffect effect = {
        .lightColor.colorValue.rgbColor.r = 255,
        .lightColor.colorValue.rgbColor.g = 255,
        .lightColor.colorValue.rgbColor.b = 255,
        .flashEffect.onTime = ON_TIME,
        .flashEffect.offTime = -1,
        .flashEffect.flashMode = HDF_LIGHT_FLASH_GRADIENT,
    };

    int32_t ret = IsSupportedLightId(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = g_lightInterface->TurnOnLight(lightId, effect);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    OsalSleep(g_sleepTime);

    ret = g_lightInterface->TurnOffLight(lightId);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
