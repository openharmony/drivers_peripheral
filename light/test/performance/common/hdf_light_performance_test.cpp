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
#include "light_if.h"
#include "light_type.h"
#include "v1_0/ilight_interface.h"

using namespace testing::ext;
using namespace OHOS::HDI::Light::V1_0;

namespace {
    constexpr int32_t MAX_VALUE = 255;
    constexpr int32_t MIN_VALUE = 0;
    constexpr uint32_t SLEEP_TIME = 3;
    const struct LightInterface *g_lightPerformanceDev = nullptr;
}

class HdfLightPerformanceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfLightPerformanceTest::SetUpTestCase()
{
    g_lightPerformanceDev = NewLightInterfaceInstance();
    if (g_lightPerformanceDev == nullptr) {
        printf("test lightHdi get Module insttace failed\n\r");
    }
}

void HdfLightPerformanceTest::TearDownTestCase()
{
    if (g_lightPerformanceDev != nullptr) {
        FreeLightInterfaceInstance();
        g_lightPerformanceDev = nullptr;
    }
}

void HdfLightPerformanceTest::SetUp()
{
}

void HdfLightPerformanceTest::TearDown()
{
}

static void InitConfig(LightEffect &effect)
{
    effect.lightColor.colorValue.rgbColor.r = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.g = MIN_VALUE;
    effect.lightColor.colorValue.rgbColor.b = MIN_VALUE;
    effect.flashEffect.flashMode = LIGHT_FLASH_NONE;
}

/**
  * @tc.name: TurnOnLightRed001
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I9EKU9
  */
HWTEST_F(HdfLightPerformanceTest, TurnOnLightRed_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightPerformanceDev);

    LightEffect effect;
    InitConfig(effect);
    effect.lightColor.colorValue.rgbColor.r = MAX_VALUE;

    int32_t ret = g_lightPerformanceDev->TurnOnLight(LIGHT_ID_BATTERY, &effect);
    EXPECT_EQ(HDF_SUCCESS, ret);

    OsalSleep(SLEEP_TIME);

    ret = g_lightPerformanceDev->TurnOffLight(LIGHT_ID_BATTERY);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
  * @tc.name: Interface_coverage
  * @tc.desc: Turn on the light always on red.
  * @tc.type: FUNC
  * @tc.require: #I9EKU9
  */
HWTEST_F(HdfLightPerformanceTest, Interface_coverage, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_lightPerformanceDev);
    int32_t ret = FreeLightInterfaceInstance();
    EXPECT_EQ(ret, HDF_SUCCESS);
}