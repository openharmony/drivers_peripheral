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
#include "osal_mem.h"
#include "light_if.h"
#include "light_type.h"

using namespace testing::ext;

namespace {
    const uint32_t type = 1;
    const struct LightInterface *g_lightDev = nullptr;
    static struct LightInfo *g_lightInfo = nullptr;
    static uint32_t g_count = 0;
    const int32_t g_onTime = 500;
    const int32_t g_offTime = 500;
    const int32_t LIGHT_WAIT_TIME = 30;
    struct LightEffect *g_effect = nullptr;
}

class HdfLightTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfLightTest::SetUpTestCase()
{
    g_effect = (struct LightEffect *)OsalMemCalloc(sizeof(*g_effect));
    if (g_effect == nullptr) {
        printf("malloc failed\n\r");
    }
    g_lightDev = NewLightInterfaceInstance();
    if (g_lightDev == nullptr) {
        printf("test lightHdi get Module instance failed\n\r");
    }
    int32_t ret = g_lightDev->GetLightInfo(&g_lightInfo, &g_count);
    if (ret == -1) {
        printf("get light informations failed\n\r");
    }
}

void HdfLightTest::TearDownTestCase()
{
    if (g_effect != nullptr) {
        OsalMemFree(g_effect);
        g_effect = nullptr;
    }

    if (g_lightDev != nullptr) {
        FreeLightInterfaceInstance();
        g_lightDev = nullptr;
    }
}

void HdfLightTest::SetUp()
{
}

void HdfLightTest::TearDown()
{
}

/**
  * @tc.name: GetLightList001
  * @tc.desc: Obtains information about all lights in the system. Validity check of input parameters.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869Q
  */
HWTEST_F(HdfLightTest, GetLightList001, TestSize.Level1)
{
    struct LightInfo *info = nullptr;

    if (g_lightInfo == nullptr) {
        EXPECT_NE(nullptr, g_lightInfo);
        return;
    }

    printf("get light list num[%d]\n\r", g_count);
    info = g_lightInfo;

    for (int i = 0; i < g_count; ++i) {
        printf("get lightId[%d]\n\r", info->lightType);
        info++;
    }
}

/**
  * @tc.name: EnableLight001
  * @tc.desc: Enables the light available in the light list based on the specified light type.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869R, AR000F8QNL
  */
HWTEST_F(HdfLightTest, EnableLight001, TestSize.Level1)
{
    g_effect->lightBrightness = 0xFFFF0000;
    g_effect->flashEffect.flashMode = LIGHT_FLASH_NONE;
    g_effect->flashEffect.onTime = 0;
    g_effect->flashEffect.offTime = 0;
    int32_t ret = g_lightDev->TurnOnLight(type, g_effect);
    EXPECT_EQ(0, ret);

    OsalSleep(LIGHT_WAIT_TIME);

    ret = g_lightDev->TurnOffLight(type);
    EXPECT_EQ(0, ret);
}

/**
  * @tc.name: EnableLight002
  * @tc.desc: Enables the light available in the light list based on the specified light type.
  * @tc.type: FUNC
  * @tc.require: SR000F869M, AR000F869R, AR000F8QNL
  */
HWTEST_F(HdfLightTest, EnableLight002, TestSize.Level1)
{
    g_effect->lightBrightness = 0xFFFF0000;
    g_effect->flashEffect.flashMode = LIGHT_FLASH_TIMED;
    g_effect->flashEffect.onTime = g_onTime;
    g_effect->flashEffect.offTime = g_offTime;
    int32_t ret = g_lightDev->TurnOnLight(type, g_effect);
    EXPECT_EQ(0, ret);

    OsalSleep(LIGHT_WAIT_TIME);

    ret = g_lightDev->TurnOffLight(type);
    EXPECT_EQ(0, ret);
}