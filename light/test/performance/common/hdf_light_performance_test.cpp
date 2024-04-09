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
