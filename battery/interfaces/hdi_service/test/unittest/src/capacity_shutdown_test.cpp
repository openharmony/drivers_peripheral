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

#include "capacity_shutdown_test.h"
#include "battery_thread_test.h"
#include "power_supply_provider.h"
#include <csignal>
#include <iostream>

using namespace testing::ext;
using namespace OHOS::HDI::Battery::V1_2;
using namespace std;

namespace CapacityShutdownTest {
void CapacityShutdownTest::SetUpTestCase(void) {}

void CapacityShutdownTest::TearDownTestCase(void) {}

void CapacityShutdownTest::SetUp(void) {}

void CapacityShutdownTest::TearDown(void) {}

/**
 * @tc.name: HdiServiceShutdown001
 * @tc.desc: capacity shutdown test
 * @tc.type: FUNC
 */
HWTEST_F(CapacityShutdownTest, HdiServiceShutdown001, TestSize.Level1)
{
    ASSERT_TRUE(true);
}
} // namespace CapacityShutdownTest
