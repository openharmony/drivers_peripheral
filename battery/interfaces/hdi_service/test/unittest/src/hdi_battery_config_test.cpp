/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hdi_battery_config_test.h"

#include "battery_config.h"

using namespace OHOS::HDI::Battery;
using namespace OHOS::HDI::Battery::V2_0;
using namespace testing::ext;
using namespace OHOS;

namespace {
auto& g_configTest = BatteryConfig::GetInstance();
}

void HdiBatteryConfigTest::SetUpTestCase(void)
{
}

void HdiBatteryConfigTest::TearDownTestCase(void)
{
}

void HdiBatteryConfigTest::DestroyJsonValue(cJSON*& value)
{
    if (value) {
        cJSON_Delete(value);
        value = nullptr;
    }
}

namespace {
/**
 * @tc.name: HdiBatteryConfigTest001
 * @tc.desc: Test ParseChargerConfig
 * @tc.type: FUNC
 */
HWTEST_F(HdiBatteryConfigTest, HdiBatteryConfigTest001, TestSize.Level0)
{
    std::string jsonStr = R"({"current_limit": {"path": "/test/current_limit"}})";
    cJSON* parseResult = cJSON_Parse(jsonStr.c_str());
    ASSERT_TRUE(parseResult);
    g_configTest.ParseChargerConfig(parseResult);
    EXPECT_TRUE(g_configTest.chargerConfig_.currentPath == "/test/current_limit");
    DestroyJsonValue(parseResult);

    jsonStr = R"({"voltage_limit": {"path": "/test/voltage_limit"}})";
    parseResult = cJSON_Parse(jsonStr.c_str());
    ASSERT_TRUE(parseResult);
    g_configTest.ParseChargerConfig(parseResult);
    EXPECT_TRUE(g_configTest.chargerConfig_.voltagePath == "/test/voltage_limit");
    DestroyJsonValue(parseResult);

    jsonStr = R"({"type": {"path": "/test/type"}})";
    parseResult = cJSON_Parse(jsonStr.c_str());
    ASSERT_TRUE(parseResult);
    g_configTest.ParseChargerConfig(parseResult);
    EXPECT_TRUE(g_configTest.chargerConfig_.chargeTypePath == "/test/type");
    DestroyJsonValue(parseResult);
}
}
