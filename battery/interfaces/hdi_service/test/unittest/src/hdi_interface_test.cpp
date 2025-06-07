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

#include "hdi_interface_test.h"

#include <fstream>
#include "v2_0/battery_interface_proxy.h"
#include "v2_0/types.h"
#include "battery_log.h"

using namespace OHOS::HDI::Battery;
using namespace OHOS::HDI::Battery::V2_0;
using namespace testing::ext;
using namespace OHOS;

namespace {
sptr<IBatteryInterface> g_batteryInterface = nullptr;
}

void HdiInterfaceTest::SetUpTestCase(void)
{
    g_batteryInterface = IBatteryInterface::Get(true);
    if (g_batteryInterface == nullptr) {
        BATTERY_HILOGI(LABEL_TEST, "Failed to get g_batteryInterface");
        return;
    }
}

void HdiInterfaceTest::TearDownTestCase(void)
{
}

void HdiInterfaceTest::SetUp(void)
{
}

void HdiInterfaceTest::TearDown(void)
{
}

static std::string CreateFile(std::string path, std::string content)
{
    std::ofstream stream(path.c_str());
    if (!stream.is_open()) {
        BATTERY_HILOGI(LABEL_TEST, "Cannot create file");
        return nullptr;
    }
    stream << content.c_str() << std::endl;
    stream.close();
    return path;
}

namespace {
/**
 * @tc.name: HdiInterfaceTest001
 * @tc.desc: Test limit charging current
 * @tc.type: FUNC
 */
HWTEST_F (HdiInterfaceTest, HdiInterfaceTest001, TestSize.Level0)
{
    std::string currentPath = "/data/service/el0/battery/current_limit";
    CreateFile(currentPath, "");
    ChargingLimit scLimit;
    scLimit.type = TYPE_CURRENT;
    scLimit.protocol = "sc";
    scLimit.value = 1000;
    ChargingLimit buckLimit;
    buckLimit.type = TYPE_CURRENT;
    buckLimit.protocol = "buck";
    buckLimit.value = 1100;
    std::vector<ChargingLimit> chargeLimitList;
    chargeLimitList.push_back(scLimit);
    chargeLimitList.push_back(buckLimit);
    int32_t result = g_batteryInterface->SetChargingLimit(chargeLimitList);
    EXPECT_EQ(true, result == ERR_OK);

    std::string line;
    std::string chargeLimitStr;
    std::string writeChargeInfo = scLimit.protocol + " " + std::to_string(scLimit.value) + "\n" +
        buckLimit.protocol + " " + std::to_string(buckLimit.value) + "\n";
    std::ifstream fin(currentPath.c_str());
    if (fin) {
        while (getline(fin, line)) {
            chargeLimitStr += line + "\n";
        }
    }
    EXPECT_EQ(true, chargeLimitStr == writeChargeInfo);
}

/**
 * @tc.name: HdiInterfaceTest002
 * @tc.desc: Test limit charging voltage
 * @tc.type: FUNC
 */
HWTEST_F (HdiInterfaceTest, HdiInterfaceTest002, TestSize.Level0)
{
    std::string voltagePath = "/data/service/el0/battery/voltage_limit";
    CreateFile(voltagePath, "");
    ChargingLimit scLimit;
    scLimit.type = TYPE_VOLTAGE;
    scLimit.protocol = "sc";
    scLimit.value = 2000;
    ChargingLimit buckLimit;
    buckLimit.type = TYPE_VOLTAGE;
    buckLimit.protocol = "buck";
    buckLimit.value = 3000;
    std::vector<ChargingLimit> chargeLimitList;
    chargeLimitList.push_back(scLimit);
    chargeLimitList.push_back(buckLimit);
    int32_t result = g_batteryInterface->SetChargingLimit(chargeLimitList);
    EXPECT_EQ(true, result == ERR_OK);

    std::string line;
    std::string voltageLimitStr;
    std::string writeVoltageInfo = scLimit.protocol + " " + std::to_string(scLimit.value) + "\n" +
        buckLimit.protocol + " " + std::to_string(buckLimit.value) + "\n";
    std::ifstream fin(voltagePath.c_str());
    if (fin) {
        while (getline(fin, line)) {
            voltageLimitStr += line + "\n";
        }
    }
    EXPECT_EQ(true, voltageLimitStr == writeVoltageInfo);
}

/**
 * @tc.name: HdiInterfaceTest003
 * @tc.desc: Test SetBatteryConfig
 * @tc.type: FUNC
 */
HWTEST_F (HdiInterfaceTest, HdiInterfaceTest003, TestSize.Level0)
{
    string sceneName = "testScene";
    string value = "";
    int32_t result = g_batteryInterface->SetBatteryConfig(sceneName, value);
    EXPECT_EQ(true, result == HDF_ERR_NOT_SUPPORT);
}
}
