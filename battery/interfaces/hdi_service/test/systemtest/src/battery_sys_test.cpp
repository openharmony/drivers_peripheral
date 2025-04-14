/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "battery_sys_test.h"

#include "battery_config.h"
#include "battery_log.h"

using namespace testing::ext;
using namespace OHOS::HDI::Battery;
using namespace OHOS::HDI::Battery::V2_0;
using namespace std;

namespace {
static auto &g_batteryconfig = BatteryConfig::GetInstance();
} // namespace

namespace {
/**
 * @tc.name: BatteryConfig001
 * @tc.desc: Parse config
 * @tc.type: FUNC
 */

HWTEST_F(BatterySysTest, BatterySysTest_01, TestSize.Level0)
{
    ASSERT_TRUE(g_batteryconfig.ParseConfig());
}

/**
 *
 * @tc.name: BatterySysTest_002
 * @tc.desc: Parse config
 * @tc.type: FUNC
 */

HWTEST_F(BatterySysTest, BatterySysTest_02, TestSize.Level0)
{
    BATTERY_HILOGD(LABEL_TEST, "BatteryConfig002 begin");
    const std::vector<BatteryConfig::LightConfig> lightConf = g_batteryconfig.GetLightConfig();
    ASSERT_TRUE(lightConf.size());

    uint32_t maxRgb = (255 << 16) | (255 << 8) | 255;
    for (uint32_t i = 0; i < lightConf.size(); ++i) {
        // The value ranges from 0 to 100
        BATTERY_HILOGD(LABEL_TEST, "lightConf[i].beginSoc: %{public}d:", lightConf[i].beginSoc);
        ASSERT_TRUE(lightConf[i].beginSoc >= 0 && lightConf[i].beginSoc <= 100);
        ASSERT_TRUE(lightConf[i].endSoc >= 0 && lightConf[i].endSoc <= 100);
        // The start range is smaller than the end range
        ASSERT_TRUE(lightConf[i].beginSoc < lightConf[i].endSoc);
        // The value ranges from 0 to maxRgb
        ASSERT_TRUE(lightConf[i].rgb >= 0 && lightConf[i].rgb <= maxRgb);
    }
    BATTERY_HILOGD(LABEL_TEST, "BatteryConfig002 end");
}

/**
 * @tc.name: BatteryConfig001
 * @tc.desc: test power conf
 * @tc.type: FUNC
 */
HWTEST_F(BatterySysTest, BatteryConfig001, TestSize.Level0)
{
    BATTERY_HILOGI(LABEL_TEST, "BatteryConfig001 begin");
    const std::map<std::string, BatteryConfig::ChargeSceneConfig>
        chargeSceneConfigMap = g_batteryconfig.GetChargeSceneConfigMap();
    if (chargeSceneConfigMap.size() == 0) {
        BATTERY_HILOGI(LABEL_TEST, "BatteryConfig001 chargeSceneConfigMap is empty");
        return;
    }
    for (auto it = chargeSceneConfigMap.begin(); it != chargeSceneConfigMap.end(); it++) {
        ASSERT_TRUE(!(it->first).empty());

        auto chargeSceneConfig = it->second;
        ASSERT_TRUE(!chargeSceneConfig.setPath.empty() || !chargeSceneConfig.getPath.empty()
            || !chargeSceneConfig.supportPath.empty());
    }
    BATTERY_HILOGI(LABEL_TEST, "BatteryConfig001 end");
}

/**
 * @tc.name: BatteryConfig002
 * @tc.desc: test refactor GetChargerConf
 * @tc.type: FUNC
 */
HWTEST_F(BatterySysTest, BatteryConfig002, TestSize.Level0)
{
    BATTERY_HILOGI(LABEL_TEST, "BatteryConfig002 begin");
    const BatteryConfig::ChargerConfig chargerConf = g_batteryconfig.GetChargerConfig();
    ASSERT_TRUE(chargerConf.currentPath.size());
    ASSERT_TRUE(chargerConf.voltagePath.size());
    ASSERT_TRUE(chargerConf.chargeTypePath.size());
    
    BATTERY_HILOGI(LABEL_TEST, "BatteryConfig002 end");
}
}