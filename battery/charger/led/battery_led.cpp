/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "battery_led.h"

#include "file_ex.h"
#include "errors.h"
#include "power_supply_provider.h"
#include "battery_log.h"
#include "v1_0/ilight_interface.h"
#include "v1_0/light_types.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V1_0 {
namespace {
using namespace OHOS::HDI::Light::V1_0;

constexpr int32_t CAPACITY_FULL = 100;
constexpr int32_t LED_COLOR_GREEN = 2;
constexpr int32_t LED_COLOR_RED = 4;
constexpr int32_t LED_COLOR_YELLOW = 6;
sptr<ILightInterface> g_light;
static std::vector<HdfLightInfo> g_info;
}

void BatteryLed::InitLightInfo()
{
    if (g_light == nullptr) {
        g_light = ILightInterface::Get();
        if (g_light == nullptr) {
            BATTERY_HILOGE(FEATURE_CHARGING, "failed to get light hdi interface");
            return;
        }
    }

    int32_t ret = g_light->GetLightInfo(g_info);
    if (ret < 0) {
        BATTERY_HILOGW(FEATURE_CHARGING, "get HdfLightInfo failed");
        return;
    }

    for (auto iter: g_info) {
        BATTERY_HILOGD(FEATURE_CHARGING, "HdfLightInfo.lightId: %{public}d", iter.lightId);
    }
}

void BatteryLed::TurnOffLed()
{
    for (auto iter: g_info) {
        if (iter.lightId == HDF_LIGHT_ID_BATTERY) {
            g_light->TurnOffLight(iter.lightId);
            BATTERY_HILOGD(FEATURE_CHARGING, "turn off led:%{public}d", iter.lightId);
        }
    }
}

void BatteryLed::UpdateLedColor(int32_t chargeState, int32_t capacity)
{
    if ((chargeState == PowerSupplyProvider::CHARGE_STATE_NONE) ||
        (chargeState == PowerSupplyProvider::CHARGE_STATE_RESERVED)) {
        BATTERY_HILOGD(FEATURE_CHARGING, "not in charging state, turn off led");
        TurnOffLed();
        return;
    }

    std::unique_ptr<BatteryConfig> batteryConfig = std::make_unique<BatteryConfig>();
    if (batteryConfig == nullptr) {
        BATTERY_HILOGW(FEATURE_CHARGING, "make_unique BatteryConfig return nullptr");
        return;
    }
    batteryConfig->Init();

    auto ledConf = batteryConfig->GetLedConf();
    for (auto it = ledConf.begin(); it != ledConf.end(); ++it) {
        BATTERY_HILOGD(FEATURE_CHARGING, "capacity=%{public}d, ledConf.begin()=%{public}d, ledConf.end()=%{public}d",
            capacity, it->capacityBegin, it->capacityEnd);
        if ((capacity >= it->capacityBegin) && (capacity < it->capacityEnd)) {
            switch (it->color) {
                case (LED_COLOR_GREEN): {
                    BATTERY_HILOGD(FEATURE_CHARGING, "led color display green");
                    WriteLedInfo(0, it->brightness, 0);
                    break;
                }
                case (LED_COLOR_RED): {
                    BATTERY_HILOGD(FEATURE_CHARGING, "led color display red");
                    WriteLedInfo(it->brightness, 0, 0);
                    break;
                }
                case (LED_COLOR_YELLOW): {
                    BATTERY_HILOGD(FEATURE_CHARGING, "led color display yellow");
                    WriteLedInfo(it->brightness, it->brightness, 0);
                    break;
                }
                default: {
                    BATTERY_HILOGD(FEATURE_CHARGING, "led color display error.");
                    break;
                }
            }
            break;
        }

        if (capacity == CAPACITY_FULL) {
            BATTERY_HILOGD(FEATURE_CHARGING, "led color display green");
            WriteLedInfo(0, it->brightness, 0);
            break;
        }
    }
}

void BatteryLed::WriteLedInfo(int32_t redBrightness, int32_t greenBrightness, int32_t blueBrightness)
{
    BATTERY_HILOGD(FEATURE_CHARGING,
        "redBrightness: %{public}d, greenBrightness: %{public}d, blueBrightness: %{public}d",
        redBrightness, greenBrightness, blueBrightness);

    struct HdfLightEffect effect = {
        .lightBrightness = (redBrightness << 16) | (greenBrightness << 8) | blueBrightness,
    };

    for (auto iter: g_info) {
        if (iter.lightId == HDF_LIGHT_ID_BATTERY) {
            g_light->TurnOnLight(iter.lightId, effect);
        }
    }
}
}  // namespace V1_0
}  // namespace Battery
}  // namespace HDI
}  // namespace OHOS
