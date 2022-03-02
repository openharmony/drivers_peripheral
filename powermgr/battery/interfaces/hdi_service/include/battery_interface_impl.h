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

#ifndef OHOS_HDI_BATTERY_V1_0_BATTERYINTERFACEIMPL_H
#define OHOS_HDI_BATTERY_V1_0_BATTERYINTERFACEIMPL_H

#include "batteryd_api.h"
#include "battery_config.h"
#include "battery_led.h"
#include "battery_thread.h"
#include "power_supply_provider.h"
#include "v1_0/battery_interface_stub.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V1_0 {
class BatteryInterfaceImpl : public BatteryInterfaceStub {
public:
    BatteryInterfaceImpl();
    virtual ~BatteryInterfaceImpl() {}
    int32_t Init();
    int32_t Register(const sptr<IBatteryCallback>& event) override;
    int32_t UnRegister() override;
    int32_t ChangePath(const std::string& path) override;
    int32_t GetCapacity(int32_t& capacity) override;
    int32_t GetTotalEnergy(int32_t& totalEnergy) override;
    int32_t GetCurrentAverage(int32_t& curAverage) override;
    int32_t GetCurrentNow(int32_t& curNow) override;
    int32_t GetRemainEnergy(int32_t& remainEnergy) override;
    int32_t GetBatteryInfo(BatteryInfo& info) override;
    int32_t GetVoltage(int32_t& voltage) override;
    int32_t GetTemperature(int32_t& temperature) override;
    int32_t GetHealthState(BatteryHealthState& healthState) override;
    int32_t GetPluggedType(BatteryPluggedType& pluggedType) override;
    int32_t GetChargeState(BatteryChargeState& chargeState) override;
    int32_t GetPresent(bool& present) override;
    int32_t GetTechnology(std::string& technology) override;
};
} // V1_0
} // Battery
} // HDI
} // OHOS

#endif // OHOS_HDI_BATTERY_V1_0_BATTERYINTERFACEIMPL_H
