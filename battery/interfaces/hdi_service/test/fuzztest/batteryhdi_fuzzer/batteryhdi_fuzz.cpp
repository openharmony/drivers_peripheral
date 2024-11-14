/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "batteryhdi_fuzz.h"

#include "securec.h"
#include <cstdint>
#include <cstdlib>
#include <datetime_ex.h>
#include <map>
#include <random>
#include <vector>

#include "v2_0/battery_interface_proxy.h"
#include "v2_0/ibattery_callback.h"
#include "v2_0/types.h"

using namespace OHOS::HDI::Battery::V2_0;
using namespace HDI::Battery;

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V2_0 {
namespace {
class BatteryCallback : public IBatteryCallback {
public:
    BatteryCallback() {};
    ~BatteryCallback() override {};
    int32_t Update([[maybe_unused]] const BatteryInfo &event) override
    {
        return 0;
    };
};
sptr<IBatteryInterface> g_batteryInterface = IBatteryInterface::Get();
} // namespace

void Register([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    sptr<IBatteryCallback> callback = new BatteryCallback();
    g_batteryInterface->Register(callback);
    g_batteryInterface->Register(nullptr);
}

void UnRegister([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    g_batteryInterface->UnRegister();
}

void ChangePath(const uint8_t *data, size_t size)
{
    std::string result(reinterpret_cast<const char *>(data), size);
    g_batteryInterface->ChangePath(result);
}

void GetCapacity([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    int32_t out;
    g_batteryInterface->GetCapacity(out);
}

void GetVoltage([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    int32_t out;
    g_batteryInterface->GetVoltage(out);
}

void GetTemperature([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    int32_t out;
    g_batteryInterface->GetTemperature(out);
}

void GetHealthState([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    BatteryHealthState state;
    g_batteryInterface->GetHealthState(state);
}

void GetPluggedType([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    BatteryPluggedType type;
    g_batteryInterface->GetPluggedType(type);
}

void GetChargeState([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    BatteryChargeState state;
    g_batteryInterface->GetChargeState(state);
}

void GetPresent([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    bool present;
    g_batteryInterface->GetPresent(present);
}

void GetTechnology([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    std::string str;
    g_batteryInterface->GetTechnology(str);
}

void GetTotalEnergy([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    int32_t out;
    g_batteryInterface->GetTotalEnergy(out);
}

void GetCurrentAverage([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    int32_t out;
    g_batteryInterface->GetCurrentAverage(out);
}

void GetCurrentNow([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    int32_t out;
    g_batteryInterface->GetCurrentNow(out);
}

void GetRemainEnergy([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    int32_t out;
    g_batteryInterface->GetRemainEnergy(out);
}

void GetBatteryInfo([[maybe_unused]] const uint8_t *data, [[maybe_unused]] size_t size)
{
    BatteryInfo info;
    g_batteryInterface->GetBatteryInfo(info);
}

void SetChargingLimit(const uint8_t *data, size_t size)
{
    int32_t inputData;
    if (size < sizeof(inputData)) {
        return;
    }
    if (memcpy_s(&inputData, sizeof(inputData), data, sizeof(inputData)) != EOK) {
        return;
    }
    int32_t minVectorSize = 0;
    int32_t maxVectorSize = 5000;
    int32_t length = (inputData < minVectorSize) ? minVectorSize : inputData;
    length = (length > maxVectorSize) ? maxVectorSize : length;
    std::vector<ChargingLimit> scLimit;
    scLimit.resize(length);
    for (auto &item : scLimit) {
        item.type = ChargingLimitType(inputData);
        item.protocol = std::string(reinterpret_cast<const char *>(data), size);
        item.value = inputData;
    }
    g_batteryInterface->SetChargingLimit(scLimit);
}

static std::vector<std::function<void(const uint8_t *, size_t)>> fuzzFunc = {
    &Register,
    &UnRegister,
    &ChangePath,
    &GetCapacity,
    &GetVoltage,
    &GetTemperature,
    &GetHealthState,
    &GetPluggedType,
    &GetChargeState,
    &GetPresent,
    &GetTechnology,
    &GetTotalEnergy,
    &GetCurrentAverage,
    &GetCurrentNow,
    &GetRemainEnergy,
    &GetBatteryInfo,
    &SetChargingLimit,
};

void BatteryHdiFuzzTest(const uint8_t *data, size_t size)
{
    int32_t number = GetTickCount() % fuzzFunc.size();
    fuzzFunc[number](data, size);
}
} // namespace V2_0
} // namespace Battery
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::Battery::V2_0::BatteryHdiFuzzTest(data, size);
    return 0;
}
