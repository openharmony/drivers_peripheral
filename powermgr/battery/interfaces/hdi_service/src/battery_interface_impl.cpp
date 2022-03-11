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

#include "battery_interface_impl.h"
#include "hdf_base.h"
#include "hdf_log.h"

#define HDF_LOG_TAG BatteryInterfaceImpl

using namespace OHOS::HDI::Battery::V1_0;

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V1_0 {
static std::unique_ptr<OHOS::HDI::Battery::V1_0::PowerSupplyProvider> giver_ = nullptr;
static std::unique_ptr<OHOS::HDI::Battery::V1_0::BatteryThread> loop_ = nullptr;
static std::unique_ptr<OHOS::HDI::Battery::V1_0::BatteryConfig> batteryConfig_ = nullptr;
static std::unique_ptr<OHOS::HDI::Battery::V1_0::BatteryLed> batteryLed_ = nullptr;
static sptr<IBatteryCallback> g_cbEvent;

BatteryInterfaceImpl::BatteryInterfaceImpl()
{
    Init();
}

int32_t BatteryInterfaceImpl::Init()
{
    giver_ = std::make_unique<OHOS::HDI::Battery::V1_0::PowerSupplyProvider>();
    if (giver_ == nullptr) {
        HDF_LOGE("%{public}s: instantiate PowerSupplyProvider error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    giver_->InitBatteryPath();
    giver_->InitPowerSupplySysfs();

    batteryConfig_ = std::make_unique<OHOS::HDI::Battery::V1_0::BatteryConfig>();
    if (batteryConfig_ == nullptr) {
        HDF_LOGI("%{public}s: instantiate batteryconfig error.", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    batteryConfig_->Init();

    batteryLed_ = std::make_unique<OHOS::HDI::Battery::V1_0::BatteryLed>();
    if (batteryLed_ == nullptr) {
        HDF_LOGE("%{public}s: instantiate BatteryLed error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    batteryLed_->InitLedsSysfs();

    loop_ = std::make_unique<OHOS::HDI::Battery::V1_0::BatteryThread>();
    if (loop_ == nullptr) {
        HDF_LOGE("%{public}s: Instantiate BatteryThread error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (g_cbEvent != nullptr) {
        loop_->InitCallback(g_cbEvent);
    } else {
        HDF_LOGE("%{public}s: g_cbEvent is nullptr.", __func__);
    }
    loop_->StartThread(this);

    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::Register(const sptr<IBatteryCallback>& event)
{
    HDF_LOGI("%{public}s subcriber is %{public}p", __func__, event.GetRefPtr());
    g_cbEvent = event;

    if (g_cbEvent != nullptr) {
        loop_->InitCallback(g_cbEvent);
    } else {
        HDF_LOGE("%{public}s: g_cbEvent is nullptr.", __func__);
    }

    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::UnRegister()
{
    g_cbEvent = nullptr;
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::ChangePath(const std::string& path)
{
    HDF_LOGI("%{public}s enter, path is %{public}s", __func__, path.c_str());
    giver_->SetSysFilePath(path);
    giver_->InitPowerSupplySysfs();
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetCapacity(int32_t& capacity)
{
    return giver_->ParseCapacity(&capacity);
}

int32_t BatteryInterfaceImpl::GetVoltage(int32_t& voltage)
{
    return giver_->ParseVoltage(&voltage);
}

int32_t BatteryInterfaceImpl::GetTemperature(int32_t& temperature)
{
    return giver_->ParseTemperature(&temperature);
}

int32_t BatteryInterfaceImpl::GetHealthState(BatteryHealthState& healthState)
{
    int32_t state = 0;
    int32_t ret = giver_->ParseHealthState(&state);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    healthState = BatteryHealthState(state);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetPluggedType(BatteryPluggedType& pluggedType)
{
    int32_t type = 0;
    int32_t ret = giver_->ParsePluggedType(&type);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    pluggedType = BatteryPluggedType(type);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetChargeState(BatteryChargeState& chargeState)
{
    int32_t state = 0;
    int32_t ret = giver_->ParseChargeState(&state);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    chargeState = BatteryChargeState(state);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetPresent(bool& present)
{
    int8_t isPresent = 0;
    int32_t ret = giver_->ParsePresent(&isPresent);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    present = bool(isPresent);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetTechnology(std::string& technology)
{
    return giver_->ParseTechnology(technology);
}

int32_t BatteryInterfaceImpl::GetTotalEnergy(int32_t& totalEnergy)
{
    return giver_->ParseTotalEnergy(&totalEnergy);
}

int32_t BatteryInterfaceImpl::GetCurrentAverage(int32_t& curAverage)
{
    return giver_->ParseCurrentAverage(&curAverage);
}

int32_t BatteryInterfaceImpl::GetCurrentNow(int32_t& curNow)
{
    return giver_->ParseCurrentNow(&curNow);
}

int32_t BatteryInterfaceImpl::GetRemainEnergy(int32_t& remainEnergy)
{
    return giver_->ParseRemainEnergy(&remainEnergy);
}

int32_t BatteryInterfaceImpl::GetBatteryInfo(BatteryInfo& info)
{
    if (giver_ == nullptr) {
        return HDF_FAILURE;
    }

    BatterydInfo batteryInfo = giver_->GetBatteryInfo();
    info.capacity = batteryInfo.capacity_;
    info.voltage = batteryInfo.voltage_;
    info.temperature = batteryInfo.temperature_;
    info.healthState = batteryInfo.healthState_;
    info.pluggedType = batteryInfo.pluggedType_;
    info.pluggedMaxCurrent = batteryInfo.pluggedMaxCurrent_;
    info.pluggedMaxVoltage = batteryInfo.pluggedMaxVoltage_;
    info.chargeState = batteryInfo.chargeState_;
    info.chargeCounter = batteryInfo.chargeCounter_;
    info.present = batteryInfo.present_;
    info.technology = batteryInfo.technology_;

    return HDF_SUCCESS;
}
} // V1_0
} // Battery
} // Hdi
} // OHOS
