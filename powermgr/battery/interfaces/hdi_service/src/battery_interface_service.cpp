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

#include "battery_interface_service.h"
#include "hdf_base.h"
#include "hdf_log.h"

#define HDF_LOG_TAG BatteryInterfaceService

using namespace OHOS::HDI::Battery::V1_0;

namespace hdi {
namespace battery {
namespace v1_0 {
static std::unique_ptr<PowerSupplyProvider> giver_ = nullptr;
static std::unique_ptr<BatteryThread> loop_ = nullptr;
static std::unique_ptr<BatteryConfig> batteryConfig_ = nullptr;
static std::unique_ptr<BatteryLed> batteryLed_ = nullptr;
static sptr<IBatteryCallback> g_cbEvent;

BatteryInterfaceService::BatteryInterfaceService()
{
    Init();
}

int32_t BatteryInterfaceService::Init()
{
    giver_ = std::make_unique<PowerSupplyProvider>();
    if (giver_ == nullptr) {
        HDF_LOGE("%{public}s: instantiate PowerSupplyProvider error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    giver_->InitBatteryPath();
    giver_->InitPowerSupplySysfs();

    batteryConfig_ = std::make_unique<BatteryConfig>();
    if (batteryConfig_ == nullptr) {
        HDF_LOGI("%{public}s: instantiate batteryconfig error.", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    batteryConfig_->Init();

    batteryLed_ = std::make_unique<BatteryLed>();
    if (batteryLed_ == nullptr) {
        HDF_LOGE("%{public}s: instantiate BatteryLed error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    batteryLed_->InitLedsSysfs();

    loop_ = std::make_unique<BatteryThread>();
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

int32_t BatteryInterfaceService::Register(const sptr<IBatteryCallback>& event)
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

int32_t BatteryInterfaceService::UnRegister()
{
    g_cbEvent = nullptr;
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::ChangePath(const std::string& path)
{
    HDF_LOGI("%{public}s enter, path is %{public}s", __func__, path.c_str());
    giver_->SetSysFilePath(path);
    giver_->InitPowerSupplySysfs();
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::GetCapacity(int32_t& capacity)
{
    int32_t ret = giver_->ParseCapacity(&capacity);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::GetVoltage(int32_t& voltage)
{
    int32_t ret = giver_->ParseVoltage(&voltage);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::GetTemperature(int32_t& temperature)
{
    int32_t ret = giver_->ParseTemperature(&temperature);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::GetHealthState(BatteryHealthState& healthState)
{
    int32_t state = 0;
    int32_t ret = giver_->ParseHealthState(&state);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    healthState = BatteryHealthState(state);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::GetPluggedType(BatteryPluggedType& pluggedType)
{
    int32_t type = 0;
    int32_t ret = giver_->ParsePluggedType(&type);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    pluggedType = BatteryPluggedType(type);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::GetChargeState(BatteryChargeState& chargeState)
{
    int32_t state = 0;
    int32_t ret = giver_->ParseChargeState(&state);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    chargeState = BatteryChargeState(state);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::GetPresent(bool& present)
{
    int8_t isPresent = 0;
    int32_t ret = giver_->ParsePresent(&isPresent);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    present = bool(isPresent);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceService::GetTechnology(std::string& technology)
{
    int32_t ret = giver_->ParseTechnology(technology);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    return HDF_SUCCESS;
}
} // v1_0
} // battery
} // hdi
