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
#include "battery_config.h"
#include "battery_log.h"

namespace OHOS {
namespace HDI {
namespace Battery {
namespace V1_1 {
namespace {
sptr<BatteryInterfaceImpl::BatteryDeathRecipient> g_deathRecipient = nullptr;
bool g_isHdiStart = false;
}

extern "C" IBatteryInterface *BatteryInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Battery::V1_1::BatteryInterfaceImpl;
    BatteryInterfaceImpl *service = new (std::nothrow) BatteryInterfaceImpl();
    if (service == nullptr) {
        return nullptr;
    }

    if (service->Init() != HDF_SUCCESS) {
        delete service;
        return nullptr;
    }

    return service;
}

int32_t BatteryInterfaceImpl::Init()
{
    provider_ = std::make_unique<OHOS::HDI::Battery::V1_1::PowerSupplyProvider>();
    if (provider_ == nullptr) {
        BATTERY_HILOGE(COMP_HDI, "make_unique PowerSupplyProvider error");
        return HDF_ERR_MALLOC_FAIL;
    }
    provider_->InitBatteryPath();
    provider_->InitPowerSupplySysfs();

    auto& batteryConfig = BatteryConfig::GetInstance();
    batteryConfig.ParseConfig();
    currentPath_ = batteryConfig.GetString("charger.current_limit.path");
    voltagePath_ = batteryConfig.GetString("charger.voltage_limit.path");

    // The configuration can be released when it is not needed
    BatteryConfig::DestroyInstance();

    loop_ = std::make_unique<OHOS::HDI::Battery::V1_1::BatteryThread>();
    if (loop_ == nullptr) {
        BATTERY_HILOGE(COMP_HDI, "make_unique BatteryThread error");
        return HDF_ERR_MALLOC_FAIL;
    }

    if (batteryCallback_ != nullptr) {
        loop_->InitCallback(batteryCallback_);
    } else {
        BATTERY_HILOGW(COMP_HDI, "batteryCallback_ is nullptr");
    }
    loop_->StartThread(this);

    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::Register(const sptr<IBatteryCallback>& callback)
{
    if (callback == nullptr) {
        BATTERY_HILOGW(FEATURE_BATT_INFO, "callback is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!g_isHdiStart) {
        batteryCallback_ = callback;
        loop_->InitCallback(batteryCallback_);

        g_deathRecipient = new BatteryInterfaceImpl::BatteryDeathRecipient(this);
        if (g_deathRecipient == nullptr) {
            BATTERY_HILOGE(COMP_HDI, "Failed to allocate BatteryDeathRecipient");
            return HDF_ERR_MALLOC_FAIL;
        }
        AddBatteryDeathRecipient(batteryCallback_);
        g_isHdiStart = true;
    }
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::UnRegister()
{
    RemoveBatteryDeathRecipient(batteryCallback_);
    batteryCallback_ = nullptr;
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::ChangePath(const std::string& path)
{
    provider_->SetSysFilePath(path);
    provider_->InitPowerSupplySysfs();
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetCapacity(int32_t& capacity)
{
    return provider_->ParseCapacity(&capacity);
}

int32_t BatteryInterfaceImpl::GetVoltage(int32_t& voltage)
{
    return provider_->ParseVoltage(&voltage);
}

int32_t BatteryInterfaceImpl::GetTemperature(int32_t& temperature)
{
    return provider_->ParseTemperature(&temperature);
}

int32_t BatteryInterfaceImpl::GetHealthState(BatteryHealthState& healthState)
{
    int32_t state = 0;
    int32_t ret = provider_->ParseHealthState(&state);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    healthState = BatteryHealthState(state);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetPluggedType(BatteryPluggedType& pluggedType)
{
    int32_t type = 0;
    int32_t ret = provider_->ParsePluggedType(&type);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    pluggedType = BatteryPluggedType(type);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetChargeState(BatteryChargeState& chargeState)
{
    int32_t state = 0;
    int32_t ret = provider_->ParseChargeState(&state);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    chargeState = BatteryChargeState(state);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetPresent(bool& present)
{
    int8_t isPresent = 0;
    int32_t ret = provider_->ParsePresent(&isPresent);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    present = bool(isPresent);
    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::GetTechnology(std::string& technology)
{
    return provider_->ParseTechnology(technology);
}

int32_t BatteryInterfaceImpl::GetTotalEnergy(int32_t& totalEnergy)
{
    return provider_->ParseTotalEnergy(&totalEnergy);
}

int32_t BatteryInterfaceImpl::GetCurrentAverage(int32_t& curAverage)
{
    return provider_->ParseCurrentAverage(&curAverage);
}

int32_t BatteryInterfaceImpl::GetCurrentNow(int32_t& curNow)
{
    return provider_->ParseCurrentNow(&curNow);
}

int32_t BatteryInterfaceImpl::GetRemainEnergy(int32_t& remainEnergy)
{
    return provider_->ParseRemainEnergy(&remainEnergy);
}

int32_t BatteryInterfaceImpl::GetBatteryInfo(BatteryInfo& info)
{
    if (provider_ == nullptr) {
        return HDF_FAILURE;
    }

    BatterydInfo batteryInfo = provider_->GetBatteryInfo();
    info.capacity = batteryInfo.capacity_;
    info.voltage = batteryInfo.voltage_;
    info.temperature = batteryInfo.temperature_;
    info.healthState = batteryInfo.healthState_;
    info.pluggedType = batteryInfo.pluggedType_;
    info.pluggedMaxCurrent = batteryInfo.pluggedMaxCurrent_;
    info.pluggedMaxVoltage = batteryInfo.pluggedMaxVoltage_;
    info.chargeState = batteryInfo.chargeState_;
    info.chargeCounter = batteryInfo.chargeCounter_;
    info.curNow = batteryInfo.curNow_;
    info.curAverage = batteryInfo.curAverage_;
    info.remainEnergy = batteryInfo.remainEnergy_;
    info.totalEnergy = batteryInfo.totalEnergy_;
    info.present = batteryInfo.present_;
    info.technology = batteryInfo.technology_;

    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::SetChargingLimit(const std::vector<ChargingLimit>& chargingLimit)
{
    return provider_->SetChargingLimit(chargingLimit, currentPath_, voltagePath_);
}

int32_t BatteryInterfaceImpl::AddBatteryDeathRecipient(const sptr<IBatteryCallback>& callback)
{
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IBatteryCallback>(callback);
    bool result = remote->AddDeathRecipient(g_deathRecipient);
    if (!result) {
        BATTERY_HILOGE(COMP_HDI, "AddDeathRecipient fail");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t BatteryInterfaceImpl::RemoveBatteryDeathRecipient(const sptr<IBatteryCallback>& callback)
{
    if (callback == nullptr) {
        BATTERY_HILOGW(FEATURE_BATT_INFO, "remove callback is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IBatteryCallback>(callback);
    bool result = remote->RemoveDeathRecipient(g_deathRecipient);
    if (!result) {
        BATTERY_HILOGE(COMP_HDI, "RemoveDeathRecipient fail");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void BatteryInterfaceImpl::BatteryDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    interfaceImpl_->UnRegister();
}
}  // namespace V1_1
}  // namespace Battery
}  // namespace Hdi
}  // namespace OHOS
