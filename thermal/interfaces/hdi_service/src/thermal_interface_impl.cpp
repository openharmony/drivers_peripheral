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

#include "thermal_interface_impl.h"

#include <thread>
#include <memory>
#include <hdf_base.h>
#include "thermal_hdf_config.h"
#include "thermal_hdf_timer.h"
#include "thermal_simulation_node.h"
#include "thermal_device_mitigation.h"
#include "thermal_zone_manager.h"
#include "thermal_log.h"
#include "config_policy_utils.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
namespace {

const std::string HDI_XML_PATH = "etc/thermal_config/thermal_hdi_config.xml";
const std::string VENDOR_HDI_XML_PATH = "/vendor/etc/thermal_config/thermal_hdi_config.xml";
bool g_isHdiStart = false;
}
static sptr<IThermalCallback> theramalCb_ = nullptr;
static std::shared_ptr<HdfThermalCallbackInfo> callbackInfo_ = nullptr;
static std::shared_ptr<ThermalHdfTimer> hdfTimer_ = nullptr;
static std::shared_ptr<ThermalSimulationNode> simulation_ = nullptr;
static std::shared_ptr<ThermalDeviceMitigation> mitigation_ = nullptr;
static std::shared_ptr<ThermalZoneManager> thermalZoneMgr_ = nullptr;

extern "C" IThermalInterface *ThermalInterfaceImplGetInstance(void)
{
    return new (std::nothrow) ThermalInterfaceImpl();
}

ThermalInterfaceImpl::ThermalInterfaceImpl()
{
    Init();
}

int32_t ThermalInterfaceImpl::Init()
{
    char buf[MAX_PATH_LEN];
    bool parseConfigSuc = false;
    int32_t ret;
    char* path = GetOneCfgFile(HDI_XML_PATH.c_str(), buf, MAX_PATH_LEN);
    if (path != nullptr && *path != '\0') {
        ret = ThermalHdfConfig::GetInstance().ThermalHDIConfigInit(path);
        if (ret != HDF_SUCCESS) {
            THERMAL_HILOGE(COMP_HDI, "parse err pliocy thermal hdi XML");
            return HDF_FAILURE;
        }
        parseConfigSuc = true;
    }

    if (!parseConfigSuc) {
        ret = ThermalHdfConfig::GetInstance().ThermalHDIConfigInit(VENDOR_HDI_XML_PATH);
        if (ret != HDF_SUCCESS) {
            THERMAL_HILOGE(COMP_HDI, "failed to init XML, ret: %{public}d", ret);
            return HDF_FAILURE;
        }
    }

    if (simulation_ == nullptr) {
        simulation_ = std::make_shared<ThermalSimulationNode>();
    }

    if (thermalZoneMgr_ == nullptr) {
        thermalZoneMgr_ = std::make_shared<ThermalZoneManager>();
    }

    if (mitigation_ == nullptr) {
        mitigation_ = std::make_shared<ThermalDeviceMitigation>();
    }

    if (hdfTimer_ == nullptr) {
        hdfTimer_ = std::make_shared<ThermalHdfTimer>(simulation_, thermalZoneMgr_);
        hdfTimer_->SetSimluationFlag();
    }

    ret = simulation_->NodeInit();
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    thermalZoneMgr_->Init();
    thermalZoneMgr_->CalculateMaxCd();
    ret = thermalZoneMgr_->UpdateThermalZoneData();
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    thermalZoneMgr_->DumpPollingInfo();
    mitigation_->SetFlag(static_cast<bool>(hdfTimer_->GetSimluationFlag()));
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceImpl::SetCpuFreq(int32_t freq)
{
    if (freq <= 0) {
        THERMAL_HILOGE(COMP_HDI, "invalid freq %{public}d", freq);
        return HDF_FAILURE;
    }
    if (mitigation_ != nullptr) {
        int32_t ret = mitigation_->CpuRequest(freq);
        if (ret != HDF_SUCCESS) {
            THERMAL_HILOGE(COMP_HDI, "failed to set freq %{public}d", ret);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceImpl::SetGpuFreq(int32_t freq)
{
    if (freq <= 0) {
        THERMAL_HILOGE(COMP_HDI, "invalid freq %{public}d", freq);
        return HDF_FAILURE;
    }
    if (mitigation_ != nullptr) {
        int32_t ret = mitigation_->GpuRequest(freq);
        if (ret != HDF_SUCCESS) {
            THERMAL_HILOGE(COMP_HDI, "failed to set freq %{public}d", ret);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceImpl::SetBatteryCurrent(int32_t current)
{
    if (current <= 0) {
        THERMAL_HILOGE(COMP_HDI, "invalid current %{public}d", current);
        return HDF_FAILURE;
    }
    if (mitigation_ != nullptr) {
        int32_t ret = mitigation_->ChargerRequest(current);
        if (ret != HDF_SUCCESS) {
            THERMAL_HILOGE(COMP_HDI, "failed to set current %{public}d", ret);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceImpl::GetThermalZoneInfo(HdfThermalCallbackInfo& event)
{
    if (thermalZoneMgr_ != nullptr) {
        thermalZoneMgr_->UpdateThermalZoneData();
        event.info = thermalZoneMgr_->GetCallbackInfo().info;
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceImpl::IsolateCpu(int32_t num)
{
    if (num <= 0) {
        THERMAL_HILOGE(COMP_HDI, "invalid num %{public}d", num);
        return HDF_FAILURE;
    }
    if (mitigation_ != nullptr) {
        int32_t ret = mitigation_->IsolateCpu(num);
        if (ret != HDF_SUCCESS) {
            THERMAL_HILOGE(COMP_HDI, "failed to set isolate cpu num %{public}d", ret);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceImpl::Register(const sptr<IThermalCallback>& callbackObj)
{
    if (thermalZoneMgr_ == nullptr || callbackObj == nullptr) {
        return HDF_FAILURE;
    }

    thermalZoneMgr_->SetThermalEventCb(callbackObj);
    StartTimerThread();

    return g_isHdiStart ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t ThermalInterfaceImpl::Unregister()
{
    if (thermalZoneMgr_ == nullptr || thermalZoneMgr_->GetThermalEventCb() == nullptr) {
        return HDF_FAILURE;
    }

    thermalZoneMgr_->DelThermalEventCb();
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceImpl::RegisterFanCallback(const sptr<IFanCallback>& callbackObj)
{
    if (thermalZoneMgr_ == nullptr || callbackObj == nullptr) {
        return HDF_FAILURE;
    }

    thermalZoneMgr_->SetFanEventCb(callbackObj);
    StartTimerThread();

    return g_isHdiStart ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t ThermalInterfaceImpl::UnregisterFanCallback()
{
    if (thermalZoneMgr_ == nullptr || thermalZoneMgr_->GetFanEventCb() == nullptr) {
        return HDF_FAILURE;
    }

    thermalZoneMgr_->DelFanEventCb();
    return HDF_SUCCESS;
}

void ThermalInterfaceImpl::StartTimerThread()
{
    if (hdfTimer_ == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!g_isHdiStart) {
        int32_t ret = hdfTimer_->Init();
        if (ret != HDF_SUCCESS) {
            return;
        }
        g_isHdiStart = true;
    }

    return;
}

} // V1_1
} // Thermal
} // HDI
} // OHOS
