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

#include "thermal_interface_service.h"

#include <thread>
#include <memory>
#include <hdf_base.h>
#include <hdf_log.h>
#include "thermal_hdf_config.h"
#include "thermal_hdf_timer.h"
#include "thermal_simulation_node.h"
#include "thermal_device_mitigation.h"

namespace hdi {
namespace thermal {
namespace v1_0 {
namespace {
const std::string FILE_NAME = HDF_ETC_DIR "/thermal_config/hdf/thermal_hdi_config.xml";
}
static sptr<IThermalCallback> theramalCb_ = nullptr;
static std::shared_ptr<HdfThermalCallbackInfo> callbackInfo_ = nullptr;
static std::shared_ptr<ThermalHdfTimer> hdfTimer_ = nullptr;
static std::shared_ptr<ThermalSimulationNode> simulation_ = nullptr;
static std::shared_ptr<ThermalDeviceMitigation> mitigation_ = nullptr;

ThermalInterfaceService::ThermalInterfaceService()
{
    Init();
}

int32_t ThermalInterfaceService::Init()
{
    int32_t ret = -1;
    if (simulation_ == nullptr) {
        simulation_ = std::make_shared<ThermalSimulationNode>();
        ret = simulation_->NodeInit();
        if (ret != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    }

    ret = ThermalHdfConfig::GetInsance().ThermalHDIConfigInit(FILE_NAME);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to init XML, ret: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    if (mitigation_ == nullptr) {
        mitigation_ = std::make_shared<ThermalDeviceMitigation>();
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceService::SetCpuFreq(int32_t freq)
{
    HDF_LOGI("%{public}s: service get cpu freq=%{public}d", __func__, freq);
    if (mitigation_ != nullptr) {
        int32_t ret = mitigation_->CpuRequest(freq);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: failed to set freq %{public}d", __func__, ret);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceService::SetGpuFreq(int32_t freq)
{
    int32_t ret = mitigation_->GpuRequest(freq);
    if (mitigation_ != nullptr) {
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: failed to set freq %{public}d", __func__, ret);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceService::SetBatteryCurrent(int32_t current)
{
    if (mitigation_ != nullptr) {
        int32_t ret = mitigation_->ChargerRequest(current);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: failed to set freq %{public}d", __func__, ret);
            return ret;
        }
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceService::GetThermalZoneInfo(HdfThermalCallbackInfo& event)
{
    if (simulation_ != nullptr) {
        event.info = simulation_->GetTzInfoList();
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceService::Register(const sptr<IThermalCallback>& callbackObj)
{
    HDF_LOGI("%{public}s: service register callback", __func__);
    int32_t ret = -1;
    theramalCb_ = callbackObj;
    if (hdfTimer_ == nullptr) {
        hdfTimer_ = std::make_shared<ThermalHdfTimer>(simulation_, theramalCb_);
        ret = hdfTimer_->Init();
        if (ret != HDF_SUCCESS) {
            return ret;
        }
    }
    return HDF_SUCCESS;
}

int32_t ThermalInterfaceService::Unregister()
{
    theramalCb_ = nullptr;
    return HDF_SUCCESS;
}
} // v1_0
} // thermal
} // hdi
