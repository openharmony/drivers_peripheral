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

#include "sensor_if_service.h"
#include <refbase.h>
#include <cinttypes>
#include "hdf_log.h"
#include "hitrace_meter.h"
#include "sensor_type.h"
#include "sensor_callback_vdi.h"
#include <hdf_remote_service.h>

constexpr int DISABLE_SENSOR = 0;
constexpr int ENABLE_SENSOR = 1;

#define HDF_LOG_TAG uhdf_sensor_service

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {
SensorIfService::SensorIfService()
{
    int32_t ret = GetSensorVdiImpl();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get sensor vdi instance failed", __func__);
    }
}

SensorIfService::~SensorIfService()
{
    if (vdi_ != nullptr) {
        HdfCloseVdi(vdi_);
    }
}

int32_t SensorIfService::GetSensorVdiImpl()
{
    struct OHOS::HDI::Sensor::V1_1::WrapperSensorVdi *wrapperSensorVdi = nullptr;
    uint32_t version = 0;
    vdi_ = HdfLoadVdi(HDI_SENSOR_VDI_LIBNAME);
    if (vdi_ == nullptr || vdi_->vdiBase == nullptr) {
        HDF_LOGE("%{public}s: load sensor vdi failed", __func__);
        return HDF_FAILURE;
    }

    version = HdfGetVdiVersion(vdi_);
    if (version != 1) {
        HDF_LOGE("%{public}s: get sensor vdi version failed", __func__);
        return HDF_FAILURE;
    }

    wrapperSensorVdi = reinterpret_cast<struct OHOS::HDI::Sensor::V1_1::WrapperSensorVdi *>(vdi_->vdiBase);
    sensorVdiImpl_ = wrapperSensorVdi->sensorModule;
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor impl failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t SensorIfService::Init()
{
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = sensorVdiImpl_->Init();
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Init failed, error code is %{public}d", __func__, ret);
    }

    return ret;
}

int32_t SensorIfService::GetAllSensorInfo(std::vector<HdfSensorInformation> &info)
{
    HDF_LOGI("%{public}s: Enter the GetAllSensorInfo function.", __func__);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    std::vector<OHOS::HDI::Sensor::V1_1::HdfSensorInformationVdi> sensorInfoVdi = {};
    StartTrace(HITRACE_TAG_HDF, "GetAllSensorInfo");
    int32_t ret = sensorVdiImpl_->GetAllSensorInfo(sensorInfoVdi);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s GetAllSensors failed, error code is %{public}d", __func__, ret);
        return ret;
    }
    FinishTrace(HITRACE_TAG_HDF);

    if (sensorInfoVdi.empty()) {
        HDF_LOGE("%{public}s no sensor info in list", __func__);
        return HDF_FAILURE;
    }

    for (const auto &it : sensorInfoVdi) {
        struct HdfSensorInformation sensorInfo = {};
        sensorInfo.sensorName = it.sensorName;
        sensorInfo.vendorName = it.vendorName;
        sensorInfo.firmwareVersion = it.firmwareVersion;
        sensorInfo.hardwareVersion = it.hardwareVersion;
        sensorInfo.sensorTypeId = it.sensorTypeId;
        sensorInfo.sensorId = it.sensorId;
        sensorInfo.maxRange = it.maxRange;
        sensorInfo.accuracy = it.accuracy;
        sensorInfo.power = it.power;
        sensorInfo.minDelay = it.minDelay;
        sensorInfo.maxDelay = it.maxDelay;
        sensorInfo.fifoMaxEventCount = it.fifoMaxEventCount;
        info.push_back(std::move(sensorInfo));
    }

    return HDF_SUCCESS;
}

int32_t SensorIfService::Enable(int32_t sensorId)
{
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s:Enter the Enable function, sensorId %{public}d, service %{public}d",
             __func__, sensorId, serviceId);
    if (!SensorClientsManager::GetInstance()->IsUpadateSensorState(sensorId, serviceId, ENABLE_SENSOR)) {
        return HDF_SUCCESS;
    }
    
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Enable");
    int32_t ret = sensorVdiImpl_->Enable(sensorId);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Enable failed, error code is %{public}d", __func__, ret);
    } else {
        SensorClientsManager::GetInstance()->OpenSensor(sensorId, serviceId);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::Disable(int32_t sensorId)
{
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s:Enter the Disable function, sensorId %{public}d, service %{public}d",
             __func__, sensorId, serviceId);
    if (!SensorClientsManager::GetInstance()->IsUpadateSensorState(sensorId, serviceId, DISABLE_SENSOR)) {
        return HDF_SUCCESS;
    }

    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Disable");
    int32_t ret = sensorVdiImpl_->Disable(sensorId);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Disable failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval)
{
    HDF_LOGI("%{public}s: sensorId is %{public}d, samplingInterval is [%{public}" PRId64 "], \
        reportInterval is [%{public}" PRId64 "].", __func__, sensorId, samplingInterval, reportInterval);
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    SensorClientsManager::GetInstance()->SetClientSenSorConfig(sensorId, serviceId, samplingInterval, reportInterval);
    SensorClientsManager::GetInstance()->SetSensorBestConfig(sensorId, samplingInterval, reportInterval);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "SetBatch");
    int32_t ret = sensorVdiImpl_->SetBatch(sensorId, samplingInterval, reportInterval);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetBatch failed, error code is %{public}d", __func__, ret);
    } else {
        SensorClientsManager::GetInstance()->UpdateSensorConfig(sensorId, samplingInterval, reportInterval);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::SetMode(int32_t sensorId, int32_t mode)
{
    HDF_LOGI("%{public}s: Enter the SetMode function, sensorId is %{public}d, mode is %{public}d",
        __func__, sensorId, mode);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "SetMode");
    int32_t ret = sensorVdiImpl_->SetMode(sensorId, mode);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetMode failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::SetOption(int32_t sensorId, uint32_t option)
{
    HDF_LOGI("%{public}s: Enter the SetOption function, sensorId is %{public}d, option is %{public}u",
        __func__, sensorId, option);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "SetOption");
    int32_t ret = sensorVdiImpl_->SetOption(sensorId, option);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetOption failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::Register(int32_t groupId, const sptr<ISensorCallback> &callbackObj)
{
    int32_t ret = HDF_SUCCESS;
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s:Enter the Register function, groupId %{public}d, service %{public}d",
             __func__, groupId, serviceId);
    if (SensorClientsManager::GetInstance()->IsClientsEmpty(groupId)) {
        if (sensorVdiImpl_ == nullptr) {
            HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
            return HDF_FAILURE;
        }
        StartTrace(HITRACE_TAG_HDF, "Register");
        sptr<SensorCallbackVdi> sensorCb = new SensorCallbackVdi(callbackObj);
        ret = sensorVdiImpl_->Register(groupId, sensorCb);
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("%{public}s Register failed, error code is %{public}d", __func__, ret);
        } else {
            SensorClientsManager::GetInstance()->ReportDataCbRegister(groupId, serviceId, callbackObj);
        }
        FinishTrace(HITRACE_TAG_HDF);
    } else {
        SensorClientsManager::GetInstance()->ReportDataCbRegister(groupId, serviceId, callbackObj);
    }

    return ret;
}

int32_t SensorIfService::Unregister(int32_t groupId, const sptr<ISensorCallback> &callbackObj)
{
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    HDF_LOGI("%{public}s:Enter the Unregister function, groupId %{public}d, service %{public}d",
             __func__, groupId, serviceId);
    SensorClientsManager::GetInstance()->ReportDataCbUnRegister(groupId, serviceId, callbackObj);
    if (!SensorClientsManager::GetInstance()->IsClientsEmpty(groupId)) {
        HDF_LOGI("%{public}s: clients is not empty, do not unregister", __func__);
        return HDF_SUCCESS;
    }

    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Unregister");
    sptr<SensorCallbackVdi> sensorCb = new SensorCallbackVdi(callbackObj);
    int32_t ret = sensorVdiImpl_->Unregister(groupId, sensorCb);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s: Unregister failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::ReadData(int32_t sensorId, std::vector<HdfSensorEvents> &event)
{
    HDF_LOGI("%{public}s: Enter the ReadData function", __func__);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t SensorIfService::SetSdcSensor(int32_t sensorId, bool enabled, int32_t rateLevel)
{
    HDF_LOGI("%{public}s: Enter the SetSdcSensor function, sensorId is %{public}d, enabled is %{public}u, \
             rateLevel is %{public}u", __func__, sensorId, enabled, rateLevel);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "SetSdcSensor");
    if (enabled) {
        int32_t ret = this.SetBatch(sensorId, 0, rateLevel);
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("%{public}s SetSdcSensor setBatch failed, error code is %{public}d", __func__, ret);
        }
        ret = sensorVdiImpl_->Enable(sensorId);
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("%{public}s SetSdcSensor enable failed, error code is %{public}d", __func__, ret);
        }
    } else {
        int32_t ret = this.Disable(sensorId);
        if (ret != SENSOR_SUCCESS) {
            HDF_LOGE("%{public}s SetSdcSensor setBatch failed, error code is %{public}d", __func__, ret);
        }
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::GetSdcSensorInfo(std::vector<SdcSensorInfo>& sdcSensorInfo)
{
    HDF_LOGI("%{public}s: Enter the GetSdcSensorInfo function", __func__);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    std::vector<OHOS::HDI::Sensor::V1_1::SdcSensorInfoVdi> sdcSensorInfoVdi;
    StartTrace(HITRACE_TAG_HDF, "GetSdcSensorInfo");
    int32_t ret = sensorVdiImpl_->GetSdcSensorInfo(sdcSensorInfoVdi);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s GetSdcSensorInfo failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    for (auto infoVdi : sdcSensorInfoVdi) {
        SdcSensorInfo info;
        info.offset = infoVdi.offset;
        info.sensorId = infoVdi.sensorId;
        info.ddrSize = infoVdi.ddrSize;
        info.minRateLevel = infoVdi.minRateLevel;
        info.maxRateLevel = infoVdi.maxRateLevel;
        info.memAddr = infoVdi.memAddr;
        info.reserved = infoVdi.reserved;
        sdcSensorInfo.push_back(std::move(info));
    }

    return ret;
}

extern "C" ISensorInterface *SensorInterfaceImplGetInstance(void)
{
    SensorIfService *impl = new (std::nothrow) SensorIfService();
    if (impl == nullptr) {
        return nullptr;
    }

    int32_t ret = impl->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: service init failed, error code is %{public}d", __func__, ret);
        delete impl;
        return nullptr;
    }

    return impl;
}
} // namespace V1_1
} // namespace Sensor
} // namespace HDI
} // namespace OHOS