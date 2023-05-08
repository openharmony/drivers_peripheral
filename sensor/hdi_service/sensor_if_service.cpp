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

#define HDF_LOG_TAG uhdf_sensor_service

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_0 {
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
    struct WrapperSensorVdi *wrapperSensorVdi = nullptr;
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

    wrapperSensorVdi = reinterpret_cast<struct WrapperSensorVdi *>(vdi_->vdiBase);
    sensorVdiImpl_.reset(wrapperSensorVdi->sensorModule);
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

    std::vector<HdfSensorInformationVdi> sensorInfoVdi = {};
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
        info.push_back(std::move(sensorInfo));
    }

    return HDF_SUCCESS;
}

int32_t SensorIfService::Enable(int32_t sensorId)
{
    HDF_LOGI("%{public}s: Enter the Enable function, sensorId is %{public}d", __func__, sensorId);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Enable");
    int32_t ret = sensorVdiImpl_->Enable(sensorId);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Enable failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::Disable(int32_t sensorId)
{
    HDF_LOGI("%{public}s: Enter the Disable function, sensorId is %{public}d", __func__, sensorId);
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
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "SetBatch");
    int32_t ret = sensorVdiImpl_->SetBatch(sensorId, samplingInterval, reportInterval);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s SetBatch failed, error code is %{public}d", __func__, ret);
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
    HDF_LOGI("%{public}s: Enter the Register function, groupId is %{public}d", __func__, groupId);
    if (sensorVdiImpl_ == nullptr) {
        HDF_LOGE("%{public}s: get sensor vdi impl failed", __func__);
        return HDF_FAILURE;
    }

    StartTrace(HITRACE_TAG_HDF, "Register");
    sptr<SensorCallbackVdi> sensorCb = new SensorCallbackVdi(callbackObj);
    int32_t ret = sensorVdiImpl_->Register(groupId, sensorCb);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s Register failed, error code is %{public}d", __func__, ret);
    }
    FinishTrace(HITRACE_TAG_HDF);

    return ret;
}

int32_t SensorIfService::Unregister(int32_t groupId, const sptr<ISensorCallback> &callbackObj)
{
    HDF_LOGI("%{public}s: Enter the Unregister function, groupId is %{public}d", __func__, groupId);
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
} // namespace V1_0
} // namespace Sensor
} // namespace HDI
} // namespace OHOS
