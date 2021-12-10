/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "sensor_interface_service.h"
#include "sensor_if.h"

namespace hdi {
namespace sensor {
namespace v1_0 {
static sptr<ISensorCallback> g_sensorCallback = nullptr;

int SensorDataCallback(const struct SensorEvents *event)
{
    if (event == nullptr || event->data == nullptr) {
        HDF_LOGE("%{public}s failed, event or event.data is nullptr", __func__);
        return SENSOR_FAILURE;
    }

    if (g_sensorCallback == nullptr) {
        HDF_LOGE("%{public}s failed, g_sensorCallback is nullptr", __func__);
        return SENSOR_FAILURE;
    }

    HdfSensorEvents hdfSensorEvents;
    hdfSensorEvents.sensorId = event->sensorId;
    hdfSensorEvents.version = event->version;
    hdfSensorEvents.timestamp = event->timestamp;
    hdfSensorEvents.option = event->option;
    hdfSensorEvents.mode = event->mode;
    hdfSensorEvents.dataLen = event->dataLen;
    uint32_t len = event->dataLen;
    uint8_t *tmp = event->data;

    while (len--) {
        hdfSensorEvents.data.push_back(*tmp);
        tmp++;
    }
    g_sensorCallback->OnDataEvent(hdfSensorEvents);
    return 0;
}

int32_t SensorInterfaceService::GetAllSensorInfo(std::vector<HdfSensorInformation>& info)
{
    const SensorInterface *sensorInterface = NewSensorInterfaceInstance();
    if (sensorInterface == NULL || sensorInterface->GetAllSensors == NULL) {
        HDF_LOGE("%{public}s: get sensor Module instance failed", __func__);
        return HDF_FAILURE;
    }
    
    struct SensorInformation *sensorInfo = nullptr;
    struct SensorInformation *tmp = nullptr;
    int32_t count = 0;
    int32_t ret = sensorInterface->GetAllSensors(&sensorInfo, &count);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %d", __func__, ret);
        return ret;
    }
    if (count <=0) {
        HDF_LOGE("%{public}s failed, count<=0", __func__);
        return HDF_FAILURE;
    }
    
    tmp = sensorInfo;
    while (count--) {
        HdfSensorInformation hdfSensorInfo;
        std::string sensorName(tmp->sensorName);
        hdfSensorInfo.sensorName = sensorName;
        std::string vendorName(tmp->vendorName);
        hdfSensorInfo.vendorName = vendorName;
        std::string firmwareVersion(tmp->firmwareVersion);
        hdfSensorInfo.firmwareVersion = firmwareVersion;
        std::string hardwareVersion(tmp->hardwareVersion);
        hdfSensorInfo.hardwareVersion = hardwareVersion;
        hdfSensorInfo.sensorTypeId = tmp->sensorTypeId;
        hdfSensorInfo.sensorId = tmp->sensorId;
        hdfSensorInfo.maxRange = tmp->maxRange;
        hdfSensorInfo.accuracy = tmp->accuracy;
        hdfSensorInfo.power = tmp->power;
        info.push_back(hdfSensorInfo);
        tmp++;
    }
    
    return HDF_SUCCESS;
}

int32_t SensorInterfaceService::Enable(int32_t sensorId)
{
    const SensorInterface *sensorInterface = NewSensorInterfaceInstance();
    if (sensorInterface == NULL || sensorInterface->Enable == NULL) {
        HDF_LOGE("%{public}s: get sensor Module instance failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = sensorInterface->Enable(sensorId);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %d", __func__, ret);
    }
    return ret;
}

int32_t SensorInterfaceService::Disable(int32_t sensorId)
{
    const SensorInterface *sensorInterface = NewSensorInterfaceInstance();
    if (sensorInterface == NULL || sensorInterface->Disable == NULL) {
        HDF_LOGE("%{public}s: get sensor Module instance failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = sensorInterface->Disable(sensorId);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %d", __func__, ret);
    }
    return ret;
}

int32_t SensorInterfaceService::SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval)
{
    const SensorInterface *sensorInterface = NewSensorInterfaceInstance();
    if (sensorInterface == NULL || sensorInterface->SetBatch == NULL) {
        HDF_LOGE("%{public}s: get sensor Module instance failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = sensorInterface->SetBatch(sensorId, samplingInterval, reportInterval);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %d", __func__, ret);
    }
    return ret;
}

int32_t SensorInterfaceService::SetMode(int32_t sensorId, int32_t mode)
{
    const SensorInterface *sensorInterface = NewSensorInterfaceInstance();
    if (sensorInterface == NULL || sensorInterface->SetMode == NULL) {
        HDF_LOGE("%{public}s: get sensor Module instance failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = sensorInterface->SetMode(sensorId, mode);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %d", __func__, ret);
    }
    return ret;
}

int32_t SensorInterfaceService::SetOption(int32_t sensorId, uint32_t option)
{
    const SensorInterface *sensorInterface = NewSensorInterfaceInstance();
    if (sensorInterface == NULL || sensorInterface->SetOption == NULL) {
        HDF_LOGE("%{public}s: get sensor Module instance failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = sensorInterface->SetOption(sensorId, option);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %d", __func__, ret);
    }
    return ret;
}

int32_t SensorInterfaceService::Register(const sptr<ISensorCallback>& callbackObj)
{
    const SensorInterface *sensorInterface = NewSensorInterfaceInstance();
    if (sensorInterface == NULL || sensorInterface->Register == NULL) {
        HDF_LOGE("%{public}s: get sensor Module instance failed", __func__);
        return HDF_FAILURE;
    }
    
    g_sensorCallback = callbackObj;
    int32_t ret = sensorInterface->Register(SensorDataCallback);
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %d", __func__, ret);
        g_sensorCallback = nullptr;
    }
    
    return ret;
}

int32_t SensorInterfaceService::Unregister()
{
    const SensorInterface *sensorInterface = NewSensorInterfaceInstance();
    if (sensorInterface == NULL || sensorInterface->Unregister == NULL) {
        HDF_LOGE("%{public}s: get sensor Module instance failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = sensorInterface->Unregister();
    if (ret != SENSOR_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %d", __func__, ret);
    }
    g_sensorCallback = nullptr;
    return ret;
}
} // v1_0
} // sensor
} // hdi

hdi::sensor::v1_0::ISensorInterface *SensorInterfaceServiceConstruct()
{
    using hdi::sensor::v1_0::SensorInterfaceService;
    return new SensorInterfaceService();
}

void SensorInterfaceServiceRelease(hdi::sensor::v1_0::ISensorInterface *obj)
{
    if (obj == nullptr) {
        return;
    }
    delete obj;
}
