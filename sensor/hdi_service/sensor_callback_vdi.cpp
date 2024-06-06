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

#include "sensor_callback_vdi.h"
#include "osal_mem.h"
#include <securec.h>
#include <unordered_map>
#include "hitrace_meter.h"

#define HDF_LOG_TAG uhdf_sensor_callback_vdi

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {
namespace {
    constexpr int32_t DATA_LEN = 256;
    constexpr int64_t REPOPRT_TIME = 60000000000;
    static std::unordered_map<int32_t, int64_t> firstTimestampMap_;
    static std::unordered_map<int32_t, int64_t> lastTimestampMap_;
}

bool SensorCallbackVdi::servicesChanged = true;
bool SensorCallbackVdi::clientsChanged = true;

int32_t SensorCallbackVdi::OnDataEventVdi(const OHOS::HDI::Sensor::V1_1::HdfSensorEventsVdi& eventVdi)
{
    struct HdfSensorEvents event;
    event.sensorId = eventVdi.sensorId;
    event.version = eventVdi.version;
    event.timestamp = eventVdi.timestamp;
    event.option = eventVdi.option;
    event.mode = eventVdi.mode;
    event.data = eventVdi.data;
    event.dataLen = eventVdi.dataLen;
    int32_t ret = OnDataEvent(event);
    return ret;
}

int32_t SensorCallbackVdi::OnDataEvent(const V2_0::HdfSensorEvents& event)
{
    SensorClientsManager::GetInstance()->CopyEventData(event);
    PrintData(event);
    if (servicesChanged) {
        servicesMap_ = SensorClientsManager::GetInstance()->GetSensorUsed();
        servicesChanged = false;
    }
    if (clientsChanged) {
        if (!SensorClientsManager::GetInstance()->GetClients(HDF_TRADITIONAL_SENSOR_TYPE, sensorClientInfos_)) {
            HDF_LOGD("%{public}s groupId %{public}d is not used by anyone", __func__, HDF_TRADITIONAL_SENSOR_TYPE);
            return HDF_FAILURE;
        }
        clientsChanged = false;
    }
    if (servicesMap_.find(event.sensorId) == servicesMap_.end()) {
        HDF_LOGD("%{public}s sensor %{public}d is not enabled by anyone", __func__, event.sensorId);
        return HDF_FAILURE;
    }
    int32_t ret = ReportEachClient(servicesMap_.find(event.sensorId)->second, event);
    return ret;
}

int32_t SensorCallbackVdi::ReportEachClient(std::set<int32_t> &services, const V2_0::HdfSensorEvents& event)
{
    std::string result = "";
    int32_t sensorId = event.sensorId;
    for (auto it = services.begin(); it != services.end(); ++it) {
        int32_t serviceId = *it;
        if (sensorClientInfos_.find(serviceId) == sensorClientInfos_.end()) {
            continue;
        }
        SensorClientInfo &sensorClientInfo = sensorClientInfos_.find(serviceId)->second;
        if (IsNotNeedReportData(sensorClientInfo, sensorId, serviceId)) {
            continue;
        }
        const sptr<ISensorCallback> &callback = sensorClientInfo.GetReportDataCb();
        if (callback == nullptr) {
            HDF_LOGD("%{public}s the callback of %{public}d is nullptr", __func__, serviceId);
            continue;
        }
        StartTrace(HITRACE_TAG_HDF, "ODE,serviceId=" + std::to_string(serviceId) + ",sensorId=" +
                                    std::to_string(event.sensorId));
        int32_t ret = callback->OnDataEvent(event);
        FinishTrace(HITRACE_TAG_HDF);
        if (ret != HDF_SUCCESS) {
            HDF_LOGD("%{public}s Sensor OnDataEvent failed, error code is %{public}d", __func__, ret);
        } else {
            result += std::to_string(serviceId) + " ";
        }
    }
    HDF_LOGD("%{public}s sensorId=%{public}d, services=%{public}s", __func__, event.sensorId, result.c_str());
    return HDF_SUCCESS;
}

bool SensorCallbackVdi::IsNotNeedReportData(SensorClientInfo &sensorClientInfo, const int32_t &sensorId,
                                            const int32_t &serviceId)
{
    if (!SensorClientsManager::IsSensorContinues(sensorId)) {
        return false;
    }
    if (sensorClientInfo.periodCountMap_.find(sensorId) == sensorClientInfo.periodCountMap_.end()) {
        return false;
    }
    bool result = false;
    sensorClientInfo.PrintClientMapInfo(serviceId, sensorId);
    if (sensorClientInfo.curCountMap_[sensorId] != 0) {
        result = true;
    }
    sensorClientInfo.curCountMap_[sensorId]++;
    if (sensorClientInfo.curCountMap_[sensorId] >= sensorClientInfo.periodCountMap_[sensorId]) {
        sensorClientInfo.curCountMap_[sensorId] = 0;
    }
    return result;
}

void SensorCallbackVdi::PrintData(const HdfSensorEvents &event)
{
    std::unique_lock<std::mutex> lock(timestampMapMutex_);
    if (firstTimestampMap_[event.sensorId] == 0) {
        firstTimestampMap_[event.sensorId] = event.timestamp;
    } else {
        lastTimestampMap_[event.sensorId] = event.timestamp;
    }

    if (lastTimestampMap_[event.sensorId] - firstTimestampMap_[event.sensorId] >= REPOPRT_TIME) {
        firstTimestampMap_[event.sensorId] = lastTimestampMap_[event.sensorId];
        std::string st = {0};
        DataToStr(st, event);
        HDF_LOGI("%{public}s: %{public}s", __func__, st.c_str());
    }
    return;
}

void SensorCallbackVdi::DataToStr(std::string &str, const HdfSensorEvents &event)
{
    void *origin = OsalMemCalloc(sizeof(uint8_t) * (event.dataLen));
    if (origin == nullptr) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return;
    }

    uint8_t *eventData = static_cast<uint8_t*>(origin);
    std::copy(event.data.begin(), event.data.end(), eventData);
    float *data = reinterpret_cast<float*>(eventData);
    int32_t dataLen = event.dataLen;
    int32_t dataDimension = static_cast<int32_t>(dataLen / sizeof(float));
    std::string dataStr = {0};
    char arrayStr[DATA_LEN] = {0};

    for (int32_t i = 0; i < dataDimension; i++) {
        if (sprintf_s(arrayStr + strlen(arrayStr), DATA_LEN, "[%f]", data[i]) < 0) {
            HDF_LOGE("%{public}s: sprintf_s failed", __func__);
            OsalMemFree(origin);
            return;
        }
    }

    dataStr = arrayStr;
    str = "sensorId: " + std::to_string(event.sensorId) + ", ts: " +
        std::to_string(event.timestamp / 1e9) + ", data: " + dataStr;

    OsalMemFree(origin);
    return;
}

sptr<IRemoteObject> SensorCallbackVdi::HandleCallbackDeath()
{
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<ISensorCallback>(sensorCallback_);

    return remote;
}
} // V2_0
} // Sensor
} // HDI
} // OHOS
