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

#define HDF_LOG_TAG uhdf_sensor_callback_vdi

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {
namespace {
    constexpr int32_t DATA_LEN = 256;
    constexpr int64_t REPOPRT_TIME = 5000000000;
    static std::unordered_map<int32_t, int64_t> firstTimestampMap_;
    static std::unordered_map<int32_t, int64_t> lastTimestampMap_;
}


int32_t SensorCallbackVdi::OnDataEventVdi(const OHOS::HDI::Sensor::V1_1::HdfSensorEventsVdi& eventVdi)
{
    HDF_LOGD("%{public}s enter the OnDataEventVdi function, sensorId is %{public}d", __func__, eventVdi.sensorId);
    struct HdfSensorEvents event;
    int32_t ret;
    if (sensorCallback_ == nullptr) {
        HDF_LOGD("%{public}s sensorCallback_ is NULL", __func__);
        return HDF_FAILURE;
    }

    event.sensorId = eventVdi.sensorId;
    event.version = eventVdi.version;
    event.timestamp = eventVdi.timestamp;
    event.option = eventVdi.option;
    event.mode = eventVdi.mode;
    event.data = eventVdi.data;
    event.dataLen = eventVdi.dataLen;
    SensorClientsManager::GetInstance()->CopyEventData(event);
    PrintData(event);
    std::unordered_map<int, std::set<int>> sensorEnabled = SensorClientsManager::GetInstance()->GetSensorUsed();
    std::unordered_map<int, SensorClientInfo> client;
    if (!SensorClientsManager::GetInstance()->GetClients(HDF_TRADITIONAL_SENSOR_TYPE, client)) {
        HDF_LOGD("%{public}s groupId %{public}d is not used by anyone", __func__, HDF_TRADITIONAL_SENSOR_TYPE);
        return HDF_FAILURE;
    }
    sptr<ISensorCallback> callback;
    if (sensorEnabled.find(event.sensorId) == sensorEnabled.end()) {
        HDF_LOGD("%{public}s sensor %{public}d is not enabled by anyone", __func__, event.sensorId);
        return HDF_FAILURE;
    }
    for (auto it = sensorEnabled[event.sensorId].begin(); it != sensorEnabled[event.sensorId].end(); ++it) {
        if (client.find(*it) == client.end()) {
            continue;
        }
        sensorClientInfo_ = client[*it];
        if (SensorClientsManager::GetInstance()->IsNotNeedReportData(*it, event.sensorId)) {
            continue;
        }
        callback = sensorClientInfo_.GetReportDataCb();
        if (callback == nullptr) {
            HDF_LOGD("%{public}s the callback of %{public}d is nullptr", __func__, *it);
            continue;
        }
        ret = callback->OnDataEvent(event);
        if (ret != HDF_SUCCESS) {
            HDF_LOGD("%{public}s Sensor OnDataEvent failed, error code is %{public}d", __func__, ret);
        } else {
            HDF_LOGD("%{public}s Sensor OnDataEvent success, serviceId is %{public}d", __func__, *it);
        }
    }
    return HDF_SUCCESS;
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
    void *origin = OsalMemCalloc(sizeof(uint8_t) *(event.dataLen));
    if (origin == nullptr) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return;
    }

    uint8_t *eventData = static_cast<uint8_t*>(origin);
    std::copy(event.data.begin(), event.data.end(), eventData);
    float *data = reinterpret_cast<float*>(eventData);
    int32_t dataLen = event.dataLen;
    int32_t dataDimension = static_cast<int32_t>(dataLen/sizeof(float));
    std::string dataStr = {0};
    char arrayStr[DATA_LEN] = {0};

    for (int32_t i = 0; i < dataDimension; i++) {
        if (sprintf_s(arrayStr + strlen(arrayStr), DATA_LEN, "[%f]", data[i]) < 0) {
            HDF_LOGE("%{public}s: sprintf_s failed", __func__);
            return;
        }
    }

    dataStr = arrayStr;
    str = "sensorId: " + std::to_string(event.sensorId) + ", ts: " +
        std::to_string(event.timestamp/1e9) + ", data: " + dataStr;

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
