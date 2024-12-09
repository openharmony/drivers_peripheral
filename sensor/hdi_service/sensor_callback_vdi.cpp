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
    constexpr int64_t REPOPRT_TIME = 60000000000;
    constexpr int64_t INIT_DATA_COUNT = 1;
    static std::unordered_map<int32_t, int64_t> firstTimestampMap_;
    static std::unordered_map<int32_t, int64_t> lastTimestampMap_;
}

int32_t SensorCallbackVdi::OnDataEventVdi(const OHOS::HDI::Sensor::V1_1::HdfSensorEventsVdi& eventVdi)
{
    SENSOR_TRACE;
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
    SENSOR_TRACE;
    SensorClientsManager::GetInstance()->CopyEventData(event);
    const std::string reportResult = SensorClientsManager::GetInstance()->ReportEachClient(event);
    HDF_LOGD("%{public}s sensorId=%{public}d, %{public}s", __func__, event.sensorId, reportResult.c_str());
    bool isPrint = SensorClientsManager::GetInstance()->IsSensorNeedPrint(sensorId);
    PrintData(event, reportResult, isPrint);
    return HDF_SUCCESS;
}

void SensorCallbackVdi::PrintData(const HdfSensorEvents &event, const std::string &reportResult, bool &isPrint)
{
    SENSOR_TRACE;
    std::unique_lock<std::mutex> lock(timestampMapMutex_);
    static std::unordered_map<int32_t, int64_t> sensorDataCountMap;
    auto it = sensorDataCountMap.find(event.sensorId);
    int64_t dataCount = INIT_DATA_COUNT;
    if (it == sensorDataCountMap.end()) {
        sensorDataCountMap[event.sensorId] = INIT_DATA_COUNT;
    } else {
        it->second++;
        dataCount = it->second;
    }
    bool result = isPrint;
    if (!isPrint) {
        if (firstTimestampMap_[event.sensorId] == 0) {
            firstTimestampMap_[event.sensorId] = event.timestamp;
            result = true;
        } else {
            lastTimestampMap_[event.sensorId] = event.timestamp;
        }
        if (lastTimestampMap_[event.sensorId] - firstTimestampMap_[event.sensorId] >= REPOPRT_TIME) {
            firstTimestampMap_[event.sensorId] = lastTimestampMap_[event.sensorId];
            result = true;
        }
    }

    if (isPrint || result) {
        std::string st = {0};
        DataToStr(st, event);
        st += "sensorDataCount=" + std::to_string(dataCount);
        st += reportResult;
        HDF_LOGI("%{public}s: %{public}s", __func__, st.c_str());
    }
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
