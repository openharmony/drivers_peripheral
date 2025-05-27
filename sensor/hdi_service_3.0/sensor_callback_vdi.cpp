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
namespace V3_0 {
namespace {
    constexpr int32_t DATA_LEN = 256;
    constexpr int64_t REPOPRT_TIME = 60000000000;
    constexpr int64_t INIT_DATA_COUNT = 1;
    static std::unordered_map<SensorHandle, int64_t> firstTimestampMap_;
    static std::unordered_map<SensorHandle, int64_t> lastTimestampMap_;
}

int32_t SensorCallbackVdi::OnDataEventVdi(const OHOS::HDI::Sensor::V1_1::HdfSensorEventsVdi& eventVdi)
{
    HITRACE_METER_FMT(HITRACE_TAG_HDF, "%s: sensorId %d", __func__, eventVdi.sensorId);
    struct V3_0::HdfSensorEvents event;
    event.version = eventVdi.version;
    event.timestamp = eventVdi.timestamp;
    event.option = eventVdi.option;
    event.mode = eventVdi.mode;
    event.data = eventVdi.data;
    event.dataLen = eventVdi.dataLen;
#ifdef TV_FLAG
    event.deviceSensorInfo = eventVdi.deviceSensorInfo;
#else
    event.deviceSensorInfo = {0, eventVdi.sensorId, 0, 0};
#endif
    int32_t ret = OnDataEvent(event);
    return ret;
}

int32_t SensorCallbackVdi::OnDataEvent(const V2_0::HdfSensorEvents& event)
{
    struct V3_0::HdfSensorEvents event3_0;
    event3_0.version = event.version;
    event3_0.timestamp = event.timestamp;
    event3_0.option = event.option;
    event3_0.mode = event.mode;
    event3_0.data = event.data;
    event3_0.dataLen = event.dataLen;
    event3_0.deviceSensorInfo = {0, event.sensorId, 0, 0};
    return OnDataEvent(event3_0);
}

int32_t SensorCallbackVdi::OnDataEvent(const V3_0::HdfSensorEvents& event)
{
    SensorHandle sensorHandle = {event.deviceSensorInfo.deviceId, event.deviceSensorInfo.sensorType,
                                 event.deviceSensorInfo.sensorId, event.deviceSensorInfo.location};
    HITRACE_METER_FMT(HITRACE_TAG_HDF, "%s: sensorHandle %s", __func__, SENSOR_HANDLE_TO_C_STR(event.deviceSensorInfo));
    SensorClientsManager::GetInstance()->CopyEventData(event);
    const std::string reportResult = SensorClientsManager::GetInstance()->ReportEachClient(event);
    HDF_LOGD("%{public}s sensorHandle=%{public}s, %{public}s", __func__, SENSOR_HANDLE_TO_C_STR(event.deviceSensorInfo),
             reportResult.c_str());
    bool isPrint = SensorClientsManager::GetInstance()->IsSensorNeedPrint(sensorHandle);
    PrintData(event, reportResult, isPrint, sensorHandle);
    return HDF_SUCCESS;
}

void SensorCallbackVdi::PrintData(const HdfSensorEvents &event, const std::string &reportResult, bool &isPrint,
                                  const SensorHandle& sensorHandle)
{
    SENSOR_TRACE;
    std::unique_lock<std::mutex> lock(timestampMapMutex_);
    static std::unordered_map<SensorHandle, int64_t> sensorDataCountMap;
    auto it = sensorDataCountMap.find(sensorHandle);
    int64_t dataCount = INIT_DATA_COUNT;
    if (it == sensorDataCountMap.end()) {
        sensorDataCountMap[sensorHandle] = INIT_DATA_COUNT;
    } else {
        it->second++;
        dataCount = it->second;
    }
    bool result = isPrint;
    if (!isPrint) {
        if (firstTimestampMap_[sensorHandle] == 0) {
            firstTimestampMap_[sensorHandle] = event.timestamp;
            result = true;
        } else {
            lastTimestampMap_[sensorHandle] = event.timestamp;
        }
        if (lastTimestampMap_[sensorHandle] - firstTimestampMap_[sensorHandle] >= REPOPRT_TIME) {
            firstTimestampMap_[sensorHandle] = lastTimestampMap_[sensorHandle];
            result = true;
        }
    }

    if (result) {
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
    str = "sensorHandle: " + SENSOR_HANDLE_TO_STRING(event.deviceSensorInfo) + ", ts: " +
        std::to_string(event.timestamp / 1e9) + ", data: " + dataStr;

    OsalMemFree(origin);
    return;
}

sptr<IRemoteObject> SensorCallbackVdi::HandleCallbackDeath()
{
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<V3_0::ISensorCallback>(sensorCallback_);

    return remote;
}
} // V3_0
} // Sensor
} // HDI
} // OHOS
