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
    constexpr double DEFAULT_ERROR_RATIO = 0.1; // 10% error ratio
    constexpr int64_t DEFAULT_ACCEPTABLE_ERROR = 2;
    constexpr double COMMON_REPORT_FREQUENCY = 1000000000.0;
    constexpr int32_t ONE_SECOND = 1000;
    static std::unordered_map<SensorHandle, int64_t> firstTimestampMap_;
    static std::unordered_map<SensorHandle, int64_t> lastTimestampMap_;
    const std::vector<int32_t> NEED_PRINT_COUNT_SENSOR = {
        HDF_SENSOR_TYPE_ACCELEROMETER, HDF_SENSOR_TYPE_GYROSCOPE, HDF_SENSOR_TYPE_MAGNETIC_FIELD,
        HDF_SENSOR_TYPE_LINEAR_ACCELERATION, HDF_SENSOR_TYPE_ROTATION_VECTOR, HDF_SENSOR_TYPE_GYROSCOPE_UNCALIBRATED,
        HDF_SENSOR_TYPE_ACCELEROMETER_UNCALIBRATED};
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
    event.deviceSensorInfo = {DEFAULT_DEVICE_ID, eventVdi.sensorId, DEFAULT_SENSOR_ID, DEFAULT_LOCATION};
#endif
    int32_t ret = OnDataEvent(event);
    return ret;
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
    PrintData(event, reportResult, sensorHandle);
    return HDF_SUCCESS;
}

void SensorCallbackVdi::PrintData(const HdfSensorEvents &event, const std::string &reportResult,
                                  const SensorHandle& sensorHandle)
{
    SENSOR_TRACE;
    bool isPrint = SensorClientsManager::GetInstance()->IsSensorNeedPrint(sensorHandle);
    int64_t samplingInterval = SensorClientsManager::GetInstance()->GetSensorBestSamplingInterval(sensorHandle);

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
    if (NeedPrintCount(sensorHandle)) {
        PrintCount(sensorHandle, sensorDataCountMap, samplingInterval);
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
    if (event.dataLen < static_cast<int>(sizeof(float)) || event.dataLen > DATA_LEN) {
        HDF_LOGE("%{public}s: invalid dataLen: %d", __func__, event.dataLen);
        return;
    }
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
        int32_t ilen = DATA_LEN - strlen(arrayStr) - 1;
        if (ilen <= 0) {
            HDF_LOGE("%{public}s: bufferover failed", __func__);
            OsalMemFree(origin);
            return;
        }
        if (sprintf_s(arrayStr + strlen(arrayStr), ilen, "[%f]", data[i]) < 0) {
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

bool SensorCallbackVdi::NeedPrintCount(SensorHandle sensorHandle)
{
    return std::find(NEED_PRINT_COUNT_SENSOR.begin(), NEED_PRINT_COUNT_SENSOR.end(),
        sensorHandle.sensorType) != NEED_PRINT_COUNT_SENSOR.end();
}

void SensorCallbackVdi::PrintCount(const SensorHandle& sensorHandle,
    const std::unordered_map<SensorHandle, int64_t> &sensorDataCountMap, const int64_t &samplingInterval)
{
    static std::unordered_map<SensorHandle, std::chrono::steady_clock::time_point> lastRecordTimeMap;
    static std::unordered_map<SensorHandle, int64_t> lastDataCountMap;

    //Get the last recorded time and number of records
    auto lastRecordTimeIt = lastRecordTimeMap.find(sensorHandle);
    if (lastRecordTimeIt == lastRecordTimeMap.end()) {
        lastRecordTimeIt = lastRecordTimeMap.emplace(sensorHandle, std::chrono::steady_clock::now()).first;
    }
    auto lastDataCountIt = lastDataCountMap.find(sensorHandle);
    if (lastDataCountIt == lastDataCountMap.end()) {
        lastDataCountIt = lastDataCountMap.emplace(sensorHandle, 0).first;
    }
    std::chrono::steady_clock::time_point &lastRecordTime = lastRecordTimeIt->second;
    int64_t &lastDataCount = lastDataCountIt->second;

    //Get the current record time and number of records
    std::chrono::steady_clock::time_point currentTime = std::chrono::steady_clock::now();
    int64_t currentDataCount = 0;
    auto sensorDataCountIt = sensorDataCountMap.find(sensorHandle);
    if (sensorDataCountIt != sensorDataCountMap.end()) {
        currentDataCount = sensorDataCountIt->second;
    }

    //Calculate the sensor data and allowable error that should be reported based on frequency
    int64_t targetCount = 0;
    if (samplingInterval > 0) {
        targetCount = std::ceil(COMMON_REPORT_FREQUENCY / (double)samplingInterval);
    }
    int64_t acceptablError = std::ceil((double)targetCount * DEFAULT_ERROR_RATIO);
    if (acceptablError == 0) {
        acceptablError = DEFAULT_ACCEPTABLE_ERROR; // Ensure there's always some tolerance
    }
    
    //Check if the current record time exceeds one second
    if (std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastRecordTime).count() >= ONE_SECOND) {
        int64_t perSecondCount = currentDataCount - lastDataCount;

        lastRecordTime += std::chrono::milliseconds(ONE_SECOND);
        lastDataCount = currentDataCount;

        if (perSecondCount >= targetCount - acceptablError && perSecondCount <= targetCount + acceptablError) {
            return; // Skip logging if the count is within acceptable range
        }
        HDF_LOGE("%{public}s: %{public}s perSecondCount %{public}s targetCount %{public}s~%{public}s samplingInterval "
            "%{public}s", __func__, SENSOR_HANDLE_TO_C_STR(sensorHandle), std::to_string(perSecondCount).c_str(),
            std::to_string(targetCount - acceptablError).c_str(), std::to_string(targetCount + acceptablError).c_str(),
            std::to_string(samplingInterval / ONE_MILLION).c_str());
    }
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
