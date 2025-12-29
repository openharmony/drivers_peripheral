/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_SENSOR_V3_0_SENSORCALLBACKIMPL_H
#define OHOS_HDI_SENSOR_V3_0_SENSORCALLBACKIMPL_H

#include <hdf_base.h>
#include "v3_0/isensor_callback.h"
#include "osal_mem.h"
#include <securec.h>
#include "sensor_uhdf_log.h"
#include "isensor_interface_vdi.h"
#include "convert/v1_0/isensor_convert_interfaces.h"

#define HDF_LOG_TAG uhdf_sensor_testcase

#define DATA_LEN 256

using OHOS::HDI::Sensor::V3_0::DeviceSensorInfo;
using OHOS::HDI::Sensor::V1_1::SensorInterval;
struct SubscribedSensor {
    DeviceSensorInfo deviceSensorInfo;
    SensorInterval sensorInterval;
    int32_t sensorDataCount = 0;
    int32_t sensorDataCountOld = 0;
    int32_t expectedMinCount = 0;
    int32_t expectedMaxCount = 0;
};

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {

using namespace OHOS::HDI::Sensor::Convert::V1_0;

class SensorCallbackImpl : public ISensorCallback {
public:
    virtual ~SensorCallbackImpl() {}

    int32_t callbackId = 0;
    std::vector<SubscribedSensor> subscribedSensors;
    sptr<OHOS::HDI::Sensor::Convert::V1_0::ISensorConvertInterfaces> sensorConvertInterfaces = nullptr;
    bool printDataFlag = true;

    int32_t OnDataEvent(const HdfSensorEvents& event) override
    {
        PrintData(event);
        ConvertSensorDataTest(event);
        for (auto& it : subscribedSensors) {
            if (it.deviceSensorInfo.sensorType == event.deviceSensorInfo.sensorType) {
                it.sensorDataCount++;
            }
        }
        return HDF_SUCCESS;
    }

    int32_t OnDataEventAsync(const std::vector<HdfSensorEvents>& events) override
    {
        return HDF_SUCCESS;
    }

    int32_t ConvertSensorDataTest(const HdfSensorEvents& event)
    {
        if (sensorConvertInterfaces == nullptr) {
            printf("\033[96m[  SKIPED  ] sensorConvertInterfaces == nullptr\033[0m\n");
            return HDF_FAILURE;
        }
        std::vector<uint32_t> reserve;
        HdfDeviceStatusPolicy  HdfDeviceStatusPolicy {4, 0, reserve};
        HdfSensorData inSensorData{
            .sensorTypeId = event.deviceSensorInfo.sensorType,
            .version = event.version,
            .timestamp = event.timestamp,
            .option = event.option,
            .mode = event.mode,
            .data = event.data,
            .deviceId = event.deviceSensorInfo.deviceId,
            .sensorId = event.deviceSensorInfo.sensorId,
            .location = event.deviceSensorInfo.location,
        };
        HdfSensorData outSensorData;
        int32_t ret = sensorConvertInterfaces->ConvertSensorData(HdfDeviceStatusPolicy, inSensorData, outSensorData);
        if (ret == HDF_SUCCESS) {
            printf("\033[92m[       OK ] ConvertSensorDataTest SUCCESS\033[0m\n");
            if (printDataFlag) {
                std::string st = {0};
                DataToStr(st, outSensorData);
                printf("%s: %s\n", __func__, st.c_str());
                HDF_LOGI("%{public}s: testcase %{public}s\n", __func__, st.c_str());
            }
        }else if (ret == HDF_ERR_NOT_SUPPORT) {
            printf("\033[96m[  SKIPED  ] ConvertSensorDataTest HDF_ERR_NOT_SUPPORT\033[0m\n");
        } else {
            printf("\033[91m[  FAILED  ] ConvertSensorDataTest HDF_FAILURE\033[0m\n");
        }
        return HDF_SUCCESS;
    }

    void PrintData(const HdfSensorEvents &event)
    {
        if (printDataFlag) {
            std::string st = {0};
            DataToStr(st, event);
            printf("%s: %s\n", __func__, st.c_str());
            HDF_LOGI("%{public}s: testcase %{public}s\n", __func__, st.c_str());
        }
    }

    void DataToStr(std::string &str, const HdfSensorEvents &event)
    {
        void *origin = OsalMemCalloc(sizeof(uint8_t) * (event.dataLen));
        if (origin == nullptr) {
            printf("%s: OsalMemCalloc failed", __func__);
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
                printf("%s: sprintf_s failed", __func__);
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

    void DataToStr(std::string &str, const HdfSensorData &hdfSensorData)
    {
        SensorHandle sensorHandle = {hdfSensorData.deviceId, hdfSensorData.sensorTypeId, hdfSensorData.sensorId,
                                    hdfSensorData.location};
        void *origin = OsalMemCalloc(sizeof(uint8_t) * (hdfSensorData.data.size()));
        if (origin == nullptr) {
            printf("%s: OsalMemCalloc failed", __func__);
            return;
        }

        uint8_t *eventData = static_cast<uint8_t*>(origin);
        std::copy(hdfSensorData.data.begin(), hdfSensorData.data.end(), eventData);
        float *data = reinterpret_cast<float*>(eventData);
        int32_t dataLen = hdfSensorData.data.size();
        int32_t dataDimension = static_cast<int32_t>(dataLen / sizeof(float));
        std::string dataStr = {0};
        char arrayStr[DATA_LEN] = {0};

        for (int32_t i = 0; i < dataDimension; i++) {
            if (sprintf_s(arrayStr + strlen(arrayStr), DATA_LEN, "[%f]", data[i]) < 0) {
                printf("%s: sprintf_s failed", __func__);
                OsalMemFree(origin);
                return;
            }
        }

        dataStr = arrayStr;
        str = "sensorHandle: " + SENSOR_HANDLE_TO_STRING(sensorHandle) + ", ts: " +
              std::to_string(hdfSensorData.timestamp / 1e9) + ", data: " + dataStr;

        OsalMemFree(origin);
        return;
    }
};
} // V3_0
} // Sensor
} // HDI
} // OHOS

#endif // OHOS_HDI_SENSOR_V1_1_SENSORCALLBACKIMPL_H
