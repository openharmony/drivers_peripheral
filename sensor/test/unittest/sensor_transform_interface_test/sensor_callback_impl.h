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
class SensorCallbackImpl : public ISensorCallback {
public:
    virtual ~SensorCallbackImpl() {}

    int32_t callbackId = 0;
    std::vector<SubscribedSensor> subscribedSensors;
    sptr<OHOS::HDI::Sensor::Transform::V1_0::ISensorTransformInterfaces> sensorTransformInterfaces = nullptr;
    bool printDataFlag = false;

    int32_t OnDataEvent(const HdfSensorEvents& event) override
    {
        PrintData(event);
        TransformSensorDataTest(event);
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

    int32_t TransformSensorDataTest(const HdfSensorEvents& event)
    {
        if (sensorTransformInterfaces == nullptr) {
            printf("\033[96m[  SKIPED  ] sensorTransformInterfaces == nullptr\033[0m\n");
            return HDF_FAILURE;
        }
        HdfDeviceStatus hdfDeviceStatus{0, 0};
        HdfSensorData inSensorData{
            .sensorTypeId = event.deviceSensorInfo.sensorType;
            .version = event.version;
            .timestamp = event.timestamp;
            .option = event.option;
            .mode = event.mode;
            .data = event.data;
            .dataLen = event.dataLen;
            .deviceId = event.deviceSensorInfo.deviceId;
            .sensorId = event.deviceSensorInfo.sensorId;
            .location = event.deviceSensorInfo.location;
        };
        HdfSensorData outSensorData;
        int32_t ret = sensorTransformInterfaces->TransformSensorData(hdfDeviceStatus, inSensorData, outSensorData);
        if (ret == HDF_SUCCESS) {
            printf("\033[92m[       OK ] TransformSensorDataTest SUCCESS\033[0m\n");
        } else {
            printf("\033[91m[  FAILED  ] TransformSensorDataTest HDF_FAILURE\033[0m\n");
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
};
} // V3_0
} // Sensor
} // HDI
} // OHOS

#endif // OHOS_HDI_SENSOR_V1_1_SENSORCALLBACKIMPL_H
