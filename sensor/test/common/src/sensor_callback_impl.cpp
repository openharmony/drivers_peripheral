/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <cmath>

#include "osal_mem.h"
#include "sensor_callback_impl.h"
#include "sensor_type.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {
uint32_t SensorCallbackImpl::sensorDataFlag = 1;
namespace {
    struct SensorValueRange {
        float highThreshold;
        float lowThreshold;
    };

    struct SensorDevelopmentList {
        int32_t sensorTypeId;
        char sensorName[SENSOR_NAME_MAX_LEN];
        int32_t dataForm;    // 0: fixed, 1: range
        int32_t dataDimension;
        struct SensorValueRange *valueRange;
    };

    struct SensorValueRange g_testRange[] = {{1e5, 0.0}};
    struct SensorValueRange g_accelRange[] = {{78.0, -78.0}, {78.0, -78.0}, {78.0, -78.0}};
    struct SensorValueRange g_alsRange[] = {{10000000.0, 0.0}};
    struct SensorValueRange g_pedometerRange[] = {{10000.0, 0.0}};
    struct SensorValueRange g_proximityRange[] = {{5.0, 0.0}};
    struct SensorValueRange g_hallRange[] = {{2.0, 0.0}};
    struct SensorValueRange g_barometerRange[] = {{1100.0, -1100.0}, {1100.0, -1100.0}};
    struct SensorValueRange g_magneticRange[] = {{2000.0, -2000.0}, {2000.0, -2000.0}, {2000.0, -2000.0}};
    struct SensorValueRange g_gyroscopeRange[] = {{35.0, -35.0}, {35.0, -35.0}, {35.0, -35.0}};
    struct SensorValueRange g_gravityRange[] = {{78.0, -78.0}, {78.0, -78.0}, {78.0, -78.0}};
    struct SensorValueRange g_humidityRange[] = {{100, 0}};
    struct SensorValueRange g_temperatureRange[] = {{125, -40}};

    struct SensorDevelopmentList g_sensorList[] = {
        {SENSOR_TYPE_NONE, "sensor_test",  1, 1, g_testRange},
        {SENSOR_TYPE_ACCELEROMETER, "accelerometer",  1, 3, g_accelRange},
        {SENSOR_TYPE_PEDOMETER, "pedometer", 1, 1, g_pedometerRange},
        {SENSOR_TYPE_PROXIMITY, "proximity",  0, 1, g_proximityRange},
        {SENSOR_TYPE_HALL, "hallrometer",  1, 1, g_hallRange},
        {SENSOR_TYPE_BAROMETER, "barometer",  1, 2, g_barometerRange},
        {SENSOR_TYPE_AMBIENT_LIGHT, "als", 1, 1, g_alsRange},
        {SENSOR_TYPE_MAGNETIC_FIELD, "magnetometer",  1, 3, g_magneticRange},
        {SENSOR_TYPE_GYROSCOPE, "gyroscope", 1, 3, g_gyroscopeRange},
        {SENSOR_TYPE_GRAVITY, "gravity", 1, 3, g_gravityRange},
        {SENSOR_TYPE_HUMIDITY, "humidity", 1, 1, g_humidityRange},
        {SENSOR_TYPE_TEMPERATURE, "tenperature", 1, 1, g_temperatureRange}
    };

    constexpr int32_t g_listNum = sizeof(g_sensorList) / sizeof(g_sensorList[0]);
    constexpr float EPSINON = 1e-6;

    void SensorDataVerification(const float &data, const struct SensorDevelopmentList &sensorNode)
    {
        for (int32_t j = 0; j < sensorNode.dataDimension; ++j) {
            if (sensorNode.dataForm == 0) {
                if (std::abs(*(&data + j) - sensorNode.valueRange[j].highThreshold) < EPSINON ||
                    std::abs(*(&data + j) - sensorNode.valueRange[j].lowThreshold) < EPSINON) {
                    SensorCallbackImpl::sensorDataFlag &= 1;
                } else {
                    SensorCallbackImpl::sensorDataFlag = 0;
                    printf("%s: %s Not expected\n\r", __func__, sensorNode.sensorName);
                }
            }

            if (sensorNode.dataForm == 1) {
                if (*(&data + j) >= sensorNode.valueRange[j].lowThreshold &&
                    *(&data + j) <= sensorNode.valueRange[j].highThreshold) {
                    SensorCallbackImpl::sensorDataFlag &= 1;
                } else {
                    SensorCallbackImpl::sensorDataFlag = 0;
                    printf("%s: %s Not expected\n\r", __func__, sensorNode.sensorName);
                }
            }
        }
    }
}

int32_t SensorCallbackImpl::OnDataEvent(const HdfSensorEvents& event)
{
    void *origin = OsalMemCalloc(sizeof(uint8_t) * (event.dataLen));
    if (origin == nullptr) {
        return HDF_FAILURE;
    }
    uint8_t *tmp = static_cast<uint8_t*>(origin);
    uint8_t *eventData = tmp;
    for (auto value : event.data) {
       *tmp++ = value;
    }
    HDF_LOGI("%{public}s: event info: sensorId = %{public}d, option = %{public}d, mode = %{public}d\n\r", __func__,
        event.deviceSensorInfo.sensorType, event.option, event.mode);

    for (int32_t i = 0; i < g_listNum; ++i) {
        if (event.deviceSensorInfo.sensorType == g_sensorList[i].sensorTypeId) {
            float *data = reinterpret_cast<float*>(eventData);
            SensorDataVerification(*data, g_sensorList[i]);
        }
    }
    OsalMemFree(origin);
    return HDF_SUCCESS;
}
} // V3_0
} // Sensor
} // HDI
} // OHOS
