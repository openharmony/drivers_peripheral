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

#include "sensorconvertsensordata_fuzzer.h"
#include "hdf_base.h"
#include "v3_0/isensor_interface.h"
#include "v3_1/isensor_interface.h"
#include "convert/v1_0/isensor_convert_interfaces.h"

#define MIN_SENSOR_DATA_LEN 16
using namespace OHOS::HDI::Sensor;
using namespace OHOS::HDI::Sensor::V3_0;
using OHOS::HDI::Sensor::V3_1::GPS_CALLBACK_ID_BEGIN;
using namespace OHOS::HDI::Sensor::Convert::V1_0;

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {
int32_t SensorConvertSensorDataFuzzer::OnDataEvent(const HdfSensorEvents& event)
{
    (void)event;
    return HDF_SUCCESS;
}
} // V3_0
} // Sensor
} // HDI
} // OHOS

namespace OHOS {
    bool SensorConvertSensorDataFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        int32_t ret;
        sptr<ISensorConvertInterfaces> sensorConvertInterfaces = ISensorConvertInterfaces::Get(true);
        if (sensorConvertInterfaces == nullptr) {
            return false;
        }
        std::vector<uint32_t> reserve{*(uint32_t *)data};
        std::vector<uint8_t> sensorData;

        while (sensorData.size() < MIN_SENSOR_DATA_LEN) {
            sensorData.push_back(*(uint8_t *)data);
        }
        HdfDeviceStatusPolicy  hdfDeviceStatusPolicy {*(int32_t *)data, *(int32_t *)data, reserve};
        HdfSensorData inSensorData{
            .sensorTypeId = *(int32_t *)data,
            .version = *(int32_t *)data,
            .timestamp = *(int64_t *)data,
            .option = *(int32_t *)data,
            .mode = *(int32_t *)data,
            .data = sensorData,
            .deviceId = *(int32_t *)data,
            .sensorId = *(int32_t *)data,
            .location = *(int32_t *)data,
        };
        HdfSensorData outSensorData{
            .sensorTypeId = *(int32_t *)data,
            .version = *(int32_t *)data,
            .timestamp = *(int64_t *)data,
            .option = *(int32_t *)data,
            .mode = *(int32_t *)data,
            .data = sensorData,
            .deviceId = *(int32_t *)data,
            .sensorId = *(int32_t *)data,
            .location = *(int32_t *)data,
        };
        ret = sensorConvertInterfaces->ConvertSensorData(hdfDeviceStatusPolicy, inSensorData, outSensorData);
        if (ret == HDF_SUCCESS) {
            return true;
        }
        return result;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < sizeof(int64_t)) {
        return 0;
    }
    OHOS::SensorConvertSensorDataFuzzTest(data, size);
    return 0;
}

