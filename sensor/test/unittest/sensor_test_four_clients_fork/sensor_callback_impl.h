/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {
class SensorCallbackImpl : public ISensorCallback {
public:
    virtual ~SensorCallbackImpl() {}

    int32_t OnDataEvent(const HdfSensorEvents& event) override
    {
        sensorDataCount++;
        return HDF_SUCCESS;
    }

    int32_t OnDataEventAsync(const std::vector<HdfSensorEvents>& events) override
    {
        return HDF_SUCCESS;
    }

    static int32_t sensorDataCount;
    static int32_t sensorDataCountOld;
    static bool printDataFlag;
};
} // V3_0
} // Sensor
} // HDI
} // OHOS

#endif // OHOS_HDI_SENSOR_V1_1_SENSORCALLBACKIMPL_H
