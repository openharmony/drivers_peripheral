/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_SENSOR_V2_0_SENSORCALLBACKIMPLTEST_H
#define OHOS_HDI_SENSOR_V2_0_SENSORCALLBACKIMPLTEST_H

#include <hdf_base.h>
#include "v2_0/isensor_callback.h"
#include "sensor_uhdf_log.h"
#include "osal_mem.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {

constexpr int32_t DATA_LEN = 256;

class SensorCallbackImplTest : public ISensorCallback {
public:
    virtual ~SensorCallbackImplTest() {}

    int32_t OnDataEvent(const HdfSensorEvents& event) override;

    void PrintData(const HdfSensorEvents &event)
    {
        std::string st = {0};
        DataToStr(st, event);
        HDF_LOGI("%{public}s: %{public}s", __func__, st.c_str());
    }

    void DataToStr(std::string &str, const HdfSensorEvents &event)
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
              std::to_string(event.timestamp) + ", data: " + dataStr;

        OsalMemFree(origin);
        return;
    }
};
} // V2_0
} // Sensor
} // HDI
} // OHOS

#endif // OHOS_HDI_SENSOR_V2_0_SENSORCALLBACKIMPLTEST_H
