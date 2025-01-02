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

#ifndef HDI_SENSOR_CLIENT_H
#define HDI_SENSOR_CLIENT_H

#include <mutex>
#include <unordered_map>
#include "v2_1/isensor_interface.h"
#include "isensor_interface_vdi.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_1 {

class SensorClientInfo {
public:
    SensorClientInfo();
    ~SensorClientInfo();
    explicit SensorClientInfo(const sptr<V2_0::ISensorCallback> &callbackObj)
        : pollCallback_(callbackObj) {};
    void SetReportDataCb(const sptr<V2_0::ISensorCallback> &callbackObj);
    const sptr<V2_0::ISensorCallback> GetReportDataCb();
    std::unordered_map<int32_t, struct SensorConfig> sensorConfigMap_;
    std::unordered_map<int32_t, int32_t> periodCountMap_;
    std::unordered_map<int32_t, int32_t> curCountMap_;
    void PrintClientMapInfo(int32_t serviceId, int32_t sensorId);
    bool oneway = false;
private:
    sptr<V2_0::ISensorCallback> pollCallback_;
};

struct SensorConfig {
    int32_t samplingInterval;
    int32_t reportInterval;
};

} // V2_1
} // Sensor
} // HDI
} // OHOS

#endif // HDI_SENSOR_CLIENT_H