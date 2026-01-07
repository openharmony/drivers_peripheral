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

#ifndef SENSOR_CONVERT_IMPL_H
#define SENSOR_CONVERT_IMPL_H

#include "v1_0/isensor_convert_interfaces.h"
#include "v3_0/sensor_types.h"

namespace OHOS {
namespace HDI {
namespace SensorExtra {
namespace Convert {
namespace V1_0 {
using namespace OHOS::HDI::Sensor::Convert::V1_0;
using namespace OHOS::HDI::Sensor::V3_0;
class SensorConvertImpl : public ISensorConvertInterfaces {
public:
    SensorConvertImpl();
    virtual ~SensorConvertImpl() {};
    int32_t Init();
    int32_t ConvertSensorData(const HdfDeviceStatusPolicy& status,
        const HdfSensorData& inSensorData, HdfSensorData& outSensorData) override;
};
} // namespace V1_0
} // namespace Convert
} // namespace SensorExtra
} // namespace HDI
} // namespace OHOS
#endif /* SENSOR_CONVERT_IMPL_H */
