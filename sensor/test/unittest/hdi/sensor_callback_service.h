/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HDI_SENSOR_V1_0_SENSORCALLBACKSERVICE_H
#define HDI_SENSOR_V1_0_SENSORCALLBACKSERVICE_H

#include <hdf_base.h>
#include "sensor_callback_stub.h"

namespace sensor {
namespace v1_0 {
class SensorCallbackService : public SensorCallbackStub {
public:
    virtual ~SensorCallbackService() {}

    int32_t OnDataEvent(const HdfSensorEvents& event) override;
};
} // v1_0
} // sensor

#endif // HDI_SENSOR_V1_0_SENSORCALLBACKSERVICE_H

