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

#ifndef HDI_SENSOR_CALLBACK_VDI_H
#define HDI_SENSOR_CALLBACK_VDI_H

#include <iproxy_broker.h>
#include "hdf_log.h"
#include "isensor_callback_vdi.h"
#include "v1_0/isensor_interface.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_0 {
class SensorCallbackVdi : public ISensorCallbackVdi {
public:
    SensorCallbackVdi() = default;
    virtual ~SensorCallbackVdi() = default;
    explicit SensorCallbackVdi(sptr<ISensorCallback> sensorCallback) : sensorCallback_(sensorCallback) {}
    int32_t OnDataEventVdi(const HdfSensorEventsVdi& eventVdi) override;
    sptr<IRemoteObject> HandleCallbackDeath() override;
private:
    sptr<ISensorCallback> sensorCallback_;
};
} // V1_0
} // Sensor
} // HDI
} // OHOS

#endif // HDI_SENSOR_CALLBACK_VDI_H
