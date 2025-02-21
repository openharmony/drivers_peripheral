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
#include "sensor_uhdf_log.h"
#include "isensor_callback_vdi.h"
#include "v2_0/isensor_interface.h"
#include "v2_0/sensor_types.h"
#include "sensor_clients_manager.h"
#include "sensor_client_info.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {

class SensorCallbackVdi : public OHOS::HDI::Sensor::V1_1::ISensorCallbackVdi {
public:
    SensorCallbackVdi() = default;
    virtual ~SensorCallbackVdi() = default;
    explicit SensorCallbackVdi(sptr<ISensorCallback> sensorCallback) : sensorCallback_(sensorCallback) {}
    int32_t OnDataEventVdi(const OHOS::HDI::Sensor::V1_1::HdfSensorEventsVdi& eventVdi) override;
    int32_t OnDataEvent(const V2_0::HdfSensorEvents& event) override;
    sptr<IRemoteObject> HandleCallbackDeath() override;
private:
    void PrintData(const HdfSensorEvents &event, const std::string &reportResult, bool &isPrint);
    void DataToStr(std::string &str, const HdfSensorEvents &event);
    sptr<ISensorCallback> sensorCallback_;
    SensorClientInfo sensorClientInfo_;
    std::mutex timestampMapMutex_;
};

} // V2_0
} // Sensor
} // HDI
} // OHOS

#endif // HDI_SENSOR_CALLBACK_VDI_H
