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

#ifndef HDI_SENSOR_IF_SERVICE_H
#define HDI_SENSOR_IF_SERVICE_H

#include <map>
#include "v2_0/isensor_interface.h"
#include "isensor_interface_vdi.h"
#include "sensor_callback_vdi.h"
#include "sensor_client_info.h"
#include "sensor_clients_manager.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {

using GroupIdCallBackMap = std::unordered_map<int32_t, std::vector<sptr<ISensorCallback>>>;

class SensorIfService : public ISensorInterface {
public:
    SensorIfService();
    ~SensorIfService();
    int32_t Init(void);
    int32_t GetAllSensorInfo(std::vector<HdfSensorInformation> &info) override;
    int32_t Enable(int32_t sensorId) override;
    int32_t Disable(int32_t sensorId) override;
    int32_t SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval) override;
    int32_t SetMode(int32_t sensorId, int32_t mode) override;
    int32_t SetOption(int32_t sensorId, uint32_t option) override;
    int32_t Register(int32_t groupId, const sptr<ISensorCallback> &callbackObj) override;
    int32_t Unregister(int32_t groupId, const sptr<ISensorCallback> &callbackObj) override;
    int32_t ReadData(int32_t sensorId, std::vector<HdfSensorEvents> &event) override;
    int32_t SdcSensorActive(int32_t sensorId, bool enabled, int32_t rateLevel) override;
    int32_t GetSensorVdiImpl();

    std::mutex sensorCbMutex_;
private:
    OHOS::HDI::Sensor::V1_1::ISensorInterfaceVdi *sensorVdiImpl_ = nullptr;
    struct HdfVdiObject *vdi_ = nullptr;
    GroupIdCallBackMap callbackMap = {};
};
} // V2_0
} // Sensor
} // HDI
} // OHOS

#endif // HDI_SENSOR_IF_SERVICE_H
