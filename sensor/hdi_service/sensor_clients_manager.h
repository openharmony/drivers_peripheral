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

#ifndef HDI_SENSOR_MANAGER_H
#define HDI_SENSOR_MANAGER_H

#include <unordered_map>
#include <vector>
#include <set>
#include "v1_1/isensor_interface.h"
#include "isensor_interface_vdi.h"
#include "sensor_client_info.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_1 {


class SensorClientsManager {
public:
    ~SensorClientsManager();
    void ReportDataCbRegister(int groupId, int serviceId, const sptr<ISensorCallback> &callbackObj);
    void ReportDataCbUnRegister(int groupId, int serviceId, const sptr<ISensorCallback> &callbackObj);
    void SetSensorBestConfig(int sensorId, int64_t &samplingInterval, int64_t &reportInterval);
    bool IsUpadateSensorState(int sensorId, int serviceId, bool isOpen);
    bool GetClients(int groupId, std::unordered_map<int32_t, SensorClientInfo> &client);
    bool IsClientsEmpty(int groupId);
    std::unordered_map<int32_t, std::set<int32_t>> GetSensorUsed();
    bool IsNeedOpenSensor(int sensorId, int serviceId);
    bool IsNeedCloseSensor(int sensorId, int serviceId);
    void OpenSensor(int sensorId, int serviceId);
    void UpdateSensorConfig(int sensorId, int64_t samplingInterval, int64_t reportInterval);
    static SensorClientsManager* GetInstance();
    std::mutex clientsMutex_;
    std::mutex sensorUsedMutex_;
    std::mutex sensorConfigMutex_;
private:
    SensorClientsManager();
    static SensorClientsManager *instance;
    static std::mutex instanceMutex_;
    std::unordered_map<int32_t, std::unordered_map<int, SensorClientInfo>> clients_;
    std::unordered_map<int32_t, std::set<int32_t>> sensorUsed_;
    std::unordered_map<int32_t, struct BestSensorConfig> sensorConfig_;
};

struct BestSensorConfig {
    int32_t samplingInterval;
    int32_t reportInterval;
};

} // V1_1
} // Sensor
} // HDI
} // OHOS

#endif // HDI_SENSOR_MANAGER_H