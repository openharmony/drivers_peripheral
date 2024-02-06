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
#include "v2_0/isensor_interface.h"
#include "isensor_interface_vdi.h"
#include "sensor_client_info.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {


class SensorClientsManager {
public:
    ~SensorClientsManager();
    void ReportDataCbRegister(int groupId, int serviceId, const sptr<ISensorCallback> &callbackObj);
    void ReportDataCbUnRegister(int groupId, int serviceId, const sptr<ISensorCallback> &callbackObj);
    void SetSensorBestConfig(int sensorId, int64_t &samplingInterval, int64_t &reportInterval);
    void SetSdcSensorBestConfig(int sensorId, int64_t &samplingInterval, int64_t &reportInterval);
    void GetSensorBestConfig(int sensorId, int64_t &samplingInterval, int64_t &reportInterval);
    void EraseSdcSensorBestConfig(int sensorId);
    bool IsUpadateSensorState(int sensorId, int serviceId, bool isOpen);
    bool GetClients(int groupId, std::unordered_map<int32_t, SensorClientInfo> &client);
    bool IsClientsEmpty(int groupId);
    std::unordered_map<int32_t, std::set<int32_t>> GetSensorUsed();
    bool IsNeedOpenSensor(int sensorId, int serviceId);
    bool IsNeedCloseSensor(int sensorId, int serviceId);
    bool IsExistSdcSensorEnable(int sensorId);
    void OpenSensor(int sensorId, int serviceId);
    void UpdateSensorConfig(int sensorId, int64_t samplingInterval, int64_t reportInterval);
    void UpdateSdcSensorConfig(int sensorId, int64_t samplingInterval, int64_t reportInterval);
    int GetServiceId(int groupId, const sptr<ISensorCallback> &callbackObj);
    static SensorClientsManager* GetInstance();
    std::mutex clientsMutex_;
    std::mutex sensorUsedMutex_;
    std::mutex sensorConfigMutex_;
    std::mutex sdcSensorConfigMutex_;
    void SetClientSenSorConfig(int32_t sensorId, int32_t serviceId, int64_t samplingInterval, int64_t &reportInterval);
    bool IsNotNeedReportData(int32_t serviceId, int32_t sensorId);
    static bool IsSensorContinues(int32_t sensorId);
    void UpdateClientPeriodCount(int sensorId, int64_t samplingInterval, int64_t reportInterval);
private:
    SensorClientsManager();
    static std::mutex instanceMutex_;
    std::unordered_map<int32_t, std::unordered_map<int, SensorClientInfo>> clients_;
    std::unordered_map<int32_t, std::set<int32_t>> sensorUsed_;
    std::unordered_map<int32_t, struct BestSensorConfig> sensorConfig_;
    std::unordered_map<int32_t, struct BestSensorConfig> sdcSensorConfig_;
};

struct BestSensorConfig {
    int64_t samplingInterval;
    int64_t reportInterval;
};

} // V2_0
} // Sensor
} // HDI
} // OHOS

#endif // HDI_SENSOR_MANAGER_H