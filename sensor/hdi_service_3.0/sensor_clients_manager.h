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
#include <hdf_remote_service.h>
#include "v3_0/isensor_interface.h"
#include "sensor_client_info.h"
#include "sensor_trace.h"
#include "v1_0/isensor_interface_vdi.h"
namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {

constexpr uint32_t MAX_DUMP_DATA_SIZE = 10;

struct SensorsDataPack {
    int32_t count;
    int32_t pos;
    struct HdfSensorEvents listDumpArray[MAX_DUMP_DATA_SIZE];
};

class SensorClientsManager {
public:
    ~SensorClientsManager();
    void ReportDataCbRegister(int groupId, int serviceId, const sptr<V3_0::ISensorCallback> &callbackObj, bool oneway);
    void ReportDataCbUnRegister(int groupId, int serviceId, const sptr<V3_0::ISensorCallback> &callbackObj);
    void ReportDataCbOneWay(int groupId, int serviceId);
    void SetSensorBestConfig(SensorHandle sensorHandle, int64_t &samplingInterval, int64_t &reportInterval);
    void SetSdcSensorBestConfig(SensorHandle sensorHandle, int64_t &samplingInterval, int64_t &reportInterval);
    void GetSensorBestConfig(SensorHandle sensorHandle, int64_t &samplingInterval, int64_t &reportInterval);
    int64_t GetSensorBestSamplingInterval(SensorHandle sensorHandle);
    void EraseSdcSensorBestConfig(SensorHandle sensorHandle);
    bool IsUpadateSensorState(SensorHandle sensorHandle, int serviceId, bool isOpen);
    static bool IsNotNeedReportData(SensorClientInfo &sensorClientInfo, const SensorHandle sensorHandle,
                                    const int32_t &serviceId);
    std::string ReportEachClient(const V3_0::HdfSensorEvents& event);
    bool GetClients(int groupId, std::unordered_map<int32_t, SensorClientInfo> &client);
    std::set<int32_t> GetServiceIds(SensorHandle sensorHandle);
    bool GetBestSensorConfigMap(std::unordered_map<SensorHandle, struct BestSensorConfig> &map);
    bool IsClientsEmpty(int groupId);
    bool IsNoSensorUsed();
    std::unordered_map<SensorHandle, std::set<int32_t>> GetSensorUsed();
    bool IsNeedOpenSensor(SensorHandle sensorHandle, int serviceId);
    bool IsNeedCloseSensor(SensorHandle sensorHandle, int serviceId);
    bool IsExistSdcSensorEnable(SensorHandle sensorHandle);
    void OpenSensor(SensorHandle sensorHandle, int serviceId);
    void UpdateSensorConfig(SensorHandle sensorHandle, int64_t samplingInterval, int64_t reportInterval);
    void UpdateSdcSensorConfig(SensorHandle sensorHandle, int64_t samplingInterval, int64_t reportInterval);
    int GetServiceId(int groupId, const sptr<IRemoteObject> &iRemoteObject);
    static SensorClientsManager* GetInstance();
    std::mutex clientsMutex_;
    std::mutex sensorUsedMutex_;
    std::mutex sensorConfigMutex_;
    std::mutex sdcSensorConfigMutex_;
    std::mutex sensorInfoMutex_;
    std::mutex sensorsDataPackMutex_;
    struct SensorInfoId {
        SensorHandle sensorHandle = {};
        int32_t serviceId = 0;
        bool oneway;
        int32_t callbackVersion;
    };
    void SetClientSenSorConfig(SensorHandle sensorHandle, int32_t serviceId, int64_t samplingInterval,
                               int64_t &reportInterval);
    static bool IsSensorContinues(SensorHandle sensorHandle);
    void UpdateClientPeriodCount(SensorHandle sensorHandle, int64_t samplingInterval, int64_t reportInterval);
    void CopySensorInfo(std::vector<V3_0::HdfSensorInformation> &info, bool cFlag);
    void GetEventData(struct SensorsDataPack &dataPack);
    void CopyEventData(const struct HdfSensorEvents event);
    void ReSetSensorPrintTime(SensorHandle sensorHandle);
    bool IsSensorNeedPrint(SensorHandle sensorHandle);
    void HdiReportData(const sptr<V3_0::ISensorCallback> &callbackObj, const V3_0::HdfSensorEvents& event,
        std::string &result, SensorInfoId sensorInfoId);
    static std::unordered_map<SensorHandle, std::unordered_map<int32_t, int64_t>> sensorReportCountMap;
private:
    SensorClientsManager();
    static std::mutex instanceMutex_;
    std::unordered_map<int32_t, std::unordered_map<int, SensorClientInfo>> clients_;
    std::unordered_map<SensorHandle, std::set<int32_t>> sensorUsed_;
    std::unordered_map<SensorHandle, struct BestSensorConfig> sensorConfig_;
    std::unordered_map<SensorHandle, struct BestSensorConfig> sdcSensorConfig_;
    std::unordered_map<SensorHandle, int32_t> sensorPrintTimes_;
    std::mutex sensorPrintTimesMutex_;
    std::vector<V3_0::HdfSensorInformation> sensorInfo_;
    SensorsDataPack listDump_ = {0};
};

struct BestSensorConfig {
    int64_t samplingInterval;
    int64_t reportInterval;
};

} // V3_0
} // Sensor
} // HDI
} // OHOS

#endif // HDI_SENSOR_MANAGER_H