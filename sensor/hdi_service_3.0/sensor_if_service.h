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
#include "v3_0/isensor_interface.h"
#include "sensor_callback_vdi.h"
#include "sensor_client_info.h"
#include "sensor_clients_manager.h"
#include "v1_0/isensor_interface_vdi.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {
using namespace OHOS::HDI::Sensor;
using namespace OHOS::HDI::Sensor::V1_1;

using GroupIdCallBackMap = std::unordered_map<int32_t, std::vector<sptr<IRemoteObject>>>;

class SensorIfService : public V3_0::ISensorInterface {
//V3_0 interface
    public:
    SensorIfService();
    ~SensorIfService();
    int32_t Init(void);
    int32_t GetAllSensorInfo(std::vector<V3_0::HdfSensorInformation> &info) override;
    int32_t Enable(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo) override;
    int32_t Disable(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo) override;
    int32_t DisableSensor(const SensorHandle sensorHandle, uint32_t serviceId);
    int32_t SetBatch(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo, int64_t samplingInterval,
                     int64_t reportInterval) override;
    int32_t SetBatchSenior(int32_t serviceId, const SensorHandle sensorHandle, int32_t mode, int64_t samplingInterval,
                           int64_t reportInterval);
    void AdjustSensorConfig(const SensorHandle &sensorHandle, SensorInterval &sensorInterval,
                            SensorInterval &saSensorInterval, SensorInterval &sdcSensorInterval);
    int32_t SetBatchConfig(const SensorHandle &sensorHandle, int64_t samplingInterval, int64_t reportInterval);
    void UpdateSensorModeConfig(const SensorHandle &sensorHandle, int32_t mode, SensorInterval &saSensorInterval,
                                SensorInterval &sdcSensorInterval);
    int32_t SetMode(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo, int32_t mode) override;
    int32_t SetOption(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo, uint32_t option) override;
    int32_t Register(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj) override;
    int32_t Unregister(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj) override;
    int32_t ReadData(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo,
                     std::vector<V3_0::HdfSensorEvents> &event) override;
    int32_t SetSdcSensor(const OHOS::HDI::Sensor::V3_0::DeviceSensorInfo& deviceSensorInfo, bool enabled,
                         int32_t rateLevel) override;
    int64_t CalculateSamplingInterval(int32_t rateLevel);
    int32_t EnableSdcSensor(uint32_t serviceId, const SensorHandle& sensorHandle,
                                             int64_t samplingInterval, int64_t reportInterval);
    int32_t DisableSdcSensor(uint32_t serviceId, const SensorHandle& sensorHandle,
                                              int64_t samplingInterval, int64_t reportInterval);
    int32_t GetSdcSensorInfo(std::vector<V3_0::SdcSensorInfo> &sdcSensorInfo) override;
    int32_t RegisterAsync(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj) override;
    int32_t UnregisterAsync(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj) override;
    int32_t GetDeviceSensorInfo(int32_t deviceId,
                                std::vector<OHOS::HDI::Sensor::V3_0::HdfSensorInformation>& info) override;
    int32_t RegSensorPlugCallBack(const sptr<OHOS::HDI::Sensor::V3_0::ISensorPlugCallback>& callbackObj) override;
    int32_t UnRegSensorPlugCallBack(const sptr<OHOS::HDI::Sensor::V3_0::ISensorPlugCallback>& callbackObj) override;
    int32_t GetSensorVdiImplV1_1();
    void OnRemoteDied(const wptr<IRemoteObject> &object);
    std::mutex sensorServiceMutex_;
private:
    int32_t AddSensorDeathRecipient(const sptr<IRemoteObject> &iRemoteObject);
    int32_t RemoveSensorDeathRecipient(const sptr<IRemoteObject> &iRemoteObject);
    void  RemoveDeathNotice(int32_t groupId);
    int32_t AddCallbackMap(int32_t groupId, const sptr<IRemoteObject> &iRemoteObject);
    int32_t RemoveCallbackMap(int32_t groupId, int serviceId, const sptr<IRemoteObject> &iRemoteObject);
    bool ValidateCallbackMap(int32_t groupId, const sptr<IRemoteObject> &iRemoteObject);
    bool RemoveCallbackFromMap(int32_t groupId, const sptr<IRemoteObject> &iRemoteObject);
    void DisableUnusedSensors(int serviceId);
    void DisableSensorHandle(const SensorHandle &sensorHandle);
    sptr<SensorCallbackVdi> GetSensorCb(int32_t groupId, const sptr<V3_0::ISensorCallback> &callbackObj, bool cbFlag);
    void VoteEnable(const SensorHandle sensorHandle, uint32_t serviceId, bool& enabled);
    void VoteInterval(const SensorHandle sensorHandle, uint32_t serviceId, int64_t &samplingInterval, bool &enabled);
    void RegisteDumpHost();
    OHOS::HDI::Sensor::V1_1::ISensorInterfaceVdi *sensorVdiImplV1_1_ = nullptr;
    struct HdfVdiObject *vdi_ = nullptr;
    GroupIdCallBackMap callbackMap = {};
    sptr<SensorCallbackVdi> traditionalCb = nullptr;
    sptr<SensorCallbackVdi> medicalCb = nullptr;
    std::vector<V3_0::HdfSensorInformation> hdfSensorInformations;
    int32_t SetDelay(const SensorHandle sensorHandle, int64_t &samplingInterval, int64_t &reportInterval);
};
} // V3_0
} // Sensor
} // HDI
} // OHOS

#endif // HDI_SENSOR_IF_SERVICE_H
