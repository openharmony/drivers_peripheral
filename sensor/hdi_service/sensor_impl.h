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

#ifndef OHOS_HDI_SENSOR_V1_0_SENSORIMPL_H
#define OHOS_HDI_SENSOR_V1_0_SENSORIMPL_H

#include "sensor_if.h"
#include "v1_0/isensor_interface.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_0 {
class SensorImpl : public ISensorInterface {
public:
    SensorImpl(): sensorInterface(NULL) {}

    virtual ~SensorImpl();
    void Init();

    int32_t GetAllSensorInfo(std::vector<HdfSensorInformation>& info) override;
    int32_t Enable(int32_t sensorId) override;
    int32_t Disable(int32_t sensorId) override;
    int32_t SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval) override;
    int32_t SetMode(int32_t sensorId, int32_t mode) override;
    int32_t SetOption(int32_t sensorId, uint32_t option) override;
    int32_t Register(int32_t groupId, const sptr<ISensorCallback>& callbackObj) override;
    int32_t Unregister(int32_t groupId, const sptr<ISensorCallback>& callbackObj) override;
    void OnRemoteDied(const wptr<IRemoteObject> &object);
private:
    const SensorInterface *sensorInterface;
    int32_t AddSensorDeathRecipient(const sptr<ISensorCallback> &callbackObj);
    int32_t RemoveSensorDeathRecipient(const sptr<ISensorCallback> &callbackObj);
    int32_t UnregisterImpl(int32_t groupId, IRemoteObject *callbackObj);
    void RemoveDeathNotice(int32_t sensorType);
};
} // V1_0
} // Sensor
} // HDI
} // OHOS

#endif // OHOS_HDI_SENSOR_V1_0_SENSORIMPL_H
