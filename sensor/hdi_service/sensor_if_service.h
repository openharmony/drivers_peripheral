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

#ifndef SENSOR_V1_0_SENSORIFSERVICE_H
#define SENSOR_V1_0_SENSORIFSERVICE_H

#include "sensor_if.h"
#include "sensor_interface_stub.h"

namespace sensor {
namespace v1_0 {
class SensorIfService : public SensorInterfaceStub {
public:
    SensorIfService(): sensorInterface(NULL)
    {}

    virtual ~SensorIfService()
    {
        FreeSensorInterfaceInstance();
    }

    void Init();

    int32_t GetAllSensorInfo(std::vector<HdfSensorInformation>& info) override;

    int32_t Enable(int32_t sensorId) override;

    int32_t Disable(int32_t sensorId) override;

    int32_t SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval) override;

    int32_t SetMode(int32_t sensorId, int32_t mode) override;

    int32_t SetOption(int32_t sensorId, uint32_t option) override;

    int32_t Register(int32_t sensorId, const sptr<ISensorCallback>& callbackObj) override;

    int32_t Unregister(int32_t sensorId, const sptr<ISensorCallback>& callbackObj) override;
private:
    const SensorInterface *sensorInterface;
};
} // v1_0
} // sensor

#endif // SENSOR_V1_0_SENSORIFSERVICE_H