/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_HDI_SENSOR_V2_1_CALLBACKDEATHRECIPIENT_H
#define OHOS_HDI_SENSOR_V2_1_CALLBACKDEATHRECIPIENT_H

#include <functional>
#include "iremote_object.h"
#include "refbase.h"
#include "sensor_if_service.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_1 {
class CallBackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CallBackDeathRecipient(const wptr<SensorIfService> &sensorIfService) : sensorIfService(sensorIfService) {};
    virtual ~CallBackDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override
    {
        sptr<SensorIfService> ifService = sensorIfService.promote();
        if (ifService == nullptr) {
            return;
        }
        ifService->OnRemoteDied(object);
    };

private:
    wptr<SensorIfService> sensorIfService;
};
}  // namespace V2_1
}  // namespace Senosr
}  // namespace HDI
}  // namespace OHOS

#endif  // OHOS_HDI_SENSOR_V2_1_CALLBACKDEATHRECIPIENT_H
