/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_HDI_SENSOR_V1_0_CALLBACKDEATHRECIPIENT_H
#define OHOS_HDI_SENSOR_V1_0_CALLBACKDEATHRECIPIENT_H

#include <functional>
#include "iremote_object.h"
#include "refbase.h"
#include "sensor_impl.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_0 {
class CallBackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CallBackDeathRecipient(const wptr<SensorImpl> &sensorImpl) : sensorImpl(sensorImpl) {};
    virtual ~CallBackDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override
    {
        sptr<SensorImpl> impl = sensorImpl.promote();
        if (impl == nullptr) {
            return;
        }
        impl->OnRemoteDied(object);
    };

private:
    wptr<SensorImpl> sensorImpl;
};
}  // namespace V1_0
}  // namespace Senosr
}  // namespace HDI
}  // namespace OHOS

#endif  // OHOS_HDI_SENSOR_V1_0_CALLBACKDEATHRECIPIENT_H
