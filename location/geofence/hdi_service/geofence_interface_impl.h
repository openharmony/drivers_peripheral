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

#ifndef OHOS_HDI_LOCATION_LOCATION_GEOFENCE_V2_0_GEOFENCEINTERFACEIMPL_H
#define OHOS_HDI_LOCATION_LOCATION_GEOFENCE_V2_0_GEOFENCEINTERFACEIMPL_H

#include "v2_0/igeofence_interface.h"
#include "iremote_object.h"
#include "location_vendor_lib.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Geofence {
namespace V2_0 {

void OnGeofenceAvailabilityChange(bool isAvailable);
void OnGeofenceEventChange(int32_t geofenceId,  GnssLocation* location, int32_t event, int64_t timestamp);
void OnGeofenceOperateResultChange(int32_t geofenceId, int32_t operateCategory, int32_t result);
void GetGeofenceCallbackMethods(GeofenceCallbackIfaces* device);

class GeofenceInterfaceImpl : public IGeofenceInterface {
public:
    GeofenceInterfaceImpl() = default;
    ~GeofenceInterfaceImpl() override;

    int32_t SetGeofenceCallback(const sptr<IGeofenceCallback>& callbackObj) override;

    int32_t AddGnssGeofence(const GeofenceInfo& fence, int monitorEvent) override;

    int32_t DeleteGnssGeofence(int32_t fenceIndex) override;
    
    void ResetGeofence();
private:
    int32_t AddGeofenceDeathRecipient(const sptr<IGeofenceCallback>& callbackObj);

    int32_t RemoveGeofenceDeathRecipient(const sptr<IGeofenceCallback>& callbackObj);

    void ResetGeofenceDeathRecipient();
	
    bool IsSupportHighPowerFence();
};
class GeofenceCallBackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit GeofenceCallBackDeathRecipient(const wptr<GeofenceInterfaceImpl>& impl) : geofenceInterfaceImpl_(impl) {};
    ~GeofenceCallBackDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject>& remote) override
    {
        (void)remote;
        sptr<GeofenceInterfaceImpl> impl = geofenceInterfaceImpl_.promote();
        if (impl != nullptr) {
            impl->ResetGeofence();
        }
    };
private:
    wptr<GeofenceInterfaceImpl> geofenceInterfaceImpl_;
};
} // V2_0
} // Geofence
} // Location
} // HDI
} // OHOS

#endif // OHOS_HDI_LOCATION_LOCATION_GEOFENCE_V2_0_GEOFENCEINTERFACEIMPL_H