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

#include "geofence_interface_impl.h"
#include <hdf_base.h>
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Location {
namespace Geofence {
namespace V2_0 {
extern "C" IGeofenceInterface *GeofenceInterfaceImplGetInstance(void)
{
    return new (std::nothrow) GeofenceInterfaceImpl();
}

GeofenceInterfaceImpl::~GeofenceInterfaceImpl()
{
}

int32_t GeofenceInterfaceImpl::SetGeofenceCallback(const sptr<IGeofenceCallback>& callbackObj)
{
    return HDF_SUCCESS;
}

int32_t GeofenceInterfaceImpl::AddGnssGeofence(const GeofenceInfo& fence, int monitorEvent)
{
    return HDF_SUCCESS;
}

int32_t GeofenceInterfaceImpl::DeleteGnssGeofence(int32_t fenceIndex)
{
    return HDF_SUCCESS;
}
} // V2_0
} // Geofence
} // Location
} // HDI
} // OHOS
