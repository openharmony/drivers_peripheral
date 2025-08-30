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
#include <iproxy_broker.h>
#include <mutex>
#include <unordered_map>

#include "idevmgr_hdi.h"
#include "securec.h"
#include "location_vendor_interface.h"
#include "location_vendor_lib.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Geofence {
namespace V2_0 {
namespace {
using GeofenceCallBackMap = std::unordered_map<IRemoteObject*, sptr<IGeofenceCallback>>;
using GeofenceDeathRecipientMap = std::unordered_map<IRemoteObject*, sptr<IRemoteObject::DeathRecipient>>;
using OHOS::HDI::DeviceManager::V1_0::IDeviceManager;
sptr<IGeofenceCallback> g_geofenceCallBack;
GeofenceDeathRecipientMap g_geofenceCallBackDeathRecipientMap;
std::mutex g_mutex;
std::mutex g_deathMutex;
} // namespace
extern "C" IGeofenceInterface *GeofenceInterfaceImplGetInstance(void)
{
    return new (std::nothrow) GeofenceInterfaceImpl();
}

GeofenceInterfaceImpl::~GeofenceInterfaceImpl()
{
    ResetGeofenceDeathRecipient();
}

void OnGeofenceAvailabilityChange(bool isAvailable)
{
    HDF_LOGI("%{public}s.", __func__);
    std::unique_lock<std::mutex> lock(g_mutex);
    if (g_geofenceCallBack != nullptr) {
        g_geofenceCallBack->ReportGeofenceAvailability(isAvailable);
    }
}

void OnGeofenceEventChange(int32_t geofenceId,  GnssLocation* location, int32_t event, int64_t timestamp)
{
    HDF_LOGI("%{public}s.", __func__);
    std::unique_lock<std::mutex> lock(g_mutex);
    if (location == nullptr) {
        HDF_LOGE("OnGeofenceEventChange: location is null.");
        return;
    }
    LocationInfo locationNew;
    locationNew.fieldValidity = location->fieldValidity;
    locationNew.latitude = location->latitude;
    locationNew.longitude = location->longitude;
    locationNew.altitude = location->altitude;
    locationNew.horizontalAccuracy = location->horizontalAccuracy;
    locationNew.speed = location->speed;
    locationNew.bearing = location->bearing;
    locationNew.verticalAccuracy = location->verticalAccuracy;
    locationNew.speedAccuracy = location->speedAccuracy;
    locationNew.bearingAccuracy = location->bearingAccuracy;
    locationNew.timeForFix = location->timeForFix;
    locationNew.timeSinceBoot = location->timeSinceBoot;
    locationNew.timeUncertainty = location->timeUncertainty;
    if (g_geofenceCallBack != nullptr) {
        g_geofenceCallBack->ReportGeofenceEvent(geofenceId, locationNew, static_cast<GeofenceEvent>(event), timestamp);
    }
}

void OnGeofenceOperateResultChange(int32_t geofenceId, int32_t operateCategory, int32_t result)
{
    HDF_LOGI("%{public}s.", __func__);
    std::unique_lock<std::mutex> lock(g_mutex);
    if (g_geofenceCallBack != nullptr) {
        g_geofenceCallBack->ReportGeofenceOperateResult(geofenceId, static_cast<GeofenceOperateType>(operateCategory),
            static_cast<GeofenceOperateResult>(result));
    }
}

void GetGeofenceCallbackMethods(GeofenceCallbackIfaces* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = sizeof(GeofenceCallbackIfaces);
    device->geofenceAvailabilityUpdate = OnGeofenceAvailabilityChange;
    device->geofenceEventUpdate = OnGeofenceEventChange;
    device->geofenceOperateResultUpdate = OnGeofenceOperateResultChange;
}

int32_t GeofenceInterfaceImpl::SetGeofenceCallback(const sptr<IGeofenceCallback>& callbackObj)
{
    HDF_LOGI("%{public}s.", __func__);
    if (callbackObj == nullptr) {
        HDF_LOGE("%{public}s:invalid callbackObj", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IGeofenceCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s:invalid remote", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    static GeofenceCallbackIfaces geofencecallback;
    GetGeofenceCallbackMethods(&geofencecallback);
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::GNSS_GEOFENCING_MODULE_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto geofenceInterface =
        static_cast<const GeofenceModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (geofenceInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get geofenceInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    bool ret = geofenceInterface->setCallback(&geofencecallback);
    if (!ret) {
        HDF_LOGE("setGeofenceCallback failed.");
        return HDF_FAILURE;
    }
    HDF_LOGI("setGeofenceCallback success.");
    AddGeofenceDeathRecipient(callbackObj);
    g_geofenceCallBack = callbackObj;
    return HDF_SUCCESS;
}

int32_t GeofenceInterfaceImpl::AddGnssGeofence(const GeofenceInfo& fence, int monitorEvent)
{
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::GNSS_GEOFENCING_MODULE_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto geofenceInterface =
        static_cast<const GeofenceModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (geofenceInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get geofenceInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    bool ret = geofenceInterface->addGnssGeofence(
        fence.fenceIndex, fence.latitude, fence.longitude, fence.radius, monitorEvent);
    if (!ret) {
        HDF_LOGE("AddGnssGeofence failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t GeofenceInterfaceImpl::DeleteGnssGeofence(int32_t fenceIndex)
{
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::GNSS_GEOFENCING_MODULE_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto geofenceInterface =
        static_cast<const GeofenceModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (geofenceInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get geofenceInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    bool ret = geofenceInterface->deleteGnssGeofence(fenceIndex);
    if (!ret) {
        HDF_LOGE("DeleteGnssGeofence failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t GeofenceInterfaceImpl::AddGeofenceDeathRecipient(const sptr<IGeofenceCallback>& callbackObj)
{
    sptr<IRemoteObject::DeathRecipient> death(new (std::nothrow) GeofenceCallBackDeathRecipient(this));
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IGeofenceCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s:invalid remote", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    bool result = remote->AddDeathRecipient(death);
    if (!result) {
        HDF_LOGE("%{public}s: GeofenceInterfaceImpl add deathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    std::unique_lock<std::mutex> lock(g_deathMutex);
    g_geofenceCallBackDeathRecipientMap[remote.GetRefPtr()] = death;
    return HDF_SUCCESS;
}

int32_t GeofenceInterfaceImpl::RemoveGeofenceDeathRecipient(const sptr<IGeofenceCallback>& callbackObj)
{
    std::unique_lock<std::mutex> lock(g_deathMutex);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IGeofenceCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s:invalid remote", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    auto iter = g_geofenceCallBackDeathRecipientMap.find(remote.GetRefPtr());
    if (iter == g_geofenceCallBackDeathRecipientMap.end()) {
        HDF_LOGE("%{public}s: GeofenceInterfaceImpl can not find deathRecipient", __func__);
        return HDF_FAILURE;
    }
    auto recipient = iter->second;
    if (recipient == nullptr) {
        HDF_LOGE("%{public}s: death recipient is null", __func__);
        g_geofenceCallBackDeathRecipientMap.erase(iter);
        return HDF_FAILURE;
    }
    bool result = remote->RemoveDeathRecipient(recipient);
    g_geofenceCallBackDeathRecipientMap.erase(iter);
    if (!result) {
        HDF_LOGE("%{public}s: GeofenceInterfaceImpl remove deathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void GeofenceInterfaceImpl::ResetGeofenceDeathRecipient()
{
    std::unique_lock<std::mutex> lock(g_mutex);
    if (g_geofenceCallBack != nullptr) {
        RemoveGeofenceDeathRecipient(g_geofenceCallBack);
    }
}

void GeofenceInterfaceImpl::ResetGeofence()
{
    HDF_LOGI("%{public}s called.", __func__);
    ResetGeofenceDeathRecipient();
    std::unique_lock<std::mutex> lock(g_mutex);
    g_geofenceCallBack = nullptr;
}
} // V2_0
} // Geofence
} // Location
} // HDI
} // OHOS
