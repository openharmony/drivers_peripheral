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

#include "gnss_interface_impl.h"

#include <hdf_base.h>
#include <hdf_log.h>
#include <iproxy_broker.h>
#include <mutex>
#include <unordered_map>

#include "idevmgr_hdi.h"

#include "location_vendor_interface.h"
#include "location_vendor_lib.h"

namespace {
GnssConfigPara g_configPara;
}

namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V1_0 {
namespace {
using LocationCallBackMap = std::unordered_map<IRemoteObject*, sptr<IGnssCallback>>;
using GnssDeathRecipientMap = std::unordered_map<IRemoteObject*, sptr<IRemoteObject::DeathRecipient>>;
using OHOS::HDI::DeviceManager::V1_0::IDeviceManager;
const int32_t MAX_CALLBACK_SIZE = 1;
LocationCallBackMap g_locationCallBackMap;
GnssDeathRecipientMap g_gnssCallBackDeathRecipientMap;
std::mutex g_mutex;
std::mutex g_deathMutex;
} // namespace

extern "C" IGnssInterface* GnssInterfaceImplGetInstance(void)
{
    return new (std::nothrow) GnssInterfaceImpl();
}

static void LocationUpdate(GnssLocation* location)
{
    if (location == nullptr) {
        HDF_LOGE("%{public}s:location is nullptr.", __func__);
        return;
    }
    HDF_LOGI("%{public}s:LocationUpdate.", __func__);
    std::unique_lock<std::mutex> lock(g_mutex);
    LocationInfo locationNew;
    locationNew.latitude = location->latitude;
    locationNew.longitude = location->longitude;
    locationNew.altitude = location->altitude;
    locationNew.accuracy = location->horizontalAccuracy;
    locationNew.speed = location->speed;
    locationNew.direction = location->bearing;
    locationNew.timeStamp = location->timestamp;
    locationNew.timeSinceBoot = location->timestampSinceBoot;
    for (const auto& iter : g_locationCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->ReportLocation(locationNew);
        }
    }
}

static void StatusCallback(uint16_t* status)
{
    if (status == nullptr) {
        HDF_LOGE("%{public}s:param is nullptr.", __func__);
        return;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    GnssWorkingStatus gnssStatus = static_cast<GnssWorkingStatus>(*status);
    for (const auto& iter : g_locationCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->ReportGnssWorkingStatus(gnssStatus);
        }
    }
}

static void SvStatusCallback(GnssSatelliteStatus* svInfo)
{
    if (svInfo == nullptr) {
        HDF_LOGE("%{public}s:sv_info is null.", __func__);
        return;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    SatelliteStatusInfo svStatus;
    svStatus.satellitesNumber = svInfo->satellitesNum;
    for (unsigned int i = 0; i < svInfo->satellitesNum; i++) {
        svStatus.satelliteIds.push_back(svInfo->satellitesList[i].satelliteId);
        svStatus.constellation.push_back(
            static_cast<GnssConstellationType>(svInfo->satellitesList[i].constellationType));
        svStatus.elevation.push_back(svInfo->satellitesList[i].elevation);
        svStatus.azimuths.push_back(svInfo->satellitesList[i].azimuth);
        svStatus.carrierFrequencies.push_back(svInfo->satellitesList[i].carrierFrequencie);
        svStatus.carrierToNoiseDensitys.push_back(svInfo->satellitesList[i].cn0);
    }
    for (const auto& iter : g_locationCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->ReportSatelliteStatusInfo(svStatus);
        }
    }
}

static void NmeaCallback(int64_t timestamp, const char* nmea, int length)
{
    if (nmea == nullptr) {
        HDF_LOGE("%{public}s:nmea is nullptr.", __func__);
        return;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    for (const auto& iter : g_locationCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->ReportNmea(timestamp, nmea, length);
        }
    }
}

static void GetGnssBasicCallbackMethods(GnssBasicCallbackIfaces* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = sizeof(GnssCallbackStruct);
    device->locationUpdate = LocationUpdate;
    device->statusUpdate = StatusCallback;
    device->svStatusUpdate = SvStatusCallback;
    device->nmeaUpdate = NmeaCallback;
    device->capabilitiesUpdate = nullptr;
    device->refInfoRequest = nullptr;
    device->downloadRequestCb = nullptr;
}

static void GetGnssCacheCallbackMethods(GnssCacheCallbackIfaces* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = 0;
    device->cachedLocationCb = nullptr;
}

static void GetGnssCallbackMethods(GnssCallbackStruct* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = sizeof(GnssCallbackStruct);
    static GnssBasicCallbackIfaces basicCallback;
    GetGnssBasicCallbackMethods(&basicCallback);
    device->gnssCb = basicCallback;
    static GnssCacheCallbackIfaces cacheCallback;
    GetGnssCacheCallbackMethods(&cacheCallback);
    device->gnssCacheCb = cacheCallback;
}

GnssInterfaceImpl::GnssInterfaceImpl()
{
}

GnssInterfaceImpl::~GnssInterfaceImpl()
{
    ResetGnssDeathRecipient();
}

int32_t GnssInterfaceImpl::SetGnssConfigPara(const GnssConfigPara& para)
{
    HDF_LOGI("%{public}s.", __func__);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    // GnssConfigPara configPara;
    g_configPara.type = static_cast<uint32_t>(GnssStartClass::GNSS_START_CLASS_NORMAL);
    g_configPara.u.gnssBasicConfig.gnssMode = para.gnssBasic.gnssMode;
    g_configPara.u.gnssBasicConfig.size = sizeof(GnssBasicConfigPara);
    int ret = gnssInterface->set_gnss_config_para(&g_configPara);
    HDF_LOGI("%{public}s, ret=%{public}d", __func__, ret);
    return ret;
}

int32_t GnssInterfaceImpl::EnableGnss(const sptr<IGnssCallback>& callbackObj)
{
    HDF_LOGI("%{public}s.", __func__);
    if (callbackObj == nullptr) {
        HDF_LOGE("%{public}s:invalid callbackObj", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IGnssCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s:invalid remote", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_locationCallBackMap.size() >= MAX_CALLBACK_SIZE) {
        HDF_LOGE("%{public}s:gnss has been enabled already", __func__);
        return HDF_SUCCESS;
    }
    static GnssCallbackStruct gnssCallback;
    GetGnssCallbackMethods(&gnssCallback);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = gnssInterface->enable_gnss(&gnssCallback);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("enable_gnss failed.");
        return HDF_FAILURE;
    }
    AddGnssDeathRecipient(callbackObj);
    g_locationCallBackMap[remote.GetRefPtr()] = callbackObj;
    return ret;
}

int32_t GnssInterfaceImpl::DisableGnss()
{
    HDF_LOGI("%{public}s.", __func__);
    std::unique_lock<std::mutex> lock(g_mutex);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = gnssInterface->disable_gnss();
    g_locationCallBackMap.clear();
    return ret;
}

int32_t GnssInterfaceImpl::StartGnss(GnssStartType type)
{
    HDF_LOGI("%{public}s.", __func__);
    int startType = int(type);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = gnssInterface->start_gnss(startType);
    return ret;
}

int32_t GnssInterfaceImpl::StopGnss(GnssStartType type)
{
    HDF_LOGI("%{public}s.", __func__);
    int startType = static_cast<int>(type);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = gnssInterface->stop_gnss(startType);
    return ret;
}

int32_t GnssInterfaceImpl::SetGnssReferenceInfo(const GnssRefInfo& refInfo)
{
    HDF_LOGI("%{public}s.", __func__);
    return HDF_SUCCESS;
}

int32_t GnssInterfaceImpl::DeleteAuxiliaryData(GnssAuxiliaryData data)
{
    HDF_LOGI("%{public}s.", __func__);
    uint16_t flags = static_cast<uint16_t>(data);
    HDF_LOGI("%{public}s, flag=%{public}d", __func__, flags);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    gnssInterface->remove_auxiliary_data(flags);
    return HDF_SUCCESS;
}

int32_t GnssInterfaceImpl::SetPredictGnssData(const std::string& data)
{
    HDF_LOGI("%{public}s.", __func__);
    return HDF_SUCCESS;
}

int32_t GnssInterfaceImpl::GetCachedGnssLocationsSize(int32_t& size)
{
    HDF_LOGI("%{public}s.", __func__);
    return HDF_SUCCESS;
}

int32_t GnssInterfaceImpl::GetCachedGnssLocations()
{
    HDF_LOGI("%{public}s.", __func__);
    return HDF_SUCCESS;
}

int32_t GnssInterfaceImpl::AddGnssDeathRecipient(const sptr<IGnssCallback>& callbackObj)
{
    sptr<IRemoteObject::DeathRecipient> death(new (std::nothrow) GnssCallBackDeathRecipient(this));
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IGnssCallback>(callbackObj);
    bool result = remote->AddDeathRecipient(death);
    if (!result) {
        HDF_LOGE("%{public}s: GnssInterfaceImpl add deathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    std::unique_lock<std::mutex> lock(g_deathMutex);
    g_gnssCallBackDeathRecipientMap[remote.GetRefPtr()] = death;
    return HDF_SUCCESS;
}

int32_t GnssInterfaceImpl::RemoveGnssDeathRecipient(const sptr<IGnssCallback>& callbackObj)
{
    std::unique_lock<std::mutex> lock(g_deathMutex);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IGnssCallback>(callbackObj);
    auto iter = g_gnssCallBackDeathRecipientMap.find(remote.GetRefPtr());
    if (iter == g_gnssCallBackDeathRecipientMap.end()) {
        HDF_LOGE("%{public}s: GnssInterfaceImpl can not find deathRecipient", __func__);
        return HDF_FAILURE;
    }
    auto recipient = iter->second;
    bool result = remote->RemoveDeathRecipient(recipient);
    g_gnssCallBackDeathRecipientMap.erase(iter);
    if (!result) {
        HDF_LOGE("%{public}s: GnssInterfaceImpl remove deathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void GnssInterfaceImpl::ResetGnssDeathRecipient()
{
    std::unique_lock<std::mutex> lock(g_mutex);
    for (const auto& iter : g_locationCallBackMap) {
        const auto& callback = iter.second;
        if (callback != nullptr) {
            RemoveGnssDeathRecipient(callback);
        }
    }
}

void GnssInterfaceImpl::ResetGnss()
{
    HDF_LOGI("%{public}s called.", __func__);
    ResetGnssDeathRecipient();
    StopGnss(GNSS_START_TYPE_NORMAL);
    DisableGnss();
}
} // V1_0
} // Gnss
} // Location
} // HDI
} // OHOS
