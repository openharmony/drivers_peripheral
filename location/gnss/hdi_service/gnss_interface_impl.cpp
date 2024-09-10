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
#include "string_utils.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V2_0 {
namespace {
using LocationCallBackMap = std::unordered_map<IRemoteObject*, sptr<IGnssCallback>>;
#ifndef EMULATOR_ENABLED
using GnssMeasurementCallbackMap = std::unordered_map<IRemoteObject*, sptr<IGnssMeasurementCallback>>;
#endif
using GnssDeathRecipientMap = std::unordered_map<IRemoteObject*, sptr<IRemoteObject::DeathRecipient>>;
using OHOS::HDI::DeviceManager::V1_0::IDeviceManager;
LocationCallBackMap g_locationCallBackMap;
#ifndef EMULATOR_ENABLED
GnssMeasurementCallbackMap g_gnssMeasurementCallbackMap;
#endif
GnssDeathRecipientMap g_gnssCallBackDeathRecipientMap;
GnssConfigParameter g_configPara;
std::mutex g_mutex;
std::mutex g_deathMutex;
} // namespace

extern "C" IGnssInterface* GnssInterfaceImplGetInstance(void)
{
    return new (std::nothrow) GnssInterfaceImpl();
}

static void NiNotifyCallback(OHOS::HDI::Location::GnssNiNotificationRequest *notification)
{
    if (notification == nullptr) {
        HDF_LOGE("%{public}s:niNotificationRequest is nullptr.", __func__);
        return;
    }
    HDF_LOGI("%{public}s:NiNotifyCb.", __func__);
    std::unique_lock<std::mutex> lock(g_mutex);
    GnssNiNotificationRequest niNotification;
    niNotification.gnssNiNotificationId = notification->gnssNiNotificationId;
    niNotification.gnssNiRequestCategory = GnssNiRequestCategory(notification->gnssNiRequestCategory);
    niNotification.notificationCategory = notification->notificationCategory;
    niNotification.requestTimeout = notification->requestTimeout;
    niNotification.defaultResponseCmd = notification->defaultResponseCmd;
    niNotification.supplicantInfo = notification->supplicantInfo;
    niNotification.notificationText = notification->notificationText;
    niNotification.supplicantInfoEncoding = GnssNiRequestEncodingFormat(notification->supplicantInfoEncoding);
    niNotification.notificationTextEncoding = GnssNiRequestEncodingFormat(notification->notificationTextEncoding);

    HDF_LOGI("reportNiNotification: notificationId %{public}u, niType %{public}d, notifyType %{public}d, timeout "
        "%{public}d, defaultRespone %{private}d",
        niNotification.gnssNiNotificationId,
        niNotification.gnssNiRequestCategory,
        niNotification.notificationCategory,
        niNotification.requestTimeout,
        niNotification.defaultResponseCmd);

    for (const auto& iter : g_locationCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->ReportGnssNiNotification(niNotification);
        }
    }
    HDF_LOGI("%{public}s:NiNotifyCallback.", __func__);
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
    for (const auto& iter : g_locationCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->ReportLocation(locationNew);
        }
    }
}

#ifndef EMULATOR_ENABLED
static void SetGnssClock(OHOS::HDI::Location::Gnss::V2_0::GnssMeasurementInfo* gnssMeasurementInfoNew,
    OHOS::HDI::Location::GnssMeasurementInfo* gnssMeasurementInfo)
{
    gnssMeasurementInfoNew->gnssClock.fieldValidFlags = gnssMeasurementInfo->gnssClock.fieldValidFlags;
    gnssMeasurementInfoNew->gnssClock.leapSecond = gnssMeasurementInfo->gnssClock.leapSecond;
    gnssMeasurementInfoNew->gnssClock.receiverClockTime = gnssMeasurementInfo->gnssClock.receiverClockTime;
    gnssMeasurementInfoNew->gnssClock.timeUncertainty = gnssMeasurementInfo->gnssClock.timeUncertainty;
    gnssMeasurementInfoNew->gnssClock.rcvClockFullBias = gnssMeasurementInfo->gnssClock.rcvClockFullBias;
    gnssMeasurementInfoNew->gnssClock.rcvClockSubBias = gnssMeasurementInfo->gnssClock.rcvClockSubBias;
    gnssMeasurementInfoNew->gnssClock.biasUncertainty = gnssMeasurementInfo->gnssClock.biasUncertainty;
    gnssMeasurementInfoNew->gnssClock.clockDrift = gnssMeasurementInfo->gnssClock.clockDrift;
    gnssMeasurementInfoNew->gnssClock.clockDriftUncertainty = gnssMeasurementInfo->gnssClock.clockDriftUncertainty;
    gnssMeasurementInfoNew->gnssClock.clockInterruptCnt = gnssMeasurementInfo->gnssClock.clockInterruptCnt;
    gnssMeasurementInfoNew->gnssClock.clockJumpThreshold = gnssMeasurementInfo->gnssClock.clockJumpThreshold;
    gnssMeasurementInfoNew->gnssClock.clockHWFreBiasIndicator = gnssMeasurementInfo->gnssClock.clockHWFreBiasIndicator;
    gnssMeasurementInfoNew->gnssClock.clockHWFreDriftIndicator =
        gnssMeasurementInfo->gnssClock.clockHWFreDriftIndicator;
}

static void GnssMeasurementUpdate(OHOS::HDI::Location::GnssMeasurementInfo* gnssMeasurementInfo)
{
    if (gnssMeasurementInfo == nullptr) {
        HDF_LOGE("%{public}s:gnssMeasurementInfo is nullptr.", __func__);
        return;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    OHOS::HDI::Location::Gnss::V2_0::GnssMeasurementInfo gnssMeasurementInfoNew;
    SetGnssClock(&gnssMeasurementInfoNew, gnssMeasurementInfo);
    gnssMeasurementInfoNew.elapsedRealtime = static_cast<long>(gnssMeasurementInfo->elapsedRealtime);
    gnssMeasurementInfoNew.uncertainty = static_cast<long>(gnssMeasurementInfo->uncertainty);
    gnssMeasurementInfoNew.measurementCount = static_cast<int>(gnssMeasurementInfo->measurementCount);

    std::vector<OHOS::HDI::Location::Gnss::V2_0::GnssMeasurement> gnssMeasurements;
    for (OHOS::HDI::Location::GnssMeasurement infoItem : gnssMeasurementInfo->measurements) {
        OHOS::HDI::Location::Gnss::V2_0::GnssMeasurement gnssMeasurement;
        gnssMeasurement.fieldValidflags = infoItem.fieldValidflags;
        gnssMeasurement.satelliteId = infoItem.satelliteId;
        gnssMeasurement.constellationCategory = infoItem.constellationCategory;
        gnssMeasurement.timeOffset = infoItem.timeOffset;
        gnssMeasurement.syncState = infoItem.syncState;
        gnssMeasurement.receivedSatelliteTime = infoItem.receivedSatelliteTime;
        gnssMeasurement.receivedSatelliteTimeUncertainty = infoItem.receivedSatelliteTimeUncertainty;
        gnssMeasurement.cn0 = infoItem.cn0;
        gnssMeasurement.pseudorangeRate = infoItem.pseudorangeRate;
        gnssMeasurement.pseudorangeRateUncertainty = infoItem.pseudorangeRateUncertainty;
        gnssMeasurement.accumulatedDeltaRangeFlag = infoItem.accumulatedDeltaRangeFlag;
        gnssMeasurement.accumulatedDeltaRange = infoItem.accumulatedDeltaRange;
        gnssMeasurement.accumulatedDeltaRangeUncertainty = infoItem.accumulatedDeltaRangeUncertainty;
        gnssMeasurement.carrierFrequency = infoItem.carrierFrequency;
        gnssMeasurement.carrierCyclesCount = infoItem.carrierCyclesCount;
        gnssMeasurement.carrierPhase = infoItem.carrierPhase;
        gnssMeasurement.carrierPhaseUncertainty = infoItem.carrierPhaseUncertainty;
        gnssMeasurement.multipathFlag = infoItem.multipathFlag;
        gnssMeasurement.agcGain = infoItem.agcGain;
        gnssMeasurement.codeCategory = infoItem.codeCategory;
        gnssMeasurement.ionoCorrect = infoItem.ionoCorrect;
        gnssMeasurement.tropCorrect = infoItem.tropCorrect;
        gnssMeasurement.satelliteClockBias = infoItem.satelliteClockBias;
        gnssMeasurement.satelliteClockDriftBias = infoItem.satelliteClockDriftBias;
        gnssMeasurements.push_back(gnssMeasurement);
    }
    gnssMeasurementInfoNew.measurements = gnssMeasurements;
    for (const auto& iter : g_gnssMeasurementCallbackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->ReportGnssMeasurementInfo(gnssMeasurementInfoNew);
        }
    }
}
#endif

static void GnssWorkingStatusUpdate(uint16_t* status)
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
            static_cast<ConstellationCategory>(svInfo->satellitesList[i].constellationCategory));
        svStatus.elevation.push_back(svInfo->satellitesList[i].elevation);
        svStatus.azimuths.push_back(svInfo->satellitesList[i].azimuth);
        svStatus.carrierFrequencies.push_back(svInfo->satellitesList[i].carrierFrequency);
        svStatus.carrierToNoiseDensitys.push_back(svInfo->satellitesList[i].cn0);
        svStatus.additionalInfo.push_back(svInfo->satellitesList[i].satelliteAdditionalInfo);
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
    device->gnssWorkingStatusUpdate = GnssWorkingStatusUpdate;
    device->satelliteStatusUpdate = SvStatusCallback;
    device->nmeaUpdate = NmeaCallback;
    device->capabilitiesUpdate = nullptr;
    device->requestRefInfo = nullptr;
    device->requestExtendedEphemeris = nullptr;
}

static void GetGnssCacheCallbackMethods(GnssCacheCallbackIfaces* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = 0;
    device->cachedLocationUpdate = nullptr;
}

static void GetGnssCallbackMethods(GnssCallbackStruct* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = sizeof(GnssCallbackStruct);
    static GnssBasicCallbackIfaces basicCallback;
    GetGnssBasicCallbackMethods(&basicCallback);
    device->gnssCallback = basicCallback;
    static GnssCacheCallbackIfaces cacheCallback;
    GetGnssCacheCallbackMethods(&cacheCallback);
    device->gnssCacheCallback = cacheCallback;
}

#ifndef EMULATOR_ENABLED
static void GetGnssMeasurementCallbackMethods(GnssMeasurementCallbackIfaces* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = sizeof(GnssMeasurementCallbackIfaces);
    device->gnssMeasurementUpdate = GnssMeasurementUpdate;
}
#endif

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
    g_configPara.startCategory = static_cast<uint32_t>(GnssStartCategory::GNSS_START_CATEGORY_NORMAL);
    g_configPara.u.gnssBasicConfig.gnssMode = para.gnssBasic.gnssMode;
    g_configPara.u.gnssBasicConfig.size = sizeof(GnssBasicConfigPara);
    int ret = gnssInterface->setGnssConfigPara(&g_configPara);
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
    static GnssCallbackStruct gnssCallback;
    GetGnssCallbackMethods(&gnssCallback);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = gnssInterface->enableGnss(&gnssCallback);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("enableGnss failed.");
        return HDF_FAILURE;
    }
    static GnssNetInitiatedCallbacks niCallback;
    niCallback.reportNiNotification = NiNotifyCallback;
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::GNSS_NET_INITIATED_MODULE_INTERFACE);
    auto niInterface = static_cast<const GnssNetInitiatedInterface*>
        (LocationVendorInterface::GetInstance()->GetModuleInterface(moduleType));
    if (niInterface != nullptr) {
        niInterface->setCallback(&niCallback);
    } else {
        HDF_LOGE("%{public}s:can not get gnssNiInterface.", __func__);
    }
    
    if (g_locationCallBackMap.size() > 0) {
        for (const auto& iter : g_locationCallBackMap) {
            const auto& callback = iter.second;
            if (callback != nullptr) {
                RemoveGnssDeathRecipient(callback);
            }
        }
        g_locationCallBackMap.clear();
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
    int ret = gnssInterface->disableGnss();
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
    int ret = gnssInterface->startGnss(startType);
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
    int ret = gnssInterface->stopGnss(startType);
    return ret;
}

int32_t GnssInterfaceImpl::SetGnssReferenceInfo(const GnssRefInfo& refInfo)
{
    HDF_LOGI("%{public}s.", __func__);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    GnssReferenceInfo referenceInfo;
    referenceInfo.category = refInfo.type;
    switch (refInfo.type) {
        case GNSS_REF_INFO_TIME:
            referenceInfo.u.time.size = sizeof(GnssRefTime);
            referenceInfo.u.time.time = refInfo.time.time;
            referenceInfo.u.time.elapsedRealtime = refInfo.time.elapsedRealtime;
            referenceInfo.u.time.uncertaintyOfTime = refInfo.time.uncertaintyOfTime;
            referenceInfo.size = sizeof(GnssReferenceInfo);
            return gnssInterface->injectsGnssReferenceInfo(referenceInfo.category, &referenceInfo);
        case GNSS_REF_INFO_LOCATION:
            referenceInfo.u.gnssLocation.size = sizeof(GnssLocation);
            referenceInfo.u.gnssLocation.fieldValidity = refInfo.gnssLocation.fieldValidity;
            referenceInfo.u.gnssLocation.latitude = refInfo.gnssLocation.latitude;
            referenceInfo.u.gnssLocation.longitude = refInfo.gnssLocation.longitude;
            referenceInfo.u.gnssLocation.altitude = refInfo.gnssLocation.altitude;
            referenceInfo.u.gnssLocation.speed = refInfo.gnssLocation.speed;
            referenceInfo.u.gnssLocation.bearing = refInfo.gnssLocation.bearing;
            referenceInfo.u.gnssLocation.horizontalAccuracy = refInfo.gnssLocation.horizontalAccuracy;
            referenceInfo.u.gnssLocation.verticalAccuracy = refInfo.gnssLocation.verticalAccuracy;
            referenceInfo.u.gnssLocation.speedAccuracy = refInfo.gnssLocation.speedAccuracy;
            referenceInfo.u.gnssLocation.bearingAccuracy = refInfo.gnssLocation.bearingAccuracy;
            referenceInfo.u.gnssLocation.timeForFix = refInfo.gnssLocation.timeForFix;
            referenceInfo.u.gnssLocation.timeSinceBoot = refInfo.gnssLocation.timeSinceBoot;
            referenceInfo.u.gnssLocation.timeUncertainty = refInfo.gnssLocation.timeUncertainty;
            referenceInfo.size = sizeof(GnssReferenceInfo);
            return gnssInterface->injectsGnssReferenceInfo(referenceInfo.category, &referenceInfo);
        default:
            HDF_LOGI("%{public}s: do not support now", __func__);
            return HDF_ERR_INVALID_PARAM;
    }
}

int32_t GnssInterfaceImpl::DeleteAuxiliaryData(unsigned short data)
{
    HDF_LOGI("%{public}s.", __func__);
    uint16_t flags = data;
    HDF_LOGI("%{public}s, flag=%{public}d", __func__, flags);
    auto gnssInterface = LocationVendorInterface::GetInstance()->GetGnssVendorInterface();
    if (gnssInterface == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    gnssInterface->removeAuxiliaryData(flags);
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

__attribute__((no_sanitize("cfi")))
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

int32_t GnssInterfaceImpl::SendNiUserResponse(int32_t gnssNiNotificationId, GnssNiResponseCmd userResponse)
{
    HDF_LOGI("%{public}s.", __func__);
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::GNSS_NET_INITIATED_MODULE_INTERFACE);
    auto niInterface = static_cast<const GnssNetInitiatedInterface*>
        (LocationVendorInterface::GetInstance()->GetModuleInterface(moduleType));
    if (niInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get gnssNiInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    niInterface->sendUserResponse(gnssNiNotificationId, static_cast<int32_t>(userResponse));
    return HDF_SUCCESS;
}

int32_t GnssInterfaceImpl::SendNetworkInitiatedMsg(const std::string& msg, int length)
{
    HDF_LOGI("%{public}s.", __func__);
    if (msg.empty()) {
        HDF_LOGE("%{public}s msg is empty", __func__);
        return HDF_FAILURE;
    }
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::GNSS_NET_INITIATED_MODULE_INTERFACE);
    auto niInterface = static_cast<const GnssNetInitiatedInterface*>
        (LocationVendorInterface::GetInstance()->GetModuleInterface(moduleType));
    if (niInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get gnssNiInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    std::vector<uint8_t> data = StringUtils::HexToByteVector(msg);
    HDF_LOGI("%{public}s. msg : %{public}s, length %{public}d, msg size %{public}d, data size %{public}d",
        __func__, msg.c_str(), length, int(msg.size()), int(data.size()));

    niInterface->sendNetworkInitiatedMsg(data.data(), data.size());
    return HDF_SUCCESS;
}

int32_t GnssInterfaceImpl::EnableGnssMeasurement(const sptr<IGnssMeasurementCallback>& callbackObj)
{
#ifndef EMULATOR_ENABLED
    HDF_LOGI("%{public}s.", __func__);
    if (callbackObj == nullptr) {
        HDF_LOGE("%{public}s:invalid callbackObj", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IGnssMeasurementCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s:invalid remote", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    static GnssMeasurementCallbackIfaces gnssMeasurementCallback;
    GetGnssMeasurementCallbackMethods(&gnssMeasurementCallback);
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::GNSS_MEASUREMENT_MODULE_INTERFACE);
    auto gnssMeasurementInterface = static_cast<const GnssMeasurementInterface*>
        (LocationVendorInterface::GetInstance()->GetModuleInterface(moduleType));
    if (gnssMeasurementInterface == nullptr) {
        HDF_LOGE("%{public}s:GetModuleInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    bool result = gnssMeasurementInterface->enable(&gnssMeasurementCallback);
    if (!result) {
        HDF_LOGE("enableGnssMeasurement failed.");
        return HDF_FAILURE;
    }
    if (g_gnssMeasurementCallbackMap.size() > 0) {
        g_gnssMeasurementCallbackMap.clear();
    }
    g_gnssMeasurementCallbackMap[remote.GetRefPtr()] = callbackObj;
    return HDF_SUCCESS;
#else
    return HDF_SUCCESS;
#endif
}

int32_t GnssInterfaceImpl::DisableGnssMeasurement()
{
#ifndef EMULATOR_ENABLED
    HDF_LOGI("%{public}s.", __func__);
    std::unique_lock<std::mutex> lock(g_mutex);
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::GNSS_MEASUREMENT_MODULE_INTERFACE);
    auto gnssMeasurementInterface = static_cast<const GnssMeasurementInterface*>
        (LocationVendorInterface::GetInstance()->GetModuleInterface(moduleType));
    if (gnssMeasurementInterface == nullptr) {
        HDF_LOGE("%{public}s:GnssMeasurementInterface return nullptr.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    gnssMeasurementInterface->disable();
    g_gnssMeasurementCallbackMap.clear();
#endif
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
    DisableGnssMeasurement();
}
} // V2_0
} // Gnss
} // Location
} // HDI
} // OHOS
