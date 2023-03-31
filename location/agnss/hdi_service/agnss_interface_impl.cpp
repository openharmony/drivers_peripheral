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

#include "agnss_interface_impl.h"

#include <hdf_base.h>
#include <hdf_log.h>
#include <iproxy_broker.h>
#include <mutex>
#include <unordered_map>

#include "idevmgr_hdi.h"

#include "location_vendor_interface.h"
#include "location_vendor_lib.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Agnss {
namespace V1_0 {
namespace {
using AgnssCallBackMap = std::unordered_map<IRemoteObject*, sptr<IAGnssCallback>>;
using AgnssDeathRecipientMap = std::unordered_map<IRemoteObject*, sptr<IRemoteObject::DeathRecipient>>;
using OHOS::HDI::DeviceManager::V1_0::IDeviceManager;
constexpr const char* AGNSS_SERVICE_NAME = "agnss_interface_service";
AgnssCallBackMap g_agnssCallBackMap;
AgnssDeathRecipientMap g_agnssCallBackDeathRecipientMap;
std::mutex g_mutex;
} // namespace

extern "C" IAGnssInterface* AGnssInterfaceImplGetInstance(void)
{
    return new (std::nothrow) AGnssInterfaceImpl();
}

static void OnStatusChangedCb(const AGnssStatusInfo* status)
{
    if (status == nullptr) {
        HDF_LOGE("%{public}s:status is nullptr.", __func__);
        return;
    }
    HDF_LOGI("%{public}s.", __func__);
    AGnssDataLinkRequest agnssStatus;
    agnssStatus.agnssType = static_cast<AGnssUserPlaneProtocol>(status->agnssType);
    agnssStatus.setUpType = static_cast<DataLinkSetUpType>(status->connStatus);

    for (const auto& iter : g_agnssCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->RequestSetUpAgnssDataLink(agnssStatus);
        }
    }
}

static void GetSetidCb(uint16_t type)
{
    HDF_LOGI("%{public}s.", __func__);
    for (const auto& iter : g_agnssCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->RequestSubscriberSetId(static_cast<SubscriberSetIdType>(type));
        }
    }
}
static void GetRefLocationidCb(uint32_t type)
{
    HDF_LOGI("%{public}s.", __func__);
    for (const auto& iter : g_agnssCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->RequestAgnssRefInfo();
        }
    }
}

static void GetAGnssCallbackMethods(AGnssCallbackIfaces* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = sizeof(AGnssCallbackIfaces);
    device->agnssStatusChange = OnStatusChangedCb;
    device->getSetid = GetSetidCb;
    device->getRefLoc = GetRefLocationidCb;
}

AGnssInterfaceImpl::AGnssInterfaceImpl()
{
}

AGnssInterfaceImpl::~AGnssInterfaceImpl()
{
    ResetAgnssDeathRecipient();
    g_agnssCallBackMap.clear();
}

int32_t AGnssInterfaceImpl::SetAgnssCallback(const sptr<IAGnssCallback>& callbackObj)
{
    HDF_LOGI("%{public}s.", __func__);
    if (callbackObj == nullptr) {
        HDF_LOGE("%{public}s:invalid callbackObj", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IAGnssCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s:invalid remote", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    auto callBackIter = g_agnssCallBackMap.find(remote.GetRefPtr());
    if (callBackIter != g_agnssCallBackMap.end()) {
        const sptr<IRemoteObject>& lhs = OHOS::HDI::hdi_objcast<IAGnssCallback>(callbackObj);
        const sptr<IRemoteObject>& rhs = OHOS::HDI::hdi_objcast<IAGnssCallback>(callBackIter->second);
        return lhs == rhs ? HDF_SUCCESS : HDF_FAILURE;
    }

    static AGnssCallbackIfaces agnsscallback;
    GetAGnssCallbackMethods(&agnsscallback);

    int moduleType = static_cast<int>(GnssModuleIfaceClass::AGPS_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto agnssInterface =
        static_cast<const AGnssModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (agnssInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get agnssInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    bool ret = agnssInterface->set_agnss_callback(&agnsscallback);
    if (!ret) {
        HDF_LOGE("set_agnss_callback failed.");
        return HDF_FAILURE;
    }
    AddAgnssDeathRecipient(callbackObj);
    g_agnssCallBackMap[remote.GetRefPtr()] = callbackObj;
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::SetAgnssServer(const AGnssServerInfo& server)
{
    HDF_LOGI("%{public}s.", __func__);
    int moduleType = static_cast<int>(GnssModuleIfaceClass::AGPS_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto agnssInterface =
        static_cast<const AGnssModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (agnssInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get agnssInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint16_t type = static_cast<uint16_t>(server.type);
    bool ret = agnssInterface->set_agnss_server(type, server.server.c_str(), server.server.length(), server.port);
    if (!ret) {
        HDF_LOGE("set_agnss_server failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::SetAgnssRefInfo(const AGnssRefInfo& refInfo)
{
    int moduleType = static_cast<int>(GnssModuleIfaceClass::AGPS_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto agnssInterface =
        static_cast<const AGnssModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (agnssInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get agnssInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    AGnssRefLocInfo loc;
    loc.type = static_cast<int>(refInfo.type);
    switch (refInfo.cellId.type) {
        case CELLID_TYPE_GSM:
            loc.u.cellId.type = static_cast<uint16_t>(CellIdClass::GSM_CELLID);
            break;
        case CELLID_TYPE_UMTS:
            loc.u.cellId.type = static_cast<uint16_t>(CellIdClass::UMTS_CELLID);
            break;
        case CELLID_TYPE_LTE:
            loc.u.cellId.type = static_cast<uint16_t>(CellIdClass::LTE_CELLID);
            break;
        case CELLID_TYPE_NR:
            loc.u.cellId.type = static_cast<uint16_t>(CellIdClass::NR_CELLID);
            break;
        default:
            HDF_LOGE("%{public}s wrong cellType.", __func__);
            return HDF_ERR_INVALID_PARAM;
    }
    loc.u.cellId.mcc = refInfo.cellId.mcc;
    loc.u.cellId.mnc = refInfo.cellId.mnc;
    loc.u.cellId.lac = refInfo.cellId.lac;
    loc.u.cellId.cid = refInfo.cellId.cid;
    loc.u.cellId.tac = refInfo.cellId.tac;
    loc.u.cellId.pcid = refInfo.cellId.pcid;
    bool ret = agnssInterface->set_ref_location(&loc);
    if (!ret) {
        HDF_LOGE("set_ref_location failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::SetSubscriberSetId(const SubscriberSetId& id)
{
    HDF_LOGI("%{public}s.", __func__);
    int moduleType = static_cast<int>(GnssModuleIfaceClass::AGPS_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto agnssInterface =
        static_cast<const AGnssModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (agnssInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get agnssInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint16_t type = static_cast<uint16_t>(id.type);
    int ret = agnssInterface->set_setid(type, id.id.c_str(), id.id.length());
    if (!ret) {
        HDF_LOGE("set_setid failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::AddAgnssDeathRecipient(const sptr<IAGnssCallback>& callbackObj)
{
    sptr<IRemoteObject::DeathRecipient> death(new (std::nothrow) AgnssCallBackDeathRecipient(this));
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IAGnssCallback>(callbackObj);
    bool result = remote->AddDeathRecipient(death);
    if (!result) {
        HDF_LOGE("%{public}s: AGnssInterfaceImpl add deathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    g_agnssCallBackDeathRecipientMap[remote.GetRefPtr()] = death;
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::RemoveAgnssDeathRecipient(const sptr<IAGnssCallback>& callbackObj)
{
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IAGnssCallback>(callbackObj);
    auto iter = g_agnssCallBackDeathRecipientMap.find(remote.GetRefPtr());
    if (iter == g_agnssCallBackDeathRecipientMap.end()) {
        HDF_LOGE("%{public}s: AgnssInterfaceImpl can not find deathRecipient", __func__);
        return HDF_FAILURE;
    }
    auto recipient = iter->second;
    bool result = remote->RemoveDeathRecipient(recipient);
    g_agnssCallBackDeathRecipientMap.erase(iter);
    if (!result) {
        HDF_LOGE("%{public}s: AgnssInterfaceImpl remove deathRecipient fail", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void AGnssInterfaceImpl::ResetAgnssDeathRecipient()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& iter : g_agnssCallBackMap) {
        const auto& callback = iter.second;
        if (callback != nullptr) {
            RemoveAgnssDeathRecipient(callback);
        }
    }
}

void AGnssInterfaceImpl::UnloadAgnssDevice()
{
    auto devmgr = IDeviceManager::Get();
    if (devmgr == nullptr) {
        HDF_LOGE("fail to get devmgr.");
        return;
    }
    if (devmgr->UnloadDevice(AGNSS_SERVICE_NAME) != 0) {
        HDF_LOGE("unload agnss service failed!");
    }
    return;
}

void AGnssInterfaceImpl::ResetAgnss()
{
    HDF_LOGI("%{public}s called.", __func__);
    ResetAgnssDeathRecipient();
    g_agnssCallBackMap.clear();
    UnloadAgnssDevice();
}
} // V1_0
} // Agnss
} // Location
} // HDI
} // OHOS
