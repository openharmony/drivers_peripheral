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
#include "securec.h"
#include "location_vendor_interface.h"
#include "location_vendor_lib.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Agnss {
namespace V2_0 {
namespace {
using AgnssCallBackMap = std::unordered_map<IRemoteObject*, sptr<IAGnssCallback>>;
using AgnssDeathRecipientMap = std::unordered_map<IRemoteObject*, sptr<IRemoteObject::DeathRecipient>>;
using OHOS::HDI::DeviceManager::V1_0::IDeviceManager;
AgnssCallBackMap g_agnssCallBackMap;
AgnssDeathRecipientMap g_agnssCallBackDeathRecipientMap;
std::mutex g_mutex;
std::mutex g_deathMutex;
uint32_t g_refInfoType; // reference loction info type
const int MAC_LEN = 6;
} // namespace

extern "C" IAGnssInterface* AGnssInterfaceImplGetInstance(void)
{
    return new (std::nothrow) AGnssInterfaceImpl();
}

void RequestSetupAgnssDataConnection(const AgnssDataConnectionRequest* status)
{
    if (status == nullptr) {
        HDF_LOGE("%{public}s:status is nullptr.", __func__);
        return;
    }
    HDF_LOGI("%{public}s.", __func__);
    AGnssDataLinkRequest agnssStatus;
    agnssStatus.agnssType = static_cast<AGnssUserPlaneProtocol>(status->agnssCategory);
    agnssStatus.setUpType = static_cast<DataLinkSetUpType>(status->requestCategory);
    std::unique_lock<std::mutex> lock(g_mutex);
    for (const auto& iter : g_agnssCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->RequestSetUpAgnssDataLink(agnssStatus);
        }
    }
}

void GetSetidCb(uint16_t type)
{
    HDF_LOGI("%{public}s.", __func__);
    std::unique_lock<std::mutex> lock(g_mutex);
    for (const auto& iter : g_agnssCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->RequestSubscriberSetId(static_cast<SubscriberSetIdType>(type));
        }
    }
}

void GetRefLocationidCb(uint32_t type)
{
    HDF_LOGI("%{public}s, type=%{public}d", __func__, type);
    std::unique_lock<std::mutex> lock(g_mutex);
    g_refInfoType = type;
    for (const auto& iter : g_agnssCallBackMap) {
        auto& callback = iter.second;
        if (callback != nullptr) {
            callback->RequestAgnssRefInfo(static_cast<AGnssRefInfoType>(type));
        }
    }
}

void GetAGnssCallbackMethods(AgnssCallbackIfaces* device)
{
    if (device == nullptr) {
        return;
    }
    device->size = sizeof(AgnssCallbackIfaces);
    device->requestSetupDataLink = RequestSetupAgnssDataConnection;
    device->requestSetid = GetSetidCb;
    device->requestRefInfo = GetRefLocationidCb;
}

AGnssInterfaceImpl::AGnssInterfaceImpl()
{
    g_refInfoType = 0;
}

AGnssInterfaceImpl::~AGnssInterfaceImpl()
{
    ResetAgnssDeathRecipient();
}

int32_t AGnssInterfaceImpl::SetAgnssCallback(const sptr<IAGnssCallback>& callbackObj)
{
    HDF_LOGI("%{public}s.", __func__);
    if (callbackObj == nullptr) {
        HDF_LOGE("%{public}s:invalid callbackObj", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IAGnssCallback>(callbackObj);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s:invalid remote", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    auto callBackIter = g_agnssCallBackMap.find(remote.GetRefPtr());
    if (callBackIter != g_agnssCallBackMap.end()) {
        const sptr<IRemoteObject>& lhs = OHOS::HDI::hdi_objcast<IAGnssCallback>(callbackObj);
        const sptr<IRemoteObject>& rhs = OHOS::HDI::hdi_objcast<IAGnssCallback>(callBackIter->second);
        return lhs == rhs ? HDF_SUCCESS : HDF_FAILURE;
    }

    static AgnssCallbackIfaces agnsscallback;
    GetAGnssCallbackMethods(&agnsscallback);

    int moduleType = static_cast<int>(GnssModuleIfaceCategory::AGNSS_MODULE_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto agnssInterface =
        static_cast<const AgnssModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (agnssInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get agnssInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    bool ret = agnssInterface->setAgnssCallback(&agnsscallback);
    if (!ret) {
        HDF_LOGE("setAgnssCallback failed.");
    }
    AddAgnssDeathRecipient(callbackObj);
    g_agnssCallBackMap[remote.GetRefPtr()] = callbackObj;
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::SetAgnssServer(const AGnssServerInfo& server)
{
    HDF_LOGI("%{public}s.", __func__);
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::AGNSS_MODULE_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto agnssInterface =
        static_cast<const AgnssModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (agnssInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get agnssInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint16_t type = static_cast<uint16_t>(server.type);
    bool ret = agnssInterface->setAgnssServer(type, server.server.c_str(), server.server.length(), server.port);
    if (!ret) {
        HDF_LOGE("setAgnssServer failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::SetAgnssRefInfo(const AGnssRefInfo& refInfo)
{
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::AGNSS_MODULE_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto agnssInterface =
        static_cast<const AgnssModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (agnssInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get agnssInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s, g_refInfoType=%{public}d", __func__, refInfo.type);
    AgnssReferenceInfo loc;
    loc.category = g_refInfoType;
    if (loc.category == static_cast<uint32_t>(AgnssRefInfoCategory::AGNSS_REF_INFO_CATEGORY_MAC)) {
        for (size_t i = 0; i < MAC_LEN; i++) {
            loc.u.mac.mac[i] = refInfo.mac.mac[i];
        }
        loc.u.mac.size = MAC_LEN;
    } else if (loc.category == static_cast<uint32_t>(AgnssRefInfoCategory::AGNSS_REF_INFO_CATEGORY_CELLID)) {
        switch (refInfo.cellId.type) {
            case CELLID_TYPE_GSM:
                loc.u.cellId.category = static_cast<uint16_t>(CellIdCategory::CELLID_CATEGORY_GSM);
                break;
            case CELLID_TYPE_UMTS:
                loc.u.cellId.category = static_cast<uint16_t>(CellIdCategory::CELLID_CATEGORY_UMTS);
                break;
            case CELLID_TYPE_LTE:
                loc.u.cellId.category = static_cast<uint16_t>(CellIdCategory::CELLID_CATEGORY_LTE);
                break;
            case CELLID_TYPE_NR:
                loc.u.cellId.category = static_cast<uint16_t>(CellIdCategory::CELLID_CATEGORY_NR);
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
        loc.u.cellId.nci = refInfo.cellId.nci;
    }
    bool ret = agnssInterface->setAgnssReferenceInfo(&loc);
    if (!ret) {
        HDF_LOGE("setAgnssReferenceInfo failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::SetSubscriberSetId(const SubscriberSetId& id)
{
    HDF_LOGI("%{public}s.", __func__);
    int moduleType = static_cast<int>(GnssModuleIfaceCategory::AGNSS_MODULE_INTERFACE);
    LocationVendorInterface* interface = LocationVendorInterface::GetInstance();
    auto agnssInterface =
        static_cast<const AgnssModuleInterface*>(interface->GetModuleInterface(moduleType));
    if (agnssInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get agnssInterface.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint16_t type = static_cast<uint16_t>(id.type);
    int ret = agnssInterface->setSetid(type, id.id.c_str(), id.id.length());
    if (!ret) {
        HDF_LOGE("setSetid failed.");
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
    std::unique_lock<std::mutex> lock(g_deathMutex);
    g_agnssCallBackDeathRecipientMap[remote.GetRefPtr()] = death;
    return HDF_SUCCESS;
}

int32_t AGnssInterfaceImpl::RemoveAgnssDeathRecipient(const sptr<IAGnssCallback>& callbackObj)
{
    std::unique_lock<std::mutex> lock(g_deathMutex);
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

int32_t AGnssInterfaceImpl::SendNetworkState(const NetworkState& state)
{
    return HDF_SUCCESS;
}

void AGnssInterfaceImpl::ResetAgnssDeathRecipient()
{
    std::unique_lock<std::mutex> lock(g_mutex);
    for (const auto& iter : g_agnssCallBackMap) {
        const auto& callback = iter.second;
        if (callback != nullptr) {
            RemoveAgnssDeathRecipient(callback);
        }
    }
}

void AGnssInterfaceImpl::ResetAgnss()
{
    HDF_LOGI("%{public}s called.", __func__);
    ResetAgnssDeathRecipient();
    std::unique_lock<std::mutex> lock(g_mutex);
    g_agnssCallBackMap.clear();
}
} // V2_0
} // Agnss
} // Location
} // HDI
} // OHOS
