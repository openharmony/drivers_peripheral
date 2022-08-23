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

#include "ril_interface_impl.h"

#include <hdf_base.h>
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Ril {
namespace V1_0 {
static std::mutex mutex_;
static sptr<IRilCallback> callback_;
namespace {
sptr<RilInterfaceImpl::RilDeathRecipient> g_deathRecipient = nullptr;
}
extern "C" IRilInterface *RilInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Ril::V1_0::RilInterfaceImpl;
    RilInterfaceImpl *service = new (std::nothrow) RilInterfaceImpl();
    if (service == nullptr) {
        return nullptr;
    }
    if (service->Init() != HDF_SUCCESS) {
        delete service;
        service = nullptr;
        return nullptr;
    }
    return service;
}

int32_t RilInterfaceImpl::SetEmergencyCallList(
    int32_t slotId, int32_t serialId, const IEmergencyInfoList &emergencyInfoList)
{
    return TaskSchedule(&Telephony::HRilManager::SetEmergencyCallList, slotId, serialId, emergencyInfoList);
}

int32_t RilInterfaceImpl::GetEmergencyCallList(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetEmergencyCallList, slotId, serialId);
}

int32_t RilInterfaceImpl::ActivatePdpContext(int32_t slotId, int32_t serialId, const IDataCallInfo &dataCallInfo)
{
    return TaskSchedule(&Telephony::HRilManager::ActivatePdpContext, slotId, serialId, dataCallInfo);
}

int32_t RilInterfaceImpl::DeactivatePdpContext(int32_t slotId, int32_t serialId, const IUniInfo &uniInfo)
{
    return TaskSchedule(&Telephony::HRilManager::DeactivatePdpContext, slotId, serialId, uniInfo);
}

int32_t RilInterfaceImpl::GetPdpContextList(int32_t slotId, int32_t serialId, const IUniInfo &uniInfo)
{
    return TaskSchedule(&Telephony::HRilManager::GetPdpContextList, slotId, serialId, uniInfo);
}

int32_t RilInterfaceImpl::SetInitApnInfo(
    int32_t slotId, int32_t serialId, const IDataProfileDataInfo &dataProfileDataInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetInitApnInfo, slotId, serialId, dataProfileDataInfo);
}

int32_t RilInterfaceImpl::GetLinkBandwidthInfo(int32_t slotId, int32_t serialId, int32_t cid)
{
    return TaskSchedule(&Telephony::HRilManager::GetLinkBandwidthInfo, slotId, serialId, cid);
}

int32_t RilInterfaceImpl::SetLinkBandwidthReportingRule(
    int32_t slotId, int32_t serialId, const IDataLinkBandwidthReportingRule &dataLinkBandwidthReportingRule)
{
    return TaskSchedule(
        &Telephony::HRilManager::SetLinkBandwidthReportingRule, slotId, serialId, dataLinkBandwidthReportingRule);
}

int32_t RilInterfaceImpl::SetDataPermitted(int32_t slotId, int32_t serialId, int32_t dataPermitted)
{
    return TaskSchedule(&Telephony::HRilManager::SetDataPermitted, slotId, serialId, dataPermitted);
}

int32_t RilInterfaceImpl::SetDataProfileInfo(
    int32_t slotId, int32_t serialId, const IDataProfilesInfo &dataProfilesInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetDataProfileInfo, slotId, serialId, dataProfilesInfo);
}

int32_t RilInterfaceImpl::SetCallback(const sptr<IRilCallback> &rilCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = rilCallback;
    if (callback_ == nullptr) {
        UnRegister();
        return HDF_SUCCESS;
    }
    g_deathRecipient = new RilDeathRecipient(this);
    if (g_deathRecipient == nullptr) {
        HDF_LOGE("SetCallback fail g_deathRecipient is null");
        return HDF_FAILURE;
    }
    AddRilDeathRecipient(callback_);
    if (Telephony::HRilManager::manager_ == nullptr) {
        HDF_LOGE("SetCallback fail manager_ is null");
        return HDF_FAILURE;
    }
    Telephony::HRilManager::manager_->SetRilCallback(callback_);
    return HDF_SUCCESS;
}

int32_t RilInterfaceImpl::AddRilDeathRecipient(const sptr<IRilCallback> &callback)
{
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IRilCallback>(callback);
    if (!remote->AddDeathRecipient(g_deathRecipient)) {
        HDF_LOGE("AddRilDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t RilInterfaceImpl::RemoveRilDeathRecipient(const sptr<IRilCallback> &callback)
{
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IRilCallback>(callback);
    if (!remote->RemoveDeathRecipient(g_deathRecipient)) {
        HDF_LOGI("RemoveRilDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void RilInterfaceImpl::RilDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    if (rilInterfaceImpl_ == nullptr) {
        HDF_LOGE("RilInterfaceImpl::RilDeathRecipient::OnRemoteDied fail rilInterfaceImpl_ is null");
        return;
    }
    rilInterfaceImpl_->UnRegister();
}

int32_t RilInterfaceImpl::UnRegister()
{
    HDF_LOGI("UnRegister");
    RemoveRilDeathRecipient(callback_);
    callback_ = nullptr;
    if (Telephony::HRilManager::manager_ == nullptr) {
        HDF_LOGE("RilInterfaceImpl::UnRegister fail manager_ is null");
        return HDF_FAILURE;
    }
    Telephony::HRilManager::manager_->SetRilCallback(nullptr);
    return HDF_SUCCESS;
}

int32_t RilInterfaceImpl::Init()
{
    if (Telephony::HRilManager::manager_ == nullptr) {
        HDF_LOGE("RilInterfaceImpl::Init is manager_ is null");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
} // namespace V1_0
} // namespace Ril
} // namespace HDI
} // namespace OHOS
