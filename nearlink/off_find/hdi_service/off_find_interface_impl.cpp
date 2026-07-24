/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <hdf_base.h>
#include <iproxy_broker.h>
#include "off_find_log.h"
#include "vendor_interface.h"
#include "off_find_interface_impl.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace OffFind {
namespace V1_0 {
using VendorInterface = OHOS::HDI::Nearlink::OffFind::V1_0::VendorInterface;
const std::string OFF_FIND_FFRT_THREAD = "OffFindHdf";

extern "C" IOffFindInterface *OffFindInterfaceImplGetInstance(void)
{
    return new (std::nothrow) OffFindInterfaceImpl();
}


OffFindInterfaceImpl::OffFindInterfaceImpl()
{
    remoteDeathRecipient_ =
        new RemoteDeathRecipient(std::bind(&OffFindInterfaceImpl::OnRemoteDied, this, std::placeholders::_1));
    if (eventQueue_ != nullptr) {
        HDF_LOGI("eventQueue already init");
    } else {
        eventQueue_ = std::make_shared<ffrt::queue>(OFF_FIND_FFRT_THREAD.c_str());
        HDF_LOGI("Create a new eventQueue, threadName:%{public}s", OFF_FIND_FFRT_THREAD.c_str());
    }
}

OffFindInterfaceImpl::~OffFindInterfaceImpl()
{
    if (callbacks_ != nullptr) {
        RemoveHciDeathRecipient(callbacks_);
        callbacks_ = nullptr;
    }
    if (eventQueue_) {
        eventQueue_.reset();
    }
}

int32_t OffFindInterfaceImpl::SetReservedPower()
{
    HDF_LOGI("OffFindInterfaceImpl::SetReservedPower");
    auto func = []() {
        HDF_LOGI("asyc SetReservedPower work start");
        VendorInterface::GetInstance()->SetReservedPower();
    };

    if (eventQueue_ == nullptr) {
        HDF_LOGE("eventQueue is nullptr!");
        return HDF_FAILURE;
    }
    eventQueue_->submit(func);
    return HDF_SUCCESS;
}

int32_t OffFindInterfaceImpl::EnableOffFind(
    const sptr<OHOS::HDI::Nearlink::OffFind::V1_0::IOffFindCallback>& callbackObj,
    const std::vector<OHOS::HDI::Nearlink::OffFind::V1_0::OffFindParam>& data,
    const OHOS::HDI::Nearlink::OffFind::V1_0::OffFindExtraInfo& info)
{
    HDF_LOGI("OffFindInterfaceImpl::EnableOffFind");
    auto func = [callbackObj, data, info, this]() {
        HDF_LOGI("Enter EnableOffFind");
        if (callbackObj == nullptr) {
            HDF_LOGE("OffFindInterfaceImpl callbackObj null");
            return ;
        }
        VendorInterface::GetInstance()->RegisterClearOffFindCallback(
            [this]() {
                HDF_LOGI("clear callbacks is success !");
                if (callbacks_ != nullptr) {
                    RemoveHciDeathRecipient(callbacks_);
                    callbacks_ = nullptr;
                }
            }
        );
        bool result = VendorInterface::GetInstance()->Initialize(
            [callbackObj](int32_t result) {callbackObj->OnOffFindEnableResult(result); }, data, info);
        if (result) {
            callbacks_ = callbackObj;
            AddHciDeathRecipient(callbacks_);
        }
    };
    if (eventQueue_ == nullptr) {
        HDF_LOGE("eventQueue is nullptr!");
        return HDF_FAILURE;
    }
    eventQueue_->submit(func);
    return HDF_SUCCESS;
}

int32_t OffFindInterfaceImpl::DisableOffFind()
{
    HDF_LOGI("OffFindInterfaceImpl::DisableOffFind");
    auto func = []() {
        HDF_LOGI("asyc disable work start");
        VendorInterface::GetInstance()->DisableOffFindMode();
    };

    if (eventQueue_ == nullptr) {
        HDF_LOGE("eventQueue is nullptr!");
        return HDF_FAILURE;
    }
    eventQueue_->submit(func);
    VendorInterface::DestroyInstance();
    return HDF_SUCCESS;
}

void OffFindInterfaceImpl::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    HDF_LOGI("OffFindInterfaceImpl");
    callbacks_ = nullptr;
    VendorInterface::GetInstance()->CleanUp();
    VendorInterface::DestroyInstance();
}

int32_t OffFindInterfaceImpl::AddHciDeathRecipient(const sptr<IOffFindCallback>& callbackObj)
{
    HDF_LOGI("OffFindInterfaceImpl");
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IOffFindCallback>(callbackObj);
    if (!remote) {
        HDF_LOGE("remote is nullptr");
        return HDF_FAILURE;
    }
    bool result = remote->AddDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("OffFindInterfaceImpl AddDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t OffFindInterfaceImpl::RemoveHciDeathRecipient(const sptr<IOffFindCallback>& callbackObj)
{
    HDF_LOGI("OffFindInterfaceImpl");
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IOffFindCallback>(callbackObj);
    if (!remote) {
        HDF_LOGE("remote is nullptr");
        return HDF_FAILURE;
    }
    bool result = remote->RemoveDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("OffFindInterfaceImpl RemoveDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

} // V1_0
} // OffFind
} // Nearlink
} // HDI
} // OHOS