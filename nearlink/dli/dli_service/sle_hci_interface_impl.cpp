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

#include "sle_hci_interface_impl.h"
#include <unistd.h>
#include <hdf_base.h>
#include "nearlink_hdf_log.h"
#include <iproxy_broker.h>
#include "vendor_interface.h"
#include "sle_hal_constant.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Hci {
namespace V1_1 {
    using VendorInterface = OHOS::HDI::Nearlink::Dli::V1_1::VendorInterface;
    using DliPacketType = OHOS::HDI::Nearlink::Dli::DliPacketType;
    thread_local bool SleHciInterfaceImpl::isThreadPromoted = false;
    using namespace OHOS::HDI::Nearlink::Dli;


extern "C" ISleHciInterface *SleHciInterfaceImplGetInstance(void)
{
    return new (std::nothrow) SleHciInterfaceImpl();
}

SleHciInterfaceImpl::SleHciInterfaceImpl()
{
    remoteDeathRecipient_ =
        new RemoteDeathRecipient(std::bind(&SleHciInterfaceImpl::OnRemoteDied, this, std::placeholders::_1));
}

SleHciInterfaceImpl::~SleHciInterfaceImpl()
{
    std::lock_guard<std::mutex> lock(dliCallbackMutex_);
    if (callbacks_ != nullptr) {
        RemoveDliDeathRecipient(callbacks_);
        callbacks_ = nullptr;
    }
}

int32_t SleHciInterfaceImpl::SleHalInit(const sptr<OHOS::HDI::Nearlink::Hci::V1_0::ISleHciCallback>& callbackObj)
{
    HDF_LOGI("SleHciInterfaceImpl %{public}s", __func__);
    if (callbackObj == nullptr) {
        HDF_LOGE("SleHciInterfaceImpl %{public}s callbackObj null", __func__);
        return HDF_FAILURE;
    }

    VendorInterface::ReceiveCallback callback = {
        .onAcbReceive =
            [callbackObj](
                const std::vector<uint8_t> &packet) { callbackObj->hciPacketReceived(SleType::ACB_DATA, packet); },
        .onIcbReceive =
            [callbackObj](
                const std::vector<uint8_t> &packet) { callbackObj->hciPacketReceived(SleType::ICB_DATA, packet); },
        .onEventReceive =
            [callbackObj](
                const std::vector<uint8_t> &packet) { callbackObj->hciPacketReceived(SleType::HCI_EVENT, packet); },
    };

    bool result = VendorInterface::GetInstance()->Initialize(
        [callbackObj](bool status) {
                callbackObj->initializationComplete(status ? SleStatus::SUCCESS : SleStatus::INITIALIZATION_ERROR);
        }, callback);
    if (result) {
        std::lock_guard<std::mutex> lock(dliCallbackMutex_);
        callbacks_ = callbackObj;
        AddDliDeathRecipient(callbacks_);
    }
    return result ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t SleHciInterfaceImpl::SleSendHciPacket(const std::vector<uint8_t>& data)
{
    HDF_LOGD("SleHciInterfaceImpl %{public}s", __func__);
    if (data.empty()) {
        return HDF_FAILURE;
    }
    SetRTSchedule();

    size_t result = VendorInterface::GetInstance()->SendPacket(data);
    return result ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t SleHciInterfaceImpl::CheckOnBoardState(bool& result)
{
    HDF_LOGI("SleHciInterfaceImpl %{public}s", __func__);
    result = true;
    return HDF_SUCCESS;
}

int32_t SleHciInterfaceImpl::Close()
{
    HDF_LOGI("SleHciInterfaceImpl %{public}s", __func__);
    {
        std::lock_guard<std::mutex> lock(dliCallbackMutex_);
        if (callbacks_ != nullptr) {
            RemoveDliDeathRecipient(callbacks_);
            callbacks_ = nullptr;
        }
    }
    VendorInterface::GetInstance()->CleanUp();
    VendorInterface::DestroyInstance();
    return HDF_SUCCESS;
}

void SleHciInterfaceImpl::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    HDF_LOGI("SleHciInterfaceImpl %{public}s", __func__);
    {
        std::lock_guard<std::mutex> lock(dliCallbackMutex_);
        callbacks_ = nullptr;
    }
    VendorInterface::GetInstance()->CleanUp();
    VendorInterface::DestroyInstance();
}

int32_t SleHciInterfaceImpl::AddDliDeathRecipient(const sptr<ISleHciCallback>& callbackObj)
{
    HDF_LOGI("SleHciInterfaceImpl %{public}s", __func__);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<ISleHciCallback>(callbackObj);
    if (!remote) {
        HDF_LOGE("remote is nullptr");
        return HDF_FAILURE;
    }
    bool result = remote->AddDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("SleHciInterfaceImpl AddDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SleHciInterfaceImpl::RemoveDliDeathRecipient(const sptr<ISleHciCallback>& callbackObj)
{
    HDF_LOGI("SleHciInterfaceImpl %{public}s", __func__);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<ISleHciCallback>(callbackObj);
    if (!remote) {
        HDF_LOGE("remote is nullptr");
        return HDF_FAILURE;
    }
    bool result = remote->RemoveDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("SleHciInterfaceImpl RemoveDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void SleHciInterfaceImpl::SetRTSchedule()
{
    if (isThreadPromoted) {
        return;
    }
    pid_t tid = gettid();
    struct sched_param rtParams = {.sched_priority = SLE_THREAD_PRIORITY};
    int rc = sched_setscheduler(tid, SCHED_FIFO, &rtParams);
    isThreadPromoted = (rc != 0) ? false : true;
}
} // V1_1
} // Hci
} // Nearlink
} // HDI
} // OHOS