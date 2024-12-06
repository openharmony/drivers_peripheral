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

#include "hci_interface_impl.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <iproxy_broker.h>
#include "vendor_interface.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000105

namespace OHOS {
namespace HDI {
namespace Bluetooth {
namespace Hci {
namespace V1_0 {
using VendorInterface = OHOS::HDI::Bluetooth::Hci::V1_0::VendorInterface;
using HciPacketType = OHOS::HDI::Bluetooth::Hci::HciPacketType;

extern "C" IHciInterface *HciInterfaceImplGetInstance(void)
{
    return new (std::nothrow) HciInterfaceImpl();
}

HciInterfaceImpl::HciInterfaceImpl()
{
    remoteDeathRecipient_ =
        new RemoteDeathRecipient(std::bind(&HciInterfaceImpl::OnRemoteDied, this, std::placeholders::_1));
}

HciInterfaceImpl::~HciInterfaceImpl()
{
    if (callbacks_ != nullptr) {
        RemoveHciDeathRecipient(callbacks_);
        callbacks_ = nullptr;
    }
}

int32_t HciInterfaceImpl::Init(const sptr<IHciCallback>& callbackObj)
{
    HDF_LOGI("HciInterfaceImpl %{public}s", __func__);
    if (callbackObj == nullptr) {
        HDF_LOGE("HciInterfaceImpl %{public}s callbackObj null", __func__);
        return HDF_FAILURE;
    }

    AddHciDeathRecipient(callbackObj);
    callbacks_ = callbackObj;

    VendorInterface::ReceiveCallback callback = {
        .onAclReceive =
            [callbackObj](
                const std::vector<uint8_t> &packet) { callbackObj->OnReceivedHciPacket(BtType::ACL_DATA, packet); },
        .onScoReceive =
            [callbackObj](
                const std::vector<uint8_t> &packet) { callbackObj->OnReceivedHciPacket(BtType::SCO_DATA, packet); },
        .onEventReceive =
            [callbackObj](
                const std::vector<uint8_t> &packet) { callbackObj->OnReceivedHciPacket(BtType::HCI_EVENT, packet); },
        .onIsoReceive =
            [callbackObj](
                const std::vector<uint8_t> &packet) { callbackObj->OnReceivedHciPacket(BtType::ISO_DATA, packet); },
    };

    bool result = VendorInterface::GetInstance()->Initialize(
        [callbackObj](bool status) { callbackObj->OnInited(status ? BtStatus::SUCCESS : BtStatus::INITIAL_ERROR); },
        callback);
    if (!result) {
        RemoveHciDeathRecipient(callbackObj);
        callbacks_ = nullptr;
    }
    return result ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t HciInterfaceImpl::SendHciPacket(BtType type, const std::vector<uint8_t>& data)
{
    HDF_LOGD("HciInterfaceImpl %{public}s, %{public}d", __func__, type);
    if (data.empty()) {
        return HDF_FAILURE;
    }

    size_t result = VendorInterface::GetInstance()->SendPacket(static_cast<HciPacketType>(type), data);
    return result ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t HciInterfaceImpl::Close()
{
    HDF_LOGI("HciInterfaceImpl %{public}s", __func__);
    if (callbacks_ != nullptr) {
        RemoveHciDeathRecipient(callbacks_);
        callbacks_ = nullptr;
    }
    VendorInterface::GetInstance()->CleanUp();
    return HDF_SUCCESS;
}

void HciInterfaceImpl::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    HDF_LOGI("HciInterfaceImpl %{public}s", __func__);
    callbacks_ = nullptr;
    VendorInterface::GetInstance()->CleanUp();
}

int32_t HciInterfaceImpl::AddHciDeathRecipient(const sptr<IHciCallback>& callbackObj)
{
    HDF_LOGI("HciInterfaceImpl %{public}s", __func__);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IHciCallback>(callbackObj);
    bool result = remote->AddDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("HciInterfaceImpl AddDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HciInterfaceImpl::RemoveHciDeathRecipient(const sptr<IHciCallback>& callbackObj)
{
    HDF_LOGI("HciInterfaceImpl %{public}s", __func__);
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IHciCallback>(callbackObj);
    bool result = remote->RemoveDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("HciInterfaceImpl RemoveDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
} // V1_0
} // Hci
} // Bluetooth
} // HDI
} // OHOS
