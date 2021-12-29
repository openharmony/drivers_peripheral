/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "bt_hci_service.h"
#include "vendor_interface.h"
#include <hdf_log.h>

namespace ohos {
namespace hardware {
namespace bt {
namespace v1_0 {

using VendorInterface = OHOS::HDI::BT::V1_0::VendorInterface;
using HciPacketType = OHOS::HDI::BT::HCI::HciPacketType;

int32_t BtHciService::Init(const sptr<IBtHciCallbacks> &callbacks)
{
    HDF_LOGI("%{public}s, ", __func__);
    if (callbacks == nullptr) {
        HDF_LOGI("%{public}s, ", __func__);
        return HDF_FAILURE;
    }

    VendorInterface::ReceiveCallback callback = {
        .onAclReceive =
            [&](const std::vector<uint8_t> &packet) {
                callbacks->OnReceivedHciPacket(BtType::ACL_DATA, packet);
            },
        .onScoReceive =
            [&](const std::vector<uint8_t> &packet) {
                callbacks->OnReceivedHciPacket(BtType::SCO_DATA, packet);
            },
        .onEventReceive =
            [&](const std::vector<uint8_t> &packet) {
                callbacks->OnReceivedHciPacket(BtType::HCI_EVENT, packet);
            },
    };

    bool result = VendorInterface::GetInstance()->Initialize(
        [&](bool status) { callbacks->OnInited(status ? BtStatus::SUCCESS : BtStatus::INITIAL_ERROR); }, callback);

    return result ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t BtHciService::SendHciPacket(BtType type, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s, ", __func__);
    if (data.empty()) {
        return HDF_FAILURE;
    }

    size_t result =
        VendorInterface::GetInstance()->SendPacket(static_cast<HciPacketType>(type), data);
    return result ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t BtHciService::Close()
{
    VendorInterface::GetInstance()->CleanUp();
    VendorInterface::DestroyInstance();
    return HDF_SUCCESS;
}

}  // namespace v1_0
}  // namespace bt
}  // namespace hardware
}  // namespace ohos
