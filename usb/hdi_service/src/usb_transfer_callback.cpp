/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <hdf_log.h>
#include "usb_transfer_callback.h"
#include "usbd_wrapper.h"
#define HDF_LOG_TAG UsbTransferCb

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {

int32_t UsbTransferCb::OnTransferWriteCallback(int32_t status, int32_t actLength,
    const std::vector<HDI::Usb::V1_2::UsbIsoPacketDescriptor> &isoInfo, const uint64_t userData)
{
    HDF_LOGD("%{public}s: enter", __func__);
    if (transferCallback_ == nullptr) {
        HDF_LOGE("%{public}s: transferCallback_ is nullptr", __func__);
        return HDF_FAILURE;
    }
    const std::vector<V2_0::UsbIsoPacketDescriptor> &UsbInfo =
        reinterpret_cast<const std::vector<V2_0::UsbIsoPacketDescriptor> &>(isoInfo);
    return transferCallback_->OnTransferWriteCallback(status, actLength, UsbInfo, userData);
}

int32_t UsbTransferCb::OnTransferReadCallback(int32_t status, int32_t actLength,
    const std::vector<HDI::Usb::V1_2::UsbIsoPacketDescriptor> &isoInfo, const uint64_t userData)
{
    HDF_LOGD("%{public}s: enter", __func__);
    if (transferCallback_ == nullptr) {
        HDF_LOGE("%{public}s: transferCallback_ is nullptr", __func__);
        return HDF_FAILURE;
    }
    const std::vector<V2_0::UsbIsoPacketDescriptor> &UsbInfo =
        reinterpret_cast<const std::vector<V2_0::UsbIsoPacketDescriptor> &>(isoInfo);
    return transferCallback_->OnTransferReadCallback(status, actLength, UsbInfo, userData);
}

} // V2_0
} // Usb
} // HDI
} // OHOS
