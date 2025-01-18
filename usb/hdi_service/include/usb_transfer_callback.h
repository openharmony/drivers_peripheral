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

#ifndef USB_TRANSFER_CALLBACK_H
#define USB_TRANSFER_CALLBACK_H

#include <iproxy_broker.h>
#include "v1_2/iusbd_transfer_callback.h"
#include "v2_0/iusb_host_interface.h"
#include "v2_0/usb_types.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {

class UsbTransferCb : public OHOS::HDI::Usb::V1_2::IUsbdTransferCallback {
public:
    UsbTransferCb() = default;
    virtual ~UsbTransferCb() = default;
    explicit UsbTransferCb(sptr<V2_0::IUsbdTransferCallback> transferCallback) : transferCallback_(transferCallback) {}
    int32_t OnTransferWriteCallback(int32_t status, int32_t actLength,
        const std::vector<HDI::Usb::V1_2::UsbIsoPacketDescriptor> &isoInfo, const uint64_t userData) override;
    int32_t OnTransferReadCallback(int32_t status, int32_t actLength,
        const std::vector<HDI::Usb::V1_2::UsbIsoPacketDescriptor> &isoInfo, const uint64_t userData) override;
private:
    sptr<V2_0::IUsbdTransferCallback> transferCallback_;
};

} // V2_0
} // Usb
} // HDI
} // OHOS

#endif // USB_TRANSFER_CALLBACK_H
