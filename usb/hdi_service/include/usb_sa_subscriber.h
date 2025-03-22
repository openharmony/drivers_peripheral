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

#ifndef USB_SA_SUBSCRIBER_H
#define USB_SA_SUBSCRIBER_H

#include "libusb_sa_subscriber.h"
#include "usbd_load_usb_service.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
class UsbSaSubscriber : public LibUsbSaSubscriber {
public:
    UsbSaSubscriber();
    ~UsbSaSubscriber() override = default;
    int32_t LoadUsbSa(const int32_t &eventId) override;
private:
    static UsbdLoadService loadUsbService_;
    static UsbdLoadService loadHdfEdm_;
};
} // namespace V1_2
} // namespace USB
} // namespace HDI
} // namespace OHOS
#endif // USB_SA_SUBSCRIBER_H
