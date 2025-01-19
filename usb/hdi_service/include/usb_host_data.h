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

#ifndef USB_HOST_DATA_H
#define USB_HOST_DATA_H

#include "data_fifo.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "osal_sem.h"
#include "refbase.h"
#include "iremote_object.h"
#include "usb_ddk.h"
#include "usb_ddk_interface.h"
#include "usb_session.h"
#include "usbd_type.h"
#include "v2_0/iusb_host_interface.h"
#include "v2_0/iusb_device_interface.h"
#include "v2_0/iusb_port_interface.h"
#include "v2_0/iusbd_bulk_callback.h"

#define MAX_SUBSCRIBER         10

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {

struct UsbdSubscriber {
    sptr<IUsbdSubscriber> subscriber;
    std::shared_ptr<void> impl;
    struct HdfDevEventlistener usbPnpListener;
    sptr<IRemoteObject> remote;
    std::shared_ptr<void> deathRecipient;
};
} // namespace V2_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // USB_HOST_DATA_H
