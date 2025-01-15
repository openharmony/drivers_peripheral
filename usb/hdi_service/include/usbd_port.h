/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_USB_V1_2_USBD_PORT_H
#define OHOS_HDI_USB_V1_2_USBD_PORT_H

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "usb_host_data.h"
#include "usbd.h"
#include "v1_0/iusbd_subscriber.h"
#include "v1_2/usb_types.h"
#include "v2_0/iusbd_subscriber.h"

#define DEFAULT_PORT_ID 1

#define PORT_MODE_HOST_STR   "host"
#define PORT_MODE_DEVICE_STR "device"

#define POWER_ROLE_NONE   0
#define POWER_ROLE_SOURCE 1
#define POWER_ROLE_SINK   2
#define POWER_ROLE_MAX    3

#define DATA_ROLE_NONE   0
#define DATA_ROLE_HOST   1
#define DATA_ROLE_DEVICE 2
#define DATA_ROLE_MAX    3

#define PORT_MODE_NONE   0
#define PORT_MODE_DEVICE 1
#define PORT_MODE_HOST   2

using OHOS::HDI::Usb::V1_2::PortInfo;

using OHOS::HDI::Usb::V1_2::IUsbdSubscriber;

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
class UsbdPort {
public:
    static UsbdPort &GetInstance();
    int32_t SetPort(int32_t portId, int32_t powerRole, int32_t dataRole,
        UsbdSubscriber *usbdSubscribers, uint32_t len);
    int32_t SetUsbPort(int32_t portId, int32_t powerRole, int32_t dataRole,
        HDI::Usb::V2_0::UsbdSubscriber *usbdSubscribers, uint32_t len);
    int32_t QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode);
    int32_t UpdatePort(int32_t mode, const sptr<HDI::Usb::V1_2::IUsbdSubscriber> &subscriber);
    int32_t UpdateUsbPort(int32_t mode, const sptr<HDI::Usb::V2_0::IUsbdSubscriber> &subscriber);
    void setPortPath(const std::string &path);

private:
    UsbdPort() = default;
    ~UsbdPort() = default;
    UsbdPort(const UsbdPort &) = delete;
    UsbdPort(UsbdPort &&) = delete;
    UsbdPort &operator=(const UsbdPort &) = delete;
    UsbdPort &operator=(UsbdPort &&) = delete;

    int32_t IfCanSwitch(int32_t portId, int32_t powerRole, int32_t dataRole);
    int32_t OpenPortFile(int32_t flags);
    int32_t WritePortFile(int32_t powerRole, int32_t dataRole, int32_t mode);
    int32_t ReadPortFile(int32_t &powerRole, int32_t &dataRole, int32_t &mode);
    int32_t SetPortInit(int32_t portId, int32_t powerRole, int32_t dataRole);
    HDI::Usb::V1_2::PortInfo currentPortInfo_ = {DEFAULT_PORT_ID, POWER_ROLE_SINK, DATA_ROLE_DEVICE, PORT_MODE_DEVICE};
    HDI::Usb::V2_0::PortInfo currentPortInfos_ = {DEFAULT_PORT_ID, POWER_ROLE_SINK, DATA_ROLE_DEVICE, PORT_MODE_DEVICE};
    std::string path_;
};
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_USB_V1_2_USBD_PORT_H
