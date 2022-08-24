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

#ifndef USB_INFO_H
#define USB_INFO_H

#include <cstdint>

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_0 {
class UsbInfo {
public:
    UsbInfo() {}

    explicit UsbInfo(const USBDeviceInfo &info) : devInfo_(info) {}

    void SetDevInfoStatus(const int32_t status)
    {
        devInfo_.status = status;
    }

    void SetDevInfoBusNum(const int32_t busNum)
    {
        devInfo_.busNum = busNum;
    }

    void SetDevInfoDevNum(const int32_t devNum)
    {
        devInfo_.devNum = devNum;
    }

    int32_t GetDevInfoStatus() const
    {
        return devInfo_.status;
    }

    int32_t GetDevInfoBusNum() const
    {
        return devInfo_.busNum;
    }

    int32_t GetDevInfoDevNum() const
    {
        return devInfo_.devNum;
    }

private:
    USBDeviceInfo devInfo_;
};
} // namespace V1_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // USBMGR_USB_INFO_H
