/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef USB_DDK_SERVICE_H
#define USB_DDK_SERVICE_H

#include "v1_1/iusb_ddk.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_1 {
class UsbDdkService : public IUsbDdk {
public:
    UsbDdkService() = default;
    virtual ~UsbDdkService() = default;

    int32_t Init() override;

    int32_t Release() override;

    int32_t GetDeviceDescriptor(uint64_t deviceId, UsbDeviceDescriptor &desc) override;

    int32_t GetConfigDescriptor(uint64_t deviceId, uint8_t configIndex, std::vector<uint8_t> &configDesc) override;

    int32_t ClaimInterface(uint64_t deviceId, uint8_t interfaceIndex, uint64_t &interfaceHandle) override;

    int32_t ReleaseInterface(uint64_t interfaceHandle) override;

    int32_t SelectInterfaceSetting(uint64_t interfaceHandle, uint8_t settingIndex) override;

    int32_t GetCurrentInterfaceSetting(uint64_t interfaceHandle, uint8_t &settingIndex) override;

    int32_t SendControlReadRequest(uint64_t interfaceHandle, const UsbControlRequestSetup &setup, uint32_t timeout,
        std::vector<uint8_t> &data) override;

    int32_t SendControlWriteRequest(uint64_t interfaceHandle, const UsbControlRequestSetup &setup, uint32_t timeout,
        const std::vector<uint8_t> &data) override;

    int32_t SendPipeRequest(const UsbRequestPipe &pipe, uint32_t size, uint32_t offset, uint32_t length,
        uint32_t &transferedLength) override;

    int32_t SendPipeRequestWithAshmem(const UsbRequestPipe &pipe, const UsbAshmem &ashmem,
        uint32_t &transferredLength) override;

    int32_t GetDeviceMemMapFd(uint64_t deviceId, int &fd) override;

    int32_t GetDevices(std::vector<uint64_t> &deviceIds) override;

    int32_t UpdateDriverInfo(const DriverAbilityInfo &driverInfo) override;

    int32_t RemoveDriverInfo(const std::string &driverUid) override;
};
} // namespace V1_1
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // USB_DDK_SERVICE_H