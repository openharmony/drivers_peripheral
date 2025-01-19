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

#ifndef OHOS_HDI_USB_V2_0_USB_HOST_IMPL_H
#define OHOS_HDI_USB_V2_0_USB_HOST_IMPL_H

#include <iostream>

#include "hdf_slist.h"
#include "usb_host_data.h"
#include "usbd_function.h"
#include "usbd_port.h"
#include "v2_0/iusb_host_interface.h"

#define BASE_CLASS_HUB 0x09
constexpr uint8_t MAX_INTERFACEID = 0xFF;
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {
class UsbHostImpl : public IUsbHostInterface {
public:

    UsbHostImpl();
    ~UsbHostImpl() override;
    int32_t OpenDevice(const UsbDev &dev) override;
    int32_t CloseDevice(const UsbDev &dev) override;
    int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor) override;
    int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor) override;
    int32_t SetConfig(const UsbDev &dev, uint8_t configIndex) override;
    int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex) override;
    int32_t ClaimInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t force) override;
    int32_t ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable) override;
    int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId) override;
    int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex) override;
    int32_t BulkTransferRead(
        const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data) override;
    int32_t BulkTransferWrite(
        const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data) override;
    int32_t ControlTransferRead(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data) override;
    int32_t ControlTransferWrite(
        const UsbDev &dev, const UsbCtrlTransfer &ctrl, const std::vector<uint8_t> &data) override;
    int32_t BindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber) override;
    int32_t UnbindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber) override;
    int32_t GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool &unactivated) override;
    int32_t GetDeviceSpeed(const UsbDev &dev, uint8_t &speed) override;
    int32_t BulkTransferReadwithLength(const UsbDev &dev,
        const UsbPipe &pipe, int32_t timeout, int32_t length, std::vector<uint8_t> &data) override;
    int32_t GetDeviceFileDescriptor(const UsbDev &dev, int32_t &fd) override;
    int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe) override;
    int32_t ControlTransferReadwithLength(
        const UsbDev &dev, const UsbCtrlTransferParams &ctrlParams, std::vector<uint8_t> &data) override;
    int32_t ResetDevice(const UsbDev &dev) override;
    int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, const std::vector<uint8_t> &clientData,
        const std::vector<uint8_t> &buffer) override;
    int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor) override;
    int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor) override;
    int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd) override;
    int32_t InterruptTransferRead(
        const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data) override;
    int32_t InterruptTransferWrite(
        const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data) override;
    int32_t IsoTransferRead(
        const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data) override;
    int32_t IsoTransferWrite(
        const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data) override;
    int32_t RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe, const sptr<IUsbdBulkCallback> &cb) override;
    int32_t UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe) override;
    int32_t BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem) override;
    int32_t BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem) override;
    int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe) override;
    int32_t RequestWait(
        const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer, int32_t timeout) override;
    int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe) override;
    int32_t UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info, const sptr<IUsbdTransferCallback> &cb,
        const sptr<Ashmem> &ashmem) override;
    int32_t UsbCancelTransfer(const UsbDev &dev, const int32_t endpoint) override;
private:
    static bool isGadgetConnected_;
};
} // namespace V2_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_USB_V2_0_USB_HOST_IMPL_H