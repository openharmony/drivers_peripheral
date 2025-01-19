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

#include "usb_host_impl.h"

#include <cerrno>
#include <climits>
#include <hdf_base.h>
#include <hdf_log.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "hitrace_meter.h"
#include "libusb_adapter.h"
#include "parameter.h"
#include "parameters.h"
#include "usb_transfer_callback.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG UsbHostImpl
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {
constexpr uint8_t MAX_DEVICE_ADDRESS = 255;
constexpr uint8_t MAX_DEVICE_BUSNUM = 255;
constexpr uint8_t MAX_ENDPOINT_ID = 158;
constexpr uint8_t MAX_INTERFACE_ID = 255;
constexpr uint8_t LIBUSB_INTERFACE_ID = 0x80;
bool UsbHostImpl::isGadgetConnected_ = false;
extern "C" IUsbHostInterface *UsbHostInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Usb::V2_0::UsbHostImpl;
    UsbHostImpl *service = new (std::nothrow) UsbHostImpl();
    if (service == nullptr) {
        return nullptr;
    }
    return service;
}

UsbHostImpl::UsbHostImpl() {}

UsbHostImpl::~UsbHostImpl() {}

int32_t UsbHostImpl::OpenDevice(const UsbDev &dev)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->OpenDevice(usbDev_);
}

int32_t UsbHostImpl::CloseDevice(const UsbDev &dev)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->CloseDevice(usbDev_);
}

int32_t UsbHostImpl::GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetStringDescriptor(usbDev_, descId, descriptor);
}

int32_t UsbHostImpl::GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetRawDescriptor(usbDev_, descriptor);
}

int32_t UsbHostImpl::SetConfig(const UsbDev &dev, uint8_t configIndex)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->SetConfig(usbDev_, configIndex);
}

int32_t UsbHostImpl::GetConfig(const UsbDev &dev, uint8_t &configIndex)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetConfig(usbDev_, configIndex);
}

int32_t UsbHostImpl::ClaimInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t force)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->ClaimInterface(usbDev_, interfaceId, force);
}

int32_t UsbHostImpl::ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->ManageInterface(usbDev_, interfaceId, disable);
}

int32_t UsbHostImpl::ReleaseInterface(const UsbDev &dev, uint8_t interfaceId)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->ReleaseInterface(usbDev_, interfaceId);
}

int32_t UsbHostImpl::SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->SetInterface(usbDev_, interfaceId, altIndex);
}

int32_t UsbHostImpl::BulkTransferRead(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->BulkTransferRead(usbDev_, usbPipe_, timeout, data);
}

int32_t UsbHostImpl::BulkTransferWrite(const UsbDev &dev,
    const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->BulkTransferWrite(usbDev_, usbPipe_, timeout, data);
}

int32_t UsbHostImpl::ControlTransferRead(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbCtrlTransfer &usbCtrl_ = reinterpret_cast<const V1_2::UsbCtrlTransfer &>(ctrl);
    return V1_2::LibusbAdapter::GetInstance()->ControlTransferRead(usbDev_, usbCtrl_, data);
}

int32_t UsbHostImpl::ControlTransferWrite(
    const UsbDev &dev, const UsbCtrlTransfer &ctrl, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbCtrlTransfer &usbCtrl_ = reinterpret_cast<const V1_2::UsbCtrlTransfer &>(ctrl);
    return V1_2::LibusbAdapter::GetInstance()->ControlTransferWrite(usbDev_, usbCtrl_, data);
}

int32_t UsbHostImpl::GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool &unactivated)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetInterfaceActiveStatus(usbDev_, interfaceId, unactivated);
}

int32_t UsbHostImpl::GetDeviceSpeed(const UsbDev &dev, uint8_t &speed)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetDeviceSpeed(usbDev_, speed);
}

int32_t UsbHostImpl::BulkTransferReadwithLength(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, int32_t length, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->BulkTransferReadwithLength(usbDev_, usbPipe_, timeout, length, data);
}

int32_t UsbHostImpl::GetDeviceFileDescriptor(const UsbDev &dev, int32_t &fd)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetDeviceFileDescriptor(usbDev_, fd);
}

int32_t UsbHostImpl::ClearHalt(const UsbDev &dev, const UsbPipe &pipe)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->ClearHalt(usbDev_, usbPipe_);
}

int32_t UsbHostImpl::ControlTransferReadwithLength(
    const UsbDev &dev, const UsbCtrlTransferParams &ctrlParams, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbCtrlTransferParams &usbCtrlParams_ =
        reinterpret_cast<const V1_2::UsbCtrlTransferParams &>(ctrlParams);
    return V1_2::LibusbAdapter::GetInstance()->ControlTransferReadwithLength(usbDev_, usbCtrlParams_, data);
}

int32_t UsbHostImpl::ResetDevice(const UsbDev &dev)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->ResetDevice(usbDev_);
}

int32_t UsbHostImpl::GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetDeviceDescriptor(usbDev_, descriptor);
}

int32_t UsbHostImpl::GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetConfigDescriptor(usbDev_, descId, descriptor);
}

int32_t UsbHostImpl::GetFileDescriptor(const UsbDev &dev, int32_t &fd)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->GetFileDescriptor(usbDev_, fd);
}

int32_t UsbHostImpl::InterruptTransferRead(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->InterruptTransferRead(usbDev_, usbPipe_, timeout, data);
}

int32_t UsbHostImpl::InterruptTransferWrite(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->InterruptTransferWrite(usbDev_, usbPipe_, timeout, data);
}

int32_t UsbHostImpl::IsoTransferRead(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->IsoTransferRead(usbDev_, usbPipe_, timeout, data);
}

int32_t UsbHostImpl::IsoTransferWrite(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->IsoTransferWrite(usbDev_, usbPipe_, timeout, data);
}

int32_t UsbHostImpl::RegBulkCallback(
    const UsbDev &dev, const UsbPipe &pipe, const sptr<IUsbdBulkCallback> &cb)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->RegBulkCallback(usbDev_, usbPipe_, cb);
}

int32_t UsbHostImpl::UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->UnRegBulkCallback(usbDev_, usbPipe_);
}

int32_t UsbHostImpl::BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->BulkRead(usbDev_, usbPipe_, ashmem);
}

int32_t UsbHostImpl::BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->BulkWrite(usbDev_, usbPipe_, ashmem);
}

int32_t UsbHostImpl::BulkCancel(const UsbDev &dev, const UsbPipe &pipe)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::UsbPipe &usbPipe_ = reinterpret_cast<const V1_2::UsbPipe &>(pipe);
    return V1_2::LibusbAdapter::GetInstance()->BulkCancel(usbDev_, usbPipe_);
}

int32_t UsbHostImpl::UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
    const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (cb == nullptr) {
        HDF_LOGE("%{public}s: cb is nullptr", __func__);
        return HDF_FAILURE;
    }
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    const V1_2::USBTransferInfo &usbTransferInfo_ = reinterpret_cast<const V1_2::USBTransferInfo &>(info);
    sptr<UsbTransferCb> usbTransferCb_ = new UsbTransferCb(cb);
    if (usbTransferCb_ == nullptr) {
        HDF_LOGE("%{public}s: usbTransferCb_ is nullptr", __func__);
        return HDF_FAILURE;
    }
    return V1_2::LibusbAdapter::GetInstance()->AsyncSubmitTransfer(usbDev_, usbTransferInfo_, usbTransferCb_, ashmem);
}

int32_t UsbHostImpl::UsbCancelTransfer(const UsbDev &dev, const int32_t endpoint)
{
    HDF_LOGI("%{public}s: enter", __func__);
    const V1_2::UsbDev &usbDev_ = reinterpret_cast<const V1_2::UsbDev &>(dev);
    return V1_2::LibusbAdapter::GetInstance()->AsyncCancelTransfer(usbDev_, endpoint);
}

int32_t UsbHostImpl::RequestQueue(const UsbDev &dev, const UsbPipe &pipe,
    const std::vector<uint8_t> &clientData, const std::vector<uint8_t> &buffer)
{
    if ((dev.devAddr >= MAX_DEVICE_ADDRESS) || (dev.busNum >= MAX_DEVICE_BUSNUM) ||
        (pipe.endpointId >= MAX_ENDPOINT_ID) || (pipe.intfId >= LIBUSB_INTERFACE_ID)) {
        HDF_LOGE("%{public}s:Invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

int32_t UsbHostImpl::RequestWait(
    const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer, int32_t timeout)
{
    if ((dev.devAddr >= MAX_DEVICE_ADDRESS) || (dev.busNum >= MAX_DEVICE_BUSNUM)) {
        HDF_LOGE("%{public}s:Invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

int32_t UsbHostImpl::RequestCancel(const UsbDev &dev, const UsbPipe &pipe)
{
    if (pipe.intfId == MAX_INTERFACE_ID && pipe.endpointId == MAX_ENDPOINT_ID) {
        HDF_LOGW("%{public}s: intfId = %{public}d, endpointId = %{public}d", __func__,
            pipe.intfId, pipe.endpointId);
        return HDF_SUCCESS;
    }
    if ((dev.devAddr >= MAX_DEVICE_ADDRESS) || (dev.busNum >= MAX_DEVICE_BUSNUM) ||
        (pipe.endpointId >= MAX_ENDPOINT_ID) || (pipe.intfId >= LIBUSB_INTERFACE_ID)) {
        HDF_LOGE("%{public}s:Invalid parameter", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

int32_t UsbHostImpl::BindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber)
{
    HDF_LOGI("%{public}s: enter", __func__);
    return V1_2::LibusbAdapter::GetInstance()->SetSubscriber(subscriber);
}

int32_t UsbHostImpl::UnbindUsbdHostSubscriber(const sptr<IUsbdSubscriber> &subscriber)
{
    HDF_LOGI("%{public}s: enter", __func__);
    return V1_2::LibusbAdapter::GetInstance()->RemoveSubscriber(subscriber);
}
} // namespace V2_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS