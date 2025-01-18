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

#ifndef OHOS_HDI_USB_V2_0_USB_DEVICE_IMPL_H
#define OHOS_HDI_USB_V2_0_USB_DEVICE_IMPL_H

#include <iostream>

#include "hdf_slist.h"
#include "hdf_usb_pnp_manage.h"
#include "iproxy_broker.h"
#include "iremote_object.h"
#include "osal_mutex.h"
#include "usb_host_data.h"
#include "usbd_function.h"
#include "usbd_load_usb_service.h"
#include "usbd_port.h"
#include "v2_0/iusb_device_interface.h"

#define BASE_CLASS_HUB 0x09
constexpr uint8_t MAX_INTERFACEID = 0xFF;
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {
using namespace OHOS;
class UsbDeviceImpl : public IUsbDeviceInterface {
public:

    UsbDeviceImpl();
    ~UsbDeviceImpl() override;
    int32_t GetCurrentFunctions(int32_t &funcs) override;
    int32_t SetCurrentFunctions(int32_t funcs) override;
    int32_t BindUsbdDeviceSubscriber(const sptr<IUsbdSubscriber> &subscriber) override;
    int32_t UnbindUsbdDeviceSubscriber(const sptr<IUsbdSubscriber> &subscriber) override;
    int32_t GetAccessoryInfo(std::vector<std::string> &accessoryInfo) override;
    int32_t OpenAccessory(int32_t &fd) override;
    int32_t CloseAccessory(int32_t fd) override;
    static int32_t UsbdEventHandle(void);
    static int32_t UsbdEventHandleRelease(void);
    class UsbDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit UsbDeathRecipient(const sptr<IUsbdSubscriber> &deathSubscriber) : deathSubscriber_(deathSubscriber) {};
        ~UsbDeathRecipient() override {};
        void OnRemoteDied(const wptr<IRemoteObject> &object) override;
    private:
        sptr<IUsbdSubscriber> deathSubscriber_;
    };
private:
    static int32_t UsbdLoadServiceCallback(void *priv, uint32_t id, HdfSBuf *data);
    static int32_t UsbdPnpLoaderEventReceived(void *priv, uint32_t id, HdfSBuf *data);
    static UsbdSubscriber subscribers_[MAX_SUBSCRIBER];
    static bool isGadgetConnected_;
    static HdfDevEventlistener listenerForLoadService_;
    static V1_2::UsbdLoadService loadUsbService_;
    static V1_2::UsbdLoadService loadHdfEdm_;
    OsalMutex lockSetFunc_;
};
} // namespace v2_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_USB_V2_0_USB_DEVICE_IMPL_H