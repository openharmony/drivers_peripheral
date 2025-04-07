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

#ifndef OHOS_HDI_USB_V2_0_USB_PORT_IMPL_H
#define OHOS_HDI_USB_V2_0_USB_PORT_IMPL_H

#include <iostream>

#include "hdf_slist.h"
#include "hdf_usb_pnp_manage.h"
#include "iproxy_broker.h"
#include "iremote_object.h"
#include "usb_host_data.h"
#include "usbd_function.h"
#include "usbd_load_usb_service.h"
#include "usbd_port.h"
#include "usbd_ports.h"
#include "v2_0/iusb_port_interface.h"

#define BASE_CLASS_HUB 0x09
constexpr uint8_t MAX_INTERFACEID = 0xFF;
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {
using namespace OHOS;
class UsbPortImpl : public IUsbPortInterface {
public:
    UsbPortImpl();
    ~UsbPortImpl() override;
    int32_t SetPortRole(int32_t portId, int32_t powerRole, int32_t dataRole) override;
    int32_t QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode) override;
    int32_t QueryPorts(std::vector<UsbPort>& portList) override;
    int32_t BindUsbdPortSubscriber(const sptr<IUsbdSubscriber> &subscriber) override;
    int32_t UnbindUsbdPortSubscriber(const sptr<IUsbdSubscriber> &subscriber) override;
    static int32_t UsbdEventHandle(const sptr<UsbPortImpl> &inst);
    class UsbDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit UsbDeathRecipient(const sptr<IUsbdSubscriber> &deathSubscriber) : deathSubscriber_(deathSubscriber) {};
        ~UsbDeathRecipient() override {};
        void OnRemoteDied(const wptr<IRemoteObject> &object) override;
    private:
        sptr<IUsbdSubscriber> deathSubscriber_;
    };
    HdfDeviceObject *device_;
private:
    static int32_t UsbdPnpLoaderEventReceived(void *priv, uint32_t id, HdfSBuf *data);
    static int32_t UsbdLoadServiceCallback(void *priv, uint32_t id, HdfSBuf *data);
    void ParsePortPath();
    bool UsbPortImplInit();
    static UsbdSubscriber subscribers_[MAX_SUBSCRIBER];
    static bool isGadgetConnected_;
};
} // namespace V2_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_USB_V2_0_USB_PORT_IMPL_H