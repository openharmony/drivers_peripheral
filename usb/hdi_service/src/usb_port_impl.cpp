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

#include "usb_port_impl.h"

#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ddk_device_manager.h"
#include "ddk_pnp_listener_mgr.h"
#include "ddk_uevent_handle.h"
#include "device_resource_if.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "parameter.h"
#include "parameters.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG UsbPortImpl
using namespace OHOS::HiviewDFX;
bool g_productFlag = false;
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {
UsbdSubscriber UsbPortImpl::subscribers_[MAX_SUBSCRIBER] = {{0}};
bool UsbPortImpl::isGadgetConnected_ = false;
std::vector<int32_t> usbPid_;
extern "C" IUsbPortInterface *UsbPortInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Usb::V2_0::UsbPortImpl;
    UsbPortImpl *service = new (std::nothrow) UsbPortImpl();
    if (service == nullptr) {
        return nullptr;
    }
    return service;
}

UsbPortImpl::UsbPortImpl() : device_(nullptr) {}

UsbPortImpl::~UsbPortImpl() {}

int32_t UsbPortImpl::SetPortRole(int32_t portId, int32_t powerRole, int32_t dataRole)
{
    HDF_LOGI("%{public}s: enter", __func__);
    int32_t ret = 0;
    if (g_productFlag) {
        ret = V1_2::UsbdPorts::GetInstance().SetPort(portId, powerRole, dataRole, subscribers_, MAX_SUBSCRIBER);
    } else {
        ret = V1_2::UsbdPort::GetInstance().SetUsbPort(portId, powerRole, dataRole, subscribers_, MAX_SUBSCRIBER);
    }

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SetUsbPort failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t UsbPortImpl::QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode)
{
    HDF_LOGI("%{public}s: enter", __func__);
    int32_t ret = 0;
    if (g_productFlag) {
        ret = V1_2::UsbdPorts::GetInstance().QueryPort(portId, powerRole, dataRole, mode);
    } else {
        ret = V1_2::UsbdPort::GetInstance().QueryPort(portId, powerRole, dataRole, mode);
    }
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:QueryPort failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t UsbPortImpl::QueryPorts(std::vector<UsbPort>& portList)
{
    HDF_LOGI("%{public}s: enter", __func__);
    int32_t ret = 0;
    if (g_productFlag) {
        ret = V1_2::UsbdPorts::GetInstance().QueryPorts(portList);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:QueryPorts failed, ret:%{public}d", __func__, ret);
            return ret;
        }
        return HDF_SUCCESS;
    }
    int32_t portId = 0;
    int32_t powerRole = 0;
    int32_t dataRole = 0;
    int32_t mode = 0;
    ret = V1_2::UsbdPort::GetInstance().QueryPort(portId, powerRole, dataRole, mode);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:QueryPorts failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    UsbPort port;
    port.id = portId;
    int32_t supportedModes = 0;
    ret = V1_2::UsbdPort::GetInstance().GetSupportedModes(supportedModes);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:GetSupportedModes, ret:%{public}d", __func__, ret);
        return ret;
    }
    port.supportedModes = supportedModes;
    port.usbPortStatus.currentMode = mode;
    port.usbPortStatus.currentPowerRole = powerRole;
    port.usbPortStatus.currentDataRole = dataRole;
    portList.push_back(port);
    return HDF_SUCCESS;
}

void UsbPortImpl::UsbDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    int32_t i;
    for (i = 0; i < MAX_SUBSCRIBER; i++) {
        if (UsbPortImpl::subscribers_[i].subscriber == deathSubscriber_) {
            break;
        }
    }
    if (i == MAX_SUBSCRIBER) {
        HDF_LOGE("%{public}s: current subscriber not bind", __func__);
        return;
    }
    UsbPortImpl::subscribers_[i].subscriber = nullptr;
    subscribers_[i].remote = nullptr;
    subscribers_[i].deathRecipient = nullptr;
    if (DdkListenerMgrRemove(&UsbPortImpl::subscribers_[i].usbPnpListener) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: remove listener failed", __func__);
    }
}

int32_t UsbPortImpl::UsbdPnpLoaderEventReceived(void *priv, uint32_t id, HdfSBuf *data)
{
    HDF_LOGI("%{public}s: enter %{public}u", __func__, id);
    UsbdSubscriber *usbdSubscriber = static_cast<UsbdSubscriber *>(priv);
    const sptr<IUsbdSubscriber> subscriber = usbdSubscriber->subscriber;

    int32_t ret = HDF_SUCCESS;
    if (id == USB_PNP_DRIVER_PORT_HOST) {
        HITRACE_METER_NAME(HITRACE_TAG_HDF, "USB_PNP_DRIVER_PORT_HOST");
        if (g_productFlag) {
            return V1_2::UsbdPorts::GetInstance().UpdatePort(PORT_MODE_HOST, subscriber);
        } else {
            return V1_2::UsbdPort::GetInstance().UpdateUsbPort(PORT_MODE_HOST, subscriber);
        }
    } else if (id == USB_PNP_DRIVER_PORT_DEVICE) {
        HITRACE_METER_NAME(HITRACE_TAG_HDF, "USB_PNP_DRIVER_PORT_DEVICE");
        if (g_productFlag) {
            return V1_2::UsbdPorts::GetInstance().UpdatePort(PORT_MODE_DEVICE, subscriber);
        } else {
            return V1_2::UsbdPort::GetInstance().UpdateUsbPort(PORT_MODE_DEVICE, subscriber);
        }
    } else {
        HDF_LOGW("%{public}s: port not support this id %{public}u", __func__, id);
        return HDF_ERR_NOT_SUPPORT;
    }
    return ret;
}

int32_t UsbPortImpl::BindUsbdPortSubscriber(const sptr<IUsbdSubscriber> &subscriber)
{
    HDF_LOGI("%{public}s: enter", __func__);
    int32_t i;
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:subscriber is  null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IUsbdSubscriber>(subscriber);
    for (i = 0; i < MAX_SUBSCRIBER; i++) {
        if (subscribers_[i].remote == remote) {
            break;
        }
    }
    if (i < MAX_SUBSCRIBER) {
        HDF_LOGI("%{public}s: current subscriber was bind", __func__);
        return HDF_SUCCESS;
    }
    for (i = 0; i < MAX_SUBSCRIBER; i++) {
        if (subscribers_[i].subscriber == nullptr) {
            subscribers_[i].subscriber = subscriber;
            subscribers_[i].impl = this;
            subscribers_[i].usbPnpListener.callBack = UsbdPnpLoaderEventReceived;
            subscribers_[i].usbPnpListener.priv = &subscribers_[i];
            subscribers_[i].remote = remote;
            subscribers_[i].deathRecipient = new UsbPortImpl::UsbDeathRecipient(subscriber);
            if (subscribers_[i].deathRecipient == nullptr) {
                HDF_LOGE("%{public}s: new deathRecipient failed", __func__);
                return HDF_FAILURE;
            }
            bool result = subscribers_[i].remote->AddDeathRecipient(
                static_cast<UsbDeathRecipient *>(subscribers_[i].deathRecipient));
            if (!result) {
                HDF_LOGE("%{public}s:AddUsbDeathRecipient failed", __func__);
                return HDF_FAILURE;
            }

            HDF_LOGI("%{public}s: index = %{public}d", __func__, i);
            break;
        }
    }
    if (i == MAX_SUBSCRIBER) {
        HDF_LOGE("%{public}s: too many listeners", __func__);
        return HDF_ERR_OUT_OF_RANGE;
    }
    if (DdkListenerMgrAdd(&subscribers_[i].usbPnpListener) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: register listerer failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbPortImpl::UnbindUsbdPortSubscriber(const sptr<IUsbdSubscriber> &subscriber)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s:subscriber is  null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t i;
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IUsbdSubscriber>(subscriber);
    for (i = 0; i < MAX_SUBSCRIBER; i++) {
        if (subscribers_[i].remote == remote) {
            break;
        }
    }
    if (i == MAX_SUBSCRIBER) {
        HDF_LOGE("%{public}s: current subscriber not bind", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    bool result = remote->RemoveDeathRecipient(static_cast<UsbDeathRecipient *>(subscribers_[i].deathRecipient));
    if (!result) {
        HDF_LOGE("%{public}s:RemoveUsbDeathRecipient failed", __func__);
        return HDF_FAILURE;
    }

    subscribers_[i].subscriber = nullptr;
    subscribers_[i].remote = nullptr;
    subscribers_[i].deathRecipient = nullptr;
    if (DdkListenerMgrRemove(&subscribers_[i].usbPnpListener) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: remove listener failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void UsbPortImpl::ParsePortPath()
{
    HDF_LOGI("%{public}s: enter", __func__);
    const char *path_ = nullptr;
    const char *pathDef_ = nullptr;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (iface == nullptr) {
        HDF_LOGE("%{public}s: iface is nullptr", __func__);
        return;
    }

    if (device_ == nullptr) {
        HDF_LOGE("%{public}s: device_ is nullptr", __func__);
        return;
    }
    if (iface->GetString(device_->property, "port_file_path", &path_, pathDef_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read port_file_path failed", __func__);
        return;
    }
    HDF_LOGI("%{public}s: parsePortPath path_=%{public}s", __func__, path_);

    if (strcmp(path_, "/sys/class/dual_role_pd/") == 0) {
        g_productFlag = true;
        V1_2::UsbdPorts::GetInstance().setPortPath(path_);
        return;
    }

    g_productFlag = false;
    V1_2::UsbdPort::GetInstance().setPortPath(path_);
    return;
}

int32_t UsbPortImpl::UsbdEventHandle(const sptr<UsbPortImpl> &inst)
{
    HDF_LOGI("%{public}s: enter", __func__);
    inst->ParsePortPath();
    return HDF_SUCCESS;
}
} // namespace V2_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS