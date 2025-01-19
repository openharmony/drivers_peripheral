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
constexpr uint32_t FUNCTION_VALUE_MAX_LEN = 32;
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {
UsbdSubscriber UsbPortImpl::subscribers_[MAX_SUBSCRIBER] = {{0}};
bool UsbPortImpl::isGadgetConnected_ = false;
std::vector<int32_t> usbPid_;
static const std::map<std::string, uint32_t> configMap = {
    {HDC_CONFIG_OFF, USB_FUNCTION_NONE},
    {HDC_CONFIG_HDC, USB_FUNCTION_HDC},
    {HDC_CONFIG_ON, USB_FUNCTION_HDC},
    {HDC_CONFIG_RNDIS, USB_FUNCTION_RNDIS},
    {HDC_CONFIG_STORAGE, USB_FUNCTION_STORAGE},
    {HDC_CONFIG_RNDIS_HDC, USB_FUNCTION_HDC + USB_FUNCTION_RNDIS},
    {HDC_CONFIG_STORAGE_HDC, USB_FUNCTION_HDC + USB_FUNCTION_STORAGE},
    {HDC_CONFIG_MANUFACTURE_HDC, USB_FUNCTION_MANUFACTURE}
};
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
    int32_t ret = V1_2::UsbdPort::GetInstance().SetUsbPort(portId, powerRole, dataRole, subscribers_, MAX_SUBSCRIBER);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:SetUsbPort failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t UsbPortImpl::QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode)
{
    HDF_LOGI("%{public}s: enter", __func__);
    int32_t ret = V1_2::UsbdPort::GetInstance().QueryPort(portId, powerRole, dataRole, mode);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:QueryPort failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t UsbPortImpl::QueryPorts(std::vector<UsbPort>& portList)
{
    HDF_LOGE("UsbPortImpl::QueryPorts Function not supported ");
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
        ret = V1_2::UsbdPort::GetInstance().UpdateUsbPort(PORT_MODE_HOST, subscriber);
    } else if (id == USB_PNP_DRIVER_PORT_DEVICE) {
        HITRACE_METER_NAME(HITRACE_TAG_HDF, "USB_PNP_DRIVER_PORT_DEVICE");
        ret = V1_2::UsbdPort::GetInstance().UpdateUsbPort(PORT_MODE_DEVICE, subscriber);
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
            subscribers_[i].impl = std::make_shared<UsbPortImpl>(*this);
            subscribers_[i].usbPnpListener.callBack = UsbdPnpLoaderEventReceived;
            subscribers_[i].usbPnpListener.priv = &subscribers_[i];
            subscribers_[i].remote = remote;
            subscribers_[i].deathRecipient = std::make_shared<UsbDeathRecipient>(subscriber);
            if (subscribers_[i].deathRecipient == nullptr) {
                HDF_LOGE("%{public}s: new deathRecipient failed", __func__);
                return HDF_FAILURE;
            }
            const sptr<UsbDeathRecipient>& recipient =
                static_cast<UsbDeathRecipient *>(subscribers_[i].deathRecipient.get());
            bool result = subscribers_[i].remote->AddDeathRecipient(recipient);
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
    const sptr<UsbDeathRecipient>& recipient = static_cast<UsbDeathRecipient *>(subscribers_[i].deathRecipient.get());
    bool result = remote->RemoveDeathRecipient(recipient);
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
    V1_2::UsbdPort::GetInstance().setPortPath(path_);
    return;
}

void UsbPortImpl::UpdateFunctionStatus()
{
    HDF_LOGI("%{public}s: enter", __func__);
    char cFunctionValue[FUNCTION_VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(PERSIST_SYS_USB_CONFIG, "invalid", cFunctionValue, FUNCTION_VALUE_MAX_LEN);
    if (ret <= 0) {
        HDF_LOGE("%{public}s: GetParameter failed", __func__);
    }

    std::string functionValue(cFunctionValue);
    auto it = configMap.find(functionValue);
    if (it != configMap.end()) {
        HDF_LOGI("Function is %{public}s", functionValue.c_str());
        ret = V1_2::UsbdFunction::UsbdUpdateFunction(it->second);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: UsbdUpdateFunction failed", __func__);
        }
    }
}

int32_t UsbPortImpl::UsbdEventHandle(const sptr<UsbPortImpl> &inst)
{
    HDF_LOGI("%{public}s: enter", __func__);
    UpdateFunctionStatus();
    inst->ParsePortPath();
    return HDF_SUCCESS;
}
} // namespace V2_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS