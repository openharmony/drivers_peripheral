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

#include "usb_device_impl.h"

#include <cerrno>
#include <climits>
#include <hdf_base.h>
#include <hdf_log.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "ddk_device_manager.h"
#include "ddk_pnp_listener_mgr.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "libusb_adapter.h"
#include "parameter.h"
#include "parameters.h"
#include "usb_sa_subscriber.h"
#include "usbd_accessory.h"
#include "usbd_function.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG UsbDeviceImpl
namespace {
constexpr const char* EDM_SYSTEM_CAPABILITY = "const.SystemCapability.Driver.ExternalDevice";  
}
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace HDI {
namespace Usb {
namespace V2_0 {
HdfDevEventlistener UsbDeviceImpl::listenerForLoadService_ = {nullptr};
V1_2::UsbdLoadService UsbDeviceImpl::loadUsbService_ = {USB_SYSTEM_ABILITY_ID};
V1_2::UsbdLoadService UsbDeviceImpl::loadHdfEdm_ = {HDF_EXTERNAL_DEVICE_MANAGER_SA_ID};
UsbdSubscriber UsbDeviceImpl::subscribers_[MAX_SUBSCRIBER] = {{0}};
bool UsbDeviceImpl::isGadgetConnected_ = false;
bool UsbDeviceImpl::isEdmExist_ = false;
constexpr uint32_t FUNCTION_VALUE_MAX_LEN = 32;
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
extern "C" IUsbDeviceInterface *UsbDeviceInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Usb::V2_0::UsbDeviceImpl;
    UsbDeviceImpl *service = new (std::nothrow) UsbDeviceImpl();
    if (service == nullptr) {
        return nullptr;
    }
    return service;
}

UsbDeviceImpl::UsbDeviceImpl()
{
    V1_2::UsbdFunction::UsbdInitLock();
    if (OHOS::system::GetBoolParameter("const.security.developermode.state", true)) {
        loadUsbService_.LoadService();
    }
}

UsbDeviceImpl::~UsbDeviceImpl()
{
    V1_2::UsbdFunction::UsbdDestroyLock();
}

int32_t UsbDeviceImpl::GetCurrentFunctions(int32_t &funcs)
{
    HDF_LOGI("%{public}s: enter", __func__);
    funcs = V1_2::UsbdFunction::UsbdGetFunction();
    return HDF_SUCCESS;
}

int32_t UsbDeviceImpl::SetCurrentFunctions(int32_t funcs)
{
    HDF_LOGI("%{public}s: enter", __func__);
    int32_t ret = V1_2::UsbdFunction::UsbdSetFunction(funcs);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:UsbdSetFunction failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t UsbDeviceImpl::GetAccessoryInfo(std::vector<std::string> &accessoryInfo)
{
    HDF_LOGI("%{public}s: enter", __func__);
    return V1_2::UsbdAccessory::GetInstance().GetAccessoryInfo(accessoryInfo);
}

int32_t UsbDeviceImpl::OpenAccessory(int32_t &fd)
{
    HDF_LOGI("%{public}s: enter", __func__);
    return V1_2::UsbdAccessory::GetInstance().OpenAccessory(fd);
}

int32_t UsbDeviceImpl::CloseAccessory(int32_t fd)
{
    HDF_LOGI("%{public}s: enter", __func__);
    return V1_2::UsbdAccessory::GetInstance().CloseAccessory(fd);
}

int32_t UsbDeviceImpl::UsbdPnpLoaderEventReceived(void *priv, uint32_t id, HdfSBuf *data)
{
    HDF_LOGI("%{public}s: enter %{public}u", __func__, id);
    UsbdSubscriber *usbdSubscriber = static_cast<UsbdSubscriber *>(priv);
    const sptr<IUsbdSubscriber> subscriber = usbdSubscriber->subscriber;

    int32_t ret = HDF_SUCCESS;
    if (id == USB_PNP_DRIVER_GADGET_ADD) {
        HITRACE_METER_NAME(HITRACE_TAG_HDF, "USB_PNP_DRIVER_GADGET_ADD");
        isGadgetConnected_ = true;
        USBDeviceInfo info = {ACT_UPDEVICE, 0, 0};
        if (subscriber == nullptr) {
            HDF_LOGE("%{public}s: subscriber is nullptr, %{public}d", __func__, __LINE__);
            return HDF_FAILURE;
        }
        ret = subscriber->DeviceEvent(info);
    } else if (id == USB_PNP_DRIVER_GADGET_REMOVE) {
        HITRACE_METER_NAME(HITRACE_TAG_HDF, "USB_PNP_DRIVER_GADGET_REMOVE");
        isGadgetConnected_ = false;
        USBDeviceInfo info = {ACT_DOWNDEVICE, 0, 0};
        if (subscriber == nullptr) {
            HDF_LOGE("%{public}s: subscriber is nullptr, %{public}d", __func__, __LINE__);
            return HDF_FAILURE;
        }
        V1_2::UsbdAccessory::GetInstance().HandleEvent(ACT_DOWNDEVICE);
        ret = subscriber->DeviceEvent(info);
    } else if (id == USB_ACCESSORY_START) {
        if (subscriber == nullptr) {
            HDF_LOGE("%{public}s: subscriber is nullptr, %{public}d", __func__, __LINE__);
            return HDF_FAILURE;
        }
        HITRACE_METER_NAME(HITRACE_TAG_HDF, "USB_ACCESSORY_START");
        USBDeviceInfo info = {ACT_ACCESSORYUP, 0, 0};
        ret = subscriber->DeviceEvent(info);
    } else if (id == USB_ACCESSORY_SEND) {
        if (subscriber == nullptr) {
            HDF_LOGE("%{public}s: subsciber is nullptr, %{public}d", __func__, __LINE__);
            return HDF_FAILURE;
        }
        HITRACE_METER_NAME(HITRACE_TAG_HDF, "USB_ACCESSORY_SEND");
        USBDeviceInfo info = {ACT_ACCESSORYSEND, 0, 0};
        ret = subscriber->DeviceEvent(info);
    } else {
        HDF_LOGW("%{public}s: device not support this id:%{public}u , %{public}d", __func__, id, __LINE__);
        return HDF_ERR_NOT_SUPPORT;
    }
    HDF_LOGI("%{public}s: out", __func__);
    return ret;
}

void UsbDeviceImpl::UsbDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    int32_t i;
    for (i = 0; i < MAX_SUBSCRIBER; i++) {
        if (UsbDeviceImpl::subscribers_[i].subscriber == deathSubscriber_) {
            break;
        }
    }
    if (i == MAX_SUBSCRIBER) {
        HDF_LOGE("%{public}s: current subscriber not bind", __func__);
        return;
    }
    UsbDeviceImpl::subscribers_[i].subscriber = nullptr;
    subscribers_[i].remote = nullptr;
    subscribers_[i].deathRecipient = nullptr;
    if (DdkListenerMgrRemove(&UsbDeviceImpl::subscribers_[i].usbPnpListener) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: remove listerer failed", __func__);
    }
}

int32_t UsbDeviceImpl::BindUsbdDeviceSubscriber(const sptr<IUsbdSubscriber> &subscriber)
{
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
            subscribers_[i].deathRecipient = new UsbDeviceImpl::UsbDeathRecipient(subscriber);
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

int32_t UsbDeviceImpl::UnbindUsbdDeviceSubscriber(const sptr<IUsbdSubscriber> &subscriber)
{
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
        HDF_LOGE("%{public}s: remove listerer failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbDeviceImpl::UsbdLoadServiceCallback(void *priv, uint32_t id, HdfSBuf *data)
{
    HDF_LOGI("%{public}s: enter", __func__);
    (void)priv;
    (void)data;
    if (id == USB_PNP_DRIVER_GADGET_ADD || id == USB_PNP_NOTIFY_ADD_DEVICE) {
        if (loadUsbService_.LoadService() != 0) {
            HDF_LOGE("loadUsbService_ LoadService error");
            return HDF_FAILURE;
        }
        if (isEdmExist_ && id == USB_PNP_NOTIFY_ADD_DEVICE) {
            if (loadHdfEdm_.LoadService() != 0) {
                HDF_LOGE("loadHdfEdm_ LoadService error");
                return HDF_FAILURE;
            }
        }
    }
    return HDF_SUCCESS;
}

void UsbDeviceImpl::UpdateFunctionStatus()
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

int32_t UsbDeviceImpl::UsbdEventHandle(void)
{
    HDF_LOGI("%{public}s: enter", __func__);
    UpdateFunctionStatus();
    isEdmExist_ = OHOS::system::GetBoolParameter(EDM_SYSTEM_CAPABILITY, false);
    HDF_LOGI("%{public}s: isEmdExit: %{public}d", __func__, isEdmExist_);
    listenerForLoadService_.callBack = UsbdLoadServiceCallback;
    int32_t ret = DdkListenerMgrAdd(&listenerForLoadService_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: register listerer failed", __func__);
        return HDF_FAILURE;
    }
    return ret;
}

int32_t UsbDeviceImpl::UsbdEventHandleRelease(void)
{
    HDF_LOGI("%{public}s: enter", __func__);
    int32_t ret = DdkListenerMgrRemove(&listenerForLoadService_);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DdkListenerMgrRemove failed", __func__);
    }
    listenerForLoadService_.callBack = nullptr;
    listenerForLoadService_.priv = nullptr;
    return ret;
}
} // namespace v2_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS