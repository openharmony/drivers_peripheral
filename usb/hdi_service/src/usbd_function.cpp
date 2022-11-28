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

#include "usbd_function.h"

#include <unistd.h>

#include "devmgr_hdi.h"
#include "hdf_log.h"
#include "hdf_remote_service.h"
#include "hdf_sbuf.h"
#include "iservmgr_hdi.h"
#include "message_option.h"
#include "message_parcel.h"
#include "osal_time.h"
#include "parameter.h"
#include "securec.h"
#include "string_ex.h"
#include "usbd_type.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_0 {
uint32_t UsbdFunction::currentFuncs_ = USB_FUNCTION_HDC;

using OHOS::HDI::ServiceManager::V1_0::IServiceManager;
constexpr uint32_t UDC_NAME_MAX_LEN = 32;
constexpr int32_t WAIT_UDC_MAX_LOOP = 30;
constexpr uint32_t WAIT_UDC_TIME = 100000;
#define UDC_PATH "/config/usb_gadget/g1/UDC"

int32_t UsbdFunction::SendCmdToService(const char *name, int32_t cmd, unsigned char funcMask)
{
    auto servMgr = IServiceManager::Get();
    if (servMgr == nullptr) {
        HDF_LOGE("%{public}s: get IServiceManager failed", __func__);
        return HDF_FAILURE;
    }

    sptr<IRemoteObject> remote = servMgr->GetService(name);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s: get remote object failed: %{public}s", __func__, name);
        return HDF_FAILURE;
    }

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    if (!data.WriteInterfaceToken(Str8ToStr16(HDF_USB_USBFN_DESC))) {
        HDF_LOGE("%{public}s: WriteInterfaceToken failed", __func__);
        return HDF_FAILURE;
    }

    if (!data.WriteUint8(funcMask)) {
        HDF_LOGE("%{public}s: WriteInt8 failed: %{public}d", __func__, funcMask);
        return HDF_FAILURE;
    }

    int32_t ret = remote->SendRequest(cmd, data, reply, option);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: send request to %{public}s failed, ret=%{public}d", __func__, name, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::RemoveHdc()
{
    int32_t status = SetParameter(SYS_USB_CONFIG, HDC_CONFIG_OFF);
    if (status != 0) {
        HDF_LOGE("%{public}s:remove hdc config error = %{public}d", __func__, status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::AddHdc()
{
    int32_t status = SetParameter(SYS_USB_CONFIG, HDC_CONFIG_ON);
    if (status != 0) {
        HDF_LOGE("%{public}s:add hdc config error = %{public}d", __func__, status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToRndis()
{
    int32_t status = SetParameter(SYS_USB_CONFIG, HDC_CONFIG_RNDIS);
    if (status != 0) {
        HDF_LOGE("%{public}s:add rndis config error = %{public}d", __func__, status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToStorage()
{
    int32_t status = SetParameter(SYS_USB_CONFIG, HDC_CONFIG_STORAGE);
    if (status != 0) {
        HDF_LOGE("%{public}s:add storage config error = %{public}d", __func__, status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToRndisHdc()
{
    int32_t status = SetParameter(SYS_USB_CONFIG, HDC_CONFIG_RNDIS_HDC);
    if (status != 0) {
        HDF_LOGE("%{public}s:add rndis hdc config error = %{public}d", __func__, status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToStorageHdc()
{
    int32_t status = SetParameter(SYS_USB_CONFIG, HDC_CONFIG_STORAGE_HDC);
    if (status != 0) {
        HDF_LOGE("%{public}s:add storage hdc config error = %{public}d", __func__, status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToNone()
{
    UsbdFunction::SendCmdToService(ACM_SERVICE_NAME, ACM_RELEASE, USB_FUNCTION_ACM);
    UsbdFunction::SendCmdToService(ECM_SERVICE_NAME, ECM_RELEASE, USB_FUNCTION_ECM);
    UsbdFunction::SendCmdToService(DEV_SERVICE_NAME, FUNCTION_DEL, USB_DDK_FUNCTION_SUPPORT);
    int32_t ret = RemoveHdc();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: RemoveHdc error, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    currentFuncs_ = USB_FUNCTION_NONE;
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetDDKFunction(uint32_t funcs)
{
    uint32_t ddkFuns = static_cast<uint32_t>(funcs) & USB_DDK_FUNCTION_SUPPORT;
    if (ddkFuns == 0) {
        HDF_LOGE("%{public}s: not use ddkfunction", __func__);
        return HDF_SUCCESS;
    }
    if (UsbdFunction::SendCmdToService(DEV_SERVICE_NAME, FUNCTION_ADD, ddkFuns)) {
        HDF_LOGE("%{public}s: create dev error: %{public}d", __func__, ddkFuns);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::UsbdEnableDevice()
{
    FILE *fp = fopen(UDC_PATH, "w");
    if (fp == NULL) {
        HDF_LOGE("%{public}s: fopen failed", __func__);
        return HDF_ERR_BAD_FD;
    }

    // get udc name
    char udcName[UDC_NAME_MAX_LEN] = {0};
    int32_t ret = GetParameter("sys.usb.controller", "invalid", udcName, UDC_NAME_MAX_LEN);
    if (ret <= 0) {
        HDF_LOGE("%{public}s: GetParameter failed", __func__);
        (void)fclose(fp);
        return HDF_FAILURE;
    }

    size_t count = fwrite(udcName, strlen(udcName), 1, fp);
    (void)fclose(fp);
    if (count != 1) {
        HDF_LOGE("%{public}s: fwrite failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::UsbdWaitUdc()
{
    // get udc name
    char udcName[UDC_NAME_MAX_LEN] = {0};
    int32_t ret = GetParameter("sys.usb.controller", "invalid", udcName, UDC_NAME_MAX_LEN - 1);
    if (ret <= 0) {
        HDF_LOGE("%{public}s: GetParameter failed", __func__);
        return HDF_FAILURE;
    }

    char tmpName[UDC_NAME_MAX_LEN] = {0};
    for (int32_t i = 0; i < WAIT_UDC_MAX_LOOP; i++) {
        FILE *fp = fopen(UDC_PATH, "r");
        if (fp == NULL) {
            HDF_LOGE("%{public}s: fopen failed", __func__);
            return HDF_ERR_BAD_FD;
        }

        (void)memset_s(tmpName, UDC_NAME_MAX_LEN, 0, UDC_NAME_MAX_LEN);
        if (fread(tmpName, strlen(udcName), 1, fp) != 1) {
            HDF_LOGE("%{public}s: fread failed", __func__);
        }
        (void)fclose(fp);
        if (strcmp(udcName, tmpName) == 0) {
            return HDF_SUCCESS;
        }
        usleep(WAIT_UDC_TIME);
    }

    if (strcmp(udcName, tmpName) != 0) {
        HDF_LOGE("%{public}s: strcmp failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t UsbdFunction::UsbdInitDDKFunction(uint32_t funcs)
{
    if ((funcs & USB_FUNCTION_ACM) && UsbdFunction::SendCmdToService(ACM_SERVICE_NAME, ACM_INIT, USB_FUNCTION_ACM)) {
        HDF_LOGE("%{public}s: acm init error", __func__);
        return HDF_FAILURE;
    }
    if ((funcs & USB_FUNCTION_ECM) && UsbdFunction::SendCmdToService(ECM_SERVICE_NAME, ECM_INIT, USB_FUNCTION_ECM)) {
        HDF_LOGE("%{public}s: ecm init error", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::UsbdSetKernelFunction(int32_t kfuns)
{
    switch (kfuns) {
        case USB_FUNCTION_HDC:
            HDF_LOGI("%{public}s: set hdc", __func__);
            return UsbdFunction::AddHdc();
            break;
        case USB_FUNCTION_RNDIS:
            HDF_LOGI("%{public}s: set rndis", __func__);
            return UsbdFunction::SetFunctionToRndis();
            break;
        case USB_FUNCTION_STORAGE:
            HDF_LOGI("%{public}s: set mass_storage", __func__);
            return UsbdFunction::SetFunctionToStorage();
            break;
        case USB_FUNCTION_RNDIS | USB_FUNCTION_HDC:
            HDF_LOGI("%{public}s: set rndis hdc", __func__);
            return UsbdFunction::SetFunctionToRndisHdc();
            break;
        case USB_FUNCTION_STORAGE | USB_FUNCTION_HDC:
            HDF_LOGI("%{public}s: set storage hdc", __func__);
            return UsbdFunction::SetFunctionToStorageHdc();
            break;
        default:
            HDF_LOGI("%{public}s: enable device", __func__);
            return UsbdEnableDevice();
            break;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::UsbdSetFunction(uint32_t funcs)
{
    HDF_LOGI("%{public}s: UsbdSetFunction funcs=%{public}d", __func__, funcs);
    if ((funcs | USB_FUNCTION_SUPPORT) != USB_FUNCTION_SUPPORT) {
        HDF_LOGE("%{public}s: funcs invalid", __func__);
        return HDF_FAILURE;
    }

    uint32_t kfuns = static_cast<uint32_t>(funcs) & (~USB_DDK_FUNCTION_SUPPORT);
    if (UsbdFunction::SetFunctionToNone()) {
        HDF_LOGW("%{public}s: setFunctionToNone error", __func__);
    }

    if (UsbdFunction::SetDDKFunction(funcs)) {
        HDF_LOGE("%{public}s:SetDDKFunction error", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = UsbdSetKernelFunction(kfuns);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, set kernel func failed", __func__);
        return HDF_FAILURE;
    }

    if (funcs == USB_FUNCTION_NONE) {
        HDF_LOGI("%{public}s, none function", __func__);
        return HDF_SUCCESS;
    }

    if (UsbdWaitUdc() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, wait udc failed", __func__);
        return HDF_FAILURE;
    }
    if (UsbdInitDDKFunction(funcs) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, init ddk func failed", __func__);
        return HDF_FAILURE;
    }
    currentFuncs_ = funcs;
    return HDF_SUCCESS;
}

int32_t UsbdFunction::UsbdGetFunction(void)
{
    return currentFuncs_;
}
} // namespace V1_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS
