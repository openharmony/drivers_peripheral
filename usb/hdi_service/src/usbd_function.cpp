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
#include <hdf_sbuf.h>
#include <iservmgr_hdi.h>
#include <message_option.h>
#include <message_parcel.h>
#include <string_ex.h>
#include "devmgr_hdi.h"
#include "hdf_log.h"
#include "hdf_remote_service.h"
#include "osal_time.h"
#include "parameter.h"
#include "securec.h"
#include "usbd_type.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_0 {
uint8_t UsbdFunction::currentFuncs_ = USB_FUNCTION_HDC;
uint8_t UsbdFunction::waitSleepTime_ = 10;

using OHOS::HDI::ServiceManager::V1_0::IServiceManager;

int32_t UsbdFunction::SendCmdToService(const char *name, int32_t cmd, unsigned char funcMask)
{
    auto servMgr = IServiceManager::Get();
    if (servMgr == nullptr) {
        HDF_LOGE("%{public}s:get IServiceManager failed!", __func__);
        return HDF_FAILURE;
    }

    sptr<IRemoteObject> remote = servMgr->GetService(name);
    if (remote == nullptr) {
        HDF_LOGE("%{public}s:get remote object failed!", __func__);
        return HDF_FAILURE;
    }

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    if (!data.WriteInterfaceToken(Str8ToStr16(HDF_USB_USBFN_DESC))) {
        HDF_LOGE("%{public}s: WriteInterfaceToken failed!", __func__);
        return HDF_FAILURE;
    }

    if (!data.WriteUint8(funcMask)) {
        HDF_LOGE("%{public}s: WriteInt8 failed!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = remote->SendRequest(cmd, data, reply, option);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed, error code is %{public}d", __func__, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::RemoveHdc()
{
    uint8_t status = SetParameter(SYS_USB_CONFIG, HDC_CONFIG_OFF);
    if (status) {
        HDF_LOGE("%{public}s:remove hdc config error = %{public}hhu", __func__, status);
        return HDF_FAILURE;
    }
    status = SetParameter(SYS_USB_CONFIGFS, HDC_CONFIGFS_OFF);
    if (status) {
        HDF_LOGE("%{public}s:remove hdc configfs error = %{public}hhu", __func__, status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::AddHdc()
{
    uint8_t status = SetParameter(SYS_USB_CONFIGFS, HDC_CONFIGFS_ON);
    if (status) {
        HDF_LOGE("%{public}s:add hdc configfs error = %{public}hhu", __func__, status);
        return HDF_FAILURE;
    }
    status = SetParameter(SYS_USB_CONFIG, HDC_CONFIG_ON);
    if (status) {
        HDF_LOGE("%{public}s:add hdc config error = %{public}hhu", __func__, status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToNone()
{
    int32_t ret = RemoveHdc();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:RemoveHdc error, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    UsbdFunction::SendCmdToService(ACM_SERVICE_NAME, ACM_RELEASE, USB_FUNCTION_ACM);
    UsbdFunction::SendCmdToService(ECM_SERVICE_NAME, ECM_RELEASE, USB_FUNCTION_ECM);
    UsbdFunction::SendCmdToService(DEV_SERVICE_NAME, FUNCTION_DEL, USB_FUNCTION_ACM_ECM);
    currentFuncs_ = USB_FUNCTION_NONE;
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToACM()
{
    if (UsbdFunction::SendCmdToService(DEV_SERVICE_NAME, FUNCTION_ADD, USB_FUNCTION_ACM)) {
        HDF_LOGE("%{public}s:create acm dev error", __func__);
        return HDF_FAILURE;
    }

    if (UsbdFunction::SendCmdToService(ACM_SERVICE_NAME, ACM_INIT, USB_FUNCTION_ACM)) {
        HDF_LOGE("%{public}s:acm init error", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToECM()
{
    if (UsbdFunction::SendCmdToService(DEV_SERVICE_NAME, FUNCTION_ADD, USB_FUNCTION_ECM)) {
        HDF_LOGE("%{public}s:create ecm dev error", __func__);
        return HDF_FAILURE;
    }

    if (UsbdFunction::SendCmdToService(ECM_SERVICE_NAME, ECM_INIT, USB_FUNCTION_ECM)) {
        HDF_LOGE("%{public}s:ecm init error", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::SetFunctionToACMECM()
{
    if (UsbdFunction::SendCmdToService(DEV_SERVICE_NAME, FUNCTION_ADD, USB_FUNCTION_ACM_ECM)) {
        HDF_LOGE("%{public}s:create acm&ecm dev error", __func__);
        return HDF_FAILURE;
    }

    if (UsbdFunction::SendCmdToService(ACM_SERVICE_NAME, ACM_INIT, USB_FUNCTION_ACM)) {
        HDF_LOGE("%{public}s:acm init error", __func__);
        return HDF_FAILURE;
    }

    if (UsbdFunction::SendCmdToService(ECM_SERVICE_NAME, ECM_INIT, USB_FUNCTION_ECM)) {
        HDF_LOGE("%{public}s:ecm init dev error", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdFunction::UsbdSetFunction(int funcs)
{
    uint8_t acmEcm = funcs & USB_FUNCTION_ACM_ECM;
    if (funcs < USB_FUNCTION_NONE || funcs >= FUNCTIONS_MAX) {
        HDF_LOGI("%{public}s:funcs invalid", __func__);
        return HDF_FAILURE;
    }

    if (UsbdFunction::SetFunctionToNone()) {
        HDF_LOGI("%{public}s:setFunctionToNone error", __func__);
    }

    if (funcs & USB_FUNCTION_HDC) {
        if (UsbdFunction::AddHdc()) {
            HDF_LOGE("%{public}s:AddHdc error", __func__);
            return HDF_FAILURE;
        }
    }

    if (acmEcm == USB_FUNCTION_ACM) {
        if (SetFunctionToACM()) {
            HDF_LOGE("%{public}s:set function to acm error", __func__);
            return HDF_FAILURE;
        }
    } else if (acmEcm == USB_FUNCTION_ECM) {
        if (SetFunctionToECM()) {
            HDF_LOGE("%{public}s:set function to ecm error", __func__);
            return HDF_FAILURE;
        }
    } else if (acmEcm == USB_FUNCTION_ACM_ECM) {
        if (SetFunctionToACMECM()) {
            HDF_LOGE("%{public}s:set function to acm&ecm error", __func__);
            return HDF_FAILURE;
        }
    }
    OsalMSleep(waitSleepTime_);
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
