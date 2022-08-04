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

#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_sbuf_ipc.h>
#include "v1_0/pin_auth_interface_stub.h"
#include "pin_auth.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_HDI

using namespace OHOS::HDI::PinAuth::V1_0;

struct HdfPinAuthInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t PinAuthInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    IAM_LOGI("start");
    if (client == nullptr || data == nullptr || reply == nullptr || client->device == nullptr ||
        client->device->service == nullptr) {
        IAM_LOGE("invalid param");
        return HDF_ERR_INVALID_PARAM;
    }
    auto *hdfPinAuthInterfaceHost = CONTAINER_OF(client->device->service,
        struct HdfPinAuthInterfaceHost, ioService);
    if (hdfPinAuthInterfaceHost == nullptr || hdfPinAuthInterfaceHost->stub == nullptr) {
        IAM_LOGE("hdfPinAuthInterfaceHost is invalid");
        return HDF_ERR_INVALID_PARAM;
    }

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        IAM_LOGE("invalid data sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        IAM_LOGE("invalid reply sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfPinAuthInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfPinAuthInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr) {
        IAM_LOGE("deviceObject is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi =
        OHOS::UserIam::Common::MakeShared<OHOS::UserIam::PinAuth::PinAuth>();
    constexpr uint32_t SUCCESS = 0;
    if (pinHdi == nullptr || pinHdi->Init() != SUCCESS) {
        IAM_LOGE("Pin hal init failed");
        return HDF_FAILURE;
    }
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_USERAUTH)) {
        IAM_LOGE("set pin auth hdf class failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int HdfPinAuthInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr) {
        IAM_LOGE("deviceObject is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    auto *hdfPinAuthInterfaceHost = new (std::nothrow) HdfPinAuthInterfaceHost;
    if (hdfPinAuthInterfaceHost == nullptr) {
        IAM_LOGE("failed to create create HdfPinAuthInterfaceHost object");
        return HDF_FAILURE;
    }

    hdfPinAuthInterfaceHost->ioService.Dispatch = PinAuthInterfaceDriverDispatch;
    hdfPinAuthInterfaceHost->ioService.Open = NULL;
    hdfPinAuthInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IPinAuthInterface::Get(true);
    if (serviceImpl == nullptr) {
        IAM_LOGE("failed to get of implement service");
        delete hdfPinAuthInterfaceHost;
        return HDF_FAILURE;
    }

    hdfPinAuthInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IPinAuthInterface::GetDescriptor());
    if (hdfPinAuthInterfaceHost->stub == nullptr) {
        IAM_LOGE("failed to get stub object");
        delete hdfPinAuthInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfPinAuthInterfaceHost->ioService;
    IAM_LOGI("success");
    return HDF_SUCCESS;
}

static void HdfPinAuthInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        IAM_LOGE("deviceObject is invalid");
        return;
    }
    auto *hdfPinAuthInterfaceHost = CONTAINER_OF(deviceObject->service,
        struct HdfPinAuthInterfaceHost, ioService);
    if (hdfPinAuthInterfaceHost == nullptr) {
        IAM_LOGE("hdfPinAuthInterfaceHost is nullptr");
        return;
    }
    delete hdfPinAuthInterfaceHost;
    IAM_LOGI("success");
}

static struct HdfDriverEntry g_pinAuthInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "drivers_peripheral_pin_auth",
    .Bind = HdfPinAuthInterfaceDriverBind,
    .Init = HdfPinAuthInterfaceDriverInit,
    .Release = HdfPinAuthInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_pinAuthInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
