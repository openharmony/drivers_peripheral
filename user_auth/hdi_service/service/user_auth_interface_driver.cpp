/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "v4_0/user_auth_interface_service.h"
#include "v4_0/user_auth_interface_stub.h"

#include "iam_logger.h"
#include "useriam_common.h"
#include "user_auth_hdi.h"

#undef LOG_TAG
#define LOG_TAG "USER_AUTH_HDI"

namespace {
struct HdfUserAuthInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

using UserAuthInterfaceService = OHOS::HDI::UserAuth::V4_0::UserAuthInterfaceService;
using IUserAuthInterface = OHOS::HDI::UserAuth::V4_0::IUserAuthInterface;

int32_t UserAuthInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr || client->device == nullptr ||
        client->device->service == nullptr) {
        IAM_LOGE("invalid param");
        return HDF_ERR_INVALID_PARAM;
    }

    auto *hdfUserAuthInterfaceHost = CONTAINER_OF(client->device->service, struct HdfUserAuthInterfaceHost, ioService);
    if (hdfUserAuthInterfaceHost == nullptr || hdfUserAuthInterfaceHost->stub == nullptr) {
        IAM_LOGE("hdfUserAuthInterfaceHost is invalid");
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

    return hdfUserAuthInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfUserAuthInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("HdfUserAuthInterfaceDriverInit enter");
    if (deviceObject == nullptr) {
        IAM_LOGE("deviceObject is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_USERAUTH)) {
        IAM_LOGE("set pin auth hdf class failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int HdfUserAuthInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("HdfUserAuthInterfaceDriverBind enter");
    if (deviceObject == nullptr) {
        IAM_LOGE("deviceObject is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    auto *hdfUserAuthInterfaceHost = new (std::nothrow) HdfUserAuthInterfaceHost;
    if (hdfUserAuthInterfaceHost == nullptr) {
        IAM_LOGE("failed to create create HdfUserAuthInterfaceHost object");
        return HDF_FAILURE;
    }

    hdfUserAuthInterfaceHost->ioService.Dispatch = UserAuthInterfaceDriverDispatch;
    hdfUserAuthInterfaceHost->ioService.Open = nullptr;
    hdfUserAuthInterfaceHost->ioService.Release = nullptr;

    OHOS::sptr<UserAuthInterfaceService> serviceImpl(new (std::nothrow) UserAuthInterfaceService());
    if (serviceImpl == nullptr) {
        IAM_LOGE("failed to get of implement service");
        delete hdfUserAuthInterfaceHost;
        return HDF_FAILURE;
    }

    hdfUserAuthInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(
        serviceImpl, IUserAuthInterface::GetDescriptor());
    if (hdfUserAuthInterfaceHost->stub == nullptr) {
        IAM_LOGE("failed to get stub object");
        delete hdfUserAuthInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfUserAuthInterfaceHost->ioService;
    OHOS::UserIam::Common::Init();
    return HDF_SUCCESS;
}

void HdfUserAuthInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("HdfUserAuthInterfaceDriverRelease enter");
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        IAM_LOGE("deviceObject is invalid");
        return;
    }
    auto *hdfUserAuthInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfUserAuthInterfaceHost, ioService);
    if (hdfUserAuthInterfaceHost == nullptr) {
        IAM_LOGE("hdfUserAuthInterfaceHost is nullptr");
        return;
    }
    delete hdfUserAuthInterfaceHost;
}

struct HdfDriverEntry g_userAuthInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "drivers_peripheral_user_auth",
    .Bind = HdfUserAuthInterfaceDriverBind,
    .Init = HdfUserAuthInterfaceDriverInit,
    .Release = HdfUserAuthInterfaceDriverRelease,
};
} // namespace

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_userAuthInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
