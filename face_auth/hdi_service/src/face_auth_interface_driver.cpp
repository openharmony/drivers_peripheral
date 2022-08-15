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

#include "iam_logger.h"
#include "v1_0/face_auth_interface_stub.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_FACE_AUTH_HDI

using namespace OHOS::HDI::FaceAuth::V1_0;

struct HdfFaceAuthInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

namespace {
int32_t FaceAuthInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    IAM_LOGI("start");
    if (client == nullptr || data == nullptr || reply == nullptr || client->device == nullptr ||
        client->device->service == nullptr) {
        IAM_LOGE("invalid param");
        return HDF_ERR_INVALID_PARAM;
    }

    auto *hdfFaceAuthInterfaceHost = CONTAINER_OF(client->device->service, struct HdfFaceAuthInterfaceHost, ioService);
    if (hdfFaceAuthInterfaceHost == nullptr || hdfFaceAuthInterfaceHost->stub == nullptr) {
        IAM_LOGE("hdfFaceAuthInterfaceHost is invalid");
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

    return hdfFaceAuthInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfFaceAuthInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr) {
        IAM_LOGE("deviceObject is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_USERAUTH)) {
        IAM_LOGE("set face auth hdf class failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int HdfFaceAuthInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr) {
        IAM_LOGE("deviceObject is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    auto *hdfFaceAuthInterfaceHost = new (std::nothrow) HdfFaceAuthInterfaceHost;
    if (hdfFaceAuthInterfaceHost == nullptr) {
        IAM_LOGE("failed to create create HdfFaceAuthInterfaceHost object");
        return HDF_FAILURE;
    }

    hdfFaceAuthInterfaceHost->ioService.Dispatch = FaceAuthInterfaceDriverDispatch;
    hdfFaceAuthInterfaceHost->ioService.Open = NULL;
    hdfFaceAuthInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IFaceAuthInterface::Get(true);
    if (serviceImpl == nullptr) {
        IAM_LOGE("failed to get of implement service");
        delete hdfFaceAuthInterfaceHost;
        return HDF_FAILURE;
    }

    hdfFaceAuthInterfaceHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, IFaceAuthInterface::GetDescriptor());
    if (hdfFaceAuthInterfaceHost->stub == nullptr) {
        IAM_LOGE("failed to get stub object");
        delete hdfFaceAuthInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfFaceAuthInterfaceHost->ioService;
    IAM_LOGI("success");
    return HDF_SUCCESS;
}

void HdfFaceAuthInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        IAM_LOGE("deviceObject is invalid");
        return;
    }
    auto *hdfFaceAuthInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfFaceAuthInterfaceHost, ioService);
    if (hdfFaceAuthInterfaceHost == nullptr) {
        IAM_LOGE("hdfFaceAuthInterfaceHost is nullptr");
        return;
    }
    delete hdfFaceAuthInterfaceHost;
    IAM_LOGI("success");
}

struct HdfDriverEntry g_faceAuthInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "drivers_peripheral_face_auth",
    .Bind = HdfFaceAuthInterfaceDriverBind,
    .Init = HdfFaceAuthInterfaceDriverInit,
    .Release = HdfFaceAuthInterfaceDriverRelease,
};
} // namespace

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_faceAuthInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
