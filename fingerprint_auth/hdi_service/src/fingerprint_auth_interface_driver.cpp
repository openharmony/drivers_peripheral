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
#include "v1_0/fingerprint_auth_interface_stub.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_FINGERPRINT_AUTH_HDI

using namespace OHOS::HDI::FingerprintAuth::V1_0;

struct HdfFingerprintAuthInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

namespace {
int32_t FingerprintAuthInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    IAM_LOGI("start");
    if (client == nullptr || data == nullptr || reply == nullptr || client->device == nullptr ||
        client->device->service == nullptr) {
        IAM_LOGE("invalid param");
        return HDF_ERR_INVALID_PARAM;
    }
    auto *hdfFingerprintAuthInterfaceHost = CONTAINER_OF(client->device->service,
        struct HdfFingerprintAuthInterfaceHost, ioService);
    if (hdfFingerprintAuthInterfaceHost == nullptr || hdfFingerprintAuthInterfaceHost->stub == nullptr) {
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

    return hdfFingerprintAuthInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfFingerprintAuthInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr) {
        IAM_LOGE("deviceObject is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_USERAUTH)) {
        IAM_LOGE("set fingerprint auth hdf class failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int HdfFingerprintAuthInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr) {
        IAM_LOGE("deviceObject is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    auto *hdfFingerprintAuthInterfaceHost = new (std::nothrow) HdfFingerprintAuthInterfaceHost;
    if (hdfFingerprintAuthInterfaceHost == nullptr) {
        IAM_LOGE("failed to create create HdfFingerprinteAuthInterfaceHost object");
        return HDF_FAILURE;
    }

    hdfFingerprintAuthInterfaceHost->ioService.Dispatch =FingerprintAuthInterfaceDriverDispatch;
    hdfFingerprintAuthInterfaceHost->ioService.Open = NULL;
    hdfFingerprintAuthInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IFingerprintAuthInterface::Get(true);
    if (serviceImpl == nullptr) {
        IAM_LOGE("failed to get of implement service");
        delete hdfFingerprintAuthInterfaceHost;
        return HDF_FAILURE;
    }

    hdfFingerprintAuthInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IFingerprintAuthInterface::GetDescriptor());
    if (hdfFingerprintAuthInterfaceHost->stub == nullptr) {
        IAM_LOGE("failed to get stub object");
        delete hdfFingerprintAuthInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfFingerprintAuthInterfaceHost->ioService;
    IAM_LOGI("success");
    return HDF_SUCCESS;
}

void HdfFingerprintAuthInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    IAM_LOGI("start");
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        IAM_LOGE("deviceObject is invalid");
        return;
    }
    auto *hdfFingerprintAuthInterfaceHost = CONTAINER_OF(deviceObject->service,
        struct HdfFingerprintAuthInterfaceHost, ioService);
    if (hdfFingerprintAuthInterfaceHost == nullptr) {
        IAM_LOGE("hdfFaceAuthInterfaceHost is nullptr");
        return;
    }
    delete hdfFingerprintAuthInterfaceHost;
    IAM_LOGI("success");
}

struct HdfDriverEntry g_fingerprintAuthInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "drivers_peripheral_fingerprint_auth",
    .Bind = HdfFingerprintAuthInterfaceDriverBind,
    .Init = HdfFingerprintAuthInterfaceDriverInit,
    .Release = HdfFingerprintAuthInterfaceDriverRelease,
};
} // namespace

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_fingerprintAuthInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */

