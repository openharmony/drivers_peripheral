/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "vibrator_uhdf_log.h"
#include <osal_mem.h>
#include "v2_0/vibrator_interface_stub.h"

#define HDF_LOG_TAG    uhdf_vibrator_service

using namespace OHOS::HDI::Vibrator::V2_0;

struct HdfVibratorInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t VibratorInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfVibratorInterfaceHost = CONTAINER_OF(client->device->service, struct HdfVibratorInterfaceHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfVibratorInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfVibratorInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfVibratorInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfVibratorInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    auto *hdfVibratorInterfaceHost = new (std::nothrow) HdfVibratorInterfaceHost;
    if (hdfVibratorInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfVibratorInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfVibratorInterfaceHost->ioService.Dispatch = VibratorInterfaceDriverDispatch;
    hdfVibratorInterfaceHost->ioService.Open = nullptr;
    hdfVibratorInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = OHOS::HDI::Vibrator::V2_0::IVibratorInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfVibratorInterfaceHost;
        return HDF_FAILURE;
    }

    hdfVibratorInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Vibrator::V2_0::IVibratorInterface::GetDescriptor());
    if (hdfVibratorInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfVibratorInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfVibratorInterfaceHost->ioService;
    HDF_LOGI("HdfVibratorInterfaceDriverBind Success");
    return HDF_SUCCESS;
}

static void HdfVibratorInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfVibratorInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfVibratorInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfVibratorInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfVibratorInterfaceHost, ioService);
    delete hdfVibratorInterfaceHost;
}

static struct HdfDriverEntry g_vibratorInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "vibrator_service",
    .Bind = HdfVibratorInterfaceDriverBind,
    .Init = HdfVibratorInterfaceDriverInit,
    .Release = HdfVibratorInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_vibratorInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
