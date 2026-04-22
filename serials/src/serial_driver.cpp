/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>

#include "v1_0/serials_interface_stub.h"

using namespace OHOS::HDI::Serials::V1_0;

#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519

struct HdfSerialsInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t SerialsInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfSerialsInterfaceHost = CONTAINER_OF(client->device->service, struct HdfSerialsInterfaceHost,
        ioService);

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

    return hdfSerialsInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfSerialsInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfSerialsInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfSerialsInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfSerialsInterfaceDriverBind enter");

    auto *hdfSerialsInterfaceHost = new (std::nothrow) HdfSerialsInterfaceHost;
    if (hdfSerialsInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfSerialsInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfSerialsInterfaceHost->ioService.Dispatch = SerialsInterfaceDriverDispatch;
    hdfSerialsInterfaceHost->ioService.Open = NULL;
    hdfSerialsInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = ISerial::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfSerialsInterfaceHost;
        return HDF_FAILURE;
    }

    hdfSerialsInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        ISerial::GetDescriptor());
    if (hdfSerialsInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfSerialsInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfSerialsInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfSerialsInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfSerialsInterfaceDriverRelease enter");
    auto *hdfSerialsInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfSerialsInterfaceHost,
        ioService);
    delete hdfSerialsInterfaceHost;
}

static struct HdfDriverEntry g_serialsinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "serials_service",
    .Bind = HdfSerialsInterfaceDriverBind,
    .Init = HdfSerialsInterfaceDriverInit,
    .Release = HdfSerialsInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_serialsinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
