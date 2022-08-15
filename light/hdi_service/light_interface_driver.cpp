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
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>
#include <osal_mem.h>
#include "v1_0/light_interface_stub.h"

#define HDF_LOG_TAG           hdf_light_if_driver

using namespace OHOS::HDI::Light::V1_0;

struct HdfLightInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t LightInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfLightInterfaceHost = CONTAINER_OF(client->device->service, struct HdfLightInterfaceHost, ioService);

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

    return hdfLightInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfLightInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    (void)deviceObject;

    HDF_LOGI("HdfLightInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfLightInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    auto *hdfLightInterfaceHost = new (std::nothrow) HdfLightInterfaceHost;
    if (hdfLightInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfLightInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfLightInterfaceHost->ioService.Dispatch = LightInterfaceDriverDispatch;
    hdfLightInterfaceHost->ioService.Open = nullptr;
    hdfLightInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = ILightInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfLightInterfaceHost;
        return HDF_FAILURE;
    }

    hdfLightInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        ILightInterface::GetDescriptor());
    if (hdfLightInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfLightInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfLightInterfaceHost->ioService;
    HDF_LOGI("HdfLightInterfaceDriverBind success");
    return HDF_SUCCESS;
}

static void HdfLightInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfLightInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfLightInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfLightInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfLightInterfaceHost, ioService);
    delete hdfLightInterfaceHost;
}

struct HdfDriverEntry g_lightinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "light_service",
    .Bind = HdfLightInterfaceDriverBind,
    .Init = HdfLightInterfaceDriverInit,
    .Release = HdfLightInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_lightinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
