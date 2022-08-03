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
#include "v1_0/input_interfaces_stub.h"

using namespace OHOS::HDI::Input::V1_0;

struct HdfInputInterfacesHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t InputInterfacesDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfInputInterfacesHost = CONTAINER_OF(client->device->service, struct HdfInputInterfacesHost, ioService);

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

    return hdfInputInterfacesHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfInputInterfacesDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfInputInterfacesDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfInputInterfacesDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfInputInterfacesDriverBind enter");

    auto *hdfInputInterfacesHost = new (std::nothrow) HdfInputInterfacesHost;
    if (hdfInputInterfacesHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfInputInterfacesHost object", __func__);
        return HDF_FAILURE;
    }

    hdfInputInterfacesHost->ioService.Dispatch = InputInterfacesDriverDispatch;
    hdfInputInterfacesHost->ioService.Open = nullptr;
    hdfInputInterfacesHost->ioService.Release = nullptr;

    auto serviceImpl = IInputInterfaces::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfInputInterfacesHost;
        return HDF_FAILURE;
    }

    hdfInputInterfacesHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IInputInterfaces::GetDescriptor());
    if (hdfInputInterfacesHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfInputInterfacesHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfInputInterfacesHost->ioService;
    return HDF_SUCCESS;
}

static void HdfInputInterfacesDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfInputInterfacesDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfInputInterfacesDriverRelease not initted");
        return;
    }

    auto *hdfInputInterfacesHost = CONTAINER_OF(deviceObject->service, struct HdfInputInterfacesHost, ioService);
    delete hdfInputInterfacesHost;
}

struct HdfDriverEntry g_inputinterfacesDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "input_service",
    .Bind = HdfInputInterfacesDriverBind,
    .Init = HdfInputInterfacesDriverInit,
    .Release = HdfInputInterfacesDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_inputinterfacesDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
