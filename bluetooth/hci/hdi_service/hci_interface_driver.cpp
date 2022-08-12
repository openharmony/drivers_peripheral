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
#include "v1_0/hci_interface_stub.h"

using namespace OHOS::HDI::Bluetooth::Hci::V1_0;

struct HdfHciInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
    HdfHciInterfaceHost()
    {
        ioService.object.objectId = 0;
        ioService.Open = nullptr;
        ioService.Release = nullptr;
        ioService.Dispatch = nullptr;
    }
};

static int32_t HciInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfHciInterfaceHost = CONTAINER_OF(client->device->service, struct HdfHciInterfaceHost, ioService);

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

    return hdfHciInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfHciInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    (void)deviceObject;
    HDF_LOGI("HdfHciInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfHciInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfHciInterfaceDriverBind enter");

    auto *hdfHciInterfaceHost = new (std::nothrow) HdfHciInterfaceHost;
    if (hdfHciInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfHciInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfHciInterfaceHost->ioService.Dispatch = HciInterfaceDriverDispatch;
    hdfHciInterfaceHost->ioService.Open = NULL;
    hdfHciInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IHciInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfHciInterfaceHost;
        return HDF_FAILURE;
    }

    hdfHciInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IHciInterface::GetDescriptor());
    if (hdfHciInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfHciInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfHciInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfHciInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfHciInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfHciInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfHciInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfHciInterfaceHost, ioService);
    delete hdfHciInterfaceHost;
}

static struct HdfDriverEntry g_hciinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "bluetooth_hci",
    .Bind = HdfHciInterfaceDriverBind,
    .Init = HdfHciInterfaceDriverInit,
    .Release = HdfHciInterfaceDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_hciinterfaceDriverEntry);
#ifndef __cplusplus
}
#endif
