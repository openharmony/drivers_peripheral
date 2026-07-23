/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "v1_1/sle_hci_interface_stub.h"

#define HDF_LOG_TAG    sle_dli_interface_driver

using namespace OHOS::HDI::Nearlink::Hci::V1_1;

struct HdfSleDliInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
    HdfSleDliInterfaceHost()
    {
        ioService.object.objectId = 0;
        ioService.Open = nullptr;
        ioService.Release = nullptr;
        ioService.Dispatch = nullptr;
    }
};

static int32_t SleDliInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfSleDliInterfaceHost = CONTAINER_OF(client->device->service, struct HdfSleDliInterfaceHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfSleDliInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfSleDliInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfSleDliInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfSleDliInterfaceHost = new (std::nothrow) HdfSleDliInterfaceHost;
    if (hdfSleDliInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfSleDliInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfSleDliInterfaceHost->ioService.Dispatch = SleDliInterfaceDriverDispatch;
    hdfSleDliInterfaceHost->ioService.Open = NULL;
    hdfSleDliInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Nearlink::Hci::V1_1::ISleHciInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfSleDliInterfaceHost;
        return HDF_FAILURE;
    }

    hdfSleDliInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Nearlink::Hci::V1_1::ISleHciInterface::GetDescriptor());
    if (hdfSleDliInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfSleDliInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfSleDliInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfSleDliInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfSleDliInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfSleDliInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfSleDliInterfaceHost, ioService);
    if (hdfSleDliInterfaceHost != nullptr) {
        delete hdfSleDliInterfaceHost;
    }
}

struct HdfDriverEntry g_sledliinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "nearlink_dli",
    .Bind = HdfSleDliInterfaceDriverBind,
    .Init = HdfSleDliInterfaceDriverInit,
    .Release = HdfSleDliInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_sledliinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
