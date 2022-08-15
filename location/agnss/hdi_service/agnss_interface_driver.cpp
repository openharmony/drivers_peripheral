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
#include "v1_0/agnss_interface_stub.h"

using namespace OHOS::HDI::Location::Agnss::V1_0;

struct HdfAGnssInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;

    HdfAGnssInterfaceHost()
    {
        ioService.object.objectId = 0;
        ioService.Open = nullptr;
        ioService.Release = nullptr;
        ioService.Dispatch = nullptr;
    }
};

static int32_t AGnssInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfAGnssInterfaceHost = CONTAINER_OF(client->device->service, struct HdfAGnssInterfaceHost, ioService);

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

    return hdfAGnssInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfAGnssInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfAGnssInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfAGnssInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfAGnssInterfaceDriverBind enter");

    auto *hdfAGnssInterfaceHost = new (std::nothrow) HdfAGnssInterfaceHost;
    if (hdfAGnssInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfAGnssInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfAGnssInterfaceHost->ioService.Dispatch = AGnssInterfaceDriverDispatch;

    auto serviceImpl = IAGnssInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfAGnssInterfaceHost;
        return HDF_FAILURE;
    }

    hdfAGnssInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IAGnssInterface::GetDescriptor());
    if (hdfAGnssInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfAGnssInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfAGnssInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfAGnssInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfAGnssInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfAGnssInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfAGnssInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfAGnssInterfaceHost, ioService);
    delete hdfAGnssInterfaceHost;
    deviceObject->service = nullptr;
}

static struct HdfDriverEntry g_agnssinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "location_agnss",
    .Bind = HdfAGnssInterfaceDriverBind,
    .Init = HdfAGnssInterfaceDriverInit,
    .Release = HdfAGnssInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_agnssinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
