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
#include "v1_0/gnss_interface_stub.h"

using namespace OHOS::HDI::Location::Gnss::V1_0;

struct HdfGnssInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;

    HdfGnssInterfaceHost()
    {
        ioService.object.objectId = 0;
        ioService.Open = nullptr;
        ioService.Release = nullptr;
        ioService.Dispatch = nullptr;
    }
};

static int32_t GnssInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfGnssInterfaceHost = CONTAINER_OF(client->device->service, struct HdfGnssInterfaceHost, ioService);

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

    return hdfGnssInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfGnssInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfGnssInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfGnssInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfGnssInterfaceDriverBind enter");

    auto *hdfGnssInterfaceHost = new (std::nothrow) HdfGnssInterfaceHost;
    if (hdfGnssInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfGnssInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfGnssInterfaceHost->ioService.Dispatch = GnssInterfaceDriverDispatch;

    auto serviceImpl = IGnssInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfGnssInterfaceHost;
        return HDF_FAILURE;
    }

    hdfGnssInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IGnssInterface::GetDescriptor());
    if (hdfGnssInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfGnssInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfGnssInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfGnssInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfGnssInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfGnssInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfGnssInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfGnssInterfaceHost, ioService);
    delete hdfGnssInterfaceHost;
    deviceObject->service = nullptr;
}

static struct HdfDriverEntry g_gnssinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "location_gnss",
    .Bind = HdfGnssInterfaceDriverBind,
    .Init = HdfGnssInterfaceDriverInit,
    .Release = HdfGnssInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_gnssinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
