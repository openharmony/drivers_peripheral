/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
#include "v1_1/connected_nfc_tag_stub.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000307
#define HDF_LOG_TAG NFCTAG_HOST

using namespace OHOS::HDI::ConnectedNfcTag::V1_1;

struct HdfConnectedNfcTagHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t ConnectedNfcTagDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfConnectedNfcTagHost =
        CONTAINER_OF(client->device->service, struct HdfConnectedNfcTagHost, ioService);

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

    return hdfConnectedNfcTagHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfConnectedNfcTagDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfConnectedNfcTagDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);

    auto *hdfConnectedNfcTagHost = new (std::nothrow) HdfConnectedNfcTagHost;
    if (hdfConnectedNfcTagHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfConnectedNfcTagHost Object!", __func__);
        return HDF_FAILURE;
    }

    hdfConnectedNfcTagHost->ioService.Dispatch = ConnectedNfcTagDriverDispatch;
    hdfConnectedNfcTagHost->ioService.Open = nullptr;
    hdfConnectedNfcTagHost->ioService.Release = nullptr;

    auto serviceImpl = OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTag::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfConnectedNfcTagHost;
        return HDF_FAILURE;
    }

    hdfConnectedNfcTagHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTag::GetDescriptor());
    if (hdfConnectedNfcTagHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfConnectedNfcTagHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfConnectedNfcTagHost->ioService;
    HDF_LOGI("HdfConnectedNfcTagDriverBind Success");
    return HDF_SUCCESS;
}

static void HdfConnectedNfcTagDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfConnectedNfcTagDriverRelease not inited");
        return;
    }

    auto *hdfConnectedNfcTagHost =
        CONTAINER_OF(deviceObject->service, struct HdfConnectedNfcTagHost, ioService);
    if (hdfConnectedNfcTagHost != nullptr) {
        delete hdfConnectedNfcTagHost;
    }
    HDF_LOGI("%{public}s: driver release Success", __func__);
}

static struct HdfDriverEntry g_connectedNfcTagDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "",
    .Bind = HdfConnectedNfcTagDriverBind,
    .Init = HdfConnectedNfcTagDriverInit,
    .Release = HdfConnectedNfcTagDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_connectedNfcTagDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
