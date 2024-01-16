/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "v1_1/metadata_stub.h"

#undef LOG_TAG
#define LOG_TAG "METADATA_DRV"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002515

using namespace OHOS::HDI::Display::Buffer::V1_1;

struct HdfMetadataHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t MetadataDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfMetadataHost = CONTAINER_OF(client->device->service, struct HdfMetadataHost, ioService);

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

    return hdfMetadataHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfMetadataDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfMetadataDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfMetadataHost = new (std::nothrow) HdfMetadataHost;
    if (hdfMetadataHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfMetadataHost object", __func__);
        return HDF_FAILURE;
    }

    hdfMetadataHost->ioService.Dispatch = MetadataDriverDispatch;
    hdfMetadataHost->ioService.Open = NULL;
    hdfMetadataHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Display::Buffer::V1_1::IMetadata::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfMetadataHost;
        return HDF_FAILURE;
    }

    hdfMetadataHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Display::Buffer::V1_1::IMetadata::GetDescriptor());
    if (hdfMetadataHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfMetadataHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfMetadataHost->ioService;
    return HDF_SUCCESS;
}

static void HdfMetadataDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfMetadataHost = CONTAINER_OF(deviceObject->service, struct HdfMetadataHost, ioService);
    if (hdfMetadataHost != nullptr) {
        delete hdfMetadataHost;
    }
}

struct HdfDriverEntry g_metadataDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "display_buffer",
    .Bind = HdfMetadataDriverBind,
    .Init = HdfMetadataDriverInit,
    .Release = HdfMetadataDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_metadataDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
