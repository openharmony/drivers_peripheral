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
#include "innrt_device_vdi.h"

#undef LOG_TAG
#define LOG_TAG "NNRT_DRV"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002600

using namespace OHOS::HDI::Nnrt::V2_0;

struct HdfNnrtHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t NnrtDriverDispatch(
    struct HdfDeviceIoClient* client, int cmdId, struct HdfSBuf* data, struct HdfSBuf* reply)
{
    if ((client == nullptr) || (client->device == nullptr)) {
        HDF_LOGE("%{public}s: param is nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    auto* hdfNnrtHost = CONTAINER_OF(client->device->service, struct HdfNnrtHost, ioService);

    OHOS::MessageParcel* dataParcel = nullptr;
    OHOS::MessageParcel* replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfNnrtHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfNnrtDriverInit(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    return HDF_SUCCESS;
}

static int HdfNnrtDriverBind(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    auto* hdfNnrtHost = new (std::nothrow) HdfNnrtHost;
    if (hdfNnrtHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create hdfNnrtHost object", __func__);
        return HDF_FAILURE;
    }

    hdfNnrtHost->ioService.Dispatch = NnrtDriverDispatch;
    hdfNnrtHost->ioService.Open = NULL;
    hdfNnrtHost->ioService.Release = NULL;

    auto serviceImpl = INnrtDevice::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get the implement of service", __func__);
        delete hdfNnrtHost;
        return HDF_FAILURE;
    }

    hdfNnrtHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, INnrtDevice::GetDescriptor());
    if (hdfNnrtHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfNnrtHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfNnrtHost->ioService;
    return HDF_SUCCESS;
}

static void HdfNnrtDriverRelease(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (deviceObject->service == nullptr) {
        HDF_LOGE("%{public}s: service is nullptr", __func__);
        return;
    }

    auto* hdfNnrtHost = CONTAINER_OF(deviceObject->service, struct HdfNnrtHost, ioService);
    delete hdfNnrtHost;
}

static struct HdfDriverEntry g_nnrtDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "nnrt",
    .Bind = HdfNnrtDriverBind,
    .Init = HdfNnrtDriverInit,
    .Release = HdfNnrtDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_nnrtDriverEntry);
#ifdef __cplusplus
}
#endif
