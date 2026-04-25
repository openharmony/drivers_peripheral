/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 #include <hdf_base.h>
#include <hdf_core_log.h>
#include <hdf_device_desc.h>
#include <hdf_sbuf_ipc.h>
#include "v1_0/hdi_z_factory_stub.h"

#define HDF_LOG_TAG    hdi_z_factory_driver

using namespace OHOS::HDI::Codec::Zcodec::V1_0;

struct HdfHdiZFactoryHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t HdiZFactoryDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfHdiZFactoryHost = CONTAINER_OF(client->device->service, struct HdfHdiZFactoryHost, ioService);

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

    return hdfHdiZFactoryHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfHdiZFactoryDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfHdiZFactoryDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfHdiZFactoryHost = new (std::nothrow) HdfHdiZFactoryHost;
    if (hdfHdiZFactoryHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfHdiZFactoryHost object", __func__);
        return HDF_FAILURE;
    }

    hdfHdiZFactoryHost->ioService.Dispatch = HdiZFactoryDriverDispatch;
    hdfHdiZFactoryHost->ioService.Open = nullptr;
    hdfHdiZFactoryHost->ioService.Release = nullptr;

    auto serviceImpl = OHOS::HDI::Codec::Zcodec::V1_0::HdiZFactory::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfHdiZFactoryHost;
        return HDF_FAILURE;
    }

    hdfHdiZFactoryHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Codec::Zcodec::V1_0::HdiZFactory::GetDescriptor());
    if (hdfHdiZFactoryHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfHdiZFactoryHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfHdiZFactoryHost->ioService;
    return HDF_SUCCESS;
}

static void HdfHdiZFactoryDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfHdiZFactoryHost = CONTAINER_OF(deviceObject->service, struct HdfHdiZFactoryHost, ioService);
    if (hdfHdiZFactoryHost != nullptr) {
        delete hdfHdiZFactoryHost;
    }
}

struct HdfDriverEntry g_hdizfactoryDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "",
    .Bind = HdfHdiZFactoryDriverBind,
    .Init = HdfHdiZFactoryDriverInit,
    .Release = HdfHdiZFactoryDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_hdizfactoryDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
