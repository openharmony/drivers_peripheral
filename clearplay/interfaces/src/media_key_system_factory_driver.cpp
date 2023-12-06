/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>
#include "v1_0/media_key_system_factory_stub.h"
#include "v1_0/imedia_key_system_factory.h"

#define HDF_LOG_TAG media_key_system_factory_driver

using namespace OHOS::HDI::Drm::V1_0;

struct HdfMediaKeySystemFactoryHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t MediaKeySystemFactoryDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfMediaKeySystemFactoryHost =
        CONTAINER_OF(client->device->service, struct HdfMediaKeySystemFactoryHost, ioService);

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

    return hdfMediaKeySystemFactoryHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfMediaKeySystemFactoryDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfMediaKeySystemFactoryDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfMediaKeySystemFactoryHost = new (std::nothrow) HdfMediaKeySystemFactoryHost;
    if (hdfMediaKeySystemFactoryHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfMediaKeySystemFactoryHost object", __func__);
        return HDF_FAILURE;
    }
    int ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, "ohos.hdi.drm.v1_0.IMediaKeySystemFactory");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to HdfDeviceObjectSetInterfaceDesc", __func__);
    }

    hdfMediaKeySystemFactoryHost->ioService.Dispatch = MediaKeySystemFactoryDriverDispatch;
    hdfMediaKeySystemFactoryHost->ioService.Open = NULL;
    hdfMediaKeySystemFactoryHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory::Get("clearplay_service", true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfMediaKeySystemFactoryHost;
        return HDF_FAILURE;
    }

    hdfMediaKeySystemFactoryHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory::GetDescriptor());
    if (hdfMediaKeySystemFactoryHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfMediaKeySystemFactoryHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfMediaKeySystemFactoryHost->ioService;
    return HDF_SUCCESS;
}

static void HdfMediaKeySystemFactoryDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfMediaKeySystemFactoryHost =
        CONTAINER_OF(deviceObject->service, struct HdfMediaKeySystemFactoryHost, ioService);
    if (hdfMediaKeySystemFactoryHost != nullptr) {
        delete hdfMediaKeySystemFactoryHost;
    }
}

struct HdfDriverEntry g_mediakeysystemfactoryDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "clearplay_service",
    .Bind = HdfMediaKeySystemFactoryDriverBind,
    .Init = HdfMediaKeySystemFactoryDriverInit,
    .Release = HdfMediaKeySystemFactoryDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_mediakeysystemfactoryDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
