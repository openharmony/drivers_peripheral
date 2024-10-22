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
#include <hdf_sbuf_ipc.h>
#include "v1_0/hid_ddk_stub.h"
#include "emit_event_manager.h"
#include "input_uhdf_log.h"

#define HDF_LOG_TAG hid_ddk_driver

using namespace OHOS::HDI::Input::Ddk::V1_0;

struct HdfHidDdkHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t HidDdkDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfHidDdkHost = CONTAINER_OF(client->device->service, struct HdfHidDdkHost, ioService);

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

    return hdfHidDdkHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfHidDdkDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfHidDdkDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfHidDdkHost = new (std::nothrow) HdfHidDdkHost;
    if (hdfHidDdkHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfHidDdkHost object", __func__);
        return HDF_FAILURE;
    }

    hdfHidDdkHost->ioService.Dispatch = HidDdkDriverDispatch;
    hdfHidDdkHost->ioService.Open = NULL;
    hdfHidDdkHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Input::Ddk::V1_0::IHidDdk::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfHidDdkHost;
        return HDF_FAILURE;
    }

    hdfHidDdkHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Input::Ddk::V1_0::IHidDdk::GetDescriptor());
    if (hdfHidDdkHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfHidDdkHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfHidDdkHost->ioService;
    return HDF_SUCCESS;
}

static void HdfHidDdkDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    OHOS::ExternalDeviceManager::EmitEventManager::GetInstance().ClearDeviceMap();

    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfHidDdkHost = CONTAINER_OF(deviceObject->service, struct HdfHidDdkHost, ioService);
    if (hdfHidDdkHost != nullptr) {
        delete hdfHidDdkHost;
    }
}

static struct HdfDriverEntry g_hidddkDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "",
    .Bind = HdfHidDdkDriverBind,
    .Init = HdfHidDdkDriverInit,
    .Release = HdfHidDdkDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_hidddkDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
