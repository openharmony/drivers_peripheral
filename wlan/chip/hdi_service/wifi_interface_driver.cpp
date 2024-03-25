/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved
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
#include "v1_0/wifi_stub.h"

#define HDF_LOG_TAG wifi_driver

using namespace OHOS::HDI::Wlan::Chip::V1_0;

struct HdfWifiHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t WifiDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfWifiHost = CONTAINER_OF(client->device->service, struct HdfWifiHost, ioService);

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

    return hdfWifiHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfWifiDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfWifiDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfWifiHost = new (std::nothrow) HdfWifiHost;
    if (hdfWifiHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create hdfWifiHost object", __func__);
        return HDF_FAILURE;
    }

    hdfWifiHost->ioService.Dispatch = WifiDriverDispatch;
    hdfWifiHost->ioService.Open = NULL;
    hdfWifiHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Wlan::Chip::V1_0::IWifi::Get("chip_interface_service", true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfWifiHost;
        return HDF_FAILURE;
    }

    hdfWifiHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Wlan::Chip::V1_0::IWifi::GetDescriptor());
    if (hdfWifiHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfWifiHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfWifiHost->ioService;
    return HDF_SUCCESS;
}

static void HdfWifiDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfWifiHost = CONTAINER_OF(deviceObject->service, struct HdfWifiHost, ioService);
    if (hdfWifiHost != nullptr) {
        delete hdfWifiHost;
    }
}

struct HdfDriverEntry g_wifiDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "chip",
    .Bind = HdfWifiDriverBind,
    .Init = HdfWifiDriverInit,
    .Release = HdfWifiDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_wifiDriverEntry);
#ifdef  __cplusplus
}
#endif