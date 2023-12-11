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

#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "hdf_sbuf_ipc.h"
#include "battery_log.h"
#include "v2_0/battery_interface_stub.h"

using namespace OHOS::HDI::Battery::V2_0;
using namespace OHOS::HDI::Battery;

namespace {
struct HdfBatteryInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};
}

static int32_t BatteryInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfBatteryInterfaceHost = CONTAINER_OF(client->device->service, struct HdfBatteryInterfaceHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        BATTERY_HILOGE(COMP_HDI, "invalid data sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        BATTERY_HILOGE(COMP_HDI, "invalid reply sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfBatteryInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int32_t HdfBatteryInterfaceDriverInit([[maybe_unused]] struct HdfDeviceObject *deviceObject)
{
    return HDF_SUCCESS;
}

static int32_t HdfBatteryInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    auto *hdfBatteryInterfaceHost = new (std::nothrow) HdfBatteryInterfaceHost;
    if (hdfBatteryInterfaceHost == nullptr) {
        BATTERY_HILOGE(COMP_HDI, "%{public}s: failed to create HdfBatteryInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfBatteryInterfaceHost->ioService.Dispatch = BatteryInterfaceDriverDispatch;
    hdfBatteryInterfaceHost->ioService.Open = nullptr;
    hdfBatteryInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = IBatteryInterface::Get(true);
    if (serviceImpl == nullptr) {
        BATTERY_HILOGE(COMP_HDI, "%{public}s: failed to get of implement service", __func__);
        delete hdfBatteryInterfaceHost;
        return HDF_FAILURE;
    }

    hdfBatteryInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IBatteryInterface::GetDescriptor());
    if (hdfBatteryInterfaceHost->stub == nullptr) {
        BATTERY_HILOGE(COMP_HDI, "%{public}s: failed to get stub object", __func__);
        delete hdfBatteryInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfBatteryInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfBatteryInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    if (deviceObject->service == nullptr) {
        BATTERY_HILOGE(COMP_HDI, "HdfBatteryInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfBatteryInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfBatteryInterfaceHost, ioService);
    delete hdfBatteryInterfaceHost;
}

static struct HdfDriverEntry g_batteryInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "battery_interface_service",
    .Bind = HdfBatteryInterfaceDriverBind,
    .Init = HdfBatteryInterfaceDriverInit,
    .Release = HdfBatteryInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_batteryInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
