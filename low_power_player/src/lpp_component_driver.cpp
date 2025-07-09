/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <hdf_base.h>
#include <hdf_log.h>
#include <hdf_device_desc.h>
#include <iremote_object.h>
#include <hdf_sbuf_ipc.h>
#include <object_collector.h>
#include "v1_0/ilow_power_player_factory.h"

using namespace OHOS::HDI::LowPowerPlayer::V1_0;
struct HdfLppCompFactoryHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t LppCompFactoryDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfLppCompFactoryHost = CONTAINER_OF(client->device->service, struct HdfLppCompFactoryHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("invalid data sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("invalid reply sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfLppCompFactoryHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfLppCompFactoryDriverInit(struct HdfDeviceObject *deviceObject)
{
    return HDF_SUCCESS;
}

static int HdfLppCompFactoryDriverBind(struct HdfDeviceObject *deviceObject)
{
    auto *hdfLppCompFactoryHost = new (std::nothrow) HdfLppCompFactoryHost;
    if (hdfLppCompFactoryHost == nullptr) {
        HDF_LOGE("failed to create create hdfLppCompFactoryHost object");
        return HDF_FAILURE;
    }

    hdfLppCompFactoryHost->ioService.Dispatch = LppCompFactoryDriverDispatch;
    hdfLppCompFactoryHost->ioService.Open = NULL;
    hdfLppCompFactoryHost->ioService.Release = NULL;

    auto serviceImpl = ILowPowerPlayerFactory::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("failed to get of implement service");
        delete hdfLppCompFactoryHost;
        return HDF_FAILURE;
    }

    hdfLppCompFactoryHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, ILowPowerPlayerFactory::GetDescriptor());
    if (hdfLppCompFactoryHost->stub == nullptr) {
        HDF_LOGE("failed to get stub object");
        delete hdfLppCompFactoryHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfLppCompFactoryHost->ioService;
    return HDF_SUCCESS;
}

static void HdfLppCompFactoryDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfLppCompFactoryDriverRelease not initted");
        return;
    }

    auto *hdfLppCompFactoryHost =
        CONTAINER_OF(deviceObject->service, struct HdfLppCompFactoryHost, ioService);
    delete hdfLppCompFactoryHost;
}

static struct HdfDriverEntry g_LppCompFactoryDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "low_power_player_factory_service",
    .Bind = HdfLppCompFactoryDriverBind,
    .Init = HdfLppCompFactoryDriverInit,
    .Release = HdfLppCompFactoryDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_LppCompFactoryDriverEntry);
#ifdef __cplusplus
}
#endif