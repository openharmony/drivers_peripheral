/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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
#include "codec_component_config.h"
#include "codec_log_wrapper.h"
#include "v4_0/codec_component_manager_stub.h"
#include "codec_dfx_service.h"
#include <devhost_dump_reg.h>
using namespace OHOS::HDI::Codec::V4_0;
namespace {
    struct HdfCodecComponentManagerHost {
        struct IDeviceIoService ioService;
        OHOS::sptr<OHOS::IRemoteObject> stub;
    };
}

static int32_t CodecComponentManagerDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
                                                   struct HdfSBuf *reply)
{
    auto *hdfCodecComponentManagerHost =
        CONTAINER_OF(client->device->service, struct HdfCodecComponentManagerHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        CODEC_LOGE("invalid data sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        CODEC_LOGE("invalid reply sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfCodecComponentManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfCodecComponentManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecComponentManagerDriverInit enter");
    if (DevHostRegisterDumpHost(CodecDfxService::DevCodecHostDump) != HDF_SUCCESS) {
        CODEC_LOGE("DevHostRegisterDumpHost error!");
    }
    return HDF_SUCCESS;
}

static int HdfCodecComponentManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecComponentManagerDriverBind enter");

    auto *hdfCodecComponentManagerHost = new (std::nothrow) HdfCodecComponentManagerHost;
    if (hdfCodecComponentManagerHost == nullptr) {
        CODEC_LOGE("failed to create create HdfCodecComponentManagerHost object");
        return HDF_FAILURE;
    }

    hdfCodecComponentManagerHost->ioService.Dispatch = CodecComponentManagerDriverDispatch;
    hdfCodecComponentManagerHost->ioService.Open = NULL;
    hdfCodecComponentManagerHost->ioService.Release = NULL;

    auto serviceImpl = ICodecComponentManager::Get(true);
    if (serviceImpl == nullptr) {
        CODEC_LOGE("failed to get of implement service");
        delete hdfCodecComponentManagerHost;
        return HDF_FAILURE;
    }

    hdfCodecComponentManagerHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, ICodecComponentManager::GetDescriptor());
    if (hdfCodecComponentManagerHost->stub == nullptr) {
        CODEC_LOGE("failed to get stub object");
        delete hdfCodecComponentManagerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfCodecComponentManagerHost->ioService;
    return HDF_SUCCESS;
}

static void HdfCodecComponentManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecComponentManagerDriverRelease enter");
    if (deviceObject->service == nullptr) {
        CODEC_LOGE("HdfCodecComponentManagerDriverRelease not initted");
        return;
    }

    auto *hdfCodecComponentManagerHost =
        CONTAINER_OF(deviceObject->service, struct HdfCodecComponentManagerHost, ioService);
    delete hdfCodecComponentManagerHost;
}

static struct HdfDriverEntry g_codeccomponentmanagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "codec_component_manager_service",
    .Bind = HdfCodecComponentManagerDriverBind,
    .Init = HdfCodecComponentManagerDriverInit,
    .Release = HdfCodecComponentManagerDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_codeccomponentmanagerDriverEntry);
#ifndef __cplusplus
}
#endif
