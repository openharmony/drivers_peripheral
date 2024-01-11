/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <hdf_device_object.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include "codec_config_parser.h"
#include "codec_service.h"
#include "codec_stub.h"

static int32_t CodecServiceDispatch(struct HdfDeviceIoClient *client, int cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    return CodecServiceOnRemoteRequest(client, cmdId, data, reply);
}

static void HdfCodecDriverRelease(struct HdfDeviceObject *deviceObject)
{
    if (deviceObject == NULL) {
        HDF_LOGE("invalid parameter");
        return;
    }
    struct IDeviceIoService *testService = deviceObject->service;
    OsalMemFree(testService);
    ClearCapabilityGroup();
    DeinitOemIfaceLock();
}

static int HdfCodecDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfCodecDriverBind enter!");
    if (deviceObject == NULL) {
        HDF_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    struct IDeviceIoService *ioService = (struct IDeviceIoService *)OsalMemAlloc(sizeof(struct IDeviceIoService));
    if (ioService == NULL) {
        HDF_LOGE("HdfCodecDriverBind OsalMemAlloc IDeviceIoService failed!");
        return HDF_FAILURE;
    }

    ioService->Dispatch = CodecServiceDispatch;
    ioService->Open = NULL;
    ioService->Release = NULL;
    int ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, "ohos.hdi.codec_service");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("failed to set interface desc");
        return ret;
    }
    deviceObject->service = ioService;
    return HDF_SUCCESS;
}

static int HdfCodecDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfSampleDriverCInit enter, new hdi impl");
    if (deviceObject == NULL) {
        HDF_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    if (LoadCodecCapabilityFromHcs(deviceObject->property) != HDF_SUCCESS) {
        HDF_LOGE("LoadCodecCapabilityFromHcs failed");
        ClearCapabilityGroup();
    }
    InitOemIfaceLock();
    return HDF_SUCCESS;
}

struct HdfDriverEntry g_codecHostDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "libcodec_server.z.so",
    .Bind = HdfCodecDriverBind,
    .Init = HdfCodecDriverInit,
    .Release = HdfCodecDriverRelease,
};

HDF_INIT(g_codecHostDriverEntry);