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

#include <devhost_dump_reg.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <osal_mem.h>
#include "codec_component_capability_config.h"
#include "codec_component_manager_service.h"
#include "codec_component_type_stub.h"
#include "codec_dfx_service.h"
#include "codec_log_wrapper.h"

struct HdfCodecComponentTypeHost {
    struct IDeviceIoService ioservice;
    struct CodecComponentManagerSerivce *service;
};

static int32_t CodecComponentTypeDriverDispatch(struct HdfDeviceIoClient *client, int32_t cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL) {
        CODEC_LOGE("invalid paramter");
        return HDF_ERR_INVALID_PARAM;
    }
    if (client->device == NULL) {
        CODEC_LOGE("invalid paramter");
        return HDF_ERR_INVALID_PARAM;
    }
    struct HdfCodecComponentTypeHost *omxcomponenttypeHost =
        CONTAINER_OF(client->device->service, struct HdfCodecComponentTypeHost, ioservice);
    if (omxcomponenttypeHost == NULL) {
        CODEC_LOGE("null pointer");
        return HDF_FAILURE;
    }
    if (omxcomponenttypeHost->service == NULL || omxcomponenttypeHost->service->stub.OnRemoteRequest == NULL) {
        CODEC_LOGE("invalid service obj");
        return HDF_ERR_INVALID_OBJECT;
    }
    if (!HdfDeviceObjectCheckInterfaceDesc(client->device, data)) {
        CODEC_LOGE("check interface desc failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    return omxcomponenttypeHost->service->stub.OnRemoteRequest(&omxcomponenttypeHost->service->stub.interface, cmdId,
                                                               data, reply);
}

static int32_t HdfCodecComponentTypeDriverInit(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecComponentTypeDriverInit enter.");
    if (deviceObject == NULL) {
        return HDF_FAILURE;
    }
    InitDataNode(deviceObject->property);
    if (LoadCapabilityData() != HDF_SUCCESS) {
        ClearCapabilityData();
    }
    return HDF_SUCCESS;
}

static int32_t HdfCodecComponentTypeDriverBind(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecComponentTypeDriverBind enter.");
    if (deviceObject == NULL) {
        HDF_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    struct HdfCodecComponentTypeHost *omxcomponenttypeHost =
        (struct HdfCodecComponentTypeHost *)OsalMemAlloc(sizeof(struct HdfCodecComponentTypeHost));
    if (omxcomponenttypeHost == NULL) {
        HDF_LOGE("HdfCodecComponentTypeDriverBind OsalMemAlloc HdfCodecComponentTypeHost failed!");
        return HDF_FAILURE;
    }
    int ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, COMPONENT_MANAGER_SERVICE_DESC);
    if (ret != HDF_SUCCESS) {
        OsalMemFree(omxcomponenttypeHost);
        HDF_LOGE("Failed to set interface desc");
        return ret;
    }

    omxcomponenttypeHost->ioservice.Dispatch = CodecComponentTypeDriverDispatch;
    omxcomponenttypeHost->ioservice.Open = NULL;
    omxcomponenttypeHost->ioservice.Release = NULL;
    omxcomponenttypeHost->service = CodecComponentManagerSerivceGet();
    if (omxcomponenttypeHost->service == NULL) {
        OsalMemFree(omxcomponenttypeHost);
        return HDF_FAILURE;
    }

    deviceObject->service = &omxcomponenttypeHost->ioservice;
    return HDF_SUCCESS;
}

static void HdfCodecComponentTypeDriverRelease(struct HdfDeviceObject *deviceObject)
{
    CODEC_LOGI("HdfCodecComponentTypeDriverRelease enter.");
    if (deviceObject == NULL) {
        CODEC_LOGE("invalid paramter");
        return;
    }
    struct HdfCodecComponentTypeHost *omxcomponenttypeHost =
        CONTAINER_OF(deviceObject->service, struct HdfCodecComponentTypeHost, ioservice);
    OmxComponentManagerSeriveRelease(omxcomponenttypeHost->service);
    OsalMemFree(omxcomponenttypeHost);
    ClearCapabilityData();
}

struct HdfDriverEntry g_codecComponentDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "codec_hdi_omx_server",
    .Bind = HdfCodecComponentTypeDriverBind,
    .Init = HdfCodecComponentTypeDriverInit,
    .Release = HdfCodecComponentTypeDriverRelease,
};

HDF_INIT(g_codecComponentDriverEntry);