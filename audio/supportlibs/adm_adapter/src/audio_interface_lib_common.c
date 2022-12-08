/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "audio_interface_lib_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "audio_common.h"
#include "audio_if_lib_render.h"
#include "audio_uhdf_log.h"
#include "hdf_io_service_if.h"
#include "hdf_sbuf.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_LIB

#define ADAPTER_PORT_ID_MSB        10
#define ADAPTER_NAME_SUFFIX        2
#define SUPPORT_CAPTURE_OR_RENDER  1
#define SUPPORT_CAPTURE_AND_RENDER 2

struct HdfIoService *HdfIoServiceBindName(const char *serviceName)
{
    if (serviceName == NULL) {
        AUDIO_FUNC_LOGE("service name NULL!");
        return NULL;
    }
    if (strcmp(serviceName, "hdf_audio_control") == 0) {
        return (HdfIoServiceBind("hdf_audio_control"));
    }
    if (strcmp(serviceName, "hdf_audio_render") == 0) {
        return (HdfIoServiceBind("hdf_audio_render"));
    }
    if (strcmp(serviceName, "hdf_audio_capture") == 0) {
        return (HdfIoServiceBind("hdf_audio_capture"));
    }
    AUDIO_FUNC_LOGE("service name not support!");
    return NULL;
}

int32_t AudioGetElemValue(struct HdfSBuf *reply, struct AudioCtrlElemInfo *volThreshold)
{
    if (reply == NULL || volThreshold == NULL) {
        AUDIO_FUNC_LOGE("reply or volThreshold is null!");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold->type)) {
        AUDIO_FUNC_LOGE("Failed to Get volThreshold->type!");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold->max)) {
        AUDIO_FUNC_LOGE("Failed to Get volThreshold->max!");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold->min)) {
        AUDIO_FUNC_LOGE("Failed to Get volThreshold->min!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void AudioFreeHdfSBuf(struct HdfSBuf *sBuf, struct HdfSBuf *reply)
{
    if (sBuf != NULL) {
        HdfSbufRecycle(sBuf);
        sBuf = NULL;
    }

    if (reply != NULL) {
        HdfSbufRecycle(reply);
        reply = NULL;
    }
}

int32_t AudioServiceDispatch(void *obj, int cmdId, struct HdfSBuf *sBuf, struct HdfSBuf *reply)
{
    struct HdfIoService *service = obj;

    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("param is null!");
        return HDF_FAILURE;
    }

    return service->dispatcher->Dispatch(&(service->object), cmdId, sBuf, reply);
}

int32_t AudioSetElemValue(struct HdfSBuf *sBuf, const struct AudioCtlElemValue *elemValue, bool isSendData)
{
    if (sBuf == NULL || elemValue == NULL) {
        AUDIO_FUNC_LOGE("param is empty!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (isSendData) {
        if (!HdfSbufWriteInt32(sBuf, elemValue->value[0])) {
            AUDIO_FUNC_LOGE("SetVolumeSBuf value[0] Write Fail!");
            return HDF_FAILURE;
        }
    }

    if (!HdfSbufWriteInt32(sBuf, elemValue->id.iface)) {
        AUDIO_FUNC_LOGE("GetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, elemValue->id.cardServiceName)) {
        AUDIO_FUNC_LOGE("GetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, elemValue->id.itemName)) {
        AUDIO_FUNC_LOGE("GetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioAllocHdfSBuf(struct HdfSBuf **reply, struct HdfSBuf **sBuf)
{
    if (reply == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("param is empty!");
        return HDF_ERR_INVALID_PARAM;
    }

    *sBuf = HdfSbufObtainDefaultSize();
    if (*sBuf == NULL) {
        AUDIO_FUNC_LOGE("GetVolume Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    *reply = HdfSbufObtainDefaultSize();
    if (*reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply");
        AudioFreeHdfSBuf(*sBuf, NULL);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static struct DevHandle *AudioBindServiceObject(struct DevHandle * const handle, const char *name)
{
    if (handle == NULL || name == NULL) {
        AUDIO_FUNC_LOGE("service name or handle is NULL!");
        return NULL;
    }

    char *serviceName = (char *)OsalMemCalloc(NAME_LEN);
    if (serviceName == NULL) {
        AUDIO_FUNC_LOGE("Failed to alloc serviceName");
        return NULL;
    }

    int ret = snprintf_s(serviceName, NAME_LEN - 1, SERVIC_NAME_MAX_LEN + 1, "hdf_audio_%s", name);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to snprintf_s");
        AudioMemFree((void **)&serviceName);
        return NULL;
    }

    struct HdfIoService *service = HdfIoServiceBindName(serviceName);
    if (service == NULL) {
        AUDIO_FUNC_LOGE("Failed to get service!");
        AudioMemFree((void **)&serviceName);
        return NULL;
    }

    AudioMemFree((void **)&serviceName);
    handle->object = service;
    return handle->object;
}

struct DevHandle *AudioBindService(const char *name)
{
    struct DevHandle *handle = NULL;
    struct DevHandle *object = NULL;
    if (name == NULL) {
        AUDIO_FUNC_LOGE("service name NULL!");
        return NULL;
    }

    handle = (struct DevHandle *)OsalMemCalloc(sizeof(struct DevHandle));
    if (handle == NULL) {
        AUDIO_FUNC_LOGE("Failed to alloc handle");
        return NULL;
    }

    object = AudioBindServiceObject(handle, name);
    if (object == NULL) {
        AUDIO_FUNC_LOGE("handle->object is NULL!");
        AudioMemFree((void **)&handle);
        return NULL;
    }

    handle->object = object;

    AUDIO_FUNC_LOGI("BIND SERVICE SUCCESS!");
    return handle;
}

void AudioCloseService(const struct DevHandle *handle)
{
    AUDIO_FUNC_LOGI();
    if (handle == NULL || handle->object == NULL) {
        AUDIO_FUNC_LOGE("Capture handle or handle->object is NULL");
        return;
    }
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    HdfIoServiceRecycle(service);
    AudioMemFree((void **)&handle);
    return;
}

static int8_t AudioCardParsePortId(const char *name)
{
    if (name == NULL) {
        AUDIO_FUNC_LOGE("adapterName is null");
        return HDF_FAILURE;
    }

    uint8_t i = 0;
    uint8_t portId = 0;
    size_t nameLen = strlen(name);

    /* Get audio card device id */
    for (i = ADAPTER_NAME_SUFFIX; i > 0 ; i--) {
        if (name[nameLen - i] > '9' || name[nameLen - i] < '0') {
            continue;
        }

        portId += (name[nameLen - i] - '0') * ((i - 1) ? ADAPTER_PORT_ID_MSB : 1);
    }

    return portId;
}

static char *AudioCardNameTransform(const char *name, int8_t *portId)
{
    if (name == NULL) {
        AUDIO_FUNC_LOGE("adapterName is null");
        return NULL;
    }

    *portId = AudioCardParsePortId(name);
    if (*portId < 0) {
        AUDIO_FUNC_LOGE("AudioCardParsePortId failed");
        return NULL;
    }

    if (strstr(name, "primary") != NULL) {
        return strdup("primary");
    } else if (strstr(name, "hdmi") != NULL) {
        return strdup("hdmi");
    } else if (strstr(name, "usb") != NULL) {
        return strdup("usb");
    } else {
        AUDIO_FUNC_LOGI("audio card fail to identify");
        return NULL;
    }
}

static int32_t AudioReadCardPortToDesc(struct HdfSBuf *reply, struct AudioAdapterDescriptor *desc, int8_t portId)
{
    uint8_t portNum;

    if (desc == NULL) {
        AUDIO_FUNC_LOGE("descs is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint8(reply, &portNum)) {
        AUDIO_FUNC_LOGE("read portNum failed!");
        return HDF_FAILURE;
    }

    if (portNum == PORT_IN || portNum == PORT_OUT) {
        portNum = SUPPORT_CAPTURE_OR_RENDER;
    } else if (portNum == PORT_OUT_IN) {
        portNum = SUPPORT_CAPTURE_AND_RENDER;
    } else {
        AUDIO_FUNC_LOGE("portNum value failed!");
        return HDF_FAILURE;
    }

#ifndef AUDIO_HDI_SERVICE_MODE
    desc->portNum = portNum;
#else
    desc->portsLen = portNum;
#endif

    desc->ports = (struct AudioPort *)OsalMemCalloc(sizeof(struct AudioPort) * portNum);
    if (desc->ports == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc failed!");
        return HDF_FAILURE;
    }

    for (uint32_t i = 0; i < portNum; i++) {
        if (!HdfSbufReadUint8(reply, (uint8_t *)&desc->ports[i].dir)) {
            AUDIO_FUNC_LOGE("read dir failed!");
            AudioMemFree((void **)&desc->ports);
            return HDF_FAILURE;
        }

        // Compatible with IDL
        desc->ports[i].portName = strdup("useless");
        desc->ports[i].portId = portId;
    }

    return HDF_SUCCESS;
}

static void AudioPortNameFree(struct AudioPort *dataBlock, uint32_t portsLen)
{
    if (dataBlock == NULL) {
        return;
    }

    for (uint32_t i = 0; i < portsLen; i++) {
        OsalMemFree((void *)dataBlock[i].portName);
        dataBlock[i].portName = NULL;
    }
    OsalMemFree(dataBlock);
}

static void AudioFreeDesc(struct AudioAdapterDescriptor **descs, uint32_t sndCardNum)
{
    if (descs == NULL || *descs == NULL) {
        AUDIO_FUNC_LOGE("AudioFreeDesc failed!");
        return;
    }

    for (uint32_t index = 0; index < sndCardNum; index++) {
        if ((*descs)[index].adapterName != NULL) {
            AudioMemFree((void **)&((*descs)[index].adapterName));
            (*descs)[index].adapterName = NULL;
        }
#ifndef AUDIO_HDI_SERVICE_MODE
        AudioPortNameFree((*descs)[index].ports, (*descs)[index].portNum);
#else
        AudioPortNameFree((*descs)[index].ports, (*descs)[index].portsLen);
#endif
    }
    AudioMemFree((void **)descs);
}

static int32_t AudioReadCardInfoToDesc(struct HdfSBuf *reply, struct AudioAdapterDescriptor **descs, int *sndCardNum)
{
    int32_t index = 0;
    int8_t portId = 0;

    if (!HdfSbufReadInt32(reply, sndCardNum)) {
        AUDIO_FUNC_LOGE("read snd card num failed!");
        return HDF_FAILURE;
    }

    if (*descs  == NULL) {
        AUDIO_FUNC_LOGI("*descs is NULL");
        *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(sizeof(struct AudioAdapterDescriptor) * (*sndCardNum));
        if (*descs == NULL) {
            AUDIO_FUNC_LOGE("OsalMemCalloc descs is NULL");
            return HDF_FAILURE;
        }
    }

    // Make sure the primary sound card is on the front
    for (index = (*sndCardNum - 1); index >= 0; index--) {
        (*descs)[index].adapterName = AudioCardNameTransform(HdfSbufReadString(reply), &portId);
        if ((*descs)[index].adapterName == NULL) {
            AudioFreeDesc(descs, *sndCardNum);
            return HDF_FAILURE;
        }

        if (AudioReadCardPortToDesc(reply, &(*descs)[index], portId) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("read port failed!");
            AudioFreeDesc(descs, *sndCardNum);
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioGetAllCardInfo(struct AudioAdapterDescriptor **descs, int32_t *sndCardNum)
{
    if (descs == NULL || sndCardNum == NULL) {
        return HDF_FAILURE;
    }

    struct DevHandle *handle = AudioBindService(CTRL_CMD);
    if (handle == NULL) {
        AUDIO_FUNC_LOGE("AudioBindService failed!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        AudioCloseService(handle);
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }

    if (AudioServiceDispatch(handle->object, AUDIODRV_CTL_IOCTL_ELEM_CARD - CTRL_NUM, NULL, reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("GetAllCardInfo Failed to send service call!");
        AudioFreeHdfSBuf(reply, NULL);
        AudioCloseService(handle);
        return HDF_FAILURE;
    }

    if (AudioReadCardInfoToDesc(reply, descs, sndCardNum) != HDF_SUCCESS) {
        AudioFreeHdfSBuf(reply, NULL);
        AudioCloseService(handle);
        return HDF_FAILURE;
    }

    HdfSbufRecycle(reply);
    AudioCloseService(handle);
    return HDF_SUCCESS;
}
