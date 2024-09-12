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

#define DECADE 10

#define PORTNUM_FIRST  1
#define PORTNUM_SECOND 2

static int32_t AudioMixerCtlElemList(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data);
static int32_t AudioMixerCtlGetElemProp(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data);
static int32_t AudioMixerCtlSetElemProp(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data);
static int32_t AudioGetAllCardList(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data);

static struct AudioMixerOps g_AudioMixerOpsTbl[] = {
    {MIXER_CTL_IOCTL_ELEM_INFO,     NULL                    },
    {MIXER_CTL_IOCTL_ELEM_READ,     NULL                    },
    {MIXER_CTL_IOCTL_ELEM_WRITE,    NULL                    },
    {MIXER_CTL_IOCTL_ELEM_LIST,     AudioMixerCtlElemList   },
    {MIXER_CTL_IOCTL_ELEM_GET_PROP, AudioMixerCtlGetElemProp},
    {MIXER_CTL_IOCTL_ELEM_SET_PROP, AudioMixerCtlSetElemProp},
    {MIXER_CTL_IOCTL_GET_CARDS,     AudioGetAllCardList     },
    {MIXER_CTL_IOCTL_GET_CHMAP,     NULL                    },
    {MIXER_CTL_IOCTL_SET_CHMAP,     NULL                    },
    {MIXER_CTL_IOCTL_BUTT,          NULL                    },
};

static bool AudioCheckServiceIsAvailable(const struct HdfIoService *service)
{
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("Invalid service handle!");
        return false;
    }

    return true;
}

struct HdfIoService *HdfIoServiceBindName(const char *serviceName)
{
    uint32_t i;

    if (serviceName == NULL) {
        AUDIO_FUNC_LOGE("service name NULL!");
        return NULL;
    }

    static const char *serviceNameList [] = {
        "hdf_audio_control",
        "hdf_audio_render",
        "hdf_audio_capture"
    };

    for (i = 0; i < (uint32_t)HDF_ARRAY_SIZE(serviceNameList); i++) {
        if (strcmp(serviceName, serviceNameList[i]) == 0) {
            return HdfIoServiceBind(serviceName);
        }
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
        AudioMemFree((void **)&handle);
        return NULL;
    }

    int ret = snprintf_s(serviceName, NAME_LEN - 1, SERVIC_NAME_MAX_LEN + 1, "hdf_audio_%s", name);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to snprintf_s");
        AudioMemFree((void **)&serviceName);
        AudioMemFree((void **)&handle);
        return NULL;
    }

    struct HdfIoService *service = HdfIoServiceBindName(serviceName);
    if (service == NULL) {
        AUDIO_FUNC_LOGE("Failed to get service!");
        AudioMemFree((void **)&serviceName);
        AudioMemFree((void **)&handle);
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
    if (object != NULL) {
        handle->object = object;
    } else {
        AUDIO_FUNC_LOGE("handle->object is NULL!");
        return NULL;
    }
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

    for (i = PORTNUM_SECOND; i > 0; i--) {
        if (name[nameLen - i] > '9' || name[nameLen - i] < '0') {
            continue;
        }

        portId += (name[nameLen - i] - '0') * ((i - 1) ? DECADE : 1);
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
    uint8_t portNum = 0;

    if (desc == NULL) {
        AUDIO_FUNC_LOGE("descs is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint8(reply, &portNum)) {
        AUDIO_FUNC_LOGE("read portNum failed!");
        return HDF_FAILURE;
    }

    if (portNum == PORT_IN || portNum == PORT_OUT) {
        portNum = PORTNUM_FIRST; // support capture | render
    } else if (portNum == PORT_OUT_IN) {
        portNum = PORTNUM_SECOND; // support capture & render
    } else {
        AUDIO_FUNC_LOGE("portNum value failed!");
        return HDF_FAILURE;
    }

#ifndef AUDIO_HDI_SERVICE_MODE
    desc->portNum = portNum;
#else
    desc->portsLen = portNum;
#endif
    if (portNum == 0) {
        AUDIO_FUNC_LOGE("portNum is zero");
        return HDF_FAILURE;
    }
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

        if (desc->ports[i].dir == PORT_IN) {
            desc->ports[i].portName = strdup("AIP");
        } else if (desc->ports[i].dir == PORT_OUT) {
            desc->ports[i].portName = strdup("AOP");
        } else if (desc->ports[i].dir == PORT_OUT_IN) {
            desc->ports[i].portName = strdup("AOIP");
        } else {
            AudioMemFree((void **)&desc->ports);
            AUDIO_FUNC_LOGE("desc->ports[i].dir = %{public}d", desc->ports[i].dir);
            return HDF_FAILURE;
        }
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

    if (*descs == NULL || *sndCardNum > 0) {
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

void AudioCloseServiceSub(struct HdfIoService *service)
{
    if (service != NULL) {
        HdfIoServiceRecycle(service);
    }
}

static int32_t AudioCtlElemRealDataSpace(struct AudioCtlElemList *eList)
{
    int32_t ret;
    size_t dataSize = eList->count * sizeof(struct AudioHwCtlElemId);
    if (dataSize <= 0) {
        AUDIO_FUNC_LOGE("dataSize is zero");
        return HDF_FAILURE;
    }
    struct AudioHwCtlElemId *ctlElemListAddr = OsalMemCalloc(dataSize);
    if (ctlElemListAddr == NULL) {
        AUDIO_FUNC_LOGE("Out of memory!");
        return HDF_FAILURE;
    }

    ret = memcpy_s(ctlElemListAddr, dataSize, eList->ctlElemListAddr, dataSize);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("Failed to copy data.!");
        AudioMemFree((void **)&ctlElemListAddr);
        return HDF_FAILURE;
    }
    AudioMemFree((void **)&eList->ctlElemListAddr);
    eList->ctlElemListAddr = ctlElemListAddr;
    eList->space = eList->count;

    return HDF_SUCCESS;
}

static int32_t AudioCtlElemParseData(struct AudioCtlElemList *eList, struct HdfSBuf *reply)
{
    int32_t ret;
    uint32_t countTmp = 0;
    uint32_t spaceTmp = 0;

    const char *sndSvcName = HdfSbufReadString(reply);
    if (sndSvcName == NULL) {
        AUDIO_FUNC_LOGE("Failed to parse the cardServiceName!");
        return HDF_FAILURE;
    }
    if (strcmp(eList->cardSrvName, sndSvcName) != 0) {
        AUDIO_FUNC_LOGE("The service name does not match!");
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(reply, &countTmp)) {
        AUDIO_FUNC_LOGE("Failed to parse the count!");
        return HDF_FAILURE;
    }
    if (countTmp == 0) {
        AUDIO_FUNC_LOGE("Can't find the element because count == 0!");
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(reply, &spaceTmp)) {
        AUDIO_FUNC_LOGE("Failed to parse the space!");
        return HDF_FAILURE;
    }
    if (eList->space != spaceTmp || spaceTmp <= countTmp) {
        AUDIO_FUNC_LOGE("The data space does not match!");
        return HDF_FAILURE;
    }
    eList->count = countTmp;

    /* Space is allocated based on actual data */
    ret = AudioCtlElemRealDataSpace(eList);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    return HDF_SUCCESS;
}

static const char *AudioRenderCtlCmdId2String(int cmdId)
{
    static const char *audioRenderCtlCmdString[] = {
        "MIXER_CTL_IOCTL_ELEM_INFO",
        "MIXER_CTL_IOCTL_ELEM_READ",
        "MIXER_CTL_IOCTL_ELEM_WRITE",
        "MIXER_CTL_IOCTL_ELEM_LIST",
        "MIXER_CTL_IOCTL_ELEM_GET_PROP",
        "MIXER_CTL_IOCTL_ELEM_SET_PROP",
        "MIXER_CTL_IOCTL_GET_CARDS",
        "MIXER_CTL_IOCTL_GET_CHMAP",
        "MIXER_CTL_IOCTL_SET_CHMAP"
    };

    if (cmdId < MIXER_CTL_IOCTL_ELEM_INFO || cmdId > MIXER_CTL_IOCTL_SET_CHMAP) {
        AUDIO_FUNC_LOGE("cmdId Not Supported!");
        return "Not found!";
    }

    return audioRenderCtlCmdString[cmdId - MIXER_CTL_IOCTL_ELEM_INFO];
}

static int32_t AudioCtlGetElemList(const struct HdfIoService *service, struct AudioCtlElemList *eList, int cmdId)
{
    int32_t ret;

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, eList->cardSrvName)) {
        AUDIO_FUNC_LOGE("CardServiceName Write Fail!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(sBuf, eList->space)) {
        AUDIO_FUNC_LOGE("Elem list space Write Fail!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint64(sBuf, (uint64_t)eList->ctlElemListAddr)) {
        AUDIO_FUNC_LOGE("Elem list addr Write Fail!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    struct HdfObject *srv = (struct HdfObject *)(&service->object);
    ret = service->dispatcher->Dispatch(srv, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE(
            "Failed to send service call cmdId: %{public}s!", AudioRenderCtlCmdId2String(cmdId + MIXER_CMD_ID_BASE));
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }

    ret = AudioCtlElemParseData(eList, reply);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }
    AudioFreeHdfSBuf(sBuf, reply);

    return HDF_SUCCESS;
}

static int32_t AudioCtlElemListCts(const struct HdfIoService *service, int cmdId, struct AudioMixerContents *mData)
{
    int32_t ret;
    struct AudioCtlElemList eList = {
        .cardSrvName = mData->cardServiceName,
        .count = 0,
        .space = AUDIO_ELEMENT_NUM,
        .ctlElemListAddr = NULL
    };

    eList.ctlElemListAddr = OsalMemCalloc(eList.space * sizeof(struct AudioHwCtlElemId));
    if (eList.ctlElemListAddr == NULL) {
        AUDIO_FUNC_LOGE("Out of memory!");
        return HDF_FAILURE;
    }

    ret = AudioCtlGetElemList(service, &eList, cmdId);
    if (ret != HDF_SUCCESS) {
        AudioMemFree((void **)&eList.ctlElemListAddr);
        return ret;
    }
    mData->data = eList.ctlElemListAddr;
    mData->elemNum = eList.count;

    return HDF_SUCCESS;
}

static int32_t AudioCtlRenderElemList(const struct HdfIoService *service, int cmdId, struct AudioMixerContents *data)
{
    int32_t ret;

    ret = AudioCtlElemListCts(service, cmdId, data);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to get the element list!");
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t AudioCtlCaptureElemList(const struct HdfIoService *service, int cmdId, struct AudioMixerContents *data)
{
    return AudioCtlRenderElemList(service, cmdId, data);
}

static bool AudioChkMixerRenderCmdId(OpCode cmd)
{
    if (cmd < MIXER_CTL_IOCTL_ELEM_INFO || cmd > MIXER_CTL_IOCTL_SET_CHMAP) {
        AUDIO_FUNC_LOGE("cmdId Not Supported!");
        return false;
    }

    return true;
}

static bool AudioChkMixerCaptureCmdId(OpCode cmd)
{
    return AudioChkMixerRenderCmdId(cmd);
}

static int32_t AudioMixerCtlElemList(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data)
{
    struct AudioMixerContents *mContents = (struct AudioMixerContents *)data;

    if (pcm == PCM_CAPTURE) {
        return AudioCtlCaptureElemList(service, cmd, mContents);
    } else {
        return AudioCtlRenderElemList(service, cmd, mContents);
    }
}

static int32_t AudioFillAllAdapters(struct HdfSBuf *sbuf, int32_t num, struct AudioCardId *clist)
{
    int32_t i, j, ret;
    uint8_t offset = 0;
    uint8_t portNum = 0;
    const char *sndName = NULL;

    for (i = 0; i < num; i++) {
        sndName = HdfSbufReadString(sbuf);
        if (sndName == NULL) {
            AUDIO_FUNC_LOGE("Failed to parse the cardServiceName!");
            return HDF_FAILURE;
        }

        ret = memcpy_s(clist[i].cardName, AUDIO_CARD_SRV_NAME_LEN, sndName, strlen(sndName) + 1);
        if (ret != EOK) {
            AUDIO_FUNC_LOGE("Failed to copy card information!");
            return HDF_FAILURE;
        }

        if (!HdfSbufReadUint8(sbuf, &portNum)) {
            AUDIO_FUNC_LOGE("read portNum failed!");
            return HDF_FAILURE;
        }
        if (portNum == PORT_IN || portNum == PORT_OUT) {
            portNum = PORT_OUT;
        } else if (portNum == PORT_OUT_IN) {
            portNum = PORT_IN;
        } else {
            AUDIO_FUNC_LOGE("portNum error!");
            return HDF_FAILURE;
        }

        for (j = 0; j < portNum; j++) {
            if (!HdfSbufReadUint8(sbuf, &offset)) {
                AUDIO_FUNC_LOGE("Failed to copy card information!");
                return HDF_FAILURE;
            }
        }
        /* The sound card number starts at 0, so it needs (num -1) */
        clist[i].index = (num - 1) - i;
    }

    return HDF_SUCCESS;
}

static int32_t AudioParseAllAdaptersFromBuf(struct SndCardsList *sndCards, struct HdfSBuf *buf)
{
    int32_t ret;
    int32_t cnumber = 0;
    struct AudioCardId *clist = NULL;

    if (!HdfSbufReadInt32(buf, &cnumber)) {
        AUDIO_FUNC_LOGE("HdfSbufReadInt32 failed!");
        return HDF_FAILURE;
    }
    if (cnumber <= 0) {
        AUDIO_FUNC_LOGE("Card num error!");
        return HDF_FAILURE;
    }

    clist = OsalMemCalloc(sizeof(struct AudioCardId) * cnumber);
    if (clist == NULL) {
        AUDIO_FUNC_LOGE("Out of memory!");
        return HDF_FAILURE;
    }

    ret = AudioFillAllAdapters(buf, cnumber, clist);
    if (ret != HDF_SUCCESS) {
        AudioMemFree((void **)&clist);
        return ret;
    }
    sndCards->cardNums = (uint32_t)cnumber;
    sndCards->cardsList = clist;

    return HDF_SUCCESS;
}

static int32_t AudioCtlGetAllCards(const struct HdfIoService *service, int32_t cmdId, struct SndCardsList *sndCards)
{
    int32_t ret;
    struct HdfSBuf *reply = NULL;
    struct HdfObject *srv = NULL;

    reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }

    srv = (struct HdfObject *)(&service->object);
    ret = service->dispatcher->Dispatch(srv, cmdId, NULL, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service Dispatch!");
        AudioFreeHdfSBuf(reply, NULL);
        return ret;
    }

    ret = AudioParseAllAdaptersFromBuf(sndCards, reply);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(reply, NULL);
        return ret;
    }
    AudioFreeHdfSBuf(reply, NULL);

    return HDF_SUCCESS;
}

static int32_t AudioGetAllCardList(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data)
{
    (void)pcm;
    struct SndCardsList *sndCardsList = (struct SndCardsList *)data;

    cmd -= (MIXER_CTL_IOCTL_GET_CARDS - MIXER_CTL_IOCTL_ELEM_GET_PROP);
    if (service == NULL || sndCardsList == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    return AudioCtlGetAllCards(service, cmd, sndCardsList);
}

static int32_t AudioMixerCtlElemRoute(AudioPcmType pcm, const struct HdfIoService *service, OpCode cmd, void *data)
{
    uint32_t i, count;

    if (!AudioCheckServiceIsAvailable(service)) {
        return HDF_FAILURE;
    }

    if (pcm == PCM_CAPTURE) {
        if (!AudioChkMixerCaptureCmdId(cmd)) {
            return HDF_FAILURE;
        }
    } else {
        if (!AudioChkMixerRenderCmdId(cmd)) {
            return HDF_FAILURE;
        }
    }

    count = (uint32_t)HDF_ARRAY_SIZE(g_AudioMixerOpsTbl);
    if (count == 0) {
        AUDIO_FUNC_LOGE("The audio mixer operation table is empty!!!");
        return HDF_FAILURE;
    }

    for (i = 0; i < count; i++) {
        if (cmd == g_AudioMixerOpsTbl[i].cmdId) {
            /* Find the corresponding option */
            break;
        }
    }
    if (i == count) {
        AUDIO_FUNC_LOGE("There's no corresponding option!!!");
        return HDF_FAILURE;
    }

    if (g_AudioMixerOpsTbl[i].func == NULL) {
        AUDIO_FUNC_LOGE("The function handle is empty!!!");
        return HDF_FAILURE;
    }

    return g_AudioMixerOpsTbl[i].func(pcm, i, service, data);
}

static int32_t AudioFillDataBool(struct HdfSBuf *sBuf, struct AudioMixerCtlElemInfo *data)
{
    (void)sBuf;
    (void)data;

    return HDF_ERR_NOT_SUPPORT;
}

static int32_t AudioFillDataInt(struct HdfSBuf *sBuf, struct AudioMixerCtlElemInfo *data)
{
    struct AudioCtlElemId eId = {
        .cardServiceName = data->cardSrvName,
        .itemName = data->eIndexId.eId.name,
        .iface = data->eIndexId.eId.iface
    };

    if (!HdfSbufWriteInt32(sBuf, eId.iface)) {
        AUDIO_FUNC_LOGE("Element iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, eId.cardServiceName)) {
        AUDIO_FUNC_LOGE("Element cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, eId.itemName)) {
        AUDIO_FUNC_LOGE("Element itemName Write Fail!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioFillDataEnum(struct HdfSBuf *sBuf, struct AudioMixerCtlElemInfo *data)
{
    (void)sBuf;
    (void)data;

    return HDF_ERR_NOT_SUPPORT;
}
static int32_t AudioFillDataBytes(struct HdfSBuf *sBuf, struct AudioMixerCtlElemInfo *data)
{
    (void)sBuf;
    (void)data;

    return HDF_ERR_NOT_SUPPORT;
}

static int32_t AudioFillSendDataToBuf(struct HdfSBuf *sBuf, struct AudioMixerCtlElemInfo *data)
{
    int32_t ret;

    switch (data->type) {
        case AUDIO_CTL_ELEM_TYPE_BOOLEAN:
            ret = AudioFillDataBool(sBuf, data);
            break;
        case AUDIO_CTL_ELEM_TYPE_INTEGER:
            ret = AudioFillDataInt(sBuf, data);
            break;
        case AUDIO_CTL_ELEM_TYPE_ENUMERATED:
            ret = AudioFillDataEnum(sBuf, data);
            break;
        case AUDIO_CTL_ELEM_TYPE_BYTES:
            ret = AudioFillDataBytes(sBuf, data);
            break;
        default:
            AUDIO_FUNC_LOGE("Unknown element value type!!!");
            ret = HDF_FAILURE;
            break;
    }

    return ret;
}

static int32_t AudioParseIntegerFromBufOnly(struct HdfSBuf *reply, struct AudioMixerCtlElemInfo *data)
{
    struct AudioCtlElemValue eVal;

    (void)memset_s(&eVal, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    if (!HdfSbufReadInt32(reply, &eVal.value[0])) {
        AUDIO_FUNC_LOGE("Failed to get the value0 of the CTL element!");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &eVal.value[1])) {
        AUDIO_FUNC_LOGE("Failed to get the value1 of the CTL element!");
        return HDF_FAILURE;
    }
    data->count = eVal.value[1] <= 0 ? 1 : 2;   // 2 for number of values.
    data->value.intVal.vals[0] = (long)eVal.value[0];
    data->value.intVal.vals[1] = (long)eVal.value[1];

    return HDF_SUCCESS;
}

static int32_t AudioParseIntegerFromBuf(struct HdfSBuf *reply, struct AudioMixerCtlElemInfo *data)
{
    struct AudioCtrlElemInfo eValue;

    (void)memset_s(&eValue, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));
    if (!HdfSbufReadInt32(reply, &eValue.max)) {
        AUDIO_FUNC_LOGE("Failed to get the max value of the CTL element!");
        return HDF_FAILURE;
    }

    if (!HdfSbufReadInt32(reply, &eValue.min)) {
        AUDIO_FUNC_LOGE("Failed to get the min value of the CTL element!");
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(reply, &eValue.count)) {
        AUDIO_FUNC_LOGE("Failed to get the count of the CTL element!");
        return HDF_FAILURE;
    }
    data->count = eValue.count;
    data->value.intVal.max = eValue.max;
    data->value.intVal.min = eValue.min;
    data->value.intVal.step = 0; /* reserved */

    return HDF_SUCCESS;
}

static int32_t AudioParseEnumeratedFromBuf(struct HdfSBuf *reply, struct AudioMixerCtlElemInfo *data)
{
    (void)reply;
    (void)data;

    return HDF_SUCCESS;
}

static int32_t AudioParseBoolFromBuf(struct HdfSBuf *reply, struct AudioMixerCtlElemInfo *data)
{
    (void)reply;
    (void)data;

    return HDF_ERR_NOT_SUPPORT;
}

static int32_t AudioParseStringFromBuf(struct HdfSBuf *reply, struct AudioMixerCtlElemInfo *data)
{
    (void)reply;
    (void)data;

    return HDF_ERR_NOT_SUPPORT;
}

static int32_t AudioParseRecvDataFromBuf(struct HdfSBuf *reply, struct AudioMixerCtlElemInfo *data, int cmdId)
{
    int32_t ret;
    int32_t type = 0;

    if (cmdId == (MIXER_CTL_IOCTL_ELEM_INFO - MIXER_CMD_ID_BASE)) {
        if (!HdfSbufReadInt32(reply, &type)) {
            AUDIO_FUNC_LOGE("Failed to Get Volume type!");
            return HDF_FAILURE;
        }
        data->type = (AudioCtlElemType)type;
        switch (data->type) {
            case AUDIO_CTL_ELEM_TYPE_INTEGER:
                ret = AudioParseIntegerFromBuf(reply, data);
                break;
            case AUDIO_CTL_ELEM_TYPE_ENUMERATED:
                ret = AudioParseEnumeratedFromBuf(reply, data);
                break;
            case AUDIO_CTL_ELEM_TYPE_BOOLEAN:
                ret = AudioParseBoolFromBuf(reply, data);
                break;
            case AUDIO_CTL_ELEM_TYPE_BYTES:
                ret = AudioParseStringFromBuf(reply, data);
                break;
            default:
                AUDIO_FUNC_LOGE("An unsupported type!");
                ret = HDF_FAILURE;
                break;
        }
    } else {
        ret = AudioParseIntegerFromBufOnly(reply, data);
    }

    return ret;
}

static int32_t AudioCtlElemGetProp(const struct HdfIoService *srv, int cmdId, struct AudioMixerCtlElemInfo *data)
{
    int32_t ret;
    struct HdfSBuf *sBuf = NULL;
    struct HdfSBuf *reply = NULL;

    sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf!!!");
        return HDF_FAILURE;
    }

    ret = AudioFillSendDataToBuf(sBuf, data);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, NULL);
        return ret;
    }

    reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply!!!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    struct HdfObject *service = (struct HdfObject *)(&srv->object);
    ret = srv->dispatcher->Dispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    ret = AudioParseRecvDataFromBuf(reply, data, cmdId);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }
    AudioFreeHdfSBuf(sBuf, reply);

    return HDF_SUCCESS;
}

static int32_t AudioFillInfoDataToBuf(struct HdfSBuf *sBuf, struct AudioMixerCtlElemInfo *data)
{
    struct AudioCtrlElemInfo eInfo = {
        .id.cardServiceName = data->cardSrvName,
        .id.itemName = data->eIndexId.eId.name,
        .id.iface = data->eIndexId.eId.iface
    };

    if (!HdfSbufWriteInt32(sBuf, eInfo.id.iface)) {
        AUDIO_FUNC_LOGE("Element iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, eInfo.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("Element cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, eInfo.id.itemName)) {
        AUDIO_FUNC_LOGE("Element itemName Write Fail!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioParseInfoDataFromBuf(struct HdfSBuf *reply, struct AudioMixerCtlElemInfo *data)
{
    struct AudioCtrlElemInfo eValue;

    (void)memset_s(&eValue, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));
    if (!HdfSbufReadInt32(reply, &eValue.type)) {
        AUDIO_FUNC_LOGE("Failed to get the value0 of the CTL element!");
        return HDF_FAILURE;
    }

    if (!HdfSbufReadInt32(reply, &eValue.max)) {
        AUDIO_FUNC_LOGE("Failed to get the value1 of the CTL element!");
        return HDF_FAILURE;
    }

    if (!HdfSbufReadInt32(reply, &eValue.min)) {
        AUDIO_FUNC_LOGE("Failed to get the value1 of the CTL element!");
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(reply, &eValue.count)) {
        AUDIO_FUNC_LOGE("Failed to get the value1 of the CTL element!");
        return HDF_FAILURE;
    }
    /* type: 0-AUDIO_CONTROL_MIXER (integer), 1-AUDIO_CONTROL_MUX (enum) */
    if (eValue.type == AUDIO_CONTROL_MIXER) {
        data->type = AUDIO_CTL_ELEM_TYPE_INTEGER;
        data->count = eValue.count; /* channels */
        data->value.intVal.min = eValue.min;
        data->value.intVal.max = eValue.max;
        data->value.intVal.step = 0; /* reserved */
    } else if (eValue.type == AUDIO_CONTROL_ENUM) {
        data->type = AUDIO_CTL_ELEM_TYPE_ENUMERATED;
        data->count = eValue.count; /* channels */
        data->value.intVal.min = eValue.min;
        data->value.intVal.max = eValue.max;
        data->value.intVal.step = 0; /* reserved */
    } else {
        AUDIO_FUNC_LOGI("type is AUDIO_CONTROL_MUX!");
    }

    return HDF_SUCCESS;
}

static int32_t AudioCtlElemInfoProp(const struct HdfIoService *srv, int cmdId, struct AudioMixerCtlElemInfo *data)
{
    int32_t ret;
    struct HdfSBuf *sBuf = NULL;
    struct HdfSBuf *reply = NULL;

    sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf!!!");
        return HDF_FAILURE;
    }

    ret = AudioFillInfoDataToBuf(sBuf, data);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, NULL);
        return ret;
    }

    reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply!!!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    struct HdfObject *service = (struct HdfObject *)(&srv->object);
    ret = srv->dispatcher->Dispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    ret = AudioParseInfoDataFromBuf(reply, data);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }
    AudioFreeHdfSBuf(sBuf, reply);

    return HDF_SUCCESS;
}

static int32_t AudioFillSetDataToBuf(struct HdfSBuf *sBuf, struct AudioMixerCtlElemInfo *data)
{
    struct AudioCtlElemValue eValue = {
        .id.cardServiceName = data->cardSrvName,
        .id.itemName = data->eIndexId.eId.name,
        .id.iface = data->eIndexId.eId.iface,
        .value[0] = data->value.intVal.vals[0],
        .value[1] = data->value.intVal.vals[1]
    };

    if (!HdfSbufWriteInt32(sBuf, eValue.value[0])) {
        AUDIO_FUNC_LOGE("Element iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, eValue.id.iface)) {
        AUDIO_FUNC_LOGE("Element iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, eValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("Element cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, eValue.id.itemName)) {
        AUDIO_FUNC_LOGE("Element itemName Write Fail!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioCtlElemSetProp(const struct HdfIoService *srv, int cmdId, struct AudioMixerCtlElemInfo *data)
{
    int32_t ret;
    struct HdfSBuf *sBuf = NULL;

    sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf!!!");
        return HDF_FAILURE;
    }

    ret = AudioFillSetDataToBuf(sBuf, data);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, NULL);
        return ret;
    }

    struct HdfObject *service = (struct HdfObject *)(&srv->object);
    ret = srv->dispatcher->Dispatch(service, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Dispatch failed!!!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }
    AudioFreeHdfSBuf(sBuf, NULL);

    return HDF_SUCCESS;
}

static int32_t AudioCtlElemRoute(const struct HdfIoService *service, OpCode cmdId, struct AudioMixerCtlElemInfo *data)
{
    int32_t ret;
    int32_t fOpcode = MIXER_CTL_IOCTL_ELEM_INFO - MIXER_CMD_ID_BASE;
    int32_t rOpcode = MIXER_CTL_IOCTL_ELEM_READ - MIXER_CMD_ID_BASE;
    int32_t wOpcode = MIXER_CTL_IOCTL_ELEM_WRITE - MIXER_CMD_ID_BASE;

    if (cmdId == MIXER_CTL_IOCTL_ELEM_INFO) {
        cmdId = fOpcode;
        return AudioCtlElemInfoProp(service, cmdId, data);
    }

    cmdId -= MIXER_CTL_IOCTL_ELEM_LIST - MIXER_CMD_ID_BASE;
    if (cmdId == rOpcode) { // Read element property.
        ret = AudioCtlElemGetProp(service, cmdId, data);
        if (ret != HDF_SUCCESS) {
            return ret;
        }
        ret = AudioCtlElemGetProp(service, fOpcode, data);
    } else if (cmdId == wOpcode) { // Write element property.
        ret = AudioCtlElemSetProp(service, cmdId, data);
    } else {
        AUDIO_FUNC_LOGE("Invalid opcode for the control!");
        ret = HDF_FAILURE;
    }

    return ret;
}

static int32_t AudioCtlGetElemCts(const struct HdfIoService *service, OpCode cmdId, struct AudioMixerCtlElemInfo *data)
{
    return AudioCtlElemRoute(service, cmdId, data);
}

static int32_t AudioCtlSetElemCts(const struct HdfIoService *srv, OpCode cmdId, struct AudioMixerCtlElemInfo *data)
{
    return AudioCtlElemRoute(srv, cmdId, data);
}

static int32_t AudioCtlRenderGetElemProp(
    const struct HdfIoService *service, OpCode cmdId, struct AudioMixerCtlElemInfo *data)
{
    int32_t ret;

    ret = AudioCtlGetElemCts(service, cmdId, data);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t AudioCtlCaptureGetElemProp(
    const struct HdfIoService *service, OpCode cmdId, struct AudioMixerCtlElemInfo *data)
{
    return AudioCtlRenderGetElemProp(service, cmdId, data);
}

static int32_t AudioMixerCtlGetElemProp(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data)
{
    struct AudioMixerCtlElemInfo *infoData = (struct AudioMixerCtlElemInfo *)data;

    return (pcm == PCM_CAPTURE) ? AudioCtlCaptureGetElemProp(service, cmd, infoData) :
                                  AudioCtlRenderGetElemProp(service, cmd, infoData);
}

static int32_t AudioCtlRenderSetElemProp(
    const struct HdfIoService *service, OpCode cmdId, struct AudioMixerCtlElemInfo *data)
{
    int32_t ret;

    ret = AudioCtlSetElemCts(service, cmdId, data);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to set the element!");
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t AudioCtlCaptureSetElemProp(
    const struct HdfIoService *service, int cmdId, struct AudioMixerCtlElemInfo *data)
{
    return AudioCtlRenderSetElemProp(service, cmdId, data);
}

static int32_t AudioMixerCtlSetElemProp(AudioPcmType pcm, OpCode cmd, const struct HdfIoService *service, void *data)
{
    struct AudioMixerCtlElemInfo *infoData = (struct AudioMixerCtlElemInfo *)data;

    return (pcm == PCM_CAPTURE) ? AudioCtlCaptureSetElemProp(service, cmd, infoData) :
                                  AudioCtlRenderSetElemProp(service, cmd, infoData);
}

int32_t AudioMixerCtlElem(AudioPcmType pcm, const struct HdfIoService *service, struct AudioMixerContents *mixerCts)
{
    OpCode cmd = MIXER_CTL_IOCTL_ELEM_LIST;
    AudioPcmType stream = (pcm == PCM_CAPTURE) ? PCM_CAPTURE : PCM_RENDER;

    if (service == NULL || mixerCts == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameters!");
        return HDF_FAILURE;
    }

    return AudioMixerCtlElemRoute(stream, service, cmd, mixerCts);
}

int32_t AudioMixerCtlGetElem(AudioPcmType pcm, const struct HdfIoService *srv, struct AudioMixerCtlElemInfo *infoData)
{
    OpCode cmd = MIXER_CTL_IOCTL_ELEM_GET_PROP;
    AudioPcmType stream = (pcm == PCM_CAPTURE) ? PCM_CAPTURE : PCM_RENDER;

    if (srv == NULL || infoData == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameters!");
        return HDF_FAILURE;
    }

    return AudioMixerCtlElemRoute(stream, srv, cmd, infoData);
}

int32_t AudioMixerCtlSetElem(
    AudioPcmType pcm, const struct HdfIoService *service, struct AudioMixerCtlElemInfo *infoData)
{
    OpCode cmd = MIXER_CTL_IOCTL_ELEM_SET_PROP;
    AudioPcmType stream = (pcm == PCM_CAPTURE) ? PCM_CAPTURE : PCM_RENDER;

    if (service == NULL || infoData == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameters!");
        return HDF_FAILURE;
    }

    return AudioMixerCtlElemRoute(stream, service, cmd, infoData);
}

int32_t AudioMixerGetAllAdapters(const struct HdfIoService *service, struct SndCardsList *clist)
{
    OpCode cmd = MIXER_CTL_IOCTL_GET_CARDS;

    if (service == NULL || clist == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameters!");
        return HDF_FAILURE;
    }

    return AudioMixerCtlElemRoute(PCM_BOTTOM, service, cmd, clist);
}
