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

#include "audio_proxy_common.h"
#include "audio_proxy_manager.h"

#define AUDIO_HDF_SBUF_IPC 1
#define PROXY_VOLUME_CHANGE 100

struct HDIAudioManager *g_serviceObj;


struct HdfSBuf *AudioProxyObtainHdfSBuf()
{
    enum HdfSbufType bufType;
#ifdef AUDIO_HDF_SBUF_IPC
    bufType = SBUF_IPC;
#else
    bufType = SBUF_RAW;
#endif
    return HdfSBufTypedObtain(bufType);
}

static void ProxyMgrConstruct(struct AudioManager *proxyMgr)
{
    proxyMgr->GetAllAdapters = AudioProxyManagerGetAllAdapters;
    proxyMgr->LoadAdapter = AudioProxyManagerLoadAdapter;
    proxyMgr->UnloadAdapter = AudioProxyManagerUnloadAdapter;
}

struct AudioManager *HdfProxyIoBindServiceName(const char *serviceName)
{
    LOG_FUN_INFO();
    if (serviceName == NULL) {
        LOG_FUN_ERR("ServiceName is null");
        return NULL;
    }
    struct HDIServiceManager *serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == NULL) {
        return NULL;
    }
    struct HdfRemoteService *remote = serviceMgr->GetService(serviceMgr, serviceName);
    if (remote == NULL) {
        LOG_FUN_ERR("Remote GetService failed!");
        HDIServiceManagerRelease(serviceMgr);
        return NULL;
    }
    HDIServiceManagerRelease(serviceMgr);
    g_serviceObj = OsalMemAlloc(sizeof(struct HDIAudioManager));
    if (g_serviceObj == NULL) {
        LOG_FUN_ERR("malloc failed!");
        HdfRemoteServiceRecycle(remote);
        return NULL;
    }
    g_serviceObj->remote = remote;
    ProxyMgrConstruct(&g_serviceObj->proxyAudioManager);
    return &g_serviceObj->proxyAudioManager;
}

int32_t AudioProxyDispatchCall(int32_t id, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data == NULL || reply == NULL || g_serviceObj == NULL) {
        return HDF_FAILURE;
    }
    if (g_serviceObj->remote == NULL || g_serviceObj->remote->dispatcher == NULL ||
        g_serviceObj->remote->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("AudioProxyDispatchCall obj is null");
        return HDF_ERR_INVALID_OBJECT;
    }
    return g_serviceObj->remote->dispatcher->Dispatch(g_serviceObj->remote, id, data, reply);
}

void AudioProxyBufReplyRecycle(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data != NULL) {
        HdfSBufRecycle(data);
    }
    if (reply != NULL) {
        HdfSBufRecycle(reply);
    }
    return;
}

int32_t AudioProxyPreprocessSBuf(struct HdfSBuf **data, struct HdfSBuf **reply)
{
    if (data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    *data = AudioProxyObtainHdfSBuf();
    if (*data == NULL) {
        LOG_FUN_ERR("Failed to obtain data");
        return HDF_FAILURE;
    }
    *reply = AudioProxyObtainHdfSBuf();
    if (*reply == NULL) {
        LOG_FUN_ERR("Failed to obtain reply");
        HdfSBufRecycle(*data);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyPreprocessRender(AudioHandle render, struct HdfSBuf **data, struct HdfSBuf **reply)
{
    if (data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    const char *adapterName;
    uint32_t renderPid = getpid();
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    if (hwRender == NULL) {
        return HDF_FAILURE;
    }
    adapterName = hwRender->renderParam.renderMode.hwInfo.adapterName;
    if (AudioProxyPreprocessSBuf(data, reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(*data, adapterName)) {
        AudioProxyBufReplyRecycle(*data, *reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(*data, renderPid)) {
        AudioProxyBufReplyRecycle(*data, *reply);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyPreprocessCapture(AudioHandle capture, struct HdfSBuf **data, struct HdfSBuf **reply)
{
    if (data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    const char *adapterName;
    uint32_t capturePid = getpid();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    if (hwCapture == NULL) {
        return HDF_FAILURE;
    }
    adapterName = hwCapture->captureParam.captureMode.hwInfo.adapterName;
    if (AudioProxyPreprocessSBuf(data, reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(*data, adapterName)) {
        AudioProxyBufReplyRecycle(*data, *reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(*data, capturePid)) {
        AudioProxyBufReplyRecycle(*data, *reply);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyWriteSampleAttributes(struct HdfSBuf *data, const struct AudioSampleAttributes *attrs)
{
    if (data == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)attrs->type)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)attrs->interleaved)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)attrs->format)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->sampleRate)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->channelCount)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->period)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->frameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)(attrs->isBigEndian))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)(attrs->isSignedData))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->startThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->stopThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->silenceThreshold)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyReadSapmleAttrbutes(struct HdfSBuf *reply, struct AudioSampleAttributes *attrs)
{
    if (reply == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempType = 0;
    if (!HdfSbufReadUint32(reply, &tempType)) {
        return HDF_FAILURE;
    }
    attrs->type = (enum AudioCategory)tempType;
    uint32_t tempInterleaved = 0;
    if (!HdfSbufReadUint32(reply, &tempInterleaved)) {
        return HDF_FAILURE;
    }
    attrs->interleaved = (bool)tempInterleaved;
    uint32_t tempFormat = 0;
    if (!HdfSbufReadUint32(reply, &tempFormat)) {
        return HDF_FAILURE;
    }
    attrs->format = (enum AudioFormat)tempFormat;
    if (!HdfSbufReadUint32(reply, &attrs->sampleRate)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &attrs->channelCount)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &attrs->period)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &attrs->frameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &tempInterleaved)) {
        return HDF_FAILURE;
    }
    attrs->isBigEndian = (bool)tempInterleaved;
    if (!HdfSbufReadUint32(reply, &tempInterleaved)) {
        return HDF_FAILURE;
    }
    attrs->isSignedData = (bool)tempInterleaved;
    if (!HdfSbufReadUint32(reply, &attrs->startThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &attrs->stopThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &attrs->silenceThreshold)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyCommonSetCtrlParam(int cmId, AudioHandle handle, float param)
{
    LOG_FUN_INFO();
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (cmId == AUDIO_HDI_RENDER_SET_VOLUME || cmId == AUDIO_HDI_CAPTURE_SET_VOLUME) {
        if (param < 0 || param > 1.0) {
            LOG_FUN_ERR("volume param Is error!");
            return HDF_FAILURE;
        }
        param = param * PROXY_VOLUME_CHANGE;
    }
    if (cmId == AUDIO_HDI_RENDER_SET_GAIN || cmId == AUDIO_HDI_CAPTURE_SET_GAIN) {
        if (param < 0) {
            LOG_FUN_ERR("Set gain is error, Please check param!");
            return HDF_FAILURE;
        }
    }
    if (cmId >= AUDIO_HDI_CAPTURE_CREATE_CAPTURE) {
        if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
            return HDF_FAILURE;
        }
    } else {
        if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
            return HDF_FAILURE;
        }
    }
    uint32_t tempParam = (uint32_t)param;
    if (!HdfSbufWriteUint32(data, tempParam)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(cmId, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCommonGetCtrlParam(int cmId, AudioHandle handle, float *param)
{
    LOG_FUN_INFO();
    if (param == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (cmId >= AUDIO_HDI_CAPTURE_CREATE_CAPTURE) {
        if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
            return HDF_FAILURE;
        }
    } else {
        if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
            return HDF_FAILURE;
        }
    }
    int32_t ret = AudioProxyDispatchCall(cmId, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    uint32_t tempParam;
    if (!HdfSbufReadUint32(reply, &tempParam)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    if (cmId == AUDIO_HDI_RENDER_GET_VOLUME || cmId == AUDIO_HDI_CAPTURE_GET_VOLUME) {
        *param = (float)tempParam / PROXY_VOLUME_CHANGE;
    } else {
        *param = (float)tempParam;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}
