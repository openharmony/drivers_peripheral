/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <securec.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "framework_common.h"
#include "hdf_base.h"
#include "inttypes.h"
#include "osal_mem.h"
#include "v5_0/audio_types.h"
#include "v5_0/iaudio_manager.h"

#define MAX_AUDIO_ADAPTER_DESC         5
#define AUDIO_CHANNELCOUNT             2
#define AUDIO_SAMPLE_RATE_48K          48000
#define PATH_LEN                       256
#define DEEP_BUFFER_RENDER_PERIOD_SIZE 4096
#define INT_32_MAX                     0x7fffffff
#define EXT_PARAMS_MAXLEN              107
#define BITS_TO_FROMAT                 3

struct StrPara {
    struct IAudioRender *render;
    FILE *file;
    struct AudioSampleAttributes attrs;
    uint64_t *replyBytes;
    char *frame;
    int32_t bufferSize;
};
struct IAudioAdapter *g_adapter = NULL;
static struct IAudioManager *g_audioManager = NULL;
struct AudioDeviceDescriptor g_devDesc;
struct AudioSampleAttributes g_attrs;
struct AudioPort g_audioPort;

char g_adapterName[PATH_LEN] = {0};
bool g_isDirect = false;

static int32_t InitAttrs(struct AudioSampleAttributes *attrs)
{
    if (attrs == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    attrs->format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs->channelCount = AUDIO_CHANNELCOUNT;
    attrs->sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs->interleaved = 0;
    attrs->type = AUDIO_IN_MEDIA;
    attrs->period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs->frameSize = PCM_16_BIT * attrs->channelCount / PCM_8_BIT;
    attrs->isBigEndian = false;
    attrs->isSignedData = true;
    attrs->startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs->frameSize);
    attrs->stopThreshold = INT_32_MAX;
    attrs->silenceThreshold = 0;
    return HDF_SUCCESS;
}

static int32_t InitDevDesc(struct AudioDeviceDescriptor *devDesc, uint32_t portId)
{
    if (devDesc == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    devDesc->portId = portId;
    devDesc->pins = PIN_OUT_SPEAKER;
    devDesc->desc = strdup("cardname");
    return HDF_SUCCESS;
}

void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (dataBlock->adapterName != NULL) {
        OsalMemFree(dataBlock->adapterName);
        dataBlock->adapterName = NULL;
    }

    if (dataBlock->ports != NULL) {
        OsalMemFree(dataBlock->ports);
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

static void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if (descsLen > 0 && descs != NULL && (*descs) != NULL) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = NULL;
    }
}

static int32_t GetManagerAndLoadAdapter(struct AudioPort *renderPort)
{
    int32_t adapterIndex = 0;

    if (renderPort == NULL) {
        AUDIO_FUNC_LOGE("The Parameter is NULL");
        return HDF_FAILURE;
    }

    struct IAudioManager *audioManagerIns = IAudioManagerGet(g_isDirect);
    if (audioManagerIns == NULL) {
        AUDIO_FUNC_LOGE("Get audio Manager Fail");
        return HDF_FAILURE;
    }

    g_audioManager = audioManagerIns;

    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (MAX_AUDIO_ADAPTER_DESC));
    if (descs == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc for descs failed");
        return HDF_FAILURE;
    }

    uint32_t adapterNum = MAX_AUDIO_ADAPTER_DESC;

    int32_t ret = audioManagerIns->GetAllAdapters(audioManagerIns, descs, &adapterNum);
    if (ret < 0 || adapterNum == 0) {
        AUDIO_FUNC_LOGE("Get All Adapters Fail");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (SelectAudioCard(descs, adapterNum, &adapterIndex) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (strcpy_s(g_adapterName, PATH_LEN, descs[adapterIndex - 1].adapterName) < 0) {
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (SwitchAudioPort(&descs[adapterIndex - 1], PORT_OUT, renderPort) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (audioManagerIns->LoadAdapter(audioManagerIns, &descs[adapterIndex - 1], &g_adapter)) {
        AUDIO_FUNC_LOGE("Load Adapter Fail");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }

    ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);

    return HDF_SUCCESS;
}

static int32_t InitRenderParam(uint32_t portId)
{
    if (g_adapter == NULL || g_adapter->InitAllPorts == NULL) {
        return HDF_FAILURE;
    }
    // Initialization port information, can fill through mode and other parameters
    (void)g_adapter->InitAllPorts(g_adapter);

    // User needs to set
    if (InitAttrs(&g_attrs) < 0) {
        AUDIO_FUNC_LOGE("InitAttrs failed");
        return HDF_FAILURE;
    }

    // Specify a hardware device
    if (InitDevDesc(&g_devDesc, portId) < 0) {
        AUDIO_FUNC_LOGE("InitDevDesc failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t RenderGetAdapterAndInitEnvParams(void)
{
    struct AudioPort renderPort;

    int32_t ret = GetManagerAndLoadAdapter(&renderPort);
    if (ret < 0) {
        return ret;
    }

    if (InitRenderParam(renderPort.portId) < 0) {
        g_audioManager->UnloadAdapter(g_audioManager, g_adapterName);
        IAudioAdapterRelease(g_adapter, g_isDirect);
        g_adapter = NULL;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t InitParam(void)
{
    /* Select loading mode,end */
    g_audioPort.dir = PORT_OUT;
    g_audioPort.portId = 0;
    g_audioPort.portName = "AOP";

    if (RenderGetAdapterAndInitEnvParams() < 0) {
        AUDIO_FUNC_LOGE("GetProxyManagerFunc Fail");
        if (g_audioManager != NULL) {
            IAudioManagerRelease(g_audioManager, g_isDirect);
            g_audioManager = NULL;
        }
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void AudioIpcTestInitFunc()
{
    if (InitParam() != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("InitParam fail!");
        return;
    }

    if (g_audioManager != NULL && g_audioManager->UnloadAdapter != NULL) {
        g_audioManager->UnloadAdapter(g_audioManager, g_adapterName);
        IAudioAdapterRelease(g_adapter, g_isDirect);
        g_adapter = NULL;
        IAudioManagerRelease(g_audioManager, g_isDirect);
        g_audioManager = NULL;
    }
    return;
}
