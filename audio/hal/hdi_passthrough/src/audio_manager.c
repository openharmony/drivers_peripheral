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

#include "audio_manager.h"
#include <limits.h>
#include "osal_mem.h"
#include "audio_adapter_info_common.h"
#include "audio_interface_lib_capture.h"
#include "audio_interface_lib_render.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_IMPL

static struct AudioManager g_audioManagerFuncs = {0};
static bool g_audioAdapterAddrMgrFlag = false;
struct AudioAdapterDescriptor *g_localAddrAudioAdapterOut = NULL; // add for Fuzz
int g_localAdapterNum = 0; // add for Fuzz

BindServiceRenderSo g_bindServiceRender = NULL;
InterfaceLibModeRenderSo g_interfaceLibModeRender = NULL;
CloseServiceRenderSo g_closeServiceRender = NULL;

BindServiceCaptureSo g_bindServiceCapture = NULL;
InterfaceLibModeCaptureSo g_interfaceLibModeCapture = NULL;
CloseServiceCaptureSo g_closeServiceCapture = NULL;

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
PathSelGetConfToJsonObj g_pathSelGetConfToJsonObj = NULL;
PathSelAnalysisJson g_pathSelAnalysisJson = NULL;
#endif

static const char *g_captureSoPath = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_capture");
static const char *g_renderSoPath = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_render");

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
static const char *g_pathSelectSoPath = HDF_LIBRARY_FULL_PATH("libhdi_audio_path_select");
#endif

static void *g_ptrCaptureHandle = NULL;
static void *g_ptrRenderHandle = NULL;

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
static void *g_ptrPathSelHandle = NULL;
#endif

BindServiceRenderSo *AudioSoGetBindServiceRender(void)
{
    return &g_bindServiceRender;
}

InterfaceLibModeRenderSo *AudioSoGetInterfaceLibModeRender(void)
{
    return &g_interfaceLibModeRender;
}

CloseServiceRenderSo *AudioSoGetCloseServiceRender(void)
{
    return &g_closeServiceRender;
}

BindServiceCaptureSo *AudioSoGetBindServiceCapture(void)
{
    return &g_bindServiceCapture;
}

InterfaceLibModeCaptureSo *AudioSoGetInterfaceLibModeCapture(void)
{
    return &g_interfaceLibModeCapture;
}

CloseServiceCaptureSo *AudioSoGetCloseServiceCapture(void)
{
    return &g_closeServiceCapture;
}


#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
PathSelGetConfToJsonObj *AudioSoGetPathSelGetConfToJsonObj(void)
{
    return &g_pathSelGetConfToJsonObj;
}

PathSelAnalysisJson *AudioSoGetPathSelAnalysisJson(void)
{
    return &g_pathSelAnalysisJson;
}
#endif

static int32_t InitCaptureSoHandle(const char *captureSoPath)
{
    if (captureSoPath == NULL) {
        AUDIO_FUNC_LOGE("captureSoPath is NULL");
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(captureSoPath, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    if (g_ptrCaptureHandle == NULL) {
        g_ptrCaptureHandle = dlopen(pathBuf, RTLD_LAZY);
        if (g_ptrCaptureHandle == NULL) {
            AUDIO_FUNC_LOGE("open lib capture so fail, reason:%{public}s", dlerror());
            return HDF_FAILURE;
        }
        g_bindServiceCapture = dlsym(g_ptrCaptureHandle, "AudioBindServiceCapture");
        g_interfaceLibModeCapture = dlsym(g_ptrCaptureHandle, "AudioInterfaceLibModeCapture");
        g_closeServiceCapture = dlsym(g_ptrCaptureHandle, "AudioCloseServiceCapture");
        if (g_bindServiceCapture == NULL || g_interfaceLibModeCapture == NULL || g_closeServiceCapture == NULL) {
            AUDIO_FUNC_LOGE("lib capture so func not found!");
            AudioDlClose(&g_ptrCaptureHandle);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

static int32_t InitRenderSoHandle(const char *renderSoPath)
{
    if (renderSoPath == NULL) {
        AUDIO_FUNC_LOGE("renderSoPath is NULL");
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(renderSoPath, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    if (g_ptrRenderHandle == NULL) {
        g_ptrRenderHandle = dlopen(pathBuf, RTLD_LAZY);
        if (g_ptrRenderHandle == NULL) {
            AUDIO_FUNC_LOGE("open lib render so fail, reason:%{public}s", dlerror());
            return HDF_FAILURE;
        }
        g_bindServiceRender = dlsym(g_ptrRenderHandle, "AudioBindServiceRender");
        g_interfaceLibModeRender = dlsym(g_ptrRenderHandle, "AudioInterfaceLibModeRender");
        g_closeServiceRender = dlsym(g_ptrRenderHandle, "AudioCloseServiceRender");
        if (g_bindServiceRender == NULL || g_interfaceLibModeRender == NULL || g_closeServiceRender == NULL) {
            AUDIO_FUNC_LOGE("lib render so func not found!");
            AudioDlClose(&g_ptrRenderHandle);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
static int32_t InitPathSelectSoHandle(const char *pathSelectSoPath)
{
    if (pathSelectSoPath == NULL) {
        AUDIO_FUNC_LOGE("pathSelectSoPath is NULL");
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(pathSelectSoPath, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    if (g_ptrPathSelHandle == NULL) {
        g_ptrPathSelHandle = dlopen(pathBuf, RTLD_LAZY);
        if (g_ptrPathSelHandle == NULL) {
            AUDIO_FUNC_LOGE("open lib PathSelct so fail, reason:%s", dlerror());
            return HDF_FAILURE;
        }
        g_pathSelGetConfToJsonObj = dlsym(g_ptrPathSelHandle, "AudioPathSelGetConfToJsonObj");
        g_pathSelAnalysisJson = dlsym(g_ptrPathSelHandle, "AudioPathSelAnalysisJson");
        if (g_pathSelGetConfToJsonObj == NULL || g_pathSelAnalysisJson == NULL) {
            AUDIO_FUNC_LOGE("lib PathSelct so func not found!");
            AudioDlClose(&g_ptrPathSelHandle);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}
#endif

int32_t AudioManagerGetAllAdapters(struct AudioManager *manager,
    struct AudioAdapterDescriptor **descs, int *size)
{
    AUDIO_FUNC_LOGI();
    if (manager == NULL || descs == NULL || size == NULL) {
        AUDIO_FUNC_LOGE("param manager or descs or size is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = AudioAdaptersForUser(descs, size);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioAdaptersForUser FAIL! ret = %{public}d", ret);
        return AUDIO_HAL_ERR_NOTREADY; // Failed to read sound card configuration file
    }
    if (g_captureSoPath == NULL || g_renderSoPath == NULL) {
        AUDIO_FUNC_LOGE("sopath is error");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (*descs != NULL && size != NULL && (*size) > 0) {
        g_localAddrAudioAdapterOut  = *descs;
        g_localAdapterNum = *size;
    } else {
        AUDIO_FUNC_LOGE("Get AudioAdapterDescriptor Failed");
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    ret = InitCaptureSoHandle(g_captureSoPath);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("InitCaptureSoHandle FAIL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = InitRenderSoHandle(g_renderSoPath);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("InitRenderSoHandle FAIL!");
        AudioDlClose(&g_ptrCaptureHandle);
        return AUDIO_HAL_ERR_INTERNAL;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    ret = InitPathSelectSoHandle(g_pathSelectSoPath);
    if (ret < 0 || g_pathSelGetConfToJsonObj == NULL) {
        AUDIO_FUNC_LOGE("InitPathSelectSoHandle FAIL!");
        AudioDlClose(&g_ptrRenderHandle);
        AudioDlClose(&g_ptrCaptureHandle);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = g_pathSelGetConfToJsonObj();
    if (ret < 0) {
        AUDIO_FUNC_LOGE("g_pathSelGetConfToJsonObj FAIL!");
        AudioDlClose(&g_ptrRenderHandle);
        AudioDlClose(&g_ptrCaptureHandle);
        AudioDlClose(&g_ptrPathSelHandle);
        return AUDIO_HAL_ERR_INTERNAL;
    }
#endif
    return AUDIO_HAL_SUCCESS;
}

static int32_t LoadAdapterPrimary(const struct AudioAdapterDescriptor *desc, struct AudioAdapter **adapter)
{
    if (desc == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("param desc or adapter is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)OsalMemCalloc(sizeof(*hwAdapter));
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("alloc AudioHwAdapter failed");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    hwAdapter->common.InitAllPorts = AudioAdapterInitAllPorts;
    hwAdapter->common.CreateRender = AudioAdapterCreateRender;
    hwAdapter->common.DestroyRender = AudioAdapterDestroyRender;
    hwAdapter->common.CreateCapture = AudioAdapterCreateCapture;
    hwAdapter->common.DestroyCapture = AudioAdapterDestroyCapture;
    hwAdapter->common.GetPortCapability = AudioAdapterGetPortCapability;
    hwAdapter->common.SetPassthroughMode = AudioAdapterSetPassthroughMode;
    hwAdapter->common.GetPassthroughMode = AudioAdapterGetPassthroughMode;
    hwAdapter->common.SetMicMute = AudioAdapterSetMicMute;
    hwAdapter->common.GetMicMute = AudioAdapterGetMicMute;
    hwAdapter->common.SetVoiceVolume = AudioAdapterSetVoiceVolume;
    hwAdapter->common.UpdateAudioRoute = AudioAdapterUpdateAudioRoute;
    hwAdapter->common.ReleaseAudioRoute = AudioAdapterReleaseAudioRoute;
    hwAdapter->common.SetExtraParams = AudioAdapterSetExtraParams;
    hwAdapter->common.GetExtraParams = AudioAdapterGetExtraParams;
    hwAdapter->adapterDescriptor = *desc;
    hwAdapter->adapterMgrRenderFlag = 0; // The adapterMgrRenderFlag init is zero
    hwAdapter->adapterMgrCaptureFlag = 0; // The adapterMgrCaptureFlag init is zero
    int32_t ret = AudioAddAdapterAddrToList((AudioHandle)(&hwAdapter->common), desc);
    if (ret < 0) { // add for Fuzz
        AUDIO_FUNC_LOGE("AudioAdapterAddrGet check Failed");
        AudioMemFree((void **)&hwAdapter);
        return ret;
    }
    *adapter = &hwAdapter->common;

    return AUDIO_HAL_SUCCESS;
}

static int32_t LoadAdapterUsb(const struct AudioAdapterDescriptor *desc, struct AudioAdapter **adapter)
{
    if (desc == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("param attrs or adapter is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)OsalMemCalloc(sizeof(*hwAdapter));
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("alloc AudioHwAdapter failed");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    hwAdapter->common.InitAllPorts = AudioAdapterInitAllPorts;
    hwAdapter->common.CreateRender = AudioAdapterCreateRender;
    hwAdapter->common.DestroyRender = AudioAdapterDestroyRender;
    hwAdapter->common.CreateCapture = AudioAdapterCreateCapture;
    hwAdapter->common.DestroyCapture = AudioAdapterDestroyCapture;
    hwAdapter->common.GetPortCapability = AudioAdapterGetPortCapability;
    hwAdapter->common.SetPassthroughMode = AudioAdapterSetPassthroughMode;
    hwAdapter->common.GetPassthroughMode = AudioAdapterGetPassthroughMode;
    hwAdapter->common.UpdateAudioRoute = AudioAdapterUpdateAudioRoute;
    hwAdapter->common.ReleaseAudioRoute = AudioAdapterReleaseAudioRoute;
    hwAdapter->adapterDescriptor = *desc;
    hwAdapter->adapterMgrRenderFlag = 0; // The adapterMgrRenderFlag init is zero
    hwAdapter->adapterMgrCaptureFlag = 0; // The adapterMgrCaptureFlag init is zero
    int32_t ret = AudioAddAdapterAddrToList((AudioHandle)(&hwAdapter->common), desc);
    if (ret < 0) { // add for Fuzz
        AUDIO_FUNC_LOGE("AudioAdapterAddrGet check Failed");
        AudioMemFree((void **)&hwAdapter);
        return ret;
    }
    *adapter = &hwAdapter->common;

    return AUDIO_HAL_SUCCESS;
}

static int32_t LoadAdapterA2dp(const struct AudioAdapterDescriptor *desc, struct AudioAdapter **adapter)
{
    if (desc == NULL || adapter == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    return AUDIO_HAL_SUCCESS;
}

static int32_t SelectAppropriateAdapter(enum AudioAdapterType adapterType,
    const struct AudioAdapterDescriptor *desc, struct AudioAdapter **adapter)
{
    int32_t ret;

    if (desc == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("param desc or adapter is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    switch (adapterType) {
        case AUDIO_ADAPTER_PRIMARY:
        case AUDIO_ADAPTER_PRIMARY_EXT:
            ret = LoadAdapterPrimary(desc, adapter);
            if (ret != AUDIO_HAL_SUCCESS) {
                AUDIO_FUNC_LOGE("LoadAdapterPrimary failed. ret = %{public}d", ret);
                return ret;
            }
            break;
        case AUDIO_ADAPTER_USB:
            ret = LoadAdapterUsb(desc, adapter);
            if (ret != AUDIO_HAL_SUCCESS) {
                AUDIO_FUNC_LOGE("LoadAdapterUsb failed.ret = %{public}d", ret);
                return ret;
            }
            AUDIO_FUNC_LOGE("Can't LoadAdapterUsb.");
            break;
        case AUDIO_ADAPTER_A2DP:
            ret = LoadAdapterA2dp(desc, adapter);
            if (ret != AUDIO_HAL_SUCCESS) {
                AUDIO_FUNC_LOGE("LoadAdapterA2dp failed.");
                return ret;
            }
            break;
        default:
            AUDIO_FUNC_LOGE("An unsupported Adapter.");
            return AUDIO_HAL_ERR_NOT_SUPPORT;
    }

    return AUDIO_HAL_SUCCESS;
}

int32_t AudioManagerLoadAdapter(struct AudioManager *manager, const struct AudioAdapterDescriptor *desc,
    struct AudioAdapter **adapter)
{
    AUDIO_FUNC_LOGI();
    if (manager == NULL || desc == NULL || desc->adapterName == NULL || desc->ports == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("param is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    bool descFlag = false;
    if (g_localAdapterNum <= 0 || g_localAdapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("g_localAdapterNum is invalid!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (g_localAddrAudioAdapterOut != NULL) {
        for (int index = 0; index < g_localAdapterNum; index++) {
            if (&g_localAddrAudioAdapterOut[index] == desc) {
                descFlag = true;
                break;
            }
        }
        if (!descFlag) {
            AUDIO_FUNC_LOGE("The desc address passed in is invalid");
            return AUDIO_HAL_ERR_INVALID_OBJECT;
        }
    }
    AUDIO_FUNC_LOGI("adapter name %{public}s", desc->adapterName);
    if (AudioAdapterExist(desc->adapterName)) {
        AUDIO_FUNC_LOGE("not supported this adapter %{public}s", desc->adapterName);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    enum AudioAdapterType sndCardType = MatchAdapterType(desc->adapterName, desc->ports[0].portId);
    int32_t ret = SelectAppropriateAdapter(sndCardType, desc, adapter);
    if (ret != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("Load adapter failed. ret = %{public}d\n", ret);
        return ret;
    }

    return AUDIO_HAL_SUCCESS;
}

void AudioManagerUnloadAdapter(struct AudioManager *manager, struct AudioAdapter *adapter)
{
    int32_t ret = AudioCheckAdapterAddr((AudioHandle)adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid! ret = %{public}d", ret);
        return;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (manager == NULL || hwAdapter == NULL) {
        return;
    }
    if (hwAdapter->portCapabilitys != NULL) {
        uint32_t portNum = hwAdapter->adapterDescriptor.portNum;
        uint32_t i = 0;
        while (i < portNum) {
            if (&hwAdapter->portCapabilitys[i] != NULL) {
                AudioMemFree((void **)&hwAdapter->portCapabilitys[i].capability.subPorts);
            }
            i++;
        }
        AudioMemFree((void **)&hwAdapter->portCapabilitys);
    }
    if (AudioDelAdapterAddrFromList((AudioHandle)adapter)) {
        AUDIO_FUNC_LOGE("adapter or render not in MgrList");
    }
    AudioMemFree((void **)&adapter);
}

bool ReleaseAudioManagerObject(struct AudioManager *object)
{
    if (object != (&g_audioManagerFuncs) || object == NULL) {
        return false;
    }
    ReleaseAudioManagerObjectComm(object);
    g_audioAdapterAddrMgrFlag = false;
    return true;
}

static void AudioMgrConstruct(struct AudioManager *audioMgr)
{
    if (audioMgr == NULL) {
        AUDIO_FUNC_LOGE("Input pointer is null!");
        return;
    }
    audioMgr->GetAllAdapters = AudioManagerGetAllAdapters;
    audioMgr->LoadAdapter = AudioManagerLoadAdapter;
    audioMgr->UnloadAdapter = AudioManagerUnloadAdapter;
    audioMgr->ReleaseAudioManagerObject = ReleaseAudioManagerObject;
}

struct AudioManager *GetAudioManagerFuncs(void)
{
    if (!g_audioAdapterAddrMgrFlag) {
        AudioAdapterAddrMgrInit(); // memset for Fuzz
        AudioMgrConstruct(&g_audioManagerFuncs);
        g_audioAdapterAddrMgrFlag = true;
    }
    return &g_audioManagerFuncs;
}
