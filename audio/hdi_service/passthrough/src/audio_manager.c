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

#include <dlfcn.h>
#include <limits.h>
#include <unistd.h>
#include "hdf_base.h"
#include "hdf_types.h"
#include "osal_mem.h"
#include "securec.h"
#include "stub_collector.h"
#include "audio_adapter_info_common.h"
#include "audio_common.h"
#include "audio_uhdf_log.h"
#include "audio_internal.h"

#define HDF_LOG_TAG AUDIO_HDI_IMPL

BindServiceRenderPassthrough g_bindServiceRender = NULL;
InterfaceLibModeRenderPassthrough g_interfaceLibModeRender = NULL;
CloseServiceRenderPassthrough g_closeServiceRender = NULL;

BindServiceCapturePassthrough g_bindServiceCapture = NULL;
InterfaceLibModeCapturePassthrough g_interfaceLibModeCapture = NULL;
CloseServiceCapturePassthrough g_closeServiceCapture = NULL;

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
PathSelGetConfToJsonObj g_pathSelGetConfToJsonObj = NULL;
PathSelAnalysisJson g_pathSelAnalysisJson = NULL;
#endif

static const char *g_capturePassthroughPath = HDF_LIBRARY_FULL_PATH("libhdi_audio_capture");
static const char *g_renderPassthroughPath = HDF_LIBRARY_FULL_PATH("libhdi_audio_render");

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
static const char *g_pathSelectPassthroughPath = HDF_LIBRARY_FULL_PATH("libhdi_idl_audio_path_select");
#endif

static void *g_ptrCaptureHandle = NULL;
static void *g_ptrRenderHandle = NULL;

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
static void *g_ptrPathSelHandle = NULL;
#endif

BindServiceRenderPassthrough *AudioPassthroughGetBindServiceRender(void)
{
    return &g_bindServiceRender;
}

InterfaceLibModeRenderPassthrough *AudioPassthroughGetInterfaceLibModeRender(void)
{
    return &g_interfaceLibModeRender;
}

CloseServiceRenderPassthrough *AudioPassthroughGetCloseServiceRender(void)
{
    return &g_closeServiceRender;
}

BindServiceCapturePassthrough *AudioPassthroughGetBindServiceCapture(void)
{
    return &g_bindServiceCapture;
}

InterfaceLibModeCapturePassthrough *AudioPassthroughGetInterfaceLibModeCapture(void)
{
    return &g_interfaceLibModeCapture;
}

CloseServiceCapturePassthrough *AudioPassthroughGetCloseServiceCapture(void)
{
    return &g_closeServiceCapture;
}

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
PathSelGetConfToJsonObj *AudioPassthroughGetPathSelGetConfToJsonObj(void)
{
    return &g_pathSelGetConfToJsonObj;
}

PathSelAnalysisJson *AudioPassthroughGetPathSelAnalysisJson(void)
{
    return &g_pathSelAnalysisJson;
}
#endif

static int32_t InitCapturePassthroughHandle(const char *capturePassthroughPath)
{
    if (capturePassthroughPath == NULL) {
        AUDIO_FUNC_LOGE("capturePassthroughPath is NULL");
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(capturePassthroughPath, pathBuf) == NULL) {
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

static int32_t InitRenderPassthroughHandle(const char *renderPassthroughPath)
{
    if (renderPassthroughPath == NULL) {
        AUDIO_FUNC_LOGE("renderPassthroughPath is NULL");
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(renderPassthroughPath, pathBuf) == NULL) {
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
static int32_t InitPathSelectPassthroughHandle(const char *pathSelectPassthroughPath)
{
    if (pathSelectPassthroughPath == NULL) {
        AUDIO_FUNC_LOGE("pathSelectPassthroughPath is NULL");
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(pathSelectPassthroughPath, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    if (g_ptrPathSelHandle == NULL) {
        g_ptrPathSelHandle = dlopen(pathBuf, RTLD_LAZY);
        if (g_ptrPathSelHandle == NULL) {
            AUDIO_FUNC_LOGE("open lib PathSelct so fail, reason:%{public}s", dlerror());
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

static int32_t AudioManagerServiceGetFreeAdapterPos(struct IAudioManager *manager, const char *adapterName)
{
    int32_t i;
    if (manager == NULL || adapterName == NULL || strlen(adapterName) == 0) {
        AUDIO_FUNC_LOGE("Invalid input param!");
        return SUPPORT_ADAPTER_NUM_MAX;
    }

    struct AudioHwManager *audioManagerSer = (struct AudioHwManager *)manager;
    for (i = 0; i < SUPPORT_ADAPTER_NUM_MAX; i++) {
        if (!strncmp(adapterName, audioManagerSer->adapterInfos[i].adapterName, ADAPTER_NAME_LEN)) {
            AUDIO_FUNC_LOGE("adapterName(%{public}s) already load!", adapterName);
            return SUPPORT_ADAPTER_NUM_MAX;
        }
    }

    for (i = 0; i < SUPPORT_ADAPTER_NUM_MAX; i++) {
        if (strlen(audioManagerSer->adapterInfos[i].adapterName) == 0 &&
            audioManagerSer->adapterInfos[i].adapterServicePtr == NULL) {
            return i;
        }
    }

    AUDIO_FUNC_LOGE("no free pos!");
    return SUPPORT_ADAPTER_NUM_MAX;
}

static int32_t AudioManagerServiceAddAdapter(
    struct IAudioManager *manager, struct IAudioAdapter *adapter, int32_t pos)
{
    struct AudioHwManager *hwManager = (struct AudioHwManager *)manager;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;

    if (hwManager == NULL) {
        AUDIO_FUNC_LOGE("audioManagerSer is null!");
        return AUDIO_ERR_INVALID_PARAM;
    }
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("adapterName is null!");
        return AUDIO_ERR_INVALID_PARAM;
    }
    if (pos >= SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("pos out of range!");
        return AUDIO_ERR_INVALID_PARAM;
    }
    int32_t ret = strncpy_s(hwManager->adapterInfos[pos].adapterName, ADAPTER_NAME_LEN,
        hwAdapter->adapterDescriptor.adapterName, strlen(hwAdapter->adapterDescriptor.adapterName));
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s for adapterName failed!");
        return AUDIO_ERR_INTERNAL;
    }

    hwManager->adapterInfos[pos].adapterServicePtr = hwAdapter;
    return AUDIO_SUCCESS;
}

static uint32_t AudioManagerServiceFindAdapterPos(struct IAudioManager *manager, const char *adapterName)
{
    uint32_t i;
    if (manager == NULL || adapterName == NULL || strlen(adapterName) == 0) {
        AUDIO_FUNC_LOGE("Invalid input param!");
        return SUPPORT_ADAPTER_NUM_MAX;
    }

    struct AudioHwManager *audioManagerSer = (struct AudioHwManager *)manager;
    for (i = 0; i < SUPPORT_ADAPTER_NUM_MAX; i++) {
        if (strncmp(adapterName, audioManagerSer->adapterInfos[i].adapterName, ADAPTER_NAME_LEN) == 0 &&
            audioManagerSer->adapterInfos[i].adapterServicePtr != NULL) {
            return i;
        }
    }

    AUDIO_FUNC_LOGE("can not find adapterName(%{public}s)!", adapterName);
    return SUPPORT_ADAPTER_NUM_MAX;
}

int32_t AudioManagerGetAllAdapters(struct IAudioManager *manager, struct AudioAdapterDescriptor *descs, uint32_t *size)
{
    AUDIO_FUNC_LOGI("enter!");
    if (manager == NULL || descs == NULL || size == NULL) {
        return AUDIO_ERR_INVALID_PARAM;
    }
    int32_t ret = AudioAdaptersForUser(descs, size);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioAdaptersForUser FAIL!");
        return AUDIO_ERR_NOTREADY; // Failed to read sound card configuration file
    }
    if (g_capturePassthroughPath == NULL || g_renderPassthroughPath == NULL) {
        AUDIO_FUNC_LOGE("sopath is error");
        return AUDIO_ERR_INTERNAL;
    }
    ret = InitCapturePassthroughHandle(g_capturePassthroughPath);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("InitCapturePassthroughHandle FAIL!");
        return AUDIO_ERR_INTERNAL;
    }
    ret = InitRenderPassthroughHandle(g_renderPassthroughPath);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("InitRenderPassthroughHandle FAIL!");
        AudioDlClose(&g_ptrCaptureHandle);
        return AUDIO_ERR_INTERNAL;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    ret = InitPathSelectPassthroughHandle(g_pathSelectPassthroughPath);
    if (ret < 0 || g_pathSelGetConfToJsonObj == NULL) {
        AUDIO_FUNC_LOGE("InitPathSelectPassthroughHandle FAIL!");
        AudioDlClose(&g_ptrRenderHandle);
        AudioDlClose(&g_ptrCaptureHandle);
        return AUDIO_ERR_INTERNAL;
    }
    ret = g_pathSelGetConfToJsonObj();
    if (ret < 0) {
        AUDIO_FUNC_LOGE("g_pathSelGetConfToJsonObj FAIL!");
        AudioDlClose(&g_ptrRenderHandle);
        AudioDlClose(&g_ptrCaptureHandle);
        AudioDlClose(&g_ptrPathSelHandle);
        return AUDIO_ERR_INTERNAL;
    }
#endif
    return AUDIO_SUCCESS;
}

static int32_t LoadAdapterImpl(const struct AudioAdapterDescriptor *desc, struct IAudioAdapter **adapter)
{
    if (desc == NULL || adapter == NULL) {
        return AUDIO_ERR_INVALID_PARAM;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)OsalMemCalloc(sizeof(struct AudioHwAdapter));
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc AudioHwAdapter failed");
        return AUDIO_ERR_MALLOC_FAIL;
    }

    hwAdapter->common.InitAllPorts = AudioAdapterInitAllPorts;
    hwAdapter->common.CreateRender = AudioAdapterCreateRender;
    hwAdapter->common.DestroyRender = AudioAdapterDestroyRender;
    hwAdapter->common.CreateCapture = AudioAdapterCreateCapture;
    hwAdapter->common.DestroyCapture = AudioAdapterDestroyCapture;
    hwAdapter->common.GetPortCapability = AudioAdapterGetPortCapability;
    hwAdapter->common.SetPassthroughMode = AudioAdapterSetPassthroughMode;
    hwAdapter->common.GetPassthroughMode = AudioAdapterGetPassthroughMode;
    hwAdapter->common.GetDeviceStatus = AudioAdapterGetDeviceStatus;
    hwAdapter->adapterDescriptor = *desc;

    *adapter = &(hwAdapter->common);
    return AUDIO_SUCCESS;
}

static int32_t LoadAdapterPrimary(const struct AudioAdapterDescriptor *desc, struct IAudioAdapter **adapter)
{
    if (desc == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("primary desc or adapter is null");
        return AUDIO_ERR_INVALID_PARAM;
    }

    int32_t ret = LoadAdapterImpl(desc, adapter);
    if (ret != AUDIO_SUCCESS) {
        return ret;
    }

    return AUDIO_SUCCESS;
}

static int32_t LoadAdapterUsb(const struct AudioAdapterDescriptor *desc, struct IAudioAdapter **adapter)
{
    if (desc == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("usb desc or adapter is null");
        return AUDIO_ERR_INVALID_PARAM;
    }

    int32_t ret = LoadAdapterImpl(desc, adapter);
    if (ret != AUDIO_SUCCESS) {
        return ret;
    }

    return AUDIO_SUCCESS;
}

static int32_t LoadAdapterA2dp(const struct AudioAdapterDescriptor *desc, struct IAudioAdapter **adapter)
{
    if (desc == NULL || adapter == NULL) {
        return AUDIO_ERR_INVALID_PARAM;
    }

    return AUDIO_ERR_NOT_SUPPORT;
}

static int32_t SelectAppropriateAdapter(
    enum AudioAdapterType adapterType, const struct AudioAdapterDescriptor *desc, struct IAudioAdapter **adapter)
{
    int32_t ret;

    if (desc == NULL || adapter == NULL) {
        return AUDIO_ERR_INVALID_PARAM;
    }
    switch (adapterType) {
        case AUDIO_ADAPTER_PRIMARY:
        case AUDIO_ADAPTER_PRIMARY_EXT:
            ret = LoadAdapterPrimary(desc, adapter);
            if (ret != AUDIO_SUCCESS) {
                AUDIO_FUNC_LOGE("LoadAdapterPrimary failed.");
                return ret;
            }
            break;
        case AUDIO_ADAPTER_USB:
            ret = LoadAdapterUsb(desc, adapter);
            if (ret != AUDIO_SUCCESS) {
                AUDIO_FUNC_LOGE("LoadAdapterUsb failed.");
                return ret;
            }
            break;
        case AUDIO_ADAPTER_A2DP:
            ret = LoadAdapterA2dp(desc, adapter);
            if (ret != AUDIO_SUCCESS) {
                AUDIO_FUNC_LOGE("LoadAdapterA2dp failed.");
                return ret;
            }
            break;
        default:
            AUDIO_FUNC_LOGE("An unsupported Adapter.");
            return AUDIO_ERR_NOT_SUPPORT;
    }

    return AUDIO_SUCCESS;
}

static int32_t AudioManagerServiceRemvAdapter(struct IAudioManager *manager, uint32_t pos)
{
    if (manager == NULL || pos >= SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("Invalid input param!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    struct AudioHwManager *audioManagerSer = (struct AudioHwManager *)manager;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)audioManagerSer->adapterInfos[pos].adapterServicePtr;

    StubCollectorRemoveObject(IAUDIOADAPTER_INTERFACE_DESC, hwAdapter);

    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("manager == NULL || hwAdapter == NULL");
        return AUDIO_ERR_INVALID_PARAM;
    }
    if (hwAdapter->portCapabilitys != NULL) {
        uint32_t portsLen = hwAdapter->adapterDescriptor.portsLen;
        uint32_t i = 0;
        while (i < portsLen) {
            if (&hwAdapter->portCapabilitys[i] != NULL) {
                AudioMemFree((void **)&hwAdapter->portCapabilitys[i].capability.subPorts);
            }
            i++;
        }
        AudioMemFree((void **)&hwAdapter->portCapabilitys);
    }

    AudioMemFree((void **)&hwAdapter);
    audioManagerSer->adapterInfos[pos].adapterServicePtr = NULL;

    (void)memset_s(audioManagerSer->adapterInfos[pos].adapterName, ADAPTER_NAME_LEN, 0, ADAPTER_NAME_LEN);

    return AUDIO_SUCCESS;
}

int32_t AudioManagerLoadAdapter(
    struct IAudioManager *manager, const struct AudioAdapterDescriptor *desc, struct IAudioAdapter **adapter)
{
    if (manager == NULL || desc == NULL || desc->adapterName == NULL || desc->ports == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("Invalid input param!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    AUDIO_FUNC_LOGI("adapter name %{public}s", desc->adapterName);
    int32_t index = AudioAdapterExist(desc->adapterName);
    if (index < 0) {
        AUDIO_FUNC_LOGE("not supported this adapter %{public}s", desc->adapterName);
        return AUDIO_ERR_INVALID_PARAM;
    }

    int32_t pos = AudioManagerServiceGetFreeAdapterPos(manager, desc->adapterName);
    if (pos >= SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("AudioManagerServiceGetFreeAdapterPos failed!");
        return HDF_FAILURE;
    }

    enum AudioAdapterType sndCardType = MatchAdapterType(desc->adapterName, desc->ports[0].portId);
    int32_t ret = SelectAppropriateAdapter(sndCardType, &(AudioAdapterGetConfigDescs()[index]), adapter);
    if (ret != AUDIO_SUCCESS) {
        AUDIO_FUNC_LOGE("Load adapter failed.");
        return ret;
    }

    ret = AudioManagerServiceAddAdapter(manager, *adapter, pos);
    if (ret != AUDIO_SUCCESS) {
        AUDIO_FUNC_LOGE("Add adapter to list failed.");
        AudioManagerServiceRemvAdapter(manager, pos);
        return ret;
    }

    return AUDIO_SUCCESS;
}

int32_t AudioManagerUnloadAdapter(struct IAudioManager *manager, const char *adapterName)
{
    uint32_t pos = AudioManagerServiceFindAdapterPos(manager, adapterName);
    if (pos >= SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("AudioManagerServiceUnloadAdapter failed!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    int ret = AudioManagerServiceRemvAdapter(manager, pos);
    if (ret != AUDIO_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioManagerServiceRemvAdapter failed!");
        return ret;
    }

    AUDIO_FUNC_LOGI("AudioManagerUnloadAdapter success!");
    return AUDIO_SUCCESS;
}

int32_t ReleaseAudioManagerObject(struct IAudioManager *object)
{
    ReleaseAudioManagerObjectComm(object);
    return AUDIO_SUCCESS;
}

struct IAudioManager *AudioManagerImplGetInstance(const char *serviceName)
{
    (void)serviceName;
    struct AudioHwManager *service = (struct AudioHwManager *)OsalMemCalloc(sizeof(struct AudioHwManager));
    if (service == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc failed!");
        return NULL;
    }
    service->interface.GetAllAdapters = AudioManagerGetAllAdapters;
    service->interface.LoadAdapter = AudioManagerLoadAdapter;
    service->interface.UnloadAdapter = AudioManagerUnloadAdapter;
    service->interface.ReleaseAudioManagerObject = ReleaseAudioManagerObject;
    return &(service->interface);
}

void AudioManagerImplRelease(struct IAudioManager *instance)
{
    ReleaseAudioManagerObject(instance);
}
