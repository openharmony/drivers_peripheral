/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "audio_manager_vendor.h"

#include <dlfcn.h>
#include <malloc.h>
#include <hdf_base.h>
#include "audio_adapter_vendor.h"
#include "audio_uhdf_log.h"
#include "i_audio_manager.h"
#include "osal_mem.h"
#include "v1_0/audio_types.h"
#include "v1_0/iaudio_adapter.h"
#include "v1_0/iaudio_manager.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

typedef struct AudioHwiManager* (*GetAudioHwiManagerFuncs)(void);

struct AudioHwiManagerPriv {
    struct IAudioManager interface;
    void *handle;
    GetAudioHwiManagerFuncs managerFuncs;
    struct AudioHwiManager *hwiManager;
    struct AudioAdapterDescriptor descs[AUDIO_HW_ADAPTER_NUM_MAX];
    uint32_t descsCount;
    struct AudioAdapterHwiDescriptor *hwiDescs;
    int32_t hwiDescsCount;
};

static void AudioManagerReleasePort(struct AudioPort **ports, uint32_t portsLen)
{
    CHECK_NULL_PTR_RETURN(ports);

    if (portsLen == 0 || portsLen > AUDIO_HW_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiManager portsLen is invalid");
        return;
    }

    struct AudioPort *portsTmp = *ports;
    for (uint32_t i = 0; i < portsLen; i++) {
        OsalMemFree((void *)portsTmp[i].portName);
    }
    OsalMemFree((void *)portsTmp);
    *ports = NULL;
}

static void AudioManagerReleaseHwiPort(struct AudioHwiPort **hwiPorts, uint32_t portNum)
{
    CHECK_NULL_PTR_RETURN(hwiPorts);

    if (portNum == 0 || portNum > AUDIO_HW_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiManager portNum is invalid");
        return;
    }

    struct AudioHwiPort *portsTmp = *hwiPorts;
    for (uint32_t i = 0; i < portNum; i++) {
        OsalMemFree((void *)portsTmp[i].portName);
    }
    OsalMemFree((void *)portsTmp);
    *hwiPorts = NULL;
}

static void AudioManagerReleaseDesc(struct AudioAdapterDescriptor *desc)
{
    OsalMemFree((void *)desc->adapterName);
    desc->adapterName = NULL;
    if (desc->ports != NULL) {
        AudioManagerReleasePort(&desc->ports, desc->portsLen);
        desc->portsLen = 0;
    }
}

static void AudioManagerReleaseHwiDesc(struct AudioAdapterHwiDescriptor *hwiDesc)
{
    OsalMemFree((void *)hwiDesc->adapterName);
    hwiDesc->adapterName = NULL;
    if (hwiDesc->ports != NULL) {
        AudioManagerReleaseHwiPort(&hwiDesc->ports, hwiDesc->portNum);
        hwiDesc->portNum = 0;
    }
#if defined CONFIG_USE_JEMALLOC_DFX_INTF
    int err = mallopt(M_FLUSH_THREAD_CACHE, 0);
    if (err != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("%{public}s :release cache error, m_purge = %{public}d", __func__, err);
    }
#endif
}

static void AudioManagerReleaseDescs(struct AudioAdapterDescriptor *descs, uint32_t descsCount)
{
    if (descsCount == 0 || descsCount > AUDIO_HW_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiManager descsCount is invalid");
        return;
    }

    for (uint32_t i = 0; i < descsCount; i++) {
        AudioManagerReleaseDesc(&descs[i]);
    }
}

static int32_t AudioManagerPortToHwiPort(const struct AudioAdapterDescriptor *desc,
    struct AudioAdapterHwiDescriptor *hwiDesc)
{
    if (desc->portsLen == 0 || desc->portsLen > AUDIO_HW_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio desc portsLen is invalid");
        return HDF_ERR_NOT_SUPPORT;
    }

    struct AudioHwiPort *hwiPorts = (struct AudioHwiPort *)OsalMemCalloc(sizeof(*hwiPorts) * desc->portsLen);
    if (hwiPorts == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc AudioHwiPort fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < desc->portsLen; i++) {
        hwiPorts[i].portName = strdup(desc->ports[i].portName);
        hwiPorts[i].portId = desc->ports[i].portId;
        hwiPorts[i].dir = (enum AudioHwiPortDirection)desc->ports[i].dir;
    }

    hwiDesc->ports = hwiPorts;
    hwiDesc->portNum = desc->portsLen;

    return HDF_SUCCESS;
}

static int32_t AudioManagerHwiPortToPort(struct AudioAdapterHwiDescriptor *hwiDesc, struct AudioAdapterDescriptor *desc)
{
    if (hwiDesc->portNum == 0 || hwiDesc->portNum > AUDIO_HW_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiDesc portNum is invalid");
        return HDF_ERR_NOT_SUPPORT;
    }

    /* audio stub free ports */
    struct AudioPort *ports = (struct AudioPort *)OsalMemCalloc(sizeof(*ports) * hwiDesc->portNum);
    if (ports == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc AudioPort fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < hwiDesc->portNum; i++) {
        ports[i].portName = strdup(hwiDesc->ports[i].portName);
        ports[i].portId = hwiDesc->ports[i].portId;
        ports[i].dir = (enum AudioPortDirection)hwiDesc->ports[i].dir;
    }

    desc->ports = ports;
    desc->portsLen = hwiDesc->portNum;

    return HDF_SUCCESS;
}

static int32_t AudioManagerDescToHwiDesc(const struct AudioAdapterDescriptor *desc,
    struct AudioAdapterHwiDescriptor *hwiDesc)
{
    int32_t ret = AudioManagerPortToHwiPort(desc, hwiDesc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiManager hwiPort fail");
        return HDF_FAILURE;
    }

    hwiDesc->adapterName = strdup(desc->adapterName);
    AUDIO_FUNC_LOGI("audio hwiManager load adapterName=%{public}s", hwiDesc->adapterName);

    return HDF_SUCCESS;
}

static int32_t AudioManagerHwiDescsToDescs(struct AudioAdapterHwiDescriptor *hwiDescs, int32_t hwiDescsCount,
    struct AudioAdapterDescriptor *descs, uint32_t *descsCount)
{
    if (hwiDescsCount <= 0 || hwiDescsCount > AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiDescsCount=%{public}d is error", hwiDescsCount);
        return HDF_ERR_NOT_SUPPORT;
    }

    uint32_t count = (*descsCount <= (uint32_t)hwiDescsCount) ? (*descsCount) : (uint32_t)hwiDescsCount;
    AUDIO_FUNC_LOGI("audio hwiManager all adapter count=%{public}u, hwiCount=%{public}d", count, hwiDescsCount);

    for (uint32_t i = 0; i < count; i++) {
        int32_t ret = AudioManagerHwiPortToPort(&hwiDescs[i], &descs[i]);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("audio hwiManager port fail");
            return HDF_FAILURE;
        }
        descs[i].adapterName = strdup(hwiDescs[i].adapterName); // audio stub free adapterName
        AUDIO_FUNC_LOGI("audio hwiManager get adapterName=%{public}s", descs[i].adapterName);
    }

    *descsCount = count;

    return HDF_SUCCESS;
}

int32_t AudioManagerVendorGetAllAdapters(struct IAudioManager *manager,
    struct AudioAdapterDescriptor *descs, uint32_t *descsLen)
{
    int32_t ret;
    CHECK_NULL_PTR_RETURN_VALUE(manager, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(descs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(descsLen, HDF_ERR_INVALID_PARAM);

    struct AudioHwiManagerPriv *priv = (struct AudioHwiManagerPriv *)manager;
    if (priv->hwiManager == NULL) {
        AUDIO_FUNC_LOGE("audio hwiManager is null");
        return HDF_ERR_INVALID_PARAM;
    }

    if (priv->hwiDescsCount != 0 && priv->hwiDescs != NULL) {
        ret = AudioManagerHwiDescsToDescs(priv->hwiDescs, priv->hwiDescsCount, descs, descsLen);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("audio hwiManager DescsHwi To Descs fail, ret=%{public}d", ret);
            AudioManagerReleaseDescs(descs, *descsLen);
            return HDF_FAILURE;
        }
        return HDF_SUCCESS;
    }

    ret = priv->hwiManager->GetAllAdapters(priv->hwiManager, &priv->hwiDescs, &priv->hwiDescsCount);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiManager call GetAllAdapters fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    CHECK_NULL_PTR_RETURN_VALUE(priv->hwiDescs, HDF_ERR_NOT_SUPPORT);

    ret = AudioManagerHwiDescsToDescs(priv->hwiDescs, priv->hwiDescsCount, descs, descsLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiManager DescsHwi To Descs fail, ret=%{public}d", ret);
        AudioManagerReleaseDescs(descs, *descsLen);
        return HDF_FAILURE;
    }

    priv->descsCount = AUDIO_HW_ADAPTER_NUM_MAX;
    ret = AudioManagerHwiDescsToDescs(priv->hwiDescs, priv->hwiDescsCount, priv->descs, &priv->descsCount);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiManager DescsHwi To Descs fail, ret=%{public}d", ret);
        AudioManagerReleaseDescs(descs, *descsLen);
        AudioManagerReleaseDescs(priv->descs, priv->descsCount);
        priv->descsCount = 0;
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static uint32_t AudioManagerVendorFindAdapterPos(struct IAudioManager *manager, const char *adapterName)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapterName, AUDIO_HW_ADAPTER_NUM_MAX);
    struct AudioHwiManagerPriv *priv = (struct AudioHwiManagerPriv *)manager;
    CHECK_NULL_PTR_RETURN_VALUE(priv->hwiManager, AUDIO_HW_ADAPTER_NUM_MAX);

    for (uint32_t descIndex = 0; descIndex < priv->descsCount; descIndex++) {
        if (strcmp(adapterName, priv->descs[descIndex].adapterName) == 0) {
            return descIndex;
        }
    }
    AUDIO_FUNC_LOGI("can not find adapterName(%{public}s) pos", adapterName);
    return AUDIO_HW_ADAPTER_NUM_MAX;
}

int32_t AudioManagerVendorLoadAdapter(struct IAudioManager *manager, const struct AudioAdapterDescriptor *desc,
    struct IAudioAdapter **adapter)
{
    CHECK_NULL_PTR_RETURN_VALUE(manager, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);

    struct AudioHwiManagerPriv *priv = (struct AudioHwiManagerPriv *)manager;
    CHECK_NULL_PTR_RETURN_VALUE(priv->hwiManager, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(priv->hwiManager->LoadAdapter, HDF_ERR_INVALID_PARAM);

    uint32_t descIndex = AudioManagerVendorFindAdapterPos(manager, desc->adapterName);
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiManager find adapter pos");
        return HDF_FAILURE;
    }

    uint32_t count = AudioHwiGetAdapterRefCnt(descIndex);
    if (count > 0 && count != UINT_MAX) {
        return AudioHwiIncreaseAdapterRef(descIndex, adapter);
    }

    struct AudioAdapterHwiDescriptor hwiDesc;
    int32_t ret = AudioManagerDescToHwiDesc(desc, &hwiDesc);
    if (ret != HDF_SUCCESS) {
        AudioManagerReleaseHwiDesc(&hwiDesc);
        AUDIO_FUNC_LOGE("audio hwiManager desc To hwiDesc fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    struct AudioHwiAdapter *hwiAdapter = NULL;
    ret = priv->hwiManager->LoadAdapter(priv->hwiManager, &hwiDesc, &hwiAdapter);
    AudioManagerReleaseHwiDesc(&hwiDesc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiManager call LoadAdapter fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    *adapter = AudioHwiCreateAdapter(descIndex, hwiAdapter);
    if (*adapter == NULL) {
        AUDIO_FUNC_LOGE("audio hwiManager create adapter fail");
        priv->hwiManager->UnloadAdapter(priv->hwiManager, hwiAdapter);
        return HDF_FAILURE;
    }
    AUDIO_FUNC_LOGD("audio hwiManager load hwiAdapter success");

    return HDF_SUCCESS;
}

static int32_t AudioManagerVendorUnloadAdapter(struct IAudioManager *manager, const char *adapterName)
{
    CHECK_NULL_PTR_RETURN_VALUE(manager, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(adapterName, HDF_ERR_INVALID_PARAM);

    struct AudioHwiManagerPriv *priv = (struct AudioHwiManagerPriv *)manager;
    CHECK_NULL_PTR_RETURN_VALUE(priv->hwiManager, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(priv->hwiManager->UnloadAdapter, HDF_ERR_INVALID_PARAM);

    uint32_t descIndex = AudioManagerVendorFindAdapterPos(manager, adapterName);
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("AudioManagerVendorUnloadAdapter descIndex error");
        return HDF_ERR_INVALID_PARAM;
    }

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapterByDescIndex(descIndex);
    if (hwiAdapter == NULL) {
        AUDIO_FUNC_LOGW("audio hwiManager hwiAdapter had unloaded, index=%{public}d", descIndex);
        return HDF_SUCCESS;
    }

    uint32_t count = AudioHwiGetAdapterRefCnt(descIndex);
    if (count > 1 && count != UINT_MAX) {
        AudioHwiDecreaseAdapterRef(descIndex);
        return HDF_SUCCESS;
    }

    priv->hwiManager->UnloadAdapter(priv->hwiManager, hwiAdapter);

    AudioHwiReleaseAdapter(descIndex);
    AUDIO_FUNC_LOGD("audio hwiManager unload hwiAdapter success");

    return HDF_SUCCESS;
}

int32_t ReleaseAudioManagerVendorObject(struct IAudioManager *manager)
{
    uint32_t descIndex;

    if (manager == NULL) {
        AUDIO_FUNC_LOGI("auido manager had released");
        return HDF_SUCCESS;
    }

    struct AudioHwiManagerPriv *priv = (struct AudioHwiManagerPriv *)manager;
    if (priv->handle != NULL) {
        dlclose(priv->handle);
        priv->handle = NULL;
    }

    for (descIndex = 0; descIndex < priv->descsCount; descIndex++) {
        AudioHwiEnforceClearAdapterRefCnt(descIndex);
        int32_t ret = AudioManagerVendorUnloadAdapter(manager, priv->descs[descIndex].adapterName);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGW("audio unload adapter error, ret=%{pulbic}d, adaptername=%{pulbic}s", ret,
                priv->descs[descIndex].adapterName);
        }
    }

    AudioManagerReleaseDescs(priv->descs, priv->descsCount);
    OsalMemFree((void *)priv);

    return HDF_SUCCESS;
}

static int32_t AudioManagerLoadVendorLib(struct AudioHwiManagerPriv *priv)
{
    char *error = NULL;
    const char *hdiAudioVendorLibPath = HDF_LIBRARY_FULL_PATH("libhdi_audio");

    priv->handle = dlopen(hdiAudioVendorLibPath, RTLD_LAZY);
    if (priv->handle == NULL) {
        error = dlerror();
        AUDIO_FUNC_LOGE("audio hwiManager load path%{public}s, dlopen err=%{public}s", hdiAudioVendorLibPath, error);
        return HDF_FAILURE;
    }

    (void)dlerror(); // clear existing error

    priv->managerFuncs = dlsym(priv->handle, "GetAudioManagerFuncs");
    if (priv->managerFuncs == NULL) {
        error = dlerror();
        AUDIO_FUNC_LOGE("dlsym GetAudioManagerFuncs err=%{public}s", error);
        dlclose(priv->handle);
        priv->handle = NULL;
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGI("audio load vendor lib success");
    return HDF_SUCCESS;
}

struct IAudioManager *AudioManagerCreateIfInstance(void)
{
    AUDIO_FUNC_LOGI("audio hwiManager create instance");

    struct AudioHwiManagerPriv *priv = (struct AudioHwiManagerPriv *)OsalMemCalloc(sizeof(*priv));
    if (priv == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc AudioHwiManagerPriv failed");
        return NULL;
    }

    int32_t ret = AudioManagerLoadVendorLib(priv);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio load lib failed ret=%{pulbic}d", ret);
        OsalMemFree((void *)priv);
        return NULL;
    }

    priv->hwiManager = (struct AudioHwiManager *)priv->managerFuncs();
    if (priv->hwiManager == NULL) {
        AUDIO_FUNC_LOGE("audio call hwi manager func failed");
        OsalMemFree((void *)priv);
        return NULL;
    }

    priv->interface.GetAllAdapters = AudioManagerVendorGetAllAdapters;
    priv->interface.LoadAdapter = AudioManagerVendorLoadAdapter;
    priv->interface.UnloadAdapter = AudioManagerVendorUnloadAdapter;
    priv->interface.ReleaseAudioManagerObject = ReleaseAudioManagerVendorObject;

    return &(priv->interface);
}

int32_t AudioManagerDestroyIfInstance(struct IAudioManager *manager)
{
    return ReleaseAudioManagerVendorObject(manager);
}