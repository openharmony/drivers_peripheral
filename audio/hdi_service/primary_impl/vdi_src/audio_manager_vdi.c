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
#include "audio_manager_vdi.h"

#include <dlfcn.h>
#include <malloc.h>
#include "osal_mem.h"
#include <hdf_base.h>
#include "audio_uhdf_log.h"
#include "audio_adapter_vdi.h"
#include "audio_dfx_vdi.h"
#include "v4_0/iaudio_adapter.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL
static pthread_mutex_t g_managerMutex;

typedef struct IAudioManagerVdi* (*AudioManagerCreateIfInstanceVdi)(void);

struct AudioManagerPrivVdi {
    struct IAudioManager interface;
    void *handle;
    AudioManagerCreateIfInstanceVdi managerFuncs;
    struct IAudioManagerVdi *vdiManager;
    struct AudioAdapterDescriptor descs[AUDIO_VDI_ADAPTER_NUM_MAX];
    uint32_t descsCount;
    struct AudioAdapterDescriptorVdi *vdiDescs;
    uint32_t vdiDescsCount;
};

static void AudioManagerReleasePort(struct AudioPort **ports, uint32_t portsLen)
{
    CHECK_NULL_PTR_RETURN(ports);

    if (portsLen == 0 || portsLen > AUDIO_VDI_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiManager portsLen is invalid");
        return;
    }

    struct AudioPort *portsTmp = *ports;
    for (uint32_t i = 0; i < portsLen; i++) {
        OsalMemFree((void *)portsTmp[i].portName);
    }
    OsalMemFree((void *)portsTmp);
    *ports = NULL;
}

static void AudioManagerReleaseVdiPort(struct AudioPortVdi **vdiPorts, uint32_t portsLen)
{
    CHECK_NULL_PTR_RETURN(vdiPorts);

    if (portsLen == 0 || portsLen > AUDIO_VDI_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiManager portsLen is invalid");
        return;
    }

    struct AudioPortVdi *portsTmp = *vdiPorts;
    for (uint32_t i = 0; i < portsLen; i++) {
        OsalMemFree((void *)portsTmp[i].portName);
    }
    OsalMemFree((void *)portsTmp);
    *vdiPorts = NULL;
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

static void AudioManagerReleaseVdiDesc(struct AudioAdapterDescriptorVdi *vdiDesc)
{
    OsalMemFree((void *)vdiDesc->adapterName);
    vdiDesc->adapterName = NULL;
    if (vdiDesc->ports != NULL) {
        AudioManagerReleaseVdiPort(&vdiDesc->ports, vdiDesc->portsLen);
        vdiDesc->portsLen = 0;
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
    if (descsCount == 0 || descsCount > AUDIO_VDI_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiManager descsCount is invalid");
        return;
    }

    for (uint32_t i = 0; i < descsCount; i++) {
        AudioManagerReleaseDesc(&descs[i]);
    }
}

static int32_t AudioManagerPortToVdiPort(const struct AudioAdapterDescriptor *desc,
    struct AudioAdapterDescriptorVdi *vdiDesc)
{
    if (desc->portsLen == 0 || desc->portsLen > AUDIO_VDI_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio desc portsLen is invalid");
        return HDF_ERR_NOT_SUPPORT;
    }

    struct AudioPortVdi *vdiPorts = (struct AudioPortVdi *)OsalMemCalloc(sizeof(*vdiPorts) * desc->portsLen);
    if (vdiPorts == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc AudioPortVdi fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < desc->portsLen; i++) {
        vdiPorts[i].portName = strdup(desc->ports[i].portName);
        if (vdiPorts[i].portName == NULL) {
            vdiDesc->ports = vdiPorts;
            vdiDesc->portsLen = desc->portsLen;
            AUDIO_FUNC_LOGE("strdup fail, desc->ports[%{public}d].portName = %{public}s", i, desc->ports[i].portName);
            return HDF_FAILURE;
        }
        vdiPorts[i].portId = desc->ports[i].portId;
        vdiPorts[i].dir = (enum AudioPortDirectionVdi)desc->ports[i].dir;
    }

    vdiDesc->ports = vdiPorts;
    vdiDesc->portsLen = desc->portsLen;

    return HDF_SUCCESS;
}

static int32_t AudioManagerVdiPortToPort(struct AudioAdapterDescriptorVdi *vdiDesc, struct AudioAdapterDescriptor *desc)
{
    if (vdiDesc->portsLen == 0 || vdiDesc->portsLen > AUDIO_VDI_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiDesc portsLen is invalid");
        return HDF_ERR_NOT_SUPPORT;
    }

    /* audio stub free ports */
    struct AudioPort *ports = (struct AudioPort *)OsalMemCalloc(sizeof(*ports) * vdiDesc->portsLen);
    if (ports == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc AudioPort fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < vdiDesc->portsLen; i++) {
        ports[i].portName = strdup(vdiDesc->ports[i].portName);
        if (ports[i].portName == NULL) {
            desc->ports = ports;
            desc->portsLen = vdiDesc->portsLen;
            AUDIO_FUNC_LOGE("strdup fail, vdiDesc->ports[%{public}d].portName = %{public}s",
                i, vdiDesc->ports[i].portName);
            return HDF_FAILURE;
        }
        ports[i].portId = vdiDesc->ports[i].portId;
        ports[i].dir = (enum AudioPortDirection)vdiDesc->ports[i].dir;
    }

    desc->ports = ports;
    desc->portsLen = vdiDesc->portsLen;

    return HDF_SUCCESS;
}

static int32_t AudioManagerDescToVdiDesc(const struct AudioAdapterDescriptor *desc,
    struct AudioAdapterDescriptorVdi *vdiDesc)
{
    int32_t ret = AudioManagerPortToVdiPort(desc, vdiDesc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiManager vdiPort fail");
        return HDF_FAILURE;
    }

    vdiDesc->adapterName = strdup(desc->adapterName);
    if (vdiDesc->adapterName == NULL) {
        AUDIO_FUNC_LOGE("strdup fail, desc->adapterName = %{public}s", desc->adapterName);
        return HDF_FAILURE;
    }
    AUDIO_FUNC_LOGI("audio vdiManager load adapterName=%{public}s", vdiDesc->adapterName);

    return HDF_SUCCESS;
}

static int32_t AudioManagerVdiDescsToDescs(struct AudioAdapterDescriptorVdi *vdiDescs, uint32_t vdiDescsCount,
    struct AudioAdapterDescriptor *descs, uint32_t *descsCount)
{
    if (vdiDescsCount == 0 || vdiDescsCount > AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiDescsCount=%{public}d is error", vdiDescsCount);
        return HDF_ERR_NOT_SUPPORT;
    }

    uint32_t count = (*descsCount <= (uint32_t)vdiDescsCount) ? (*descsCount) : (uint32_t)vdiDescsCount;
    AUDIO_FUNC_LOGI("audio vdiManager all adapter count=%{public}u, vdiCount=%{public}d", count, vdiDescsCount);

    for (uint32_t i = 0; i < count; i++) {
        int32_t ret = AudioManagerVdiPortToPort(&vdiDescs[i], &descs[i]);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("audio vdiManager port fail");
            return HDF_FAILURE;
        }
        descs[i].adapterName = strdup(vdiDescs[i].adapterName); // audio stub free adapterName
        if (descs[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("strdup fail, descs[%{public}d].adapterName = %{public}s", i, descs[i].adapterName);
            return HDF_FAILURE;
        }
        AUDIO_FUNC_LOGI("audio vdiManager get adapterName=%{public}s", descs[i].adapterName);
    }

    *descsCount = count;
    return HDF_SUCCESS;
}

static int32_t AudioManagerPrivVdiGetAllAdapters(struct AudioManagerPrivVdi *priv,
    struct AudioAdapterDescriptor *descs, uint32_t *descsLen)
{
    if (*descsLen == 0) {
        AUDIO_FUNC_LOGE("descsLen is zero");
        return HDF_FAILURE;
    }
    priv->vdiDescs = (struct AudioAdapterDescriptorVdi *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptorVdi) * (*descsLen));
    if (priv->vdiDescs == NULL) {
        AUDIO_FUNC_LOGE("null point");
        return HDF_ERR_NOT_SUPPORT;
    }

    priv->vdiDescsCount = *descsLen;
    int32_t id = SetTimer("Hdi:GetAllAdapters");
    int32_t ret = priv->vdiManager->GetAllAdapters(priv->vdiManager, priv->vdiDescs, &priv->vdiDescsCount);
    CancelTimer(id);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiManager call GetAllAdapters fail, ret=%{public}d", ret);
        free(priv->vdiDescs);
        priv->vdiDescs = NULL;
        priv->vdiDescsCount = 0;
        return HDF_FAILURE;
    }

    ret = AudioManagerVdiDescsToDescs(priv->vdiDescs, priv->vdiDescsCount, descs, descsLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiManager DescsVdi To Descs fail, ret=%{public}d", ret);
        AudioManagerReleaseDescs(descs, *descsLen);
        free(priv->vdiDescs);
        priv->vdiDescs = NULL;
        priv->vdiDescsCount = 0;
        return HDF_FAILURE;
    }

    priv->descsCount = AUDIO_VDI_ADAPTER_NUM_MAX;
    ret = AudioManagerVdiDescsToDescs(priv->vdiDescs, priv->vdiDescsCount, priv->descs, &priv->descsCount);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiManager DescsVdi To Descs fail, ret=%{public}d", ret);
        AudioManagerReleaseDescs(descs, *descsLen);
        AudioManagerReleaseDescs(priv->descs, priv->descsCount);
        priv->descsCount = 0;
        free(priv->vdiDescs);
        priv->vdiDescs = NULL;
        priv->vdiDescsCount = 0;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioManagerVendorGetAllAdapters(struct IAudioManager *manager,
    struct AudioAdapterDescriptor *descs, uint32_t *descsLen)
{
    AUDIO_FUNC_LOGD("enter to %{public}s", __func__);
    CHECK_NULL_PTR_RETURN_VALUE(manager, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(descs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(descsLen, HDF_ERR_INVALID_PARAM);

    pthread_mutex_lock(&g_managerMutex);
    struct AudioManagerPrivVdi *priv = (struct AudioManagerPrivVdi *)manager;
    if (priv->vdiManager == NULL) {
        AUDIO_FUNC_LOGE("audio vdiManager is null");
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_ERR_INVALID_PARAM;
    }

    if (*descsLen > AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio adapter num demanded too large");
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_ERR_INVALID_PARAM;
    }
    if (priv->vdiDescsCount != 0 && priv->vdiDescs != NULL && priv->vdiDescsCount >= *descsLen) {
        int32_t ret = AudioManagerVdiDescsToDescs(priv->vdiDescs, priv->vdiDescsCount, descs, descsLen);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("audio vdiManager DescsVdi To Descs fail, ret=%{public}d", ret);
            AudioManagerReleaseDescs(descs, *descsLen);
            pthread_mutex_unlock(&g_managerMutex);
            return HDF_FAILURE;
        }
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_SUCCESS;
    }

    if (priv->vdiDescs != NULL) {
        free(priv->vdiDescs);
        priv->vdiDescs = NULL;
    }

    int32_t ret = AudioManagerPrivVdiGetAllAdapters(priv, descs, descsLen);
    pthread_mutex_unlock(&g_managerMutex);
    return ret;
}

static uint32_t AudioManagerVendorFindAdapterPos(struct IAudioManager *manager, const char *adapterName)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapterName, AUDIO_VDI_ADAPTER_NUM_MAX);
    struct AudioManagerPrivVdi *priv = (struct AudioManagerPrivVdi *)manager;
    CHECK_NULL_PTR_RETURN_VALUE(priv->vdiManager, AUDIO_VDI_ADAPTER_NUM_MAX);

    for (uint32_t descIndex = 0; descIndex < priv->descsCount; descIndex++) {
        if (strcmp(adapterName, priv->descs[descIndex].adapterName) == 0) {
            return descIndex;
        }
    }

    AUDIO_FUNC_LOGI("can not find adapterName(%{public}s) pos", adapterName);
    return AUDIO_VDI_ADAPTER_NUM_MAX;
}

static struct IAudioAdapter* VendorLoadAdapter(struct IAudioManagerVdi *vdiManager,
    struct AudioAdapterDescriptorVdi *vdiDesc, uint32_t descIndex)
{
    int32_t ret = HDF_SUCCESS;
    struct IAudioAdapterVdi *vdiAdapter = NULL;
    int32_t id = SetTimer("Hdi:LoadAdapter");
    HdfAudioStartTrace("Hdi:AudioManagerVendorLoadAdapter", 0);
    ret = vdiManager->LoadAdapter(vdiManager, vdiDesc, &vdiAdapter);
    HdfAudioFinishTrace();
    CancelTimer(id);

    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiManager call LoadAdapter fail, ret=%{public}d", ret);
        return NULL;
    }

    struct IAudioAdapter *adapter = AudioCreateAdapterVdi(descIndex, vdiAdapter, vdiDesc->adapterName);
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("audio vdiManager create adapter fail");
        vdiManager->UnloadAdapter(vdiManager, vdiAdapter);
        return NULL;
    }
    AudioManagerReleaseVdiDesc(&vdiDesc);
    return adapter;
}

int32_t AudioManagerVendorLoadAdapter(struct IAudioManager *manager, const struct AudioAdapterDescriptor *desc,
    struct IAudioAdapter **adapter)
{
    CHECK_NULL_PTR_RETURN_VALUE(manager, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);

    pthread_mutex_lock(&g_managerMutex);
    struct AudioManagerPrivVdi *priv = (struct AudioManagerPrivVdi *)manager;
    if (priv == NULL || priv->vdiManager == NULL || priv->vdiManager->LoadAdapter == NULL) {
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t descIndex = AudioManagerVendorFindAdapterPos(manager, desc->adapterName);
    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiManager find adapter pos");
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_FAILURE;
    }

    int32_t ret = HDF_SUCCESS;
    uint32_t count = AudioGetAdapterRefCntVdi(descIndex);
    if (count > 0 && count != UINT_MAX) {
        ret = AudioIncreaseAdapterRefVdi(descIndex, adapter);
        pthread_mutex_unlock(&g_managerMutex);
        return ret;
    }

    struct AudioAdapterDescriptorVdi vdiDesc = {0};
    ret = AudioManagerDescToVdiDesc(desc, &vdiDesc);
    if (ret != HDF_SUCCESS) {
        AudioManagerReleaseVdiDesc(&vdiDesc);
        AUDIO_FUNC_LOGE("audio vdiManager desc To vdiDesc fail, ret=%{public}d", ret);
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_FAILURE;
    }

    *adapter = VendorLoadAdapter(priv->vdiManager, descIndex, vdiDesc);
    if (*adapter == NULL) {
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_managerMutex);
    AUDIO_FUNC_LOGD("audio vdiManager load vdiAdapter success");
    return HDF_SUCCESS;
}

static int32_t AudioManagerVendorUnloadAdapter(struct IAudioManager *manager, const char *adapterName)
{
    CHECK_NULL_PTR_RETURN_VALUE(manager, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(adapterName, HDF_ERR_INVALID_PARAM);

    pthread_mutex_lock(&g_managerMutex);
    struct AudioManagerPrivVdi *priv = (struct AudioManagerPrivVdi *)manager;
    if (priv == NULL || priv->vdiManager == NULL || priv->vdiManager->LoadAdapter == NULL) {
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t descIndex = AudioManagerVendorFindAdapterPos(manager, adapterName);
    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("AudioManagerVendorUnloadAdapter descIndex error");
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_ERR_INVALID_PARAM;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterByDescIndexVdi(descIndex);
    if (vdiAdapter == NULL) {
        AUDIO_FUNC_LOGW("audio vdiManager vdiAdapter had unloaded, index=%{public}d", descIndex);
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_SUCCESS;
    }

    uint32_t count = AudioGetAdapterRefCntVdi(descIndex);
    if (count > 1 && count != UINT_MAX) {
        AudioDecreaseAdapterRefVdi(descIndex);
        pthread_mutex_unlock(&g_managerMutex);
        return HDF_SUCCESS;
    }
    HdfAudioStartTrace("Hdi:AudioManagerVendorUnloadAdapter", 0);
    priv->vdiManager->UnloadAdapter(priv->vdiManager, vdiAdapter);
    HdfAudioFinishTrace();

    AudioReleaseAdapterVdi(descIndex);
    pthread_mutex_unlock(&g_managerMutex);
    AUDIO_FUNC_LOGD("audio vdiManager unload vdiAdapter success");
    return HDF_SUCCESS;
}

int32_t ReleaseAudioManagerVendorObject(struct IAudioManager *manager)
{
    uint32_t descIndex;

    if (manager == NULL) {
        AUDIO_FUNC_LOGI("auido manager had released");
        return HDF_SUCCESS;
    }

    struct AudioManagerPrivVdi *priv = (struct AudioManagerPrivVdi *)manager;
    if (priv->handle != NULL) {
        dlclose(priv->handle);
        priv->handle = NULL;
    }

    for (descIndex = 0; descIndex < priv->descsCount; descIndex++) {
        AudioEnforceClearAdapterRefCntVdi(descIndex);
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

static int32_t AudioManagerLoadVendorLib(struct AudioManagerPrivVdi *priv)
{
    char *error = NULL;
    const char *hdiAudioVendorLibPath = HDF_LIBRARY_FULL_PATH("libaudio_primary_impl");

    priv->handle = dlopen(hdiAudioVendorLibPath, RTLD_LAZY);
    if (priv->handle == NULL) {
        error = dlerror();
        AUDIO_FUNC_LOGE("audio vdiManager load path%{public}s, dlopen err=%{public}s", hdiAudioVendorLibPath, error);
        return HDF_FAILURE;
    }

    (void)dlerror(); // clear existing error

    priv->managerFuncs = dlsym(priv->handle, "AudioManagerCreateIfInstance");
    if (priv->managerFuncs == NULL) {
        error = dlerror();
        AUDIO_FUNC_LOGE("dlsym AudioManagerCreateIfInstance err=%{public}s", error);
        dlclose(priv->handle);
        priv->handle = NULL;
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGD("audio load vendor lib success");
    return HDF_SUCCESS;
}

struct IAudioManager *AudioManagerCreateIfInstance(void)
{
    AUDIO_FUNC_LOGD("audio vdiManager create instance");

    struct AudioManagerPrivVdi *priv = (struct AudioManagerPrivVdi *)OsalMemCalloc(sizeof(*priv));
    if (priv == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc AudioManagerPrivVdi failed");
        return NULL;
    }

    int32_t ret = AudioManagerLoadVendorLib(priv);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio load lib failed ret=%{pulbic}d", ret);
        OsalMemFree((void *)priv);
        return NULL;
    }

    priv->vdiManager = (struct IAudioManagerVdi *)priv->managerFuncs();
    if (priv->vdiManager == NULL) {
        AUDIO_FUNC_LOGE("audio call vdi manager func failed");
        OsalMemFree((void *)priv);
        return NULL;
    }

    if (pthread_mutex_init(&g_managerMutex, NULL) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("init g_managerMutex failed.");
        return NULL;
    }
    if (InitAdapterMutex() != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("init g_adapterMutex failed.");
        pthread_mutex_destroy(&g_managerMutex);
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
    int32_t ret = ReleaseAudioManagerVendorObject(manager);
    pthread_mutex_destroy(&g_managerMutex);
    DeinitAdapterMutex();
    return ret;
}