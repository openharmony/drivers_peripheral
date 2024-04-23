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

#include <dlfcn.h>
#include <hdf_base.h>
#include <hdf_dlist.h>
#include <osal_mem.h>

#include "v3_0/iaudio_manager.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_SRV

typedef struct IAudioManager* (*AudioManagerCreateIfInstance)(void);
typedef int32_t (*AudioManagerDestroyIfInstance)(struct IAudioManager *);

struct AudioManagerPriv {
    void *handle;
    AudioManagerCreateIfInstance createIfInstance;
    AudioManagerDestroyIfInstance destroyIfInstance;
};

static const char *HDI_AUDIO_LIB_PATH = HDF_LIBRARY_FULL_PATH("libaudio_primary_impl_vendor");

static struct AudioManagerPriv *GetAudioManagerPriv(void)
{
    static struct AudioManagerPriv priv;
    return &priv;
}

static int32_t AudioManagerLoadPrimaryLib(struct AudioManagerPriv *priv)
{
    char *error = NULL;

    if (HDI_AUDIO_LIB_PATH == NULL || priv == NULL) {
        HDF_LOGE("%{public}s:para is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    priv->handle = dlopen(HDI_AUDIO_LIB_PATH, RTLD_LAZY);
    if (priv->handle == NULL) {
        error = dlerror();
        HDF_LOGE("%{public}s:load path%{public}s, dlopen err=%{public}s", __func__, HDI_AUDIO_LIB_PATH, error);
        return HDF_FAILURE;
    }

    (void)dlerror(); // clear existing error

    priv->createIfInstance = dlsym(priv->handle, "AudioManagerCreateIfInstance");
    if (priv->createIfInstance == NULL) {
        error = dlerror();
        HDF_LOGE("%{public}s:dlsym AudioManagerCreateIfInstance err=%{public}s", __func__, error);
        goto ERROR;
    }

    priv->destroyIfInstance = dlsym(priv->handle, "AudioManagerDestroyIfInstance");
    if (priv->destroyIfInstance == NULL) {
        error = dlerror();
        HDF_LOGE("%{public}s:dlsym AudioManagerDestroyIfInstance err=%{public}s", __func__, error);
        goto ERROR;
    }

    HDF_LOGI("%{public}s:hdi audio impl lib load success", __func__);
    return HDF_SUCCESS;

ERROR:
    if (priv->handle != NULL) {
        dlclose(priv->handle);
        priv->handle = NULL;
    }
    priv->createIfInstance = NULL;
    priv->destroyIfInstance = NULL;
    return HDF_FAILURE;
}

struct IAudioManager *AudioManagerImplGetInstance(void)
{
    struct AudioManagerPriv *priv = GetAudioManagerPriv();

    int32_t ret = AudioManagerLoadPrimaryLib(priv);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:Audio manager load lib failed, ret[%{public}d]", __func__, ret);
        return NULL;
    }

    if (priv->createIfInstance == NULL) {
        HDF_LOGE("%{public}s:Audio manager createIfInstance is NULL", __func__);
        dlclose(priv->handle);
        priv->handle = NULL;
        return NULL;
    }

    struct IAudioManager *interface = priv->createIfInstance();
    if (interface == NULL) {
        HDF_LOGE("%{public}s:call createIfInstance fail", __func__);
        dlclose(priv->handle);
        priv->handle = NULL;
        return NULL;
    }

    return interface;
}

void AudioManagerImplRelease(struct IAudioManager *manager)
{
    struct AudioManagerPriv *priv = GetAudioManagerPriv();

    if (manager == NULL) {
        HDF_LOGE("%{public}s:manager is null", __func__);
        goto ERROR;
    }

    if (priv->destroyIfInstance == NULL) {
        HDF_LOGE("%{public}s:Audio manager destroyIfInstance is NULL", __func__);
        goto ERROR;
    }

    int32_t ret = priv->destroyIfInstance(manager);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:call destroyIfInstance fail, ret=%{public}d", __func__, ret);
    }

ERROR:
    if (priv->handle != NULL) {
        dlclose(priv->handle);
        priv->handle = NULL;
    }

    priv->createIfInstance = NULL;
    priv->destroyIfInstance = NULL;
}
