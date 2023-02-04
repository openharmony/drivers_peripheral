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
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>

#include "v1_0/iaudio_manager.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_SERVICE

typedef int32_t (*AudioManagerConstructFun)(struct IAudioManager *);
typedef int32_t (*AudioManagerDestructFun)(struct IAudioManager *);

struct AudioManagerService {
    struct IAudioManager interface;
    void *handle;
    AudioManagerConstructFun implConstructFun;
    AudioManagerDestructFun implDestructFun;
};

static const char *g_hdiAudioLibPath = HDF_LIBRARY_FULL_PATH("libaudio_primary_impl");

static int32_t AudioManagerGetVersion(struct IAudioManager *self, uint32_t* majorVer, uint32_t* minorVer)
{
    (void)self;
    *majorVer = IAUDIO_MANAGER_MAJOR_VERSION;
    *minorVer = IAUDIO_MANAGER_MINOR_VERSION;
    return HDF_SUCCESS;
}

static int32_t AudioManagerImplLoadLib(struct IAudioManager *AudioManagerInterface)
{
    char *error = NULL;

    if (g_hdiAudioLibPath == NULL || AudioManagerInterface == NULL) {
        HDF_LOGE("%{public}s:para is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct AudioManagerService *service = CONTAINER_OF(AudioManagerInterface, struct AudioManagerService, interface);
    if (service->handle != NULL) {
        HDF_LOGW("%{public}s:hdi audio impl lib has been opened", __func__);
        return HDF_SUCCESS;
    }

    service->handle = dlopen(g_hdiAudioLibPath, RTLD_LAZY);
    if (service->handle == NULL) {
        error = dlerror();
        HDF_LOGE("%{public}s:load path%{public}s, dlopen err=%{public}s", __func__, g_hdiAudioLibPath, error);
        return HDF_FAILURE;
    }

    (void)dlerror(); // clear existing error

    service->implConstructFun = dlsym(service->handle, "AudioManagerConstructFun");
    if (service->implConstructFun == NULL) {
        error = dlerror();
        HDF_LOGE("%{public}s:hdi audio impl lib load AudioManagerConstructFun err=%{public}s", __func__, error);
        goto ERROR;
    }

    service->implDestructFun = dlsym(service->handle, "AudioManagerDestructFun");
    if (service->implDestructFun == NULL) {
        error = dlerror();
        HDF_LOGE("%{public}s:hdi audio impl lib load AudioManagerDestructFun err=%{public}s", __func__, error);
        goto ERROR;
    }

    HDF_LOGI("%{public}s:hdi audio impl lib load success", __func__);
    return HDF_SUCCESS;

ERROR:
    if (service->handle != NULL) {
        dlclose(service->handle);
        service->handle = NULL;
    }
    return HDF_FAILURE;
}

struct IAudioManager *AudioManagerImplGetInstance(void)
{
    struct AudioManagerService *service = (struct AudioManagerService *)OsalMemCalloc(sizeof(struct AudioManagerService));
    if (service == NULL) {
        HDF_LOGE("%{public}s:malloc AudioManagerService service failed!", __func__);
        return NULL;
    }

    int32_t ret = AudioManagerImplLoadLib(&service->interface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:Audio manager load lib failed, ret[%{public}d]", __func__, ret);
        OsalMemFree(service);
        return NULL;
    }

    ret = service->implConstructFun(&service->interface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:call implConstructFun fail, ret=%{public}d", __func__, ret);
        dlclose(service->handle);
        service->handle = NULL;
        OsalMemFree(service);
        return NULL;
    }

    service->interface.GetVersion = AudioManagerGetVersion;

    return &service->interface;
}

void AudioManagerImplRelease(struct IAudioManager *AudioManagerInterface)
{
    if (AudioManagerInterface == NULL) {
        HDF_LOGE("%{public}s:AudioManagerInterface is null", __func__);
        return;
    }

    struct AudioManagerService *service = CONTAINER_OF(AudioManagerInterface, struct AudioManagerService, interface);
    if (service == NULL || service->handle == NULL) {
        HDF_LOGW("%{public}s:hdi audio impl lib has been closed", __func__);
        OsalMemFree(service);
        return;
    }

    int32_t ret = service->implDestructFun(AudioManagerInterface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:call implDestructorFun fail, ret=%{public}d", __func__, ret);
    }

    dlclose(service->handle);
    OsalMemFree(service);
}
