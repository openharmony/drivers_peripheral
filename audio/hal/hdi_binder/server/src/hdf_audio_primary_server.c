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

#include "hdf_device_desc.h"
#include "audio_adapter_info_common.h"
#include "audio_events.h"
#include "audio_hal_log.h"
#include "hdf_audio_events.h"
#include "hdf_audio_server_common.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

#ifdef AUDIO_HAL_USER
static void *g_mpiInitSo = NULL;
#define SO_INTERFACE_LIB_MPI_PATH HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_mpi")
#endif


void AudioHdiPrimaryServerRelease(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter!");
    /* g_renderAndCaptureManage release */
    AdaptersServerManageInfomationRecycle();
    ReleaseAudioManagerObjectComm(GetAudioManagerFuncs());

    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("deviceObject is null!");
        return;
    }
    deviceObject->service = NULL;
#ifdef AUDIO_HAL_USER
    if (g_mpiInitSo == NULL) {
        return;
    }
    int32_t (*mpiExit)() = dlsym(g_mpiInitSo, "AudioMpiSysExit");
    if (mpiExit == NULL) {
        return;
    }
    mpiExit();
    dlclose(g_mpiInitSo);
#endif
    AUDIO_FUNC_LOGD("end!");
    return;
}

int AudioHdiPrimaryServerBind(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter!");
    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("deviceObject is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    static struct IDeviceIoService hdiService = {
        .Dispatch = HdiServiceDispatch,
        .Open = NULL,
        .Release = NULL,
    };
    AudioHdiSetLoadServerFlag(AUDIO_SERVER_PRIMARY);
    if (HdiServiceGetFuncs()) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, "ohos.hdi.audio_service");
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("failed to set interface desc");
        return ret;
    }
    deviceObject->service = &hdiService;

    AUDIO_FUNC_LOGD("end!");
    return AUDIO_HAL_SUCCESS;
}

int AudioHdiPrimaryServerInit(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter!");
    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("deviceObject is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
#ifdef AUDIO_HAL_USER
    void *sdkHandle;
    int (*sdkInitSp)() = NULL;
    char sdkResolvedPath[] = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_render");
    sdkHandle = dlopen(sdkResolvedPath, RTLD_LAZY);
    if (sdkHandle == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    sdkInitSp = (int32_t (*)())(dlsym(sdkHandle, "MpiSdkInit"));
    if (sdkInitSp == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    sdkInitSp();
#endif
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO)) {
        AUDIO_FUNC_LOGE("Set Primary DEVICE_CLASS_AUDIO fail!");
    }
    struct AudioEvent audioSrvEvent = {
        .eventType = HDF_AUDIO_SERVICE_VALID,
        .deviceType = HDF_AUDIO_PRIMARY_DEVICE,
    };
    AudioServiceStateChange(deviceObject, &audioSrvEvent);

    AUDIO_FUNC_LOGD("end!");
    return AUDIO_HAL_SUCCESS;
}

struct HdfDriverEntry g_hdiPrimaryServerEntry = {
    .moduleVersion = 1,
    .moduleName = "hdi_audio_primary_server",
    .Bind = AudioHdiPrimaryServerBind,
    .Init = AudioHdiPrimaryServerInit,
    .Release = AudioHdiPrimaryServerRelease,
};

HDF_INIT(g_hdiPrimaryServerEntry);
