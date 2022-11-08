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

#include "audio_uhdf_log.h"
#include "hdf_base.h"
#include "hdf_device_object.h"
#include "hdf_dlist.h"
#include "osal_mem.h"
#include "stub_collector.h"
#include "v1_0/iaudio_manager.h"

#define HDF_LOG_TAG AUDIO_HDI_SVC

struct HdfAudioManagerHost {
    struct IDeviceIoService ioService;
    struct IAudioManager *service;
    struct HdfRemoteService **stubObject;
};

static int32_t AudioManagerDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || client->device == NULL || client->device->service == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    struct HdfAudioManagerHost *audiomanagerHost =
        CONTAINER_OF(client->device->service, struct HdfAudioManagerHost, ioService);
    if (audiomanagerHost->service == NULL || audiomanagerHost->stubObject == NULL) {
        HDF_LOGE("%{public}s: invalid service obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    struct HdfRemoteService *stubObj = *audiomanagerHost->stubObject;
    if (stubObj == NULL || stubObj->dispatcher == NULL || stubObj->dispatcher->Dispatch == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }

    return stubObj->dispatcher->Dispatch((struct HdfRemoteService *)stubObj->target, cmdId, data, reply);
}

static int32_t HdfAudioManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("deviceObject is null!");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO)) {
        AUDIO_FUNC_LOGE("Set Primary DEVICE_CLASS_AUDIO fail!");
    }

    return HDF_SUCCESS;
}

static int32_t HdfAudioManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter.");
    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, IAUDIOMANAGER_INTERFACE_DESC);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGI("failed to set interface descriptor object! ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    struct HdfAudioManagerHost *audiomanagerHost =
        (struct HdfAudioManagerHost *)OsalMemCalloc(sizeof(struct HdfAudioManagerHost));
    if (audiomanagerHost == NULL) {
        AUDIO_FUNC_LOGE("alloc HdfAudioManagerHost failed!");
        return HDF_ERR_MALLOC_FAIL;
    }

    struct IAudioManager *serviceImpl = IAudioManagerGet(true);
    if (serviceImpl == NULL) {
        AUDIO_FUNC_LOGE("create serviceImpl failed!");
        OsalMemFree(audiomanagerHost);
        return HDF_FAILURE;
    }

    struct HdfRemoteService **stubObj = StubCollectorGetOrNewObject(IAUDIOMANAGER_INTERFACE_DESC, serviceImpl);
    if (stubObj == NULL) {
        OsalMemFree(audiomanagerHost);
        IAudioManagerRelease(serviceImpl, true);
        return HDF_FAILURE;
    }

    audiomanagerHost->ioService.Dispatch = AudioManagerDriverDispatch;
    audiomanagerHost->ioService.Open = NULL;
    audiomanagerHost->ioService.Release = NULL;
    audiomanagerHost->service = serviceImpl;
    audiomanagerHost->stubObject = stubObj;
    deviceObject->service = &audiomanagerHost->ioService;

    return HDF_SUCCESS;
}

static void HdfAudioManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter.");
    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return;
    }

    struct HdfAudioManagerHost *audiomanagerHost =
        CONTAINER_OF(deviceObject->service, struct HdfAudioManagerHost, ioService);
    if (audiomanagerHost == NULL) {
        AUDIO_FUNC_LOGE("HdfAudioManagerHost is NULL!");
        return;
    }

    StubCollectorRemoveObject(IAUDIOMANAGER_INTERFACE_DESC, audiomanagerHost->service);
    IAudioManagerRelease(audiomanagerHost->service, true);
    OsalMemFree(audiomanagerHost);
}

static struct HdfDriverEntry g_audiomanagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "audio_manager_service",
    .Bind = HdfAudioManagerDriverBind,
    .Init = HdfAudioManagerDriverInit,
    .Release = HdfAudioManagerDriverRelease,
};

HDF_INIT(g_audiomanagerDriverEntry);
