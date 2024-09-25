/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <hdf_remote_service.h>
#include <osal_mem.h>
#include <stub_collector.h>
#include "v4_0/iaudio_manager.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_PRIMARY_DRV

struct HdfAudioManagerHost {
    struct IDeviceIoService ioService;
    struct IAudioManager *service;
    struct HdfRemoteService **stubObject;
};

static int32_t AudioManagerDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || client->device == NULL || client->device->service == NULL) {
        HDF_LOGE("%{public}s:Param is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct HdfAudioManagerHost *audiomanagerHost =
        CONTAINER_OF(client->device->service, struct HdfAudioManagerHost, ioService);
    if (audiomanagerHost->service == NULL || audiomanagerHost->stubObject == NULL) {
        HDF_LOGE("%{public}s:invalid service obj", __func__);
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
    HDF_LOGI("%{public}s: driver init enter", __func__);

    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s:deviceObject is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO)) {
        HDF_LOGE("%{public}s:set primary DEVICE_CLASS_AUDIO fail!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    HDF_LOGI("%{public}s:driver init success", __func__);
    return HDF_SUCCESS;
}

static int32_t HdfAudioManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s:bind enter", __func__);
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s:Param is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, IAUDIOMANAGER_INTERFACE_DESC);
    if (ret != HDF_SUCCESS) {
        HDF_LOGI("%{public}s:failed to set interface descriptor object! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    struct HdfAudioManagerHost *audiomanagerHost =
        (struct HdfAudioManagerHost *)OsalMemCalloc(sizeof(struct HdfAudioManagerHost));
    if (audiomanagerHost == NULL) {
        HDF_LOGE("%{public}s:alloc HdfAudioManagerHost failed!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    struct IAudioManager *serviceImpl = IAudioManagerGet(true);
    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s:create serviceImpl failed!", __func__);
        OsalMemFree(audiomanagerHost);
        return HDF_FAILURE;
    }

    struct HdfRemoteService **stubObj = StubCollectorGetOrNewObject(IAUDIOMANAGER_INTERFACE_DESC, serviceImpl);
    if (stubObj == NULL) {
        HDF_LOGE("%{public}s:failed to get stub object", __func__);
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
    HDF_LOGI("%{public}s:bind success", __func__);
    return HDF_SUCCESS;
}

static void HdfAudioManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s:driver release enter", __func__);
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s:Param is NULL!", __func__);
        return;
    }

    struct HdfAudioManagerHost *audiomanagerHost =
        CONTAINER_OF(deviceObject->service, struct HdfAudioManagerHost, ioService);
    if (audiomanagerHost == NULL) {
        HDF_LOGE("%{public}s:HdfAudioManagerHost is NULL!", __func__);
        return;
    }

    StubCollectorRemoveObject(IAUDIOMANAGER_INTERFACE_DESC, audiomanagerHost->service);
    IAudioManagerRelease(audiomanagerHost->service, true);
    OsalMemFree(audiomanagerHost);
    HDF_LOGI("%{public}s:release success", __func__);
}

static struct HdfDriverEntry g_audiomanagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "audio_primary_driver",
    .Bind = HdfAudioManagerDriverBind,
    .Init = HdfAudioManagerDriverInit,
    .Release = HdfAudioManagerDriverRelease,
};

HDF_INIT(g_audiomanagerDriverEntry);