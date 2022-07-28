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

#include "hdf_base.h"
#include "hdf_device_object.h"
#include "hdf_dlist.h"
#include "osal_mem.h"
#include "audio_uhdf_log.h"
#include "audio_internal.h"
#include "audio_internal_manager.h"
#include "v1_0/audio_adapter_stub.h"
#include "v1_0/audio_capture_stub.h"
#include "v1_0/audio_manager_stub.h"
#include "v1_0/audio_render_stub.h"

#define HDF_LOG_TAG AUDIO_HDI_SVC

struct AudioManagerService {
    struct AudioManagerStub stub;
    struct AudioAdapterInfo adapterInfos[SUPPORT_ADAPTER_NUM_MAX];
};

struct HdfAudioManagerHost {
    struct IDeviceIoService ioservice;
    struct AudioManagerService *service;
};

static int32_t IDLAudioAdapterCreateCapture(struct AudioAdapter *self, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct AudioCapture **capture)
{
    if (self == NULL || desc == NULL || attrs == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (AudioAdapterCreateCapture(self, desc, attrs, capture) != HDF_SUCCESS || *capture == NULL) {
        return HDF_FAILURE;
    }
    struct AudioCaptureStub *captureStub = CONTAINER_OF(*capture, struct AudioCaptureStub, interface);
    if (!AudioCaptureStubConstruct(captureStub)) {
        AUDIO_FUNC_LOGE("AudioCaptureStubConstruct failed!");
        OsalMemFree(*capture);
        *capture = NULL;
        ((struct AudioHwAdapter *)self)->infos.captureServicePtr = NULL;
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t IDLAudioAdapterCreateRender(struct AudioAdapter *self, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct AudioRender **render)
{
    if (self == NULL || desc == NULL || attrs == NULL || render == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (AudioAdapterCreateRender(self, desc, attrs, render) != HDF_SUCCESS || *render == NULL) {
        return HDF_FAILURE;
    }
    struct AudioRenderStub *renderStub = CONTAINER_OF(*render, struct AudioRenderStub, interface);
    if (!AudioRenderStubConstruct(renderStub)) {
        AUDIO_FUNC_LOGE("AudioRenderStubConstruct failed!");
        OsalMemFree(*render);
        *render = NULL;
        ((struct AudioHwAdapter *)self)->infos.renderServicePtr = NULL;
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioAdapterServiceOverwrite(struct AudioAdapter *adapter)
{
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    adapter->CreateRender = IDLAudioAdapterCreateRender;
    adapter->CreateCapture = IDLAudioAdapterCreateCapture;

    return HDF_SUCCESS;
}

static int32_t AudioManagerServiceLoadAdapter(
    struct AudioManager *manager, const struct AudioAdapterDescriptor *desc, struct AudioAdapter **adapter)
{
    AUDIO_FUNC_LOGI("enter!");
    if (manager == NULL || desc == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (AudioManagerLoadAdapter(manager, desc, adapter) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("LoadAdapter error!");
        return HDF_FAILURE;
    }

    struct AudioAdapterStub *adapterStub = CONTAINER_OF(*adapter, struct AudioAdapterStub, interface);
    if (!AudioAdapterStubConstruct(adapterStub)) {
        AUDIO_FUNC_LOGE("AudioAdapterStubConstruct failed!");
        if (AudioManagerUnloadAdapter(manager, desc->adapterName) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGW("AudioManagerUnloadAdapter failed!");
        }
        return HDF_FAILURE;
    }

    if (AudioAdapterServiceOverwrite(*adapter) != HDF_SUCCESS) {
        if (AudioManagerUnloadAdapter(manager, desc->adapterName) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGW("AudioManagerUnloadAdapter failed!");
        }
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioManagerServiceUnloadAdapter(struct AudioManager *manager, const char *adapterName)
{
    return AudioManagerUnloadAdapter(manager, adapterName);
}

static int32_t AudioManagerServiceGetAllAdapters(
    struct AudioManager *manager, struct AudioAdapterDescriptor *descs, uint32_t *size)
{
    return AudioManagerGetAllAdapters(manager, descs, size);
}

static int32_t ReleaseAudioManagerServiceObject(struct AudioManager *object)
{
    return ReleaseAudioManagerObject(object);
}

static struct AudioManagerService *AudioManagerServiceGet(void)
{
    struct AudioManagerService *service =
        (struct AudioManagerService *)OsalMemCalloc(sizeof(struct AudioManagerService));
    if (service == NULL) {
        AUDIO_FUNC_LOGE("alloc AudioManagerService obj failed!");
        return NULL;
    }

    if (!AudioManagerStubConstruct(&service->stub)) {
        AUDIO_FUNC_LOGE("AudioManagerStubConstruct failed!");
        OsalMemFree(service);
        return NULL;
    }

    service->stub.interface.GetAllAdapters = AudioManagerServiceGetAllAdapters;
    service->stub.interface.LoadAdapter = AudioManagerServiceLoadAdapter;
    service->stub.interface.UnloadAdapter = AudioManagerServiceUnloadAdapter;
    service->stub.interface.ReleaseAudioManagerObject = ReleaseAudioManagerServiceObject;

    return service;
}

static void AudioManagerServiceRelease(struct AudioManagerService *instance)
{
    if (instance == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return;
    }

    ReleaseAudioManagerServiceObject(&(instance->stub.interface));
    OsalMemFree(instance);
}

static int32_t AudioManagerDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || client->device == NULL || client->device->service == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }
    struct HdfAudioManagerHost *audioManagerHost =
        CONTAINER_OF(client->device->service, struct HdfAudioManagerHost, ioservice);
    if (audioManagerHost == NULL || audioManagerHost->service == NULL ||
        audioManagerHost->service->stub.OnRemoteRequest == NULL) {
        AUDIO_FUNC_LOGE("invalid service obj");
        return HDF_ERR_INVALID_OBJECT;
    }

    if (!HdfDeviceObjectCheckInterfaceDesc(client->device, data)) {
        AUDIO_FUNC_LOGE("check interface desc failed!");
        return HDF_FAILURE;
    }

    return audioManagerHost->service->stub.OnRemoteRequest(
        &audioManagerHost->service->stub.interface, cmdId, data, reply);
}

static int32_t HdfAudioManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    (void)deviceObject;

    return HDF_SUCCESS;
}

static int32_t HdfAudioManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter.");
    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, AUDIOMANAGER_INTERFACE_DESC);
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

    audiomanagerHost->ioservice.Dispatch = AudioManagerDriverDispatch;
    audiomanagerHost->ioservice.Open = NULL;
    audiomanagerHost->ioservice.Release = NULL;
    audiomanagerHost->service = AudioManagerServiceGet();
    if (audiomanagerHost->service == NULL) {
        OsalMemFree(audiomanagerHost);
        return HDF_FAILURE;
    }
    deviceObject->service = &audiomanagerHost->ioservice;

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
        CONTAINER_OF(deviceObject->service, struct HdfAudioManagerHost, ioservice);
    AudioManagerServiceRelease(audiomanagerHost->service);
    OsalMemFree(audiomanagerHost);
}

static struct HdfDriverEntry g_audiomanagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "idl_audio_server",
    .Bind = HdfAudioManagerDriverBind,
    .Init = HdfAudioManagerDriverInit,
    .Release = HdfAudioManagerDriverRelease,
};

HDF_INIT(g_audiomanagerDriverEntry);
