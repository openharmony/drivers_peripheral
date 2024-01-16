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

#include "hdf_base.h"
#include "hdf_device_object.h"
#include "hdf_dlist.h"
#include "osal_mem.h"
#include "stub_collector.h"
#include "v1_0/ieffect_model.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_EFFECT

struct HdfEffectModelHost {
    struct IDeviceIoService ioService;
    struct IEffectModel *service;
    struct HdfRemoteService **stubObject;
};

static int32_t EffectModelDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || client->device == NULL || client->device->service == NULL) {
        HDF_LOGE("%{public}s:param is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct HdfEffectModelHost *effectModelHost =
        CONTAINER_OF(client->device->service, struct HdfEffectModelHost, ioService);
    if (effectModelHost->service == NULL || effectModelHost->stubObject == NULL) {
        HDF_LOGE("%{public}s: invalid service obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    struct HdfRemoteService *stubObj = *effectModelHost->stubObject;
    if (stubObj == NULL || stubObj->dispatcher == NULL || stubObj->dispatcher->Dispatch == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }

    return stubObj->dispatcher->Dispatch((struct HdfRemoteService *)stubObj->target, cmdId, data, reply);
}

static int32_t HdfEffectDriverInit(struct HdfDeviceObject *deviceObject)
{
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s:deviceObject is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO)) {
        HDF_LOGE("%{public}s:set primary DEVICE_CLASS_AUDIO fail!", __func__);
    }

    return HDF_SUCCESS;
}

static int32_t HdfEffectModelDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGD("enter to %{public}s.", __func__);
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s:param is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, IEFFECTMODEL_INTERFACE_DESC);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("failed to set interface descriptor object! ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    struct HdfEffectModelHost *effectModelHost =
        (struct HdfEffectModelHost *)OsalMemCalloc(sizeof(struct HdfEffectModelHost));
    if (effectModelHost == NULL) {
        HDF_LOGE("%{public}s:alloc HdfEffectModelHost failed!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    struct IEffectModel *serviceImpl = IEffectModelGet(true);
    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s:create serviceImpl failed!", __func__);
        OsalMemFree(effectModelHost);
        return HDF_FAILURE;
    }

    struct HdfRemoteService **stubObj = StubCollectorGetOrNewObject(IEFFECTMODEL_INTERFACE_DESC, serviceImpl);
    if (stubObj == NULL) {
        OsalMemFree(effectModelHost);
        IEffectModelRelease(serviceImpl, true);
        return HDF_FAILURE;
    }

    effectModelHost->ioService.Dispatch = EffectModelDriverDispatch;
    effectModelHost->ioService.Open = NULL;
    effectModelHost->ioService.Release = NULL;
    effectModelHost->service = serviceImpl;
    effectModelHost->stubObject = stubObj;
    deviceObject->service = &effectModelHost->ioService;

    return HDF_SUCCESS;
}

static void HdfEffectModelDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGD("enter to %{public}s.", __func__);
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s:param is NULL!", __func__);
        return;
    }

    struct HdfEffectModelHost *effectModelHost =
        CONTAINER_OF(deviceObject->service, struct HdfEffectModelHost, ioService);
    if (effectModelHost == NULL) {
        HDF_LOGE("%{public}s:HdfEffectModelHost is NULL!", __func__);
        return;
    }

    StubCollectorRemoveObject(IEFFECTMODEL_INTERFACE_DESC, effectModelHost->service);
    IEffectModelRelease(effectModelHost->service, true);
    OsalMemFree(effectModelHost);
}

static struct HdfDriverEntry g_effectModelDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "effect_model_service",
    .Bind = HdfEffectModelDriverBind,
    .Init = HdfEffectDriverInit,
    .Release = HdfEffectModelDriverRelease,
};

HDF_INIT(g_effectModelDriverEntry);