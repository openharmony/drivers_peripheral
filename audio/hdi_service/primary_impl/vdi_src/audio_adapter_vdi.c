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

#include "audio_adapter_vdi.h"

#include <limits.h>
#include "osal_mem.h"
#include "securec.h"
#include <hdf_base.h>
#include "audio_uhdf_log.h"
#include "audio_capture_vdi.h"
#include "audio_common_vdi.h"
#include "audio_render_vdi.h"
#include "audio_dfx_vdi.h"
#include "v4_0/iaudio_callback.h"
#include "stub_collector.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL
static pthread_rwlock_t g_rwAdapterLock = PTHREAD_RWLOCK_INITIALIZER;

struct AudioAdapterInfo {
    struct IAudioAdapterVdi *vdiAdapter;
    struct IAudioAdapter *adapter;
    uint32_t refCnt;
    char *adapterName;
};

struct AudioAdapterPrivVdi {
    struct AudioAdapterInfo adapterInfo[AUDIO_VDI_ADAPTER_NUM_MAX];
    struct IAudioCallback *callback;
    bool isRegCb;
};

static struct AudioAdapterPrivVdi g_audioAdapterVdi;

static struct AudioAdapterPrivVdi *AudioAdapterGetPrivVdi(void)
{
    return &g_audioAdapterVdi;
}

struct IAudioAdapterVdi *AudioGetVdiAdapterByDescIndexVdi(uint32_t descIndex)
{
    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();

    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("get vdiAdapter error, descIndex=%{public}d", descIndex);
        return NULL;
    }

    return priv->adapterInfo[descIndex].vdiAdapter;
}

static struct IAudioAdapterVdi *AudioGetVdiAdapterVdi(const struct IAudioAdapter *adapter)
{
    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();

    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("get vdiAdapter error");
        return NULL;
    }

    for (uint32_t i = 0; i < AUDIO_VDI_ADAPTER_NUM_MAX; i++) {
        if (adapter == priv->adapterInfo[i].adapter) {
            return priv->adapterInfo[i].vdiAdapter;
        }
    }

    AUDIO_FUNC_LOGE("audio get vdiadapter fail");
    return NULL;
}

static char *AudioGetAdapterNameVdi(const struct IAudioAdapter *adapter)
{
    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();

    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("get AdapterName error");
        return NULL;
    }

    for (uint32_t i = 0; i < AUDIO_VDI_ADAPTER_NUM_MAX; i++) {
        if (adapter == priv->adapterInfo[i].adapter) {
            return priv->adapterInfo[i].adapterName;
        }
    }

    AUDIO_FUNC_LOGE("audio get adapterName fail");
    return NULL;
}

static int32_t AudioInitAllPortsVdi(struct IAudioAdapter *adapter)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->InitAllPorts == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    ret = vdiAdapter->InitAllPorts(vdiAdapter);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter InitAllPorts fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }
EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t VerifyParamsOfAudioCreateRenderVdi(struct IAudioAdapter *adapter,
    const struct AudioDeviceDescriptor *desc, const struct AudioSampleAttributes *attrs,
    struct IAudioRender **render, uint32_t *renderId)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(renderId, HDF_ERR_INVALID_PARAM);

    if (desc->pins == PIN_OUT_LINEOUT || desc->pins == PIN_OUT_HDMI ||
        desc->pins == PIN_NONE || desc->pins >= PIN_IN_MIC) {
        AUDIO_FUNC_LOGE("invalid pin [%{public}d]", desc->pins);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t CreateRenderPre(struct IAudioAdapterVdi *vdiAdapter,
    const struct AudioDeviceDescriptor *desc, const struct AudioSampleAttributes *attrs,
    uint32_t *renderId, struct IAudioRenderVdi **vdiRender)
{
    struct AudioDeviceDescriptorVdi vdiDesc;
    struct AudioSampleAttributesVdi vdiAttrs;
    if (AudioCommonDevDescToVdiDevDescVdi(desc, &vdiDesc) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("desc to vdiDesc fail");
        return HDF_FAILURE;
    }
    AudioCommonAttrsToVdiAttrsVdi(attrs, &vdiAttrs);

    int32_t id = SetTimer("Hdi:CreateRender");
    int32_t ret = vdiAdapter->CreateRender(vdiAdapter, &vdiDesc, &vdiAttrs, vdiRender);
    CancelTimer(id);
    OsalMemFree((void *)vdiDesc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call CreateRender fail, ret=%{public}d", ret);
        return ret;
    }
    (*vdiRender)->AddAudioEffect = NULL;
    (*vdiRender)->RemoveAudioEffect = NULL;
    (*vdiRender)->GetFrameBufferSize = NULL;
    (*vdiRender)->IsSupportsPauseAndResume = NULL;
    
    return HDF_SUCCESS;
}

static int32_t AudioCreateRenderVdi(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct IAudioRender **render, uint32_t *renderId)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    AUDIO_FUNC_LOGD("enter to %{public}s", __func__);

    int32_t ret = VerifyParamsOfAudioCreateRenderVdi(adapter, desc, attrs, render, renderId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("invalid param");
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->CreateRender == NULL || vdiAdapter->DestroyRender == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    char *adapterName = AudioGetAdapterNameVdi(adapter);
    *render = FindRenderCreated(desc->pins, attrs, renderId, adapterName);
    if (*render != NULL) {
        AUDIO_FUNC_LOGE("already created");
        ret = HDF_SUCCESS;
        goto EXIT;
    }
    struct IAudioRenderVdi *vdiRender = NULL;
    ret = CreateRenderPre(vdiAdapter, desc, attrs, renderId, &vdiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CreateRenderPre failed, ret = [%{public}d]", ret);
        goto EXIT;
    }
    *render = AudioCreateRenderByIdVdi(attrs, renderId, vdiRender, desc, adapterName);
    if (*render == NULL) {
        (void)vdiAdapter->DestroyRender(vdiAdapter, vdiRender);
        AUDIO_FUNC_LOGE("Create audio render failed");
        ret = HDF_FAILURE;
        goto EXIT;
    }
    AUDIO_FUNC_LOGI("AudioCreateRenderVdi Success, renderId = [%{public}u]", *renderId);
EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioDestroyRenderVdi(struct IAudioAdapter *adapter, uint32_t renderId)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    AUDIO_FUNC_LOGD("enter to %{public}s", __func__);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    if (renderId < 0 || renderId > AUDIO_VDI_STREAM_NUM_MAX - 1) {
        AUDIO_FUNC_LOGE("renderId is invalid[%{public}u] and return ret=%{public}d", renderId, ret);
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    if (DecreaseRenderUsrCount(renderId) > 0) {
        AUDIO_FUNC_LOGE("render destroy: more than one usr");
        ret = HDF_SUCCESS;
        goto EXIT;
    }
    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioRenderVdi *vdiRender = AudioGetVdiRenderByIdVdi(renderId);
    if (vdiRender == NULL) {
        AUDIO_FUNC_LOGE("vdiRender pointer is null");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    if (vdiAdapter->DestroyRender == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    ret = vdiAdapter->DestroyRender(vdiAdapter, vdiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call DestroyRender fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }
    AudioDestroyRenderByIdVdi(renderId);
EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t CreateCapturePre(struct IAudioAdapterVdi *vdiAdapter, struct IAudioCapture **capture,
    const struct AudioDeviceDescriptor *desc, const struct AudioSampleAttributes *attrs, uint32_t *captureId)
{
    struct IAudioCaptureVdi *vdiCapture = NULL;
    struct AudioDeviceDescriptorVdi vdiDesc;
    struct AudioSampleAttributesVdi vdiAttrs;
    (void)memset_s((void *)&vdiDesc, sizeof(vdiDesc), 0, sizeof(vdiDesc));
    (void)memset_s((void *)&vdiAttrs, sizeof(vdiAttrs), 0, sizeof(vdiAttrs));
    if (AudioCommonDevDescToVdiDevDescVdi(desc, &vdiDesc) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Desc to VdiDesc fail");
        return HDF_FAILURE;
    }
    AudioCommonAttrsToVdiAttrsVdi(attrs, &vdiAttrs);

    if (vdiAdapter == NULL || vdiAdapter->CreateCapture == NULL || vdiAdapter->DestroyCapture == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t id = SetTimer("Hdi:CreateCapture");
    int32_t ret = vdiAdapter->CreateCapture(vdiAdapter, &vdiDesc, &vdiAttrs, &vdiCapture);
    CancelTimer(id);
    OsalMemFree((void *)vdiDesc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call CreateCapture fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    vdiCapture->AddAudioEffect = NULL;
    vdiCapture->RemoveAudioEffect = NULL;
    vdiCapture->GetFrameBufferSize = NULL;
    vdiCapture->IsSupportsPauseAndResume = NULL;
    *capture = AudioCreateCaptureByIdVdi(attrs, captureId, vdiCapture, desc);
    if (*capture == NULL) {
        (void)vdiAdapter->DestroyCapture(vdiAdapter, vdiCapture);
        AUDIO_FUNC_LOGE("create audio capture failed");
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

static int32_t AudioCreateCaptureVdi(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct IAudioCapture **capture, uint32_t *captureId)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    AUDIO_FUNC_LOGD("enter to %{public}s", __func__);
    int32_t ret = HDF_SUCCESS;
    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || desc == NULL || attrs == NULL || capture == NULL || captureId == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    ret = CreateCapturePre(vdiAdapter, capture, desc, attrs, captureId);
    if (*capture == NULL || ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("create audio capture failed");
        goto EXIT;
    }
    AUDIO_FUNC_LOGI("AudioCreateCaptureVdi Success, captureId = [%{public}u]", *captureId);
EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioDestroyCaptureVdi(struct IAudioAdapter *adapter, uint32_t captureId)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    AUDIO_FUNC_LOGD("enter to %{public}s", __func__);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    if (captureId < 0 || captureId > AUDIO_VDI_STREAM_NUM_MAX - 1) {
        AUDIO_FUNC_LOGE("captureId is invalid[%{public}u] and return ret=%{public}d", captureId, ret);
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    if (DecreaseCaptureUsrCount(captureId) > 0) {
        AUDIO_FUNC_LOGE("capture destroy: more than one usr");
        ret = HDF_SUCCESS;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioCaptureVdi *vdiCapture = AudioGetVdiCaptureByIdVdi(captureId);
    if (vdiCapture == NULL || vdiAdapter->DestroyCapture == NULL) {
        AUDIO_FUNC_LOGE("invalid parameter");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    ret = vdiAdapter->DestroyCapture(vdiAdapter, vdiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call DestroyCapture fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }
    AudioDestroyCaptureByIdVdi(captureId);
EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioGetPortCapabilityVdi(struct IAudioAdapter *adapter, const struct AudioPort *port,
    struct AudioPortCapability* capability)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL || port == NULL || capability == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->GetPortCapability == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    struct AudioPortCapabilityVdi vdiCap;
    struct AudioPortVdi vdiPort;
    (void)memset_s(&vdiCap, sizeof(vdiCap), 0, sizeof(vdiCap));
    (void)memset_s(&vdiPort, sizeof(vdiPort), 0, sizeof(vdiPort));

    ret = AudioCommonPortToVdiPortVdi(port, &vdiPort);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)vdiPort.portName);
        AUDIO_FUNC_LOGE("audio vdiAdapter call PortCapToVdiPortCap fail, ret=%{public}d", ret);
        goto EXIT;
    }

    ret = vdiAdapter->GetPortCapability(vdiAdapter, &vdiPort, &vdiCap);
    OsalMemFree((void *)vdiPort.portName);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call GetPortCapability fail, ret=%{public}d", ret);
        goto EXIT;
    }

    AudioCommonVdiPortCapToPortCapVdi(&vdiCap, capability);
EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioSetPassthroughModeVdi(struct IAudioAdapter *adapter, const struct AudioPort *port,
    enum AudioPortPassthroughMode mode)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL || port == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->SetPassthroughMode == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct AudioPortVdi vdiPort;
    (void)memset_s((void *)&vdiPort, sizeof(vdiPort), 0, sizeof(vdiPort));
    ret = AudioCommonPortToVdiPortVdi(port, &vdiPort);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)vdiPort.portName);
        AUDIO_FUNC_LOGE("audio vdiAdapter call PortCapToVdiPortCap fail, ret=%{public}d", ret);
        goto EXIT;
    }

    ret = vdiAdapter->SetPassthroughMode(vdiAdapter, &vdiPort, (enum AudioPortPassthroughModeVdi)mode);
    OsalMemFree((void *)vdiPort.portName);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call SetPassthroughMode fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioGetPassthroughModeVdi(struct IAudioAdapter *adapter, const struct AudioPort *port,
    enum AudioPortPassthroughMode *mode)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL || port == NULL || mode == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->GetPassthroughMode == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct AudioPortVdi vdiPort;
    (void)memset_s((void *)&vdiPort, sizeof(vdiPort), 0, sizeof(vdiPort));
    ret = AudioCommonPortToVdiPortVdi(port, &vdiPort);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)vdiPort.portName);
        AUDIO_FUNC_LOGE("audio vdiAdapter call PortCapToVdiPortCap fail, ret=%{public}d", ret);
        goto EXIT;
    }

    ret = vdiAdapter->GetPassthroughMode(vdiAdapter, &vdiPort, (enum AudioPortPassthroughModeVdi *)mode);
    OsalMemFree((void *)vdiPort.portName);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call GetPassthroughMode fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioGetDeviceStatusVdi(struct IAudioAdapter *adapter, struct AudioDeviceStatus *status)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL || status == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->GetDeviceStatus == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct AudioDeviceStatusVdi vdiStatus;
    (void)memset_s((void *)&vdiStatus, sizeof(vdiStatus), 0, sizeof(vdiStatus));
    ret = vdiAdapter->GetDeviceStatus(vdiAdapter, &vdiStatus);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call GetDeviceStatus fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

    status->pnpStatus = vdiStatus.pnpStatus;
EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioUpdateAudioRouteVdi(struct IAudioAdapter *adapter,
    const struct AudioRoute *route, int32_t *routeHandle)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL || route == NULL || routeHandle == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    if (route->sinksLen == 0 && route->sourcesLen == 0) {
        AUDIO_FUNC_LOGE("invalid route value");
        ret = HDF_FAILURE;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->UpdateAudioRoute == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct AudioRouteVdi vdiRoute;
    (void)memset_s(&vdiRoute, sizeof(vdiRoute), 0, sizeof(vdiRoute));

    ret = AudioCommonRouteToVdiRouteVdi(route, &vdiRoute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter route To vdiRoute fail");
        goto EXIT;
    }

    ret = vdiAdapter->UpdateAudioRoute(vdiAdapter, &vdiRoute, routeHandle);
    AudioCommonFreeVdiRouteVdi(&vdiRoute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call UpdateAudioRoute fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioReleaseAudioRouteVdi(struct IAudioAdapter *adapter, int32_t routeHandle)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->ReleaseAudioRoute == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    ret = vdiAdapter->ReleaseAudioRoute(vdiAdapter, routeHandle);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call ReleaseAudioRoute fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioSetMicMuteVdi(struct IAudioAdapter *adapter, bool mute)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->SetMicMute == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    ret = vdiAdapter->SetMicMute(vdiAdapter, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call SetMicMute fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioGetMicMuteVdi(struct IAudioAdapter *adapter, bool *mute)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL || mute == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->GetMicMute == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    ret = vdiAdapter->GetMicMute(vdiAdapter, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call GetMicMute fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioSetVoiceVolumeVdi(struct IAudioAdapter *adapter, float volume)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->SetVoiceVolume == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    ret = vdiAdapter->SetVoiceVolume(vdiAdapter, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call SetVoiceVolume fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioSetExtraParamsVdi(struct IAudioAdapter *adapter, enum AudioExtParamKey key, const char *condition,
    const char *value)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL || condition == NULL || value == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->SetExtraParams == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    ret = vdiAdapter->SetExtraParams(vdiAdapter, (enum AudioExtParamKeyVdi)key, condition, value);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call SetExtraParams fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static int32_t AudioGetExtraParamsVdi(struct IAudioAdapter *adapter, enum AudioExtParamKey key, const char *condition,
    char *value, uint32_t valueLen)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL || condition == NULL || value == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct IAudioAdapterVdi *vdiAdapter = AudioGetVdiAdapterVdi(adapter);
    if (vdiAdapter == NULL || vdiAdapter->GetExtraParams == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    ret = vdiAdapter->GetExtraParams(vdiAdapter, (enum AudioExtParamKeyVdi)key, condition, value,
        (int32_t)valueLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter call GetExtraParams fail, ret=%{public}d", ret);
        ret = HDF_FAILURE;
        goto EXIT;
    }

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

static void AudioInitAdapterInstanceVdi(struct IAudioAdapter *adapter)
{
    adapter->InitAllPorts = AudioInitAllPortsVdi;
    adapter->CreateRender = AudioCreateRenderVdi;
    adapter->DestroyRender = AudioDestroyRenderVdi;
    adapter->CreateCapture = AudioCreateCaptureVdi;
    adapter->DestroyCapture = AudioDestroyCaptureVdi;

    adapter->GetPortCapability = AudioGetPortCapabilityVdi;
    adapter->SetPassthroughMode = AudioSetPassthroughModeVdi;
    adapter->GetPassthroughMode = AudioGetPassthroughModeVdi;
    adapter->GetDeviceStatus = AudioGetDeviceStatusVdi;
    adapter->UpdateAudioRoute = AudioUpdateAudioRouteVdi;

    adapter->ReleaseAudioRoute = AudioReleaseAudioRouteVdi;
    adapter->SetMicMute = AudioSetMicMuteVdi;
    adapter->GetMicMute = AudioGetMicMuteVdi;
    adapter->SetVoiceVolume = AudioSetVoiceVolumeVdi;
    adapter->SetExtraParams = AudioSetExtraParamsVdi;

    adapter->GetExtraParams = AudioGetExtraParamsVdi;
}

uint32_t AudioGetAdapterRefCntVdi(uint32_t descIndex)
{
    pthread_rwlock_rdlock(&g_rwAdapterLock);
    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("get adapter ref error, descIndex=%{public}d", descIndex);
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return UINT_MAX;
    }

    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return priv->adapterInfo[descIndex].refCnt;
}

int32_t AudioIncreaseAdapterRefVdi(uint32_t descIndex, struct IAudioAdapter **adapter)
{
    pthread_rwlock_wrlock(&g_rwAdapterLock);
    int32_t ret = HDF_SUCCESS;
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }
    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("increase adapter ref error, descIndex=%{public}d", descIndex);
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();
    if (priv->adapterInfo[descIndex].adapter == NULL) {
        AUDIO_FUNC_LOGE("Invalid adapter param!");
        ret = HDF_ERR_INVALID_PARAM;
        goto EXIT;
    }

    priv->adapterInfo[descIndex].refCnt++;
    *adapter = priv->adapterInfo[descIndex].adapter;
    AUDIO_FUNC_LOGI("increase adapternameIndex[%{public}d], refCount[%{public}d]", descIndex,
        priv->adapterInfo[descIndex].refCnt);

EXIT:
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return ret;
}

void AudioDecreaseAdapterRefVdi(uint32_t descIndex)
{
    pthread_rwlock_wrlock(&g_rwAdapterLock);
    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("decrease adapter ref error, descIndex=%{public}d", descIndex);
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return;
    }

    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();
    if (priv->adapterInfo[descIndex].refCnt == 0) {
        AUDIO_FUNC_LOGE("Invalid adapterInfo[%{public}d] had released", descIndex);
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return;
    }
    priv->adapterInfo[descIndex].refCnt--;
    AUDIO_FUNC_LOGI("decrease adapternameIndex[%{public}d], refCount[%{public}d]", descIndex,
        priv->adapterInfo[descIndex].refCnt);
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return;
}

void AudioEnforceClearAdapterRefCntVdi(uint32_t descIndex)
{
    pthread_rwlock_wrlock(&g_rwAdapterLock);
    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("decrease adapter descIndex error, descIndex=%{public}d", descIndex);
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return;
    }

    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();
    priv->adapterInfo[descIndex].refCnt = 0;
    AUDIO_FUNC_LOGI("clear adapter ref count zero");
    pthread_rwlock_unlock(&g_rwAdapterLock);
}

struct IAudioAdapter *AudioCreateAdapterVdi(uint32_t descIndex, struct IAudioAdapterVdi *vdiAdapter,
    char *adapterName)
{
    pthread_rwlock_wrlock(&g_rwAdapterLock);
    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("create adapter error, descIndex=%{public}d", descIndex);
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return NULL;
    }

    if (vdiAdapter == NULL) {
        AUDIO_FUNC_LOGE("audio vdiAdapter is null");
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return NULL;
    }

    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();
    struct IAudioAdapter *adapter = priv->adapterInfo[descIndex].adapter;
    if (adapter != NULL) {
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return adapter;
    }

    adapter = (struct IAudioAdapter *)OsalMemCalloc(sizeof(struct IAudioAdapter));
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc adapter fail");
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return NULL;
    }

    AudioInitAdapterInstanceVdi(adapter);
    priv->adapterInfo[descIndex].vdiAdapter = vdiAdapter;
    priv->adapterInfo[descIndex].adapter = adapter;
    priv->adapterInfo[descIndex].refCnt = 1;
    priv->adapterInfo[descIndex].adapterName = strdup(adapterName);
    if (priv->adapterInfo[descIndex].adapterName == NULL) {
        OsalMemFree((void *)priv->adapterInfo[descIndex].adapter);
        priv->adapterInfo[descIndex].adapter = NULL;
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return NULL;
    }

    AUDIO_FUNC_LOGI(" audio vdiAdapter create adapter success, refcount[1], adapterName=[%{public}s]", adapterName);
    pthread_rwlock_unlock(&g_rwAdapterLock);
    return adapter;
}

void AudioReleaseAdapterVdi(uint32_t descIndex)
{
    pthread_rwlock_wrlock(&g_rwAdapterLock);
    if (descIndex >= AUDIO_VDI_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("adapter release fail descIndex=%{public}d", descIndex);
        pthread_rwlock_unlock(&g_rwAdapterLock);
        return;
    }

    struct AudioAdapterPrivVdi *priv = AudioAdapterGetPrivVdi();
    StubCollectorRemoveObject(IAUDIOADAPTER_INTERFACE_DESC, priv->adapterInfo[descIndex].adapter);
    OsalMemFree((void *)priv->adapterInfo[descIndex].adapter);
    priv->adapterInfo[descIndex].adapter = NULL;
    priv->adapterInfo[descIndex].vdiAdapter = NULL;
    priv->adapterInfo[descIndex].refCnt = UINT_MAX;
    OsalMemFree((void *)priv->adapterInfo[descIndex].adapterName);
    priv->adapterInfo[descIndex].adapterName = NULL;

    priv->isRegCb = false;
    priv->callback = NULL;

    AUDIO_FUNC_LOGI(" audio vdiAdapter release adapter success");
    pthread_rwlock_unlock(&g_rwAdapterLock);
}
