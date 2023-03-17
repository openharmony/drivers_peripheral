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

#include "audio_adapter_vendor.h"

#include <hdf_base.h>
#include <limits.h>
#include "audio_capture_vendor.h"
#include "audio_common_vendor.h"
#include "audio_render_vendor.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"
#include "securec.h"
#include "v1_0/iaudio_callback.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

struct AudioAdapterInfo {
    struct AudioHwiAdapter *hwiAdapter;
    struct IAudioAdapter *adapter;
    uint32_t refCnt;
};

struct AudioHwiAdapterPriv {
    struct AudioAdapterInfo adapterInfo[AUDIO_HW_ADAPTER_NUM_MAX];
    struct IAudioCallback *callback;
    bool isRegCb;
};

static struct AudioHwiAdapterPriv g_audioHwiAdapter;

static struct AudioHwiAdapterPriv *AudioHwiAdapterGetPriv(void)
{
    return &g_audioHwiAdapter;
}

static uint32_t AudioHwiGetDescIndexByAdapter(const struct IAudioAdapter *adapter)
{
    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();

    for (uint32_t i = 0; i < AUDIO_HW_ADAPTER_NUM_MAX; i++) {
        if (adapter == priv->adapterInfo[i].adapter) {
            return i;
        }
    }

    AUDIO_FUNC_LOGE("audio get desc index fail");
    return UINT_MAX;
}

struct AudioHwiAdapter *AudioHwiGetHwiAdapterByDescIndex(uint32_t descIndex)
{
    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();

    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("get hwiAdapter error, descIndex=%{public}d", descIndex);
        return NULL;
    }

    return priv->adapterInfo[descIndex].hwiAdapter;
}

struct AudioHwiAdapter *AudioHwiGetHwiAdapter(const struct IAudioAdapter *adapter)
{
    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();

    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("get hwiAdapter error");
        return NULL;
    }

    for (uint32_t i = 0; i < AUDIO_HW_ADAPTER_NUM_MAX; i++) {
        if (adapter == priv->adapterInfo[i].adapter) {
            return priv->adapterInfo[i].hwiAdapter;
        }
    }

    AUDIO_FUNC_LOGE("audio get hwiadapter fail");
    return NULL;
}

int32_t AudioHwiInitAllPorts(struct IAudioAdapter *adapter)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);

    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->InitAllPorts, HDF_ERR_INVALID_PARAM);
    int32_t ret = hwiAdapter->InitAllPorts(hwiAdapter);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter InitAllPorts fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCreateRender(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct IAudioRender **render)
{
    struct AudioHwiDeviceDescriptor hwiDesc;
    struct AudioHwiSampleAttributes hwiAttrs;
    struct AudioHwiRender *hwiRender = NULL;

    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->CreateRender, HDF_ERR_INVALID_PARAM);

    AudioHwiCommonDevDescToHwiDevDesc(desc, &hwiDesc);
    AudioHwiCommonAttrsToHwiAttrs(attrs, &hwiAttrs);

    int32_t ret = hwiAdapter->CreateRender(hwiAdapter, &hwiDesc, &hwiAttrs, &hwiRender);
    OsalMemFree((void *)hwiDesc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call CreateRender fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    uint32_t descIndex = AudioHwiGetDescIndexByAdapter(adapter);
    if (descIndex == UINT_MAX) {
        AUDIO_FUNC_LOGE("audio hwiAdapter get desc index fail");
        return HDF_FAILURE;
    }

    *render = AudioHwiCreateRenderByDesc(descIndex, desc, hwiRender);
    CHECK_NULL_PTR_RETURN_VALUE(*render, HDF_ERR_INVALID_PARAM);

    return HDF_SUCCESS;
}

int32_t AudioHwiDestroyRender(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc)
{
    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);

    uint32_t descIndex = AudioHwiGetDescIndexByAdapter(adapter);
    if (descIndex == UINT_MAX) {
        AUDIO_FUNC_LOGE("audio hwiAdapter get desc index fail");
        return HDF_FAILURE;
    }

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRenderByDesc(descIndex, desc);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);

    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->DestroyRender, HDF_ERR_INVALID_PARAM);
    int32_t ret = hwiAdapter->DestroyRender(hwiAdapter, hwiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call DestroyRender fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    AudioHwiDestroyRenderByDesc(descIndex, desc);

    return HDF_SUCCESS;
}

int32_t AudioHwiCreateCapture(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct IAudioCapture **capture)
{
    struct AudioHwiCapture *hwiCapture = NULL;

    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);

    struct AudioHwiDeviceDescriptor hwiDesc;
    struct AudioHwiSampleAttributes hwiAttrs;
    (void)memset_s((void *)&hwiDesc, sizeof(hwiDesc), 0, sizeof(hwiDesc));
    (void)memset_s((void *)&hwiAttrs, sizeof(hwiAttrs), 0, sizeof(hwiAttrs));
    AudioHwiCommonDevDescToHwiDevDesc(desc, &hwiDesc);
    AudioHwiCommonAttrsToHwiAttrs(attrs, &hwiAttrs);

    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->CreateCapture, HDF_ERR_INVALID_PARAM);
    int32_t ret = hwiAdapter->CreateCapture(hwiAdapter, &hwiDesc, &hwiAttrs, &hwiCapture);
    OsalMemFree((void *)hwiDesc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call CreateCapture fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    uint32_t descIndex = AudioHwiGetDescIndexByAdapter(adapter);
    if (descIndex == UINT_MAX) {
        AUDIO_FUNC_LOGE("audio hwiAdapter get desc index fail");
        return HDF_FAILURE;
    }

    *capture = AudioHwiCreateCaptureByDesc(descIndex, desc, hwiCapture);
    CHECK_NULL_PTR_RETURN_VALUE(*capture, HDF_ERR_INVALID_PARAM);

    return HDF_SUCCESS;
}

int32_t AudioHwiDestroyCapture(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);

    uint32_t descIndex = AudioHwiGetDescIndexByAdapter(adapter);
    if (descIndex == UINT_MAX) {
        AUDIO_FUNC_LOGE("audio hwiAdapter get desc index fail");
        return HDF_FAILURE;
    }

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCaptureByDesc(descIndex, desc);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->DestroyCapture, HDF_ERR_INVALID_PARAM);
    int32_t ret = hwiAdapter->DestroyCapture(hwiAdapter, hwiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call DestroyCapture fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    AudioHwiDestroyCaptureByDesc(descIndex, desc);

    return HDF_SUCCESS;
}

int32_t AudioHwiGetPortCapability(struct IAudioAdapter *adapter, const struct AudioPort *port,
    struct AudioPortCapability* capability)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(port, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(capability, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);

    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->GetPortCapability, HDF_ERR_INVALID_PARAM);
    struct AudioHwiPortCapability hwiCap;
    struct AudioHwiPort hwiPort;
    (void)memset_s(&hwiCap, sizeof(hwiCap), 0, sizeof(hwiCap));
    (void)memset_s(&hwiPort, sizeof(hwiPort), 0, sizeof(hwiPort));

    int32_t ret = AudioHwiCommonPortToHwiPort(port, &hwiPort);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)hwiPort.portName);
        AUDIO_FUNC_LOGE("audio hwiAdapter call PortCapToHwiPortCap fail, ret=%{public}d", ret);
        return ret;
    }

    ret = hwiAdapter->GetPortCapability(hwiAdapter, &hwiPort, &hwiCap);
    OsalMemFree((void *)hwiPort.portName);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call GetPortCapability fail, ret=%{public}d", ret);
        return ret;
    }

    ret = AudioHwiCommonHwiPortCapToPortCap(&hwiCap, capability);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call PortCapToHwiPortCap fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiSetPassthroughMode(struct IAudioAdapter *adapter, const struct AudioPort *port,
    enum AudioPortPassthroughMode mode)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(port, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->SetPassthroughMode, HDF_ERR_INVALID_PARAM);

    struct AudioHwiPort hwiPort;
    (void)memset_s((void *)&hwiPort, sizeof(hwiPort), 0, sizeof(hwiPort));
    int32_t ret = AudioHwiCommonPortToHwiPort(port, &hwiPort);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)hwiPort.portName);
        AUDIO_FUNC_LOGE("audio hwiAdapter call PortCapToHwiPortCap fail, ret=%{public}d", ret);
        return ret;
    }

    ret = hwiAdapter->SetPassthroughMode(hwiAdapter, &hwiPort, (enum AudioHwiPortPassthroughMode)mode);
    OsalMemFree((void *)hwiPort.portName);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call SetPassthroughMode fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiGetPassthroughMode(struct IAudioAdapter *adapter, const struct AudioPort *port,
    enum AudioPortPassthroughMode *mode)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(port, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(mode, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->GetPassthroughMode, HDF_ERR_INVALID_PARAM);

    struct AudioHwiPort hwiPort;
    (void)memset_s((void *)&hwiPort, sizeof(hwiPort), 0, sizeof(hwiPort));
    int32_t ret = AudioHwiCommonPortToHwiPort(port, &hwiPort);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)hwiPort.portName);
        AUDIO_FUNC_LOGE("audio hwiAdapter call PortCapToHwiPortCap fail, ret=%{public}d", ret);
        return ret;
    }

    ret = hwiAdapter->GetPassthroughMode(hwiAdapter, &hwiPort, (enum AudioHwiPortPassthroughMode *)mode);
    OsalMemFree((void *)hwiPort.portName);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call GetPassthroughMode fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiGetDeviceStatus(struct IAudioAdapter *adapter, struct AudioDeviceStatus *status)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(status, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->GetDeviceStatus, HDF_ERR_INVALID_PARAM);

    struct AudioHwiDeviceStatus hwiStatus;
    (void)memset_s((void *)&hwiStatus, sizeof(hwiStatus), 0, sizeof(hwiStatus));
    int32_t ret = hwiAdapter->GetDeviceStatus(hwiAdapter, &hwiStatus);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call GetDeviceStatus fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    status->pnpStatus = hwiStatus.pnpStatus;
    return HDF_SUCCESS;
}

int32_t AudioHwiUpdateAudioRoute(struct IAudioAdapter *adapter, const struct AudioRoute *route, int32_t *routeHandle)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(route, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(routeHandle, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->UpdateAudioRoute, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRoute hwiRoute;
    (void)memset_s(&hwiRoute, sizeof(hwiRoute), 0, sizeof(hwiRoute));

    int32_t ret = AudioHwiCommonRouteToHwiRoute(route, &hwiRoute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter route To hwiRoute fail");
        return HDF_FAILURE;
    }

    ret = hwiAdapter->UpdateAudioRoute(hwiAdapter, &hwiRoute, routeHandle);
    AudioHwiCommonFreeHwiRoute(&hwiRoute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call UpdateAudioRoute fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiReleaseAudioRoute(struct IAudioAdapter *adapter, int32_t routeHandle)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->ReleaseAudioRoute, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiAdapter->ReleaseAudioRoute(hwiAdapter, routeHandle);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call ReleaseAudioRoute fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiSetMicMute(struct IAudioAdapter *adapter, bool mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->SetMicMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiAdapter->SetMicMute(hwiAdapter, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call SetMicMute fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiGetMicMute(struct IAudioAdapter *adapter, bool *mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(mute, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->GetMicMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiAdapter->GetMicMute(hwiAdapter, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call GetMicMute fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiSetVoiceVolume(struct IAudioAdapter *adapter, float volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->SetVoiceVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiAdapter->SetVoiceVolume(hwiAdapter, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call SetVoiceVolume fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiSetExtraParams(struct IAudioAdapter *adapter, enum AudioExtParamKey key, const char *condition,
    const char *value)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(condition, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(value, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->SetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiAdapter->SetExtraParams(hwiAdapter, (enum AudioHwiExtParamKey)key, condition, value);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call SetExtraParams fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiGetExtraParams(struct IAudioAdapter *adapter, enum AudioExtParamKey key, const char *condition,
    char *value, uint32_t valueLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(condition, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(value, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->GetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiAdapter->GetExtraParams(hwiAdapter, (enum AudioHwiExtParamKey)key, condition, value,
        (int32_t)valueLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call GetExtraParams fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioHwiParamHwiCallback(enum AudioHwiExtParamKey key, const char *condition, const char *value,
    void *reserved, void *cookie)
{
    CHECK_NULL_PTR_RETURN_VALUE(condition, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(value, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(reserved, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(cookie, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();
    struct IAudioCallback *cb = priv->callback;
    int32_t ret = cb->ParamCallback(cb, (enum AudioExtParamKey)key, condition, value, reserved, *(int8_t *)cookie);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call GetExtraParams fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRegExtraParamObserver(struct IAudioAdapter *adapter, struct IAudioCallback *audioCallback,
    int8_t cookie)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(audioCallback, HDF_ERR_INVALID_PARAM);

    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();
    if (priv->isRegCb) {
        AUDIO_FUNC_LOGI("audio hwiAdapter call AudioHwiRegExtraParamObserver have registered");
        return HDF_SUCCESS;
    }

    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAdapter->RegExtraParamObserver, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiAdapter->RegExtraParamObserver(hwiAdapter, AudioHwiParamHwiCallback, &cookie);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter call RegExtraParamObserver fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    priv->callback = audioCallback;
    priv->isRegCb = true;

    return HDF_SUCCESS;
}

int32_t AudioHwiAdapterGetVersion(struct IAudioAdapter *adapter, uint32_t *majorVer, uint32_t *minorVer)
{
    (void)adapter;
    CHECK_NULL_PTR_RETURN_VALUE(majorVer, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(minorVer, HDF_ERR_INVALID_PARAM);
    *majorVer = IAUDIO_ADAPTER_MAJOR_VERSION;
    *minorVer = IAUDIO_ADAPTER_MINOR_VERSION;

    return HDF_SUCCESS;
}

static void AudioHwiInitAdapterInstance(struct IAudioAdapter *adapter)
{
    adapter->InitAllPorts = AudioHwiInitAllPorts;
    adapter->CreateRender = AudioHwiCreateRender;
    adapter->DestroyRender = AudioHwiDestroyRender;
    adapter->CreateCapture = AudioHwiCreateCapture;
    adapter->DestroyCapture = AudioHwiDestroyCapture;

    adapter->GetPortCapability = AudioHwiGetPortCapability;
    adapter->SetPassthroughMode = AudioHwiSetPassthroughMode;
    adapter->GetPassthroughMode = AudioHwiGetPassthroughMode;
    adapter->GetDeviceStatus = AudioHwiGetDeviceStatus;
    adapter->UpdateAudioRoute = AudioHwiUpdateAudioRoute;

    adapter->ReleaseAudioRoute = AudioHwiReleaseAudioRoute;
    adapter->SetMicMute = AudioHwiSetMicMute;
    adapter->GetMicMute = AudioHwiGetMicMute;
    adapter->SetVoiceVolume = AudioHwiSetVoiceVolume;
    adapter->SetExtraParams = AudioHwiSetExtraParams;

    adapter->GetExtraParams = AudioHwiGetExtraParams;
    adapter->RegExtraParamObserver = AudioHwiRegExtraParamObserver;
    adapter->GetVersion = AudioHwiAdapterGetVersion;
}

uint32_t AudioHwiGetAdapterRefCnt(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("get adapter ref error, descIndex=%{public}d", descIndex);
        return UINT_MAX;
    }

    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();
    return priv->adapterInfo[descIndex].refCnt;
}

int32_t AudioHwiIncreaseAdapterRef(uint32_t descIndex, struct IAudioAdapter **adapter)
{
    CHECK_NULL_PTR_RETURN_VALUE(adapter, HDF_ERR_INVALID_PARAM);
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("increase adapter ref error, descIndex=%{public}d", descIndex);
        return HDF_ERR_INVALID_PARAM;
    }

    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();
    if (priv->adapterInfo[descIndex].adapter == NULL) {
        AUDIO_FUNC_LOGE("Invalid adapter param!");
        return HDF_ERR_INVALID_PARAM;
    }

    priv->adapterInfo[descIndex].refCnt++;
    *adapter = priv->adapterInfo[descIndex].adapter;
    AUDIO_FUNC_LOGI("increase adapternameIndex[%{public}d], refCount[%{public}d]", descIndex,
        priv->adapterInfo[descIndex].refCnt);

    return HDF_SUCCESS;
}

void AudioHwiDecreaseAdapterRef(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("decrease adapter ref error, descIndex=%{public}d", descIndex);
    }

    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();
    if (priv->adapterInfo[descIndex].refCnt == 0) {
        AUDIO_FUNC_LOGE("Invalid adapterInfo[%{public}d] had released", descIndex);
        return;
    }
    priv->adapterInfo[descIndex].refCnt--;
    AUDIO_FUNC_LOGI("decrease adapternameIndex[%{public}d], refCount[%{public}d]", descIndex,
        priv->adapterInfo[descIndex].refCnt);
}

void AudioHwiEnforceClearAdapterRefCnt(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("decrease adapter descIndex error, descIndex=%{public}d", descIndex);
    }

    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();
    priv->adapterInfo[descIndex].refCnt = 0;
    AUDIO_FUNC_LOGI("clear adapter ref count zero");
}

struct IAudioAdapter *AudioHwiCreateAdapter(uint32_t descIndex, struct AudioHwiAdapter *hwiAdapter)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("create adapter error, descIndex=%{public}d", descIndex);
        return NULL;
    }

    if (hwiAdapter == NULL) {
        AUDIO_FUNC_LOGE("audio hwiAdapter is null");
        return NULL;
    }

    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();
    struct IAudioAdapter *adapter = priv->adapterInfo[descIndex].adapter;
    if (adapter != NULL) {
        return adapter;
    }

    adapter = (struct IAudioAdapter *)OsalMemCalloc(sizeof(struct IAudioAdapter));
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc adapter fail");
        return NULL;
    }

    AudioHwiInitAdapterInstance(adapter);
    int32_t ret = AudioHwiRenderInit(descIndex);
    if (ret != HDF_SUCCESS) {
        OsalMemFree(adapter);
        AUDIO_FUNC_LOGE(" audio hwiAdapter init render fail");
        return NULL;
    }

    ret = AudioHwiCaptureInit(descIndex);
    if (ret != HDF_SUCCESS) {
        OsalMemFree(adapter);
        AudioHwiRenderDeinit(descIndex);
        AUDIO_FUNC_LOGE(" audio hwiAdapter init capture fail");
        return NULL;
    }
    priv->adapterInfo[descIndex].hwiAdapter = hwiAdapter;
    priv->adapterInfo[descIndex].adapter = adapter;
    priv->adapterInfo[descIndex].refCnt = 1;

    AUDIO_FUNC_LOGI(" audio hwiAdapter create adapter success, refcount[1]");
    return adapter;
}

void AudioHwiReleaseAdapter(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("adapter release fail descIndex=%{public}d", descIndex);
        return;
    }

    struct AudioHwiAdapterPriv *priv = AudioHwiAdapterGetPriv();

    AudioHwiRenderDeinit(descIndex);
    AudioHwiCaptureDeinit(descIndex);
    OsalMemFree((void *)priv->adapterInfo[descIndex].adapter);
    priv->adapterInfo[descIndex].adapter = NULL;
    priv->adapterInfo[descIndex].hwiAdapter = NULL;
    priv->adapterInfo[descIndex].refCnt = UINT_MAX;

    priv->isRegCb = false;
    priv->callback = NULL;

    AUDIO_FUNC_LOGI(" audio hwiAdapter release adapter success");
}