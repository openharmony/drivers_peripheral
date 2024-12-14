/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <map>
#include <hdf_log.h>
#include <atomic>
#include "audio_internal.h"
#include "i_bluetooth_a2dp_src.h"
#include "i_bluetooth_host.h"
#include "bluetooth_a2dp_src_observer.h"
#include "bluetooth_def.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "audio_bluetooth_manager.h"

#ifdef A2DP_HDI_SERVICE
#include "bluetooth_audio_device.h"
#endif

#define HDF_LOG_TAG BTAudioBluetoothManager

namespace OHOS {
namespace Bluetooth {
using namespace OHOS::bluetooth;

#ifdef A2DP_HDI_SERVICE
using namespace OHOS::bluetooth::audio;
static const char *g_bluetoothAudioDeviceSoPath = HDF_LIBRARY_FULL_PATH("libbluetooth_audio_session");
static void *g_ptrAudioDeviceHandle = NULL;
std::atomic_bool g_allowAudioStart = true;

SetUpFunc setUpFunc;
TearDownFunc tearDownFunc;
GetStateFunc getStateFunc;
StartPlayingFunc startPlayingFunc;
SuspendPlayingFunc suspendPlayingFunc;
StopPlayingFunc stopPlayingFunc;
WriteFrameFunc writeFrameFunc;
GetLatencyFunc getLatencyFunc;

SetUpFunc fastSetUpFunc;
TearDownFunc fastTearDownFunc;
GetStateFunc fastGetStateFunc;
StartPlayingFunc fastStartPlayingFunc;
SuspendPlayingFunc fastSuspendPlayingFunc;
StopPlayingFunc fastStopPlayingFunc;
ReqMmapBufferFunc fastReqMmapBufferFunc;
ReadMmapPositionFunc fastReadMmapPositionFunc;
GetLatencyFunc fastGetLatencyFunc;
GetRealStateFunc getRealStateFunc;
GetRenderMixerStateFunc getRenderMixerStateFunc;
#endif

sptr<IBluetoothA2dpSrc> g_proxy_ = nullptr;
static sptr<BluetoothA2dpSrcObserver> g_btA2dpSrcObserverCallbacks = nullptr;
int g_playState = A2DP_NOT_PLAYING;
std::map<int, std::string> g_playdevices {};
std::mutex g_playStateMutex;

static void AudioOnConnectionStateChanged(const RawAddress &device, int state, int cause)
{
    HDF_LOGI("%{public}s, state:%{public}d", __func__, state);
    (void) state;
    (void) cause;
}

static void AudioOnPlayingStatusChanged(const RawAddress &device, int playingState, int error)
{
    HDF_LOGI("%{public}s, playingState:%{public}d", __func__, playingState);
    std::lock_guard<std::mutex> lock(g_playStateMutex);
    std::string addr = device.GetAddress();
    if (playingState) {
        for (const auto &it : g_playdevices) {
            if (strcmp(it.second.c_str(), device.GetAddress().c_str()) == 0) {
                return;
            }
        }
        g_playdevices.insert(std::make_pair(playingState, addr));
        g_playState = playingState;
    } else {
        std::map<int, std::string>::iterator it;
        for (it = g_playdevices.begin(); it != g_playdevices.end(); it++) {
            if (strcmp(it->second.c_str(), device.GetAddress().c_str()) == 0) {
                g_playdevices.erase(it);
                break;
            }
        }
        if (g_playdevices.empty()) {
            g_playState = playingState;
        }
    }
    (void) error;
}

static void AudioOnConfigurationChanged(const RawAddress &device, const BluetoothA2dpCodecInfo &info, int error)
{
    (void) device;
    (void) info;
    (void) error;
}

static void AudioOnMediaStackChanged(const RawAddress &device, int action)
{
    (void) device;
    (void) action;
}


static BtA2dpAudioCallback g_hdiCallbacks = {
    .OnConnectionStateChanged = AudioOnConnectionStateChanged,
    .OnPlayingStatusChanged = AudioOnPlayingStatusChanged,
    .OnConfigurationChanged =  AudioOnConfigurationChanged,
    .OnMediaStackChanged = AudioOnMediaStackChanged,
};

int GetPlayingState()
{
    HDF_LOGI("%{public}s: state:%{public}d", __func__, g_playState);
    return g_playState;
}

void GetProxy()
{
    HDF_LOGI("%{public}s start", __func__);
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!samgr) {
        HDF_LOGE("%{public}s: error: no samgr", __func__);
        return;
    }

    sptr<IRemoteObject> hostRemote = samgr->GetSystemAbility(BLUETOOTH_HOST_SYS_ABILITY_ID);
    if (!hostRemote) {
        HDF_LOGE("%{public}s: failed: no hostRemote", __func__);
        return;
    }

    sptr<IBluetoothHost> hostProxy = iface_cast<IBluetoothHost>(hostRemote);
    if (!hostProxy) {
        HDF_LOGE("%{public}s: error: host no proxy", __func__);
        return;
    }

    sptr<IRemoteObject> remote = hostProxy->GetProfile("A2dpSrcServer");
    if (!remote) {
        HDF_LOGE("%{public}s: error: no remote", __func__);
        return;
    }

    g_proxy_ = iface_cast<IBluetoothA2dpSrc>(remote);
    if (!g_proxy_) {
        HDF_LOGE("%{public}s: error: no proxy", __func__);
        return;
    }
}

void RegisterObserver()
{
    HDF_LOGI("%{public}s", __func__);
    g_btA2dpSrcObserverCallbacks = new (std::nothrow) BluetoothA2dpSrcObserver(&g_hdiCallbacks);
    if (!g_btA2dpSrcObserverCallbacks) {
        HDF_LOGE("%{public}s: g_btA2dpSrcObserverCallbacks is null", __func__);
        return;
    }
    if (!g_proxy_) {
        HDF_LOGE("%{public}s: g_proxy_ is null", __func__);
        return;
    }
    g_proxy_->RegisterObserver(g_btA2dpSrcObserverCallbacks);
}

void DeRegisterObserver()
{
    HDF_LOGI("%{public}s", __func__);
    if (!g_proxy_) {
        HDF_LOGE("%{public}s: g_proxy_ is null", __func__);
        return;
    }
    g_proxy_->DeregisterObserver(g_btA2dpSrcObserverCallbacks);
}

#ifdef A2DP_HDI_SERVICE
#define GET_SYM_ERRPR_RET(handle, funcType, funcPtr, funcStr)       \
    do {                                                            \
        funcPtr = (funcType)dlsym(handle, funcStr);                 \
        if (funcPtr == nullptr) {                                   \
            HDF_LOGE("%{public}s: lib so func not found", funcStr); \
            return false;                                           \
        }                                                           \
    } while (0)

static bool InitAudioDeviceSoHandle(const char *path)
{
    if (path == NULL) {
        HDF_LOGE("%{public}s: path is NULL", __func__);
        return false;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(path, pathBuf) == NULL) {
        return false;
    }
    if (g_ptrAudioDeviceHandle == NULL) {
        g_ptrAudioDeviceHandle = dlopen(pathBuf, RTLD_LAZY);
        if (g_ptrAudioDeviceHandle == NULL) {
            HDF_LOGE("%{public}s: open lib so fail, reason:%{public}s ", __func__, dlerror());
            return false;
        }
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, SetUpFunc, setUpFunc, "SetUp");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, TearDownFunc, tearDownFunc, "TearDown");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, GetStateFunc, getStateFunc, "GetState");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, StartPlayingFunc, startPlayingFunc, "StartPlaying");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, SuspendPlayingFunc, suspendPlayingFunc, "SuspendPlaying");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, StopPlayingFunc, stopPlayingFunc, "StopPlaying");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, WriteFrameFunc, writeFrameFunc, "WriteFrame");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, GetLatencyFunc, getLatencyFunc, "GetLatency");

        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, SetUpFunc, fastSetUpFunc, "FastSetUp");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, TearDownFunc, fastTearDownFunc, "FastTearDown");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, GetStateFunc, fastGetStateFunc, "FastGetState");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, StartPlayingFunc, fastStartPlayingFunc, "FastStartPlaying");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, SuspendPlayingFunc, fastSuspendPlayingFunc, "FastSuspendPlaying");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, StopPlayingFunc, fastStopPlayingFunc, "FastStopPlaying");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, ReqMmapBufferFunc, fastReqMmapBufferFunc, "FastReqMmapBuffer");
        GET_SYM_ERRPR_RET(
            g_ptrAudioDeviceHandle, ReadMmapPositionFunc, fastReadMmapPositionFunc, "FastReadMmapPosition");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, GetLatencyFunc, fastGetLatencyFunc, "FastGetLatency");
        GET_SYM_ERRPR_RET(g_ptrAudioDeviceHandle, GetRealStateFunc, getRealStateFunc, "GetRealState");
        GET_SYM_ERRPR_RET(
            g_ptrAudioDeviceHandle, GetRenderMixerStateFunc, getRenderMixerStateFunc, "GetRenderMixerState");
    }
    return true;
}

bool SetUp()
{
    bool ret = false;
    ret = InitAudioDeviceSoHandle(g_bluetoothAudioDeviceSoPath);
    if (ret == true) {
        ret = setUpFunc();
    }
    if (ret == false) {
        HDF_LOGE("%{public}s failed!", __func__);
    }
    return ret;
}

void TearDown()
{
    tearDownFunc();
}

bool FastSetUp()
{
    bool ret = InitAudioDeviceSoHandle(g_bluetoothAudioDeviceSoPath);
    if (ret) {
        ret = fastSetUpFunc();
    }
    if (!ret) {
        HDF_LOGE("%{public}s failed", __func__);
    }
    return ret;
}

void FastTearDown()
{
    fastTearDownFunc();
}

int FastStartPlaying(uint32_t sampleRate, uint32_t channelCount, uint32_t format)
{
    BTAudioStreamState state = fastGetStateFunc();
    if (!g_allowAudioStart.load()) {
        HDF_LOGE("not allow to start fast render, state=%{public}hhu", state);
        return HDF_FAILURE;
    } else if (state != BTAudioStreamState::STARTED) {
        HDF_LOGI("%{public}s, state=%{public}hhu", __func__, state);
        if (!fastStartPlayingFunc(sampleRate, channelCount, format)) {
            HDF_LOGE("%{public}s, fail to startPlaying", __func__);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int FastSuspendPlayingFromParam()
{
    int ret = 0;
    RenderMixerState renderState = getRenderMixerStateFunc();
    if (!g_allowAudioStart.load()) {
        if (renderState == RenderMixerState::INITED || renderState == RenderMixerState::NORMAL_ON_MIX_STOP) {
            HDF_LOGE("fast render is already stopping or stopped");
            return ret;
        }
    }

    BTAudioStreamState state = fastGetStateFunc();
    BTAudioStreamState realState = getRealStateFunc();
    g_allowAudioStart = false;
    if (state == BTAudioStreamState::STARTED) {
        HDF_LOGI("%{public}s", __func__);
        ret = (fastSuspendPlayingFunc() ? HDF_SUCCESS : HDF_FAILURE);
    } else if (realState == BTAudioStreamState::STARTING && renderState == RenderMixerState::FAST_STARTED) {
        HDF_LOGI("%{public}s fast render starting, so stopPlaying", __func__);
        ret = (fastStopPlayingFunc() ? HDF_SUCCESS : HDF_FAILURE);
    } else {
        HDF_LOGE("%{public}s, state=%{public}hhu is bad state, realState=%{public}hhu, renderState=%{public}hhu",
            __func__, state, realState, renderState);
    }
    return ret;
}

int FastSuspendPlaying()
{
    int ret = 0;
    BTAudioStreamState state = fastGetStateFunc();
    if (state == BTAudioStreamState::STARTED) {
        ret = (fastSuspendPlayingFunc() ? HDF_SUCCESS : HDF_FAILURE);
    } else {
        HDF_LOGE("%{public}s, state=%{public}hhu is bad state", __func__, state);
    }
    return ret;
}

int FastStopPlaying()
{
    BTAudioStreamState state = fastGetStateFunc();
    HDF_LOGI("%{public}s, state=%{public}hhu", __func__, state);
    if (state != BTAudioStreamState::INVALID) {
        fastStopPlayingFunc();
    }
    return HDF_SUCCESS;
}

int FastReqMmapBuffer(int32_t ashmemLength)
{
    return fastReqMmapBufferFunc(ashmemLength);
}

void FastReadMmapPosition(int64_t &sec, int64_t &nSec, uint64_t &frames)
{
    fastReadMmapPositionFunc(sec, nSec, frames);
}

int FastGetLatency(uint32_t &latency)
{
    return (fastGetLatencyFunc(latency) ? HDF_SUCCESS : HDF_FAILURE);
}

int SuspendPlayingFromParam()
{
    int retVal = 0;
    RenderMixerState renderState = getRenderMixerStateFunc();
    if (!g_allowAudioStart.load()) {
        if (renderState == RenderMixerState::INITED || renderState == RenderMixerState::FAST_ON_MIX_STOP) {
            HDF_LOGE("normal render is already stopping or stopped");
            return retVal;
        }
    }

    BTAudioStreamState state = getStateFunc();
    BTAudioStreamState realState = getRealStateFunc();
    g_allowAudioStart = false;
    if (state == BTAudioStreamState::STARTED) {
        HDF_LOGI("%{public}s", __func__);
        retVal = (suspendPlayingFunc() ? HDF_SUCCESS : HDF_FAILURE);
    } else if (realState == BTAudioStreamState::STARTING && renderState == RenderMixerState::INITED) {
        HDF_LOGI("%{public}s normal render starting, so stopPlaying", __func__);
        retVal = (stopPlayingFunc() ? HDF_SUCCESS : HDF_FAILURE);
    } else {
        HDF_LOGE("%{public}s, state=%{public}hhu is bad state, realState=%{public}hhu, renderState=%{public}hhu",
            __func__, state, realState, renderState);
    }
    return retVal;
}

void UnBlockStart()
{
    g_allowAudioStart = true;
}
#endif

int WriteFrame(const uint8_t *data, uint32_t size, const HDI::Audio_Bluetooth::AudioSampleAttributes *attrs)
{
    HDF_LOGD("%{public}s", __func__);
#ifdef A2DP_HDI_SERVICE
    BTAudioStreamState state = getStateFunc();
    if (!g_allowAudioStart.load()) {
        HDF_LOGE("not allow to start normal render, state=%{public}hhu", state);
        return HDF_FAILURE;
    } else if (state != BTAudioStreamState::STARTED) {
        HDF_LOGE("%{public}s: state=%{public}hhu", __func__, state);
        if (!startPlayingFunc(attrs->sampleRate, attrs->channelCount, static_cast<uint32_t>(attrs->format))) {
            HDF_LOGE("%{public}s: fail to startPlaying", __func__);
            return HDF_FAILURE;
        }
    }
    return writeFrameFunc(data, size);
#else
    if (!g_proxy_) {
        HDF_LOGE("%{public}s: g_proxy_ is null", __func__);
        return RET_BAD_STATUS;
    }
    if (g_playState == A2DP_NOT_PLAYING) {
        HDF_LOGE("%{public}s: playState is not Streaming", __func__);
        return RET_BAD_STATUS;
    }
    return g_proxy_->WriteFrame(data, size);
#endif
}

int StartPlaying()
{
    HDF_LOGI("%{public}s", __func__);
#ifdef A2DP_HDI_SERVICE
    return HDF_SUCCESS;
#else
    if (!g_proxy_) {
        HDF_LOGE("%{public}s: g_proxy_ is null", __func__);
        return RET_BAD_STATUS;
    }
    return g_proxy_->StartPlaying(g_proxy_->GetActiveSinkDevice());
#endif
}

int SuspendPlaying()
{
#ifdef A2DP_HDI_SERVICE
    int retval = 0;
    BTAudioStreamState state = getStateFunc();
    HDF_LOGE("%{public}s: state=%{public}hhu", __func__, state);
    if (state == BTAudioStreamState::STARTED) {
        retval = (suspendPlayingFunc() ? HDF_SUCCESS : HDF_FAILURE);
    } else {
        HDF_LOGE("%{public}s: state=%{public}hhu is bad state", __func__, state);
    }
    return retval;
#else
    HDF_LOGI("%{public}s", __func__);
    if (!g_proxy_) {
        HDF_LOGE("%{public}s: g_proxy_ is null", __func__);
        return RET_BAD_STATUS;
    }
    return g_proxy_->SuspendPlaying(g_proxy_->GetActiveSinkDevice());
#endif
}

int StopPlaying()
{
    HDF_LOGI("%{public}s", __func__);
#ifdef A2DP_HDI_SERVICE
    BTAudioStreamState state = getStateFunc();
    HDF_LOGE("%{public}s: state=%{public}hhu", __func__, state);
    if (state != BTAudioStreamState::INVALID) {
        stopPlayingFunc();
    }
    return HDF_SUCCESS;
#else
    if (!g_proxy_) {
        HDF_LOGE("%{public}s: g_proxy_ is null", __func__);
        return RET_BAD_STATUS;
    }
    return g_proxy_->StopPlaying(g_proxy_->GetActiveSinkDevice());
#endif
}

int GetLatency(uint32_t &latency)
{
    HDF_LOGI("%{public}s", __func__);
#ifdef A2DP_HDI_SERVICE
    return (getLatencyFunc(latency) ? HDF_SUCCESS : HDF_FAILURE);
#else
    return HDF_ERR_NOT_SUPPORT;
#endif
}
}
}
