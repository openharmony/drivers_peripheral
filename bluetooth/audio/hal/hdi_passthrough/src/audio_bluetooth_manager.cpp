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
SetUpFunc setUpFunc;
TearDownFunc tearDownFunc;
GetStateFunc getStateFunc;
StartPlayingFunc startPlayingFunc;
SuspendPlayingFunc suspendPlayingFunc;
StopPlayingFunc stopPlayingFunc;
WriteFrameFunc writeFrameFunc;
#endif

sptr<IBluetoothA2dpSrc> g_proxy_ = nullptr;
static sptr<BluetoothA2dpSrcObserver> g_btA2dpSrcObserverCallbacks = nullptr;
int g_playState = A2DP_NOT_PLAYING;
std::map<int, std::string> g_playdevices {};
std::mutex g_playStateMutex;

static void AudioOnConnectionStateChanged(const RawAddress &device, int state)
{
    HDF_LOGI("%{public}s, state:%{public}d", __func__, state);
    (void) state;
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
static bool InitAudioDeviceSoHandle(const char* path)
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

        setUpFunc = (SetUpFunc)dlsym(g_ptrAudioDeviceHandle, "SetUp");
        tearDownFunc = (TearDownFunc)dlsym(g_ptrAudioDeviceHandle, "TearDown");
        getStateFunc = (GetStateFunc)dlsym(g_ptrAudioDeviceHandle, "GetState");
        startPlayingFunc = (StartPlayingFunc)dlsym(g_ptrAudioDeviceHandle, "StartPlaying");
        suspendPlayingFunc = (SuspendPlayingFunc)dlsym(g_ptrAudioDeviceHandle, "SuspendPlaying");
        stopPlayingFunc = (StopPlayingFunc)dlsym(g_ptrAudioDeviceHandle, "StopPlaying");
        writeFrameFunc = (WriteFrameFunc)dlsym(g_ptrAudioDeviceHandle, "WriteFrame");
        if (setUpFunc == NULL || tearDownFunc == NULL || getStateFunc == NULL || startPlayingFunc == NULL ||
            suspendPlayingFunc == NULL || stopPlayingFunc == NULL || writeFrameFunc == NULL) {
                HDF_LOGE("%{public}s: lib so func not found", __func__);
                return false;
        }
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
#endif


int WriteFrame(const uint8_t *data, uint32_t size)
{
    HDF_LOGI("%{public}s", __func__);
#ifdef A2DP_HDI_SERVICE
    BTAudioStreamState state = getStateFunc();
    if (state != BTAudioStreamState::STARTED) {
        HDF_LOGE("%{public}s: state=%{public}hhu", __func__, state);
        if (!startPlayingFunc()) {
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
    HDF_LOGI("%{public}s", __func__);
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
}
}
