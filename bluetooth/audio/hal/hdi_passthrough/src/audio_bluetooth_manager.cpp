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

#include <hdf_log.h>
#include "audio_internal.h"
#include "i_bluetooth_a2dp_src.h"
#include "i_bluetooth_host.h"
#include "bluetooth_a2dp_src_observer.h"
#include "bluetooth_def.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "audio_bluetooth_manager.h"

namespace OHOS {
namespace Bluetooth {
using namespace bluetooth;

sptr<IBluetoothA2dpSrc> g_proxy_ = nullptr;
static sptr<BluetoothA2dpSrcObserver> g_btA2dpSrcObserverCallbacks = nullptr;
int g_playState = false;
RawAddress g_device;

static void AudioOnConnectionStateChanged(const RawAddress &device, int state)
{
    HDF_LOGD("audio_bluetooth_manager %{public}s, state:%{public}d", __func__, state);
    g_device = RawAddress(device);
}

static void AudioOnPlayingStatusChanged(const RawAddress &device, int playingState, int error)
{
    HDF_LOGD("audio_bluetooth_manager %{public}s, playingState:%{public}d", __func__, playingState);
    g_playState = playingState;
    (void) error;
}

static void AudioOnConfigurationChanged(const RawAddress &device, const BluetoothA2dpCodecInfo &info, int error)
{
    (void) device;
    (void) info;
    (void) error;
}


static BtA2dpAudioCallback g_hdiCallbacks = {
    .OnConnectionStateChanged = AudioOnConnectionStateChanged,
    .OnPlayingStatusChanged = AudioOnPlayingStatusChanged,
    .OnConfigurationChanged =  AudioOnConfigurationChanged,
};

int GetPlayingState()
{
    HDF_LOGD("audio_bluetooth_manager %{public}s: state:%{public}d", __func__, g_playState);
    return g_playState;
}

RawAddress& GetDevice()
{
    return g_device;
}

void GetProxy()
{
    HDF_LOGD("audio_bluetooth_manager %{public}s start", __func__);
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!samgr) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: error: no samgr", __func__);
        return;
    }

    sptr<IRemoteObject> hostRemote = samgr->GetSystemAbility(BLUETOOTH_HOST_SYS_ABILITY_ID);
    if (!hostRemote) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: failed: no hostRemote", __func__);
        return;
    }

    sptr<IBluetoothHost> hostProxy = iface_cast<IBluetoothHost>(hostRemote);
    if (!hostProxy) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: error: host no proxy", __func__);
        return;
    }

    sptr<IRemoteObject> remote = hostProxy->GetProfile("A2dpSrcServer");
    if (!remote) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: error: no remote", __func__);
        return;
    }

    g_proxy_ = iface_cast<IBluetoothA2dpSrc>(remote);
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: error: no proxy", __func__);
        return;
    }
}

void RegisterObserver()
{
    HDF_LOGD("audio_bluetooth_manager %{public}s", __func__);
    g_btA2dpSrcObserverCallbacks = new (std::nothrow) BluetoothA2dpSrcObserver(&g_hdiCallbacks);
    if (!g_btA2dpSrcObserverCallbacks) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_btA2dpSrcObserverCallbacks is null", __func__);
        return;
    }
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_proxy_ is null", __func__);
        return;
    }
    g_proxy_->RegisterObserver(g_btA2dpSrcObserverCallbacks);
}

void DeRegisterObserver()
{
    HDF_LOGD("audio_bluetooth_manager %{public}s", __func__);
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_proxy_ is null", __func__);
        return;
    }
    g_proxy_->DeregisterObserver(g_btA2dpSrcObserverCallbacks);
}

BluetoothA2dpCodecStatus GetCodecStatus()
{
    HDF_LOGD("audio_bluetooth_manager %{public}s", __func__);
    BluetoothA2dpCodecStatus codecStatus;
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_proxy_ is null", __func__);
        return codecStatus;
    }
    codecStatus = g_proxy_->GetCodecStatus(g_proxy_->GetActiveSinkDevice());
    return codecStatus;
}

int WriteFrame(const uint8_t *data, uint32_t size)
{
    HDF_LOGD("audio_bluetooth_manager %{public}s", __func__);
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_proxy_ is null", __func__);
        return RET_BAD_STATUS;
    }
    return g_proxy_->WriteFrame(data, size);
}

int StartPlaying()
{
    HDF_LOGD("audio_bluetooth_manager %{public}s", __func__);
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_proxy_ is null", __func__);
        return RET_BAD_STATUS;
    }
    return g_proxy_->StartPlaying(g_proxy_->GetActiveSinkDevice());
}

int SuspendPlaying()
{
    HDF_LOGD("audio_bluetooth_manager %{public}s", __func__);
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_proxy_ is null", __func__);
        return RET_BAD_STATUS;
    }
    return g_proxy_->SuspendPlaying(g_proxy_->GetActiveSinkDevice());
}

int StopPlaying()
{
    HDF_LOGD("audio_bluetooth_manager %{public}s", __func__);
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_proxy_ is null", __func__);
        return RET_BAD_STATUS;
    }
    return g_proxy_->StopPlaying(g_proxy_->GetActiveSinkDevice());
}

void GetRenderPosition(uint16_t &delayValue, uint16_t &dataSize, uint32_t &timeStamp)
{
    HDF_LOGD("audio_bluetooth_manager %{public}s", __func__);
    if (!g_proxy_) {
        HDF_LOGE("audio_bluetooth_manager %{public}s: g_proxy_ is null", __func__);
        return;
    }
    return g_proxy_->GetRenderPosition(delayValue, dataSize, timeStamp);
}
}
}