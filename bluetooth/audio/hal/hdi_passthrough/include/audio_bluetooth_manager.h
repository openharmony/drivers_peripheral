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

#ifndef AUDIO_BLUETOOTH_MANAGER_H
#define AUDIO_BLUETOOTH_MANAGER_H

#include "bluetooth_a2dp_codec.h"
#include "bluetooth_a2dp_a2dpCodecInfo.h"
#include "bluetooth_a2dp_a2dpCodecStatus.h"
#include "raw_address.h"
#include "audio_internal.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000105

namespace OHOS {
namespace Bluetooth {
using namespace OHOS::bluetooth;

typedef struct BtA2dpAudioCallback {
    void (*OnConnectionStateChanged)(const RawAddress &device, int state, int cause);
    void (*OnPlayingStatusChanged)(const RawAddress &device, int playingState, int error);
    void (*OnConfigurationChanged)(const RawAddress &device, const BluetoothA2dpCodecInfo &info, int error);
    void (*OnMediaStackChanged)(const RawAddress &device, int action);
}BtA2dpAudioCallback;

int GetPlayingState();
void GetProxy();
void RegisterObserver();
void DeRegisterObserver();

#ifdef A2DP_HDI_SERVICE
bool SetUp();
void TearDown();
bool FastSetUp();
void FastTearDown();
int FastStartPlaying(uint32_t sampleRate, uint32_t channelCount, uint32_t format);
int FastSuspendPlaying();
int FastStopPlaying();
int FastReqMmapBuffer(int32_t ashmemLength);
void FastReadMmapPosition(int64_t &sec, int64_t &nSec, uint64_t &frames);
int FastGetLatency(uint32_t &latency);
bool SetUpCapture();
void TearDownCapture();
int StartCapture();
int SuspendCapture();
int StopCapture();
int ReadFrame(uint8_t *data, uint64_t size);
#endif

int WriteFrame(const uint8_t *data, uint32_t size, const HDI::Audio_Bluetooth::AudioSampleAttributes *attrs);
int StartPlaying();
int SuspendPlaying();
int StopPlaying();
int GetLatency(uint32_t &latency);
}
}

#endif