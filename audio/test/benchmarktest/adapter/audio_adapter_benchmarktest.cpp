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

#include <benchmark/benchmark.h>
#include <climits>
#include <gtest/gtest.h>
#include "hdf_base.h"
#include "osal_mem.h"
#include "v5_0/iaudio_manager.h"

using namespace testing::ext;
using namespace std;

#define AUDIO_CHANNELCOUNT             2
#define AUDIO_SAMPLE_RATE_48K          48000
#define DEEP_BUFFER_RENDER_PERIOD_SIZE 4096
#define INT_32_MAX                     0x7fffffff
#define PCM_16_BIT                     16
#define PCM_8_BIT                      8

namespace {
static const uint32_t g_audioAdapterNumMax = 5;
const int32_t AUDIO_ADAPTER_BUF_TEST = 1024;
const int32_t ITERATION_FREQUENCY = 100;
const int32_t REPETITION_FREQUENCY = 3;

class AudioAdapterBenchmarkTest : public benchmark::Fixture {
public:
    struct IAudioManager *manager_ = nullptr;
    struct IAudioAdapter *adapter_ = nullptr;
    struct AudioAdapterDescriptor *adapterDescs_ = nullptr;
    uint32_t renderId_ = 0;
    uint32_t captureId_ = 0;
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
    void InitAttrs(struct AudioSampleAttributes &attrs);
    void InitDevDesc(struct AudioDeviceDescriptor &devDesc);
    void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen);
};

void AudioAdapterBenchmarkTest::AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == nullptr) {
        return;
    }

    if (dataBlock->adapterName != nullptr) {
        OsalMemFree(dataBlock->adapterName);
        dataBlock->adapterName = nullptr;
    }

    if (dataBlock->ports != nullptr) {
        OsalMemFree(dataBlock->ports);
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void AudioAdapterBenchmarkTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen)
{
    if ((descs == nullptr) || (descsLen == 0)) {
        return;
    }

    for (uint32_t i = 0; i < descsLen; i++) {
        AudioAdapterDescriptorFree(&descs[i], false);
    }
}

void AudioAdapterBenchmarkTest::InitAttrs(struct AudioSampleAttributes &attrs)
{
    attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs.channelCount = AUDIO_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs.interleaved = 1;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = PCM_16_BIT * attrs.channelCount / PCM_8_BIT;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.frameSize);
    attrs.stopThreshold = INT_32_MAX;
}

void AudioAdapterBenchmarkTest::InitDevDesc(struct AudioDeviceDescriptor &devDesc)
{
    ASSERT_NE(adapterDescs_, nullptr);
    ASSERT_NE(adapterDescs_->ports, nullptr);
    for (uint32_t index = 0; index < adapterDescs_->portsLen; index++) {
        if (adapterDescs_->ports[index].dir == PORT_OUT) {
            devDesc.portId = adapterDescs_->ports[index].portId;
            return;
        }
    }
}

void AudioAdapterBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    uint32_t size = g_audioAdapterNumMax;
    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);

    adapterDescs_ = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(adapterDescs_, nullptr);

    ASSERT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, adapterDescs_, &size));
    if (size > g_audioAdapterNumMax) {
        ReleaseAdapterDescs(adapterDescs_, g_audioAdapterNumMax);
        ASSERT_LT(size, g_audioAdapterNumMax);
    }

    if (manager_->LoadAdapter(manager_, &adapterDescs_[0], &adapter_) != HDF_SUCCESS) {
        ReleaseAdapterDescs(adapterDescs_, g_audioAdapterNumMax);
        ASSERT_TRUE(false);
    }

    if (adapter_ == nullptr) {
        ReleaseAdapterDescs(adapterDescs_, g_audioAdapterNumMax);
        ASSERT_TRUE(false);
    }
}

void AudioAdapterBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    ASSERT_NE(manager_, nullptr);
    ASSERT_NE(adapter_, nullptr);

    manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName);
    ReleaseAdapterDescs(adapterDescs_, g_audioAdapterNumMax);
    adapter_ = nullptr;
    IAudioManagerRelease(manager_, false);
    manager_ = nullptr;
}

BENCHMARK_F(AudioAdapterBenchmarkTest, InitAllPorts)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    for (auto _ : state) {
        ret = adapter_->InitAllPorts(adapter_);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, InitAllPorts)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, CreateRenderAndDestroyRender)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    struct IAudioRender *render = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_OUT_SPEAKER;
    InitAttrs(attrs);
    attrs.silenceThreshold = 0;
    attrs.streamId = 0;

    for (auto _ : state) {
        ret = adapter_->CreateRender(adapter_, &devicedesc, &attrs, &render, &renderId_);
        if (ret != HDF_SUCCESS) {
            attrs.format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
            ASSERT_EQ(HDF_SUCCESS, adapter_->CreateRender(adapter_, &devicedesc, &attrs, &render, &renderId_));
        }
        ret = adapter_->DestroyRender(adapter_, renderId_);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, CreateRenderAndDestroyRender)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, CreateCaptureAndDestroyCapture)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_IN_MIC;
    InitAttrs(attrs);
    attrs.silenceThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE;

    for (auto _ : state) {
        ret = adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_);
        if (ret != HDF_SUCCESS) {
            attrs.format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
            ASSERT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_));
        }
        ret = adapter_->DestroyCapture(adapter_, captureId_);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, CreateCaptureAndDestroyCapture)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, GetPortCapability)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    struct AudioPort port = {};
    struct AudioPortCapability capability = {};
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = const_cast<char*>("primary");

    for (auto _ : state) {
        ret = adapter_->GetPortCapability(adapter_, &port, &capability);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, GetPortCapability)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, SetPassthroughMode)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    struct AudioPort port = {};
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = const_cast<char*>("primary");
    enum AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;

    for (auto _ : state) {
        ret = adapter_->SetPassthroughMode(adapter_, &port, mode);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, SetPassthroughMode)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, GetPassthroughMode)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    struct AudioPort port = {};
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = const_cast<char*>("primary");
    enum AudioPortPassthroughMode mode;

    for (auto _ : state) {
        ret = adapter_->GetPassthroughMode(adapter_, &port, &mode);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, GetPassthroughMode)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, GetDeviceStatus)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    struct AudioDeviceStatus status = {};

    for (auto _ : state) {
        ret = adapter_->GetDeviceStatus(adapter_, &status);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, GetDeviceStatus)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, GetMicMute)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    bool mute = false;

    for (auto _ : state) {
        ret = adapter_->GetMicMute(adapter_, &mute);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, GetMicMute)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, SetVoiceVolume)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    float volume = 0;

    for (auto _ : state) {
        ret = adapter_->SetVoiceVolume(adapter_, volume);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, SetVoiceVolume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, SetExtraParams)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_LOWPOWER;
    char condition[AUDIO_ADAPTER_BUF_TEST];
    const char *value = "sup_sampling_rates=4800;sup_channels=1;sup_formats=2;";

    for (auto _ : state) {
        ret = adapter_->SetExtraParams(adapter_, key, condition, value);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, SetExtraParams)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, GetExtraParams)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    char condition[AUDIO_ADAPTER_BUF_TEST];
    char value[AUDIO_ADAPTER_BUF_TEST] = "sup_sampling_rates=4800;sup_channels=1;sup_formats=2;";
    uint32_t valueLen = AUDIO_ADAPTER_BUF_TEST;

    for (auto _ : state) {
        ret = adapter_->GetExtraParams(adapter_, key, condition, value, valueLen);
        EXPECT_NE(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, GetExtraParams)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, UpdateAudioRoute)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    struct AudioRoute route = {};
    int32_t routeHandle = 0;

    for (auto _ : state) {
        ret = adapter_->UpdateAudioRoute(adapter_, &route, &routeHandle);
        EXPECT_NE(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, UpdateAudioRoute)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, ReleaseAudioRoute)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    int32_t routeHandle = 0;

    for (auto _ : state) {
        ret = adapter_->ReleaseAudioRoute(adapter_, routeHandle);
        EXPECT_NE(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, ReleaseAudioRoute)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, RegExtraParamObserver)(benchmark::State &state)
{
    ASSERT_NE(adapter_, nullptr);
    int32_t ret;
    int8_t cookie = 0;
    struct IAudioCallback *audioCallback = nullptr;

    for (auto _ : state) {
        ret = adapter_->RegExtraParamObserver(adapter_, audioCallback, cookie);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, RegExtraParamObserver)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}
