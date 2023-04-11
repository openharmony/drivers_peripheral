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
#include "v1_0/iaudio_manager.h"

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
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen);
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

void AudioAdapterBenchmarkTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if ((descsLen > 0) && (descs != nullptr) && ((*descs) == nullptr)) {
        return;
    }

    for (uint32_t i = 0; i < descsLen; i++) {
        AudioAdapterDescriptorFree(&(*descs)[i], false);
    }
    OsalMemFree(*descs);
    *descs = nullptr;
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
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_LT(size, g_audioAdapterNumMax);
    }

    if (manager_->LoadAdapter(manager_, &adapterDescs_[0], &adapter_) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_TRUE(false);
    }

    if (adapter_ == nullptr) {
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_TRUE(false);
    }
}

void AudioAdapterBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    ASSERT_NE(manager_, nullptr);
    ASSERT_NE(adapter_, nullptr);

    manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName);
    ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
    adapter_ = nullptr;
    IAudioManagerRelease(manager_, false);
    manager_ = nullptr;
}

BENCHMARK_F(AudioAdapterBenchmarkTest, DriverSystem_AudioAdapterBenchmark_InitAllPorts)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = adapter_->InitAllPorts(adapter_);
    }
    EXPECT_EQ(HDF_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, DriverSystem_AudioAdapterBenchmark_InitAllPorts)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, DriverSystem_AudioAdapterBenchmark_CreateRender)(benchmark::State &state)
{
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
    }
    EXPECT_EQ(HDF_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, DriverSystem_AudioAdapterBenchmark_CreateRender)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, DriverSystem_AudioAdapterBenchmark_CreateCapture)(benchmark::State &state)
{
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
    }
    EXPECT_EQ(HDF_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, DriverSystem_AudioAdapterBenchmark_CreateCapture)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_F(AudioAdapterBenchmarkTest, DriverSystem_AudioAdapterBenchmark_GetPortCapability)(benchmark::State &state)
{
    int32_t ret;
    struct AudioPort port = {};
    struct AudioPortCapability capability = {};
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = const_cast<char*>("primary");

    for (auto _ : state) {
        ret = adapter_->GetPortCapability(adapter_, &port, &capability);
    }
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

BENCHMARK_REGISTER_F(AudioAdapterBenchmarkTest, DriverSystem_AudioAdapterBenchmark_GetPortCapability)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();
}
