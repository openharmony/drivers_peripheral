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
#include "v4_0/audio_types.h"
#include "v4_0/iaudio_manager.h"
#include "v4_0/iaudio_render.h"

using namespace std;
using namespace testing::ext;

namespace {
const float MAX_GAINTHRESHOLD = 15.0;
const float MIN_GAINTHRESHOLD = 0.0;
const int BUFFER_LENTH = 1024 * 16;
const int DEEP_BUFFER_RENDER_PERIOD_SIZE = 4 * 1024;
const int MOVE_LEFT_NUM = 8;
const int32_t AUDIO_RENDER_BUF_TEST = 1024;
const int32_t AUDIO_RENDER_CHANNELCOUNT = 2;
const int32_t AUDIO_SAMPLE_RATE_48K = 48000;
const int32_t MAX_AUDIO_ADAPTER_DESC = 5;
const uint64_t DEFAULT_BUFFER_SIZE = 16384;
const int32_t ITERATION_FREQUENCY = 100;
const int32_t REPETITION_FREQUENCY = 3;
const int32_t RANGE_VALUE = 4;
const float GAIN_VALUE = 1.0;
const float SPEED_VALUE = 2.0;
const float VOLUNE_VALUE = 0.2;

class AudioRenderBenchmarkTest : public benchmark::Fixture {
public:
    struct IAudioManager *manager_ = nullptr;
    struct AudioAdapterDescriptor descs_[MAX_AUDIO_ADAPTER_DESC];
    struct AudioAdapterDescriptor *desc_;
    struct IAudioAdapter *adapter_ = nullptr;
    struct IAudioRender *render_ = nullptr;
    struct AudioDeviceDescriptor devDescRender_ = {};
    struct AudioSampleAttributes attrsRender_ = {};
    uint32_t renderId_ = 0;
    char *devDescriptorName_ = nullptr;
    uint32_t size_ = MAX_AUDIO_ADAPTER_DESC;
    virtual void SetUp(const ::benchmark::State &state);
    virtual void TearDown(const ::benchmark::State &state);
    uint64_t GetRenderBufferSize();
    void InitRenderAttrs(struct AudioSampleAttributes &attrs);
    void InitRenderDevDesc(struct AudioDeviceDescriptor &devDesc);
    void FreeAdapterElements(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAllAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen);
};

uint64_t AudioRenderBenchmarkTest::GetRenderBufferSize()
{
    int32_t ret = HDF_SUCCESS;
    uint64_t frameSize = 0;
    uint64_t frameCount = 0;
    uint64_t bufferSize = 0;

    if (render_ == nullptr) {
        return DEFAULT_BUFFER_SIZE;
    }

    ret = render_->GetFrameSize(render_, &frameSize);
    if (ret != HDF_SUCCESS) {
        return DEFAULT_BUFFER_SIZE;
    }

    ret = render_->GetFrameCount(render_, &frameCount);
    if (ret != HDF_SUCCESS) {
        return DEFAULT_BUFFER_SIZE;
    }

    bufferSize = frameCount * frameSize;
    if (bufferSize == 0) {
        bufferSize = DEFAULT_BUFFER_SIZE;
    }

    return bufferSize;
}

void AudioRenderBenchmarkTest::InitRenderAttrs(struct AudioSampleAttributes &attrs)
{
    attrs.channelCount = AUDIO_RENDER_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs.interleaved = 0;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = AUDIO_FORMAT_TYPE_PCM_16_BIT * AUDIO_RENDER_CHANNELCOUNT / MOVE_LEFT_NUM;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.format * attrs.channelCount / MOVE_LEFT_NUM);
    attrs.stopThreshold = INT_MAX;
    attrs.silenceThreshold = BUFFER_LENTH;
}

void AudioRenderBenchmarkTest::InitRenderDevDesc(struct AudioDeviceDescriptor &devDesc)
{
    devDesc.pins = PIN_OUT_SPEAKER;
    devDescriptorName_ = strdup("cardname");
    devDesc.desc = devDescriptorName_;

    ASSERT_NE(desc_, nullptr);
    ASSERT_NE(desc_->ports, nullptr);
    for (uint32_t index = 0; index < desc_->portsLen; index++) {
        if (desc_->ports[index].dir == PORT_OUT) {
            devDesc.portId = desc_->ports[index].portId;
            return;
        }
    }
}

void AudioRenderBenchmarkTest::FreeAdapterElements(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == nullptr) {
        return;
    }

    OsalMemFree(dataBlock->adapterName);

    OsalMemFree(dataBlock->ports);

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void AudioRenderBenchmarkTest::ReleaseAllAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen)
{
    if (descs == nullptr || descsLen == 0) {
        return;
    }

    for (uint32_t i = 0; i < descsLen; i++) {
        FreeAdapterElements(&descs[i], false);
    }
}

void AudioRenderBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);

    ASSERT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, descs_, &size_));
    ASSERT_NE(descs_, nullptr);
    EXPECT_GE(MAX_AUDIO_ADAPTER_DESC, size_);
    desc_ = &descs_[0];
    ASSERT_EQ(HDF_SUCCESS, manager_->LoadAdapter(manager_, desc_, &adapter_));
    ASSERT_NE(adapter_, nullptr);
    InitRenderDevDesc(devDescRender_);
    InitRenderAttrs(attrsRender_);

    attrsRender_.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    int32_t ret = adapter_->CreateRender(adapter_, &devDescRender_, &attrsRender_, &render_, &renderId_);
    if (ret != HDF_SUCCESS) {
        attrsRender_.format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
        ASSERT_EQ(HDF_SUCCESS, adapter_->CreateRender(adapter_, &devDescRender_, &attrsRender_, &render_, &renderId_));
    }
    ASSERT_NE(render_, nullptr);
}

void AudioRenderBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    ASSERT_NE(devDescriptorName_, nullptr);
    free(devDescriptorName_);

    if (adapter_ != nullptr) {
        adapter_->DestroyRender(adapter_, renderId_);
        render_ = nullptr;
    }
    if (manager_ != nullptr) {
        manager_->UnloadAdapter(manager_, desc_->adapterName);
        adapter_ = nullptr;
        ReleaseAllAdapterDescs(descs_, size_);

        IAudioManagerRelease(manager_, false);
    }
}

BENCHMARK_F(AudioRenderBenchmarkTest, StartAndStop)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    for (auto _ : state) {
        ret = render_->Start(render_);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = render_->Stop(render_);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, StartAndStop)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, Pause)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret = render_->Start(render_);
    EXPECT_EQ(ret, HDF_SUCCESS);

    for (auto _ : state) {
        ret = render_->Pause(render_);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
    }

    ret = render_->Stop(render_);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, Pause)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, Resume)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret = render_->Start(render_);
    EXPECT_EQ(ret, HDF_SUCCESS);

    ret = render_->Pause(render_);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    for (auto _ : state) {
        ret = render_->Resume(render_);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }

    ret = render_->Stop(render_);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, Resume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, Flush)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    for (auto _ : state) {
        ret = render_->Flush(render_);
        EXPECT_NE(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, Flush)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, TurnStandbyMode)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    for (auto _ : state) {
        ret = render_->Start(render_);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = render_->TurnStandbyMode(render_);
        EXPECT_EQ(ret, HDF_SUCCESS);
        render_->Stop(render_);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, TurnStandbyMode)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, AudioDevDump)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    int32_t range = RANGE_VALUE;
    char pathBuf[] = "/data/RenderDump.log";

    FILE *file = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, file);
    int fd = fileno(file);
    if (fd == -1) {
        fclose(file);
        ASSERT_NE(fd, -1);
    }

    for (auto _ : state) {
        ret = render_->AudioDevDump(render_, range, fd);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
    fclose(file);
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, AudioDevDump)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetFrameSize)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint64_t frameSize = 0;

    for (auto _ : state) {
        ret = render_->GetFrameSize(render_, &frameSize);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetFrameSize)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetFrameCount)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint64_t frameCount = 0;

    for (auto _ : state) {
        ret = render_->GetFrameCount(render_, &frameCount);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetFrameCount)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, SetSampleAttributes)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    struct AudioSampleAttributes attrs = attrsRender_;
    for (auto _ : state) {
        ret = render_->SetSampleAttributes(render_, &attrs);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, SetSampleAttributes)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetSampleAttributes)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    struct AudioSampleAttributes attrs = {};

    for (auto _ : state) {
        ret = render_->GetSampleAttributes(render_, &attrs);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetSampleAttributes)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetCurrentChannelId)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint32_t channelId = 0;

    for (auto _ : state) {
        ret = render_->GetCurrentChannelId(render_, &channelId);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetCurrentChannelId)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, SelectScene)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    struct AudioSceneDescriptor scene;
    scene.scene.id = AUDIO_IN_MEDIA;
    scene.desc.pins = PIN_OUT_SPEAKER;
    scene.desc.desc = const_cast<char*>("primary");

    for (auto _ : state) {
        ret = render_->SelectScene(render_, &scene);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, SelectScene)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetLatency)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint32_t ms = 0;

    for (auto _ : state) {
        ret = render_->GetLatency(render_, &ms);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetLatency)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetRenderPosition)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time;

    for (auto _ : state) {
        ret = render_->GetRenderPosition(render_, &frames, &time);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetRenderPosition)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, SetExtraParams)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    char keyValueList[AUDIO_RENDER_BUF_TEST] =
        "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";

    for (auto _ : state) {
        ret = render_->SetExtraParams(render_, keyValueList);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, SetExtraParams)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetExtraParams)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    char keyValueList[AUDIO_RENDER_BUF_TEST] = {};
    uint32_t keyValueListLen = 0;

    for (auto _ : state) {
        ret = render_->GetExtraParams(render_, keyValueList, keyValueListLen);
        EXPECT_NE(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetExtraParams)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, SetGain)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    float gain = GAIN_VALUE;

    for (auto _ : state) {
        ret = render_->SetGain(render_, gain);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, SetGain)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetGain)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    float gain;

    for (auto _ : state) {
        ret = render_->GetGain(render_, &gain);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetGain)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetGainThreshold)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    float min = 0.0;
    float max = GAIN_VALUE;

    for (auto _ : state) {
        ret = render_->GetGainThreshold(render_, &min, &max);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
    EXPECT_GE(min, MIN_GAINTHRESHOLD);
    EXPECT_LE(max, MAX_GAINTHRESHOLD);
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetGainThreshold)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetMmapPosition)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;

    for (auto _ : state) {
        ret = render_->GetMmapPosition(render_, &frames, &time);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetMmapPosition)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, SetMute)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    bool mute = false;

    for (auto _ : state) {
        ret = render_->SetMute(render_, mute);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, SetMute)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetMute)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    bool isMute = false;

    for (auto _ : state) {
        ret = render_->GetMute(render_, &isMute);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetMute)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, SetVolume)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    float volume = VOLUNE_VALUE;

    for (auto _ : state) {
        ret = render_->SetVolume(render_, volume);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, SetVolume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetVolume)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    float val = 0.0;

    for (auto _ : state) {
        ret = render_->GetVolume(render_, &val);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetVolume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, RenderFrame)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint32_t frameLen = (uint64_t)GetRenderBufferSize();
    uint64_t requestBytes = frameLen;
    EXPECT_EQ(HDF_SUCCESS, render_->Start(render_));

    int8_t *frame = (int8_t *)calloc(1, frameLen);
    ASSERT_NE(nullptr, frame);

    for (auto _ : state) {
        ret = render_->RenderFrame(render_, frame, frameLen, &requestBytes);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    EXPECT_EQ(HDF_SUCCESS, render_->Stop(render_));

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, RenderFrame)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, SetChannelMode)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;

    for (auto _ : state) {
        ret = render_->SetChannelMode(render_, mode);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, SetChannelMode)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, SetRenderSpeed)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    float speed = SPEED_VALUE;

    for (auto _ : state) {
        ret = render_->SetRenderSpeed(render_, speed);
        EXPECT_NE(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, SetRenderSpeed)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetRenderSpeed)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    float speed = 0.0;

    ASSERT_EQ(HDF_SUCCESS, render_->Start(render_));
    for (auto _ : state) {
        ret = render_->GetRenderSpeed(render_, &speed);
        EXPECT_NE(ret, HDF_SUCCESS);
    }
    ASSERT_EQ(HDF_SUCCESS, render_->Stop(render_));
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetRenderSpeed)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetChannelMode)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    enum AudioChannelMode channelMode = AUDIO_CHANNEL_NORMAL;

    for (auto _ : state) {
        ret = render_->GetChannelMode(render_, &channelMode);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetChannelMode)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, RegCallback)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    int8_t cookie = 0;
    struct IAudioCallback *audioCallback = nullptr;

    for (auto _ : state) {
        ret = render_->RegCallback(render_, audioCallback, cookie);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, RegCallback)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, DrainBuffer)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    enum AudioDrainNotifyType type = AUDIO_DRAIN_NORMAL_MODE;

    for (auto _ : state) {
        ret = render_->DrainBuffer(render_, &type);
        EXPECT_EQ(ret, HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, DrainBuffer)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, IsSupportsDrain)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    bool support = false;

    for (auto _ : state) {
        ret = render_->IsSupportsDrain(render_, &support);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, IsSupportsDrain)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, CheckSceneCapability)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    struct AudioSceneDescriptor scene;
    bool supported = false;
    scene.scene.id = AUDIO_IN_MEDIA;
    scene.desc = devDescRender_;

    for (auto _ : state) {
        ret = render_->CheckSceneCapability(render_, &scene, &supported);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, CheckSceneCapability)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, AddAndRemoveAudioEffect)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint64_t effectId = 0;

    for (auto _ : state) {
        ret = render_->AddAudioEffect(render_, effectId);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);

        ret = render_->RemoveAudioEffect(render_, effectId);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, AddAndRemoveAudioEffect)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, GetFrameBufferSize)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    uint64_t bufferSize = BUFFER_LENTH;

    for (auto _ : state) {
        ret = render_->GetFrameBufferSize(render_, &bufferSize);
        ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, GetFrameBufferSize)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioRenderBenchmarkTest, IsSupportsPauseAndResume)(benchmark::State &state)
{
    ASSERT_NE(render_, nullptr);
    int32_t ret;
    bool supportPause = false;
    bool supportResume = false;

    for (auto _ : state) {
        ret = render_->IsSupportsPauseAndResume(render_, &supportPause, &supportResume);
        ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioRenderBenchmarkTest, IsSupportsPauseAndResume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}
