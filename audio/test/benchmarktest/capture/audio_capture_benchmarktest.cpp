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
#include "v5_0/iaudio_capture.h"
#include "v5_0/iaudio_manager.h"

using namespace std;
using namespace testing::ext;
namespace {
static const uint32_t MAX_AUDIO_ADAPTER_NUM = 5;
const int32_t AUDIO_CAPTURE_BUF_TEST = 1024;
const int BUFFER_LENTH = 1024 * 16;
const int DEEP_BUFFER_CAPTURE_PERIOD_SIZE = 4 * 1024;
const int DEFAULT_BUFFER_SIZE = 16384;
const float HALF_OF_MAX_VOLUME = 0.5;
const int MOVE_LEFT_NUM = 8;
const int TEST_SAMPLE_RATE_MASK_48000 = 48000;
const int TEST_CHANNEL_COUNT = 2;
const int32_t ITERATION_FREQUENCY = 100;
const int32_t REPETITION_FREQUENCY = 3;
const int32_t RANGE_VALUE = 4;
const float GAIN_VALUE = 1.0;

class AudioCaptureBenchmarkTest : public benchmark::Fixture {
public:
    struct IAudioManager *manager_ = nullptr;;
    struct IAudioAdapter *adapter_ = nullptr;
    struct IAudioCapture *capture_ = nullptr;
    uint32_t captureId_ = 0;
    char *devDescriptorName_ = nullptr;
    struct AudioAdapterDescriptor *adapterDescs_ = nullptr;
    virtual void SetUp(const ::benchmark::State &state);
    virtual void TearDown(const ::benchmark::State &state);
    uint64_t GetCaptureBufferSize();
    void InitCaptureDevDesc(struct AudioDeviceDescriptor &devDesc);
    void InitCaptureAttrs(struct AudioSampleAttributes &attrs);
    void FreeAdapterElements(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAllAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen);
};

uint64_t AudioCaptureBenchmarkTest::GetCaptureBufferSize()
{
    int32_t ret = HDF_SUCCESS;
    uint64_t frameSize = 0;
    uint64_t frameCount = 0;
    uint64_t bufferSize = 0;

    if (capture_ == nullptr) {
        return DEFAULT_BUFFER_SIZE;
    }

    ret = capture_->GetFrameSize(capture_, &frameSize);
    if (ret != HDF_SUCCESS) {
        return DEFAULT_BUFFER_SIZE;
    }

    ret = capture_->GetFrameCount(capture_, &frameCount);
    if (ret != HDF_SUCCESS) {
        return DEFAULT_BUFFER_SIZE;
    }

    bufferSize = frameCount * frameSize;
    if (bufferSize == 0) {
        bufferSize = DEFAULT_BUFFER_SIZE;
    }

    return bufferSize;
}

void AudioCaptureBenchmarkTest::InitCaptureDevDesc(struct AudioDeviceDescriptor &devDesc)
{
    devDesc.pins = (enum AudioPortPin)PIN_IN_MIC;
    devDescriptorName_ = strdup("cardname");
    devDesc.desc = devDescriptorName_;

    ASSERT_NE(adapterDescs_, nullptr);
    ASSERT_NE(adapterDescs_->ports, nullptr);
    for (uint32_t index = 0; index < adapterDescs_->portsLen; index++) {
        if (adapterDescs_->ports[index].dir == PORT_IN) {
            devDesc.portId = adapterDescs_->ports[index].portId;
            return;
        }
    }
}

void AudioCaptureBenchmarkTest::InitCaptureAttrs(struct AudioSampleAttributes &attrs)
{
    attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs.channelCount = TEST_CHANNEL_COUNT;
    attrs.sampleRate = TEST_SAMPLE_RATE_MASK_48000;
    attrs.interleaved = 0;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_CAPTURE_PERIOD_SIZE;
    attrs.frameSize = AUDIO_FORMAT_TYPE_PCM_16_BIT * TEST_CHANNEL_COUNT / MOVE_LEFT_NUM;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_CAPTURE_PERIOD_SIZE / (attrs.format * attrs.channelCount / MOVE_LEFT_NUM);
    attrs.stopThreshold = INT_MAX;
    attrs.silenceThreshold = BUFFER_LENTH;
}

void AudioCaptureBenchmarkTest::FreeAdapterElements(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
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

void AudioCaptureBenchmarkTest::ReleaseAllAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen)
{
    if (descs == nullptr || descsLen == 0) {
        return;
    }

    for (uint32_t i = 0; i < descsLen; i++) {
        FreeAdapterElements(&descs[i], false);
    }
}

void AudioCaptureBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    uint32_t size = MAX_AUDIO_ADAPTER_NUM;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};

    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);

    adapterDescs_ = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (MAX_AUDIO_ADAPTER_NUM));
    ASSERT_NE(adapterDescs_, nullptr);

    EXPECT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, adapterDescs_, &size));
    if (size > MAX_AUDIO_ADAPTER_NUM) {
        ReleaseAllAdapterDescs(adapterDescs_, MAX_AUDIO_ADAPTER_NUM);
        ASSERT_LT(size, MAX_AUDIO_ADAPTER_NUM);
    }

    EXPECT_EQ(HDF_SUCCESS, manager_->LoadAdapter(manager_, &adapterDescs_[0], &adapter_));
    if (adapter_ == nullptr) {
        ReleaseAllAdapterDescs(adapterDescs_, MAX_AUDIO_ADAPTER_NUM);
        EXPECT_NE(adapter_, nullptr);
    }

    InitCaptureDevDesc(devDesc);
    InitCaptureAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devDesc, &attrs, &capture_, &captureId_));
    if (capture_ == nullptr) {
        (void)manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName);
        ReleaseAllAdapterDescs(adapterDescs_, MAX_AUDIO_ADAPTER_NUM);
    }
    ASSERT_NE(capture_, nullptr);
}

void AudioCaptureBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    ASSERT_NE(devDescriptorName_, nullptr);
    free(devDescriptorName_);

    ASSERT_NE(capture_, nullptr);
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyCapture(adapter_, captureId_));

    ASSERT_NE(manager_, nullptr);
    EXPECT_EQ(HDF_SUCCESS, manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName));
    ReleaseAllAdapterDescs(adapterDescs_, MAX_AUDIO_ADAPTER_NUM);

    IAudioManagerRelease(manager_, false);
}

BENCHMARK_F(AudioCaptureBenchmarkTest, CaptureFrame)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    uint32_t frameLen = (uint64_t)GetCaptureBufferSize();
    uint64_t requestBytes = frameLen;

    int32_t ret = capture_->Start(capture_);
    EXPECT_EQ(ret, HDF_SUCCESS);

    int8_t *frame = (int8_t *)calloc(1, frameLen);
    EXPECT_NE(nullptr, frame);

    for (auto _ : state) {
        ret = capture_->CaptureFrame(capture_, frame, &frameLen, &requestBytes);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    capture_->Stop(capture_);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, CaptureFrame)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetCapturePosition)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    uint64_t frames;
    struct AudioTimeStamp time;
    uint32_t frameLen = (uint64_t)GetCaptureBufferSize();
    uint64_t requestBytes = frameLen;

    int32_t ret = capture_->Start(capture_);
    EXPECT_EQ(ret, HDF_SUCCESS);

    int8_t *frame = (int8_t *)calloc(1, frameLen);
    EXPECT_NE(nullptr, frame);

    ret = capture_->CaptureFrame(capture_, frame, &frameLen, &requestBytes);
    EXPECT_EQ(ret, HDF_SUCCESS);

    for (auto _ : state) {
        ret = capture_->GetCapturePosition(capture_, &frames, &time);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
    capture_->Stop(capture_);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetCapturePosition)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, StartAndStop)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    for (auto _ : state) {
        ret = capture_->Start(capture_);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = capture_->Stop(capture_);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, StartAndStop)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, Pause)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret = capture_->Start(capture_);
    EXPECT_EQ(ret, HDF_SUCCESS);

    for (auto _ : state) {
        ret = capture_->Pause(capture_);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
    }

    ret = capture_->Stop(capture_);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, Pause)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, Resume)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret = capture_->Start(capture_);
    EXPECT_EQ(ret, HDF_SUCCESS);

    ret = capture_->Pause(capture_);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    for (auto _ : state) {
        ret = capture_->Resume(capture_);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }

    ret = capture_->Stop(capture_);
    ASSERT_EQ(ret, HDF_SUCCESS);
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, Resume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, Flush)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    for (auto _ : state) {
        ret = capture_->Flush(capture_);
        EXPECT_NE(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, Flush)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, TurnStandbyMode)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    for (auto _ : state) {
        ret = capture_->Start(capture_);
        EXPECT_EQ(ret, HDF_SUCCESS);
        ret = capture_->TurnStandbyMode(capture_);
        EXPECT_EQ(ret, HDF_SUCCESS);
        capture_->Stop(capture_);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, TurnStandbyMode)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, AudioDevDump)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    int32_t range = RANGE_VALUE;
    char pathBuf[] = "/data/CaptureDump.log";

    FILE *file = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, file);
    int fd = fileno(file);
    if (fd == -1) {
        fclose(file);
        ASSERT_NE(fd, -1);
    }

    for (auto _ : state) {
        ret = capture_->AudioDevDump(capture_, range, fd);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
    fclose(file);
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, AudioDevDump)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, SetMute)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    bool isSupport = false;

    for (auto _ : state) {
        ret = capture_->SetMute(capture_, isSupport);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, SetMute)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetMute)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    bool isSupport = true;

    for (auto _ : state) {
        ret = capture_->GetMute(capture_, &isSupport);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetMute)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, SetVolume)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    for (auto _ : state) {
        ret = capture_->SetVolume(capture_, HALF_OF_MAX_VOLUME);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, SetVolume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetVolume)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    float volume = 0.0;

    for (auto _ : state) {
        ret = capture_->GetVolume(capture_, &volume);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetVolume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetGainThreshold)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    float bottom = 0.0;
    float top = 0.0;

    for (auto _ : state) {
        ret = capture_->GetGainThreshold(capture_, &bottom, &top);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetGainThreshold)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, SetSampleAttributes)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    struct AudioSampleAttributes attrs;
    InitCaptureAttrs(attrs);

    for (auto _ : state) {
        ret = capture_->SetSampleAttributes(capture_, &attrs);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, SetSampleAttributes)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetSampleAttributes)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    struct AudioSampleAttributes attrs = {};

    for (auto _ : state) {
        ret = capture_->GetSampleAttributes(capture_, &attrs);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetSampleAttributes)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetCurrentChannelId)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    uint32_t channelId = 0;

    for (auto _ : state) {
        ret = capture_->GetCurrentChannelId(capture_, &channelId);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetCurrentChannelId)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, SetExtraParams)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    char keyValueList[AUDIO_CAPTURE_BUF_TEST] =
        "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";

    for (auto _ : state) {
        ret = capture_->SetExtraParams(capture_, keyValueList);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, SetExtraParams)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetExtraParams)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    char keyValueListReply[AUDIO_CAPTURE_BUF_TEST] = {};
    uint32_t listLenth = AUDIO_CAPTURE_BUF_TEST;

    for (auto _ : state) {
        ret = capture_->GetExtraParams(capture_, keyValueListReply, listLenth);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetExtraParams)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, SelectScene)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    struct AudioSceneDescriptor scene;
    scene.scene.id = AUDIO_IN_MEDIA;
    scene.desc.pins = PIN_IN_MIC;
    scene.desc.desc = const_cast<char*>("primary");

    for (auto _ : state) {
        ret = capture_->SelectScene(capture_, &scene);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, SelectScene)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, SetGain)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    float gain = GAIN_VALUE;

    for (auto _ : state) {
        ret = capture_->SetGain(capture_, gain);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, SetGain)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetGain)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    float gain;

    for (auto _ : state) {
        ret = capture_->GetGain(capture_, &gain);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetGain)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetMmapPosition)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;

    for (auto _ : state) {
        ret = capture_->GetMmapPosition(capture_, &frames, &time);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetMmapPosition)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetFrameSize)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    uint64_t frameSize = 0;

    for (auto _ : state) {
        ret = capture_->GetFrameSize(capture_, &frameSize);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetFrameSize)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetFrameCount)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    uint64_t frameCount = 0;

    for (auto _ : state) {
        ret = capture_->GetFrameCount(capture_, &frameCount);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetFrameCount)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, CheckSceneCapability)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    struct AudioSceneDescriptor sceneDesc = {};
    sceneDesc.desc.pins = PIN_IN_MIC;
    sceneDesc.desc.desc = strdup("mic");
    sceneDesc.scene.id = AUDIO_IN_COMMUNICATION;
    bool isSupport = false;

    for (auto _ : state) {
        ret = capture_->CheckSceneCapability(capture_, &sceneDesc, &isSupport);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    free(sceneDesc.desc.desc);
    sceneDesc.desc.desc = nullptr;
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, CheckSceneCapability)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, AddAndRemoveAudioEffect)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    uint64_t effectId = 0;

    for (auto _ : state) {
        ret = capture_->AddAudioEffect(capture_, effectId);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);

        ret = capture_->RemoveAudioEffect(capture_, effectId);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, AddAndRemoveAudioEffect)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, GetFrameBufferSize)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    uint64_t bufferSize = 0;

    for (auto _ : state) {
        ret = capture_->GetFrameBufferSize(capture_, &bufferSize);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, GetFrameBufferSize)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioCaptureBenchmarkTest, IsSupportsPauseAndResume)(benchmark::State &state)
{
    ASSERT_NE(capture_, nullptr);
    int32_t ret;
    bool supportPause = false;
    bool supportResume = false;

    for (auto _ : state) {
        ret = capture_->IsSupportsPauseAndResume(capture_, &supportPause, &supportResume);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
    }
}

BENCHMARK_REGISTER_F(AudioCaptureBenchmarkTest, IsSupportsPauseAndResume)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}
