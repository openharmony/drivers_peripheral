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

#include <gtest/gtest.h>
#include "osal_mem.h"

#include "v5_0/audio_types.h"
#include "v5_0/iaudio_manager.h"
#include "v5_0/iaudio_render.h"

using namespace std;
using namespace testing::ext;

namespace {
const float MAX_GAINTHRESHOLD = 15.0;
const float MIN_GAINTHRESHOLD = 0.0;
const int BUFFER_LENTH = 1024 * 16;
const int DEEP_BUFFER_RENDER_PERIOD_SIZE = 4 * 1024;
const int32_t AUDIO_RENDER_BUF_TEST = 1024;
const int32_t AUDIO_RENDER_CHANNELCOUNT = 2;
const int32_t AUDIO_SAMPLE_RATE_48K = 48000;
const int32_t MAX_AUDIO_ADAPTER_DESC = 5;
const uint32_t INVALID_SCENE_ID = -1;
const uint64_t DEFAULT_BUFFER_SIZE = 16384;

class AudioUtRenderTest : public testing::Test {
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
    virtual void SetUp();
    virtual void TearDown();
    uint64_t GetRenderBufferSize();
    void InitRenderAttrs(struct AudioSampleAttributes &attrs);
    void InitRenderDevDesc(struct AudioDeviceDescriptor &devDesc);
    void FreeAdapterElements(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAllAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen);
};

uint64_t AudioUtRenderTest::GetRenderBufferSize()
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

void AudioUtRenderTest::InitRenderAttrs(struct AudioSampleAttributes &attrs)
{
    attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs.channelCount = AUDIO_RENDER_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs.interleaved = 0;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = AUDIO_FORMAT_TYPE_PCM_16_BIT * AUDIO_RENDER_CHANNELCOUNT;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.format * attrs.channelCount);
    attrs.stopThreshold = INT_MAX;
    attrs.silenceThreshold = BUFFER_LENTH;
}

void AudioUtRenderTest::InitRenderDevDesc(struct AudioDeviceDescriptor &devDesc)
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

void AudioUtRenderTest::FreeAdapterElements(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
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

void AudioUtRenderTest::ReleaseAllAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen)
{
    if (descs == nullptr || descsLen == 0) {
        return;
    }

    for (uint32_t i = 0; i < descsLen; i++) {
        FreeAdapterElements(&descs[i], false);
    }
}

void AudioUtRenderTest::SetUp()
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

    int32_t ret = adapter_->CreateRender(adapter_, &devDescRender_, &attrsRender_, &render_, &renderId_);
    if (ret != HDF_SUCCESS) {
        attrsRender_.format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
        ASSERT_EQ(HDF_SUCCESS, adapter_->CreateRender(adapter_, &devDescRender_, &attrsRender_, &render_, &renderId_));
    }
    ASSERT_NE(render_, nullptr);
}

void AudioUtRenderTest::TearDown()
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

HWTEST_F(AudioUtRenderTest, RenderStartNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->Start(nullptr));
    render_->Stop(render_);
}

HWTEST_F(AudioUtRenderTest, RenderStartNull002, TestSize.Level0)
{
    EXPECT_EQ(HDF_SUCCESS, render_->Start(render_));
    EXPECT_NE(HDF_SUCCESS, render_->Start(render_));
    EXPECT_EQ(HDF_SUCCESS, render_->Stop(render_));
    render_->Stop(render_);
}

HWTEST_F(AudioUtRenderTest, RenderStartStopIsValid001, TestSize.Level0)
{
    EXPECT_EQ(HDF_SUCCESS, render_->Start(render_));
    EXPECT_EQ(HDF_SUCCESS, render_->Stop(render_));
}

HWTEST_F(AudioUtRenderTest, RenderFlushNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->Flush(nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderFlushIsValid001, TestSize.Level0)
{
    EXPECT_NE(HDF_SUCCESS, render_->Flush(render_));
}

HWTEST_F(AudioUtRenderTest, RenderStopNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->Stop(nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderStopInvalid001, TestSize.Level0)
{
    int32_t ret = render_->Stop(render_);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_FAILURE);
}

HWTEST_F(AudioUtRenderTest, RenderGetFrameSizeNull001, TestSize.Level1)
{
    uint64_t frameSize = 0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetFrameSize(nullptr, &frameSize));
}

HWTEST_F(AudioUtRenderTest, RenderGetFrameSizeNull002, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->GetFrameSize(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderGetFrameSizeIsValid001, TestSize.Level0)
{
    uint64_t frameSize = 0;
    EXPECT_EQ(HDF_SUCCESS, render_->GetFrameSize(render_, &frameSize));
}

HWTEST_F(AudioUtRenderTest, RenderGetFrameCountNull001, TestSize.Level1)
{
    uint64_t frameCount = 0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetFrameCount(nullptr, &frameCount));
}

HWTEST_F(AudioUtRenderTest, RenderGetFrameCountNull002, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->GetFrameCount(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderGetFrameCountIsValid001, TestSize.Level0)
{
    uint64_t frameCount = 0;
    EXPECT_EQ(HDF_SUCCESS, render_->GetFrameCount(render_, &frameCount));
}

HWTEST_F(AudioUtRenderTest, RenderSetSampleAttributesNull001, TestSize.Level1)
{
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->SetSampleAttributes(nullptr, &attrs));
}

HWTEST_F(AudioUtRenderTest, RenderSetSampleAttributesNull002, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->SetSampleAttributes(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderSetSampleAttributesIsValid001, TestSize.Level0)
{
    struct AudioSampleAttributes attrs = attrsRender_;
    EXPECT_EQ(HDF_SUCCESS, render_->SetSampleAttributes(render_, &attrs));
}

HWTEST_F(AudioUtRenderTest, RenderGetSampleAttributesNull001, TestSize.Level1)
{
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetSampleAttributes(nullptr, &attrs));
}

HWTEST_F(AudioUtRenderTest, RenderGetSampleAttributesNull002, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->GetSampleAttributes(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderGetSampleAttributesIsValid001, TestSize.Level0)
{
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_SUCCESS, render_->GetSampleAttributes(render_, &attrs));
}

HWTEST_F(AudioUtRenderTest, RenderGetCurrentChannelIdNull001, TestSize.Level1)
{
    uint32_t channelId;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetCurrentChannelId(nullptr, &channelId));
}

HWTEST_F(AudioUtRenderTest, RenderGetCurrentChannelIdNull002, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->GetCurrentChannelId(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderGetCurrentChannelIdIsValid001, TestSize.Level0)
{
    uint32_t channelId;
    EXPECT_EQ(HDF_SUCCESS, render_->GetCurrentChannelId(render_, &channelId));
}

HWTEST_F(AudioUtRenderTest, RenderCheckSceneCapabilityNull001, TestSize.Level1)
{
    struct AudioSceneDescriptor scene;
    bool supported = false;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->CheckSceneCapability(nullptr, &scene, &supported));
}

HWTEST_F(AudioUtRenderTest, RenderCheckSceneCapabilityNull002, TestSize.Level1)
{
    bool supported = false;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->CheckSceneCapability(render_, nullptr, &supported));
}

HWTEST_F(AudioUtRenderTest, RenderCheckSceneCapabilityNull003, TestSize.Level1)
{
    struct AudioSceneDescriptor scene;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->CheckSceneCapability(render_, &scene, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderCheckSceneCapabilityInValid001, TestSize.Level1)
{
    struct AudioSceneDescriptor scene;
    bool supported = false;
    scene.scene.id = INVALID_SCENE_ID;
    scene.desc = devDescRender_;
    int32_t ret = render_->CheckSceneCapability(render_, &scene, &supported);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderCheckSceneCapabilityIsValid001, TestSize.Level0)
{
    struct AudioSceneDescriptor scene;
    bool supported = false;
    scene.scene.id = AUDIO_IN_MEDIA;
    scene.desc = devDescRender_;
    EXPECT_EQ(HDF_SUCCESS, render_->CheckSceneCapability(render_, &scene, &supported));
}

HWTEST_F(AudioUtRenderTest, RenderSelectSceneNull001, TestSize.Level1)
{
    struct AudioSceneDescriptor scene;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->SelectScene(nullptr, &scene));
}

HWTEST_F(AudioUtRenderTest, RenderSelectSceneNull002, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->SelectScene(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderSelectSceneInValid001, TestSize.Level1)
{
    struct AudioSceneDescriptor scene;
    scene.scene.id = INVALID_SCENE_ID;
    scene.desc.pins = PIN_OUT_HEADSET;
    scene.desc.desc = strdup("mic");
    int32_t ret = render_->SelectScene(render_, &scene);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    free(scene.desc.desc);
}

HWTEST_F(AudioUtRenderTest, RenderSelectSceneIsValid001, TestSize.Level0)
{
    struct AudioSceneDescriptor scene;
    scene.scene.id = AUDIO_IN_MEDIA;
    scene.desc.pins = PIN_OUT_HEADSET;
    scene.desc.desc = strdup("mic");
    EXPECT_EQ(HDF_SUCCESS, render_->SelectScene(render_, &scene));
    scene.desc.pins = PIN_OUT_SPEAKER;
    EXPECT_EQ(HDF_SUCCESS, render_->SelectScene(render_, &scene));
    free(scene.desc.desc);
}

HWTEST_F(AudioUtRenderTest, RenderGetLatencyNull001, TestSize.Level1)
{
    uint32_t ms = 0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetLatency(nullptr, &ms));
}

HWTEST_F(AudioUtRenderTest, RenderGetLatencyNull002, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->GetLatency(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderGetLatencyIsValid001, TestSize.Level0)
{
    uint32_t ms = 0;
    EXPECT_EQ(HDF_SUCCESS, render_->GetLatency(render_, &ms));
}

HWTEST_F(AudioUtRenderTest, RenderGetRenderPositionNull001, TestSize.Level1)
{
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetRenderPosition(nullptr, &frames, &time));
}

HWTEST_F(AudioUtRenderTest, RenderGetRenderPositionNull002, TestSize.Level1)
{
    struct AudioTimeStamp time;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->GetRenderPosition(render_, nullptr, &time));
}

HWTEST_F(AudioUtRenderTest, RenderGetRenderPositionNull003, TestSize.Level1)
{
    uint64_t frames = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->GetRenderPosition(render_, &frames, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderGetRenderPositionIsValid001, TestSize.Level0)
{
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvSec = 0;
    time.tvNSec = 0;
    int32_t ret = render_->GetRenderPosition(render_, &frames, &time);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderTest, RenderGetRenderPositionIsValid002, TestSize.Level0)
{
    uint64_t frames;
    struct AudioTimeStamp time;
    uint32_t frameLen = (uint64_t)GetRenderBufferSize();
    uint64_t requestBytes = frameLen;

    int32_t ret = render_->Start(render_);
    EXPECT_EQ(ret, HDF_SUCCESS);

    int8_t *frame = (int8_t *)calloc(1, frameLen);
    EXPECT_NE(nullptr, frame);

    ret = render_->RenderFrame(render_, frame, frameLen, &requestBytes);
    EXPECT_EQ(ret, HDF_SUCCESS);

    ret = render_->GetRenderPosition(render_, &frames, &time);
    EXPECT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);

    render_->Stop(render_);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}

HWTEST_F(AudioUtRenderTest, RenderSetExtraParamsNull001, TestSize.Level1)
{
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->SetExtraParams(nullptr, keyValueList));
}

HWTEST_F(AudioUtRenderTest, RenderSetExtraParamsNull002, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->SetExtraParams(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderSetExtraParamsIsValid001, TestSize.Level0)
{
    char keyValueList[AUDIO_RENDER_BUF_TEST] =
        "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    EXPECT_EQ(HDF_SUCCESS, render_->SetExtraParams(render_, keyValueList));
}

HWTEST_F(AudioUtRenderTest, RenderGetExtraParamsNull001, TestSize.Level1)
{
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    uint32_t keyValueListLen = 0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetExtraParams(nullptr, keyValueList, keyValueListLen));
}

HWTEST_F(AudioUtRenderTest, RenderGetExtraParamsNull002, TestSize.Level1)
{
    uint32_t keyValueListLen = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->GetExtraParams(render_, nullptr, keyValueListLen));
}

HWTEST_F(AudioUtRenderTest, RenderGetExtraParamsIsValid001, TestSize.Level0)
{
    char keyValueList[AUDIO_RENDER_BUF_TEST] = {};
    uint32_t keyValueListLen = BUFFER_LENTH;
    int32_t ret = render_->GetExtraParams(render_, keyValueList, keyValueListLen);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderTest, RenderTurnStandbyModeNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->TurnStandbyMode(nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderTurnStandbyModeIsValid001, TestSize.Level0)
{
    int32_t ret = render_->Start(render_);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render_->TurnStandbyMode(render_);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render_->Stop(render_);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_SUCCESS);
}

HWTEST_F(AudioUtRenderTest, RenderAudioDevDumpNull001, TestSize.Level1)
{
    int32_t range = 4;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->AudioDevDump(nullptr, range, -1));
}

HWTEST_F(AudioUtRenderTest, RenderAudioDevDumpIsValid001, TestSize.Level0)
{
    int32_t range = 4;
    char pathBuf[] = "/data/RenderDump.log";

    FILE *file = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, file);
    int fd = fileno(file);
    if (fd == -1) {
        fclose(file);
        ASSERT_NE(fd, -1);
    }

    int32_t ret = render_->AudioDevDump(render_, range, fd);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    fclose(file);
}

HWTEST_F(AudioUtRenderTest, RenderGetGainNull001, TestSize.Level1)
{
    float gain;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetGain(nullptr, &gain));
}

HWTEST_F(AudioUtRenderTest, RenderGetGainIsValid001, TestSize.Level0)
{
    float gain;
    int32_t ret = render_->GetGain(render_, &gain);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderGetGainThresholdNull001, TestSize.Level1)
{
    float min = 0.0;
    float max = 1.0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetGainThreshold(nullptr, &min, &max));
}

HWTEST_F(AudioUtRenderTest, RenderGetGainThresholdIsValid001, TestSize.Level0)
{
    float min = 0.0;
    float max = 1.0;
    int32_t ret = render_->GetGainThreshold(render_, &min, &max);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_GE(min, MIN_GAINTHRESHOLD);
    EXPECT_LE(max, MAX_GAINTHRESHOLD);
}

HWTEST_F(AudioUtRenderTest, RenderGetMuteNull001, TestSize.Level1)
{
    bool isMute = false;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetMute(nullptr, &isMute));
}

HWTEST_F(AudioUtRenderTest, RenderGetMuteIsValid001, TestSize.Level0)
{
    bool isMute = false;
    int32_t ret = render_->GetMute(render_, &isMute);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderGetVersionNull001, TestSize.Level1)
{
    uint32_t majorVer;
    uint32_t minorVer;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetVersion(nullptr, &majorVer, &minorVer));
}

HWTEST_F(AudioUtRenderTest, RenderGetVersionIsValid001, TestSize.Level1)
{
    uint32_t majorVer;
    uint32_t minorVer;
    ASSERT_EQ(HDF_SUCCESS, render_->GetVersion(render_, &majorVer, &minorVer));
    EXPECT_EQ(IAUDIO_MANAGER_MAJOR_VERSION, majorVer);
    EXPECT_EQ(IAUDIO_MANAGER_MINOR_VERSION, minorVer);
}

HWTEST_F(AudioUtRenderTest, RenderGetVolumeNull001, TestSize.Level1)
{
    float val = 0.0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetVolume(nullptr, &val));
}

HWTEST_F(AudioUtRenderTest, RenderGetVolumeIsValid001, TestSize.Level1)
{
    float val = 0.0;
    int32_t ret = render_->GetVolume(render_, &val);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderPauseNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->Pause(nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderResumeNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->Resume(nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderResumeInvalid001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, render_->Resume(render_));
}

HWTEST_F(AudioUtRenderTest, RenderPauseResumeIsValid001, TestSize.Level0)
{
    EXPECT_EQ(HDF_SUCCESS, render_->Start(render_));
    int32_t ret = render_->Pause(render_);

    if (ret == HDF_SUCCESS) {
        EXPECT_EQ(HDF_SUCCESS, render_->Resume(render_));
    } else if (ret == HDF_ERR_NOT_SUPPORT) {
        ASSERT_TRUE(true);
    } else {
        ASSERT_TRUE(false);
    }

    EXPECT_EQ(HDF_SUCCESS, render_->Stop(render_));
}

HWTEST_F(AudioUtRenderTest, RenderRenderFrameNull001, TestSize.Level1)
{
    uint32_t frameLen = DEFAULT_BUFFER_SIZE;
    uint64_t requestBytes = frameLen;
    int8_t *frame = (int8_t *)calloc(1, frameLen);
    ASSERT_NE(nullptr, frame);
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->RenderFrame(nullptr, frame, frameLen, &requestBytes));
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}

HWTEST_F(AudioUtRenderTest, RenderRenderFrameIsValid001, TestSize.Level0)
{
    uint32_t frameLen = (uint64_t)GetRenderBufferSize();
    uint64_t requestBytes = frameLen;
    EXPECT_EQ(HDF_SUCCESS, render_->Start(render_));

    int8_t *frame = (int8_t *)calloc(1, frameLen);
    ASSERT_NE(nullptr, frame);
    EXPECT_EQ(HDF_SUCCESS, render_->RenderFrame(render_, frame, frameLen, &requestBytes));

    EXPECT_EQ(HDF_SUCCESS, render_->Stop(render_));

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}

HWTEST_F(AudioUtRenderTest, RenderSetChannelModeNull001, TestSize.Level1)
{
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->SetChannelMode(nullptr, mode));
}

HWTEST_F(AudioUtRenderTest, RenderSetChannelModeIsValid001, TestSize.Level0)
{
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    int32_t ret = render_->SetChannelMode(render_, mode);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderSetGainNull001, TestSize.Level1)
{
    float gain = 1.0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->SetGain(nullptr, gain));
}

HWTEST_F(AudioUtRenderTest, RenderSetGainIsValid001, TestSize.Level0)
{
    float gain = 1.0;
    int32_t ret = render_->SetGain(render_, gain);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderSetMuteNull001, TestSize.Level1)
{
    bool mute = false;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->SetMute(nullptr, mute));
}

HWTEST_F(AudioUtRenderTest, RenderSetMuteIsValid001, TestSize.Level0)
{
    bool mute = false;
    int32_t ret = render_->SetMute(render_, mute);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderSetRenderSpeedNull001, TestSize.Level1)
{
    float speed = 2.0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->SetRenderSpeed(nullptr, speed));
}

HWTEST_F(AudioUtRenderTest, RenderSetRenderSpeedIsValid001, TestSize.Level1)
{
    float speed = 2.0;
    EXPECT_NE(HDF_SUCCESS, render_->SetRenderSpeed(render_, speed));
}

HWTEST_F(AudioUtRenderTest, RenderSetVolumeNull001, TestSize.Level1)
{
    float volume = 0.2;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->SetVolume(nullptr, volume));
}

HWTEST_F(AudioUtRenderTest, RenderSetVolumeIsInValid001, TestSize.Level1)
{
    float volume = -1.0;
    EXPECT_NE(HDF_SUCCESS, render_->SetVolume(render_, volume));
}

HWTEST_F(AudioUtRenderTest, RenderSetVolumeIsInValid002, TestSize.Level1)
{
    float volume = 2.0;
    EXPECT_NE(HDF_SUCCESS, render_->SetVolume(render_, volume));
}

HWTEST_F(AudioUtRenderTest, RenderSetVolumeIsValid001, TestSize.Level1)
{
    float volume = 0.2;
    int32_t ret = render_->SetVolume(render_, volume);

    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderGetRenderSpeedIsInValid001, TestSize.Level0)
{
    float speed = 0.0;
    ASSERT_EQ(HDF_SUCCESS, render_->Start(render_));
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->GetRenderSpeed(nullptr, &speed));
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, render_->GetRenderSpeed(render_, nullptr));
    EXPECT_EQ(HDF_SUCCESS, render_->Stop(render_));
}

HWTEST_F(AudioUtRenderTest, RenderGetRenderSpeedIsValid001, TestSize.Level0)
{
    float speed = 0.0;
    ASSERT_EQ(HDF_SUCCESS, render_->Start(render_));
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, render_->GetRenderSpeed(render_, &speed));
    EXPECT_EQ(HDF_SUCCESS, render_->Stop(render_));
}

HWTEST_F(AudioUtRenderTest, RenderGetChannelModeIsInValid001, TestSize.Level1)
{
    enum AudioChannelMode channelMode = AUDIO_CHANNEL_NORMAL;
    int32_t ret = render_->GetChannelMode(nullptr, &channelMode);
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);

    ret = render_->GetChannelMode(render_, nullptr);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderGetChannelModeIsValid001, TestSize.Level0)
{
    enum AudioChannelMode channelMode = AUDIO_CHANNEL_NORMAL;
    int32_t ret = render_->GetChannelMode(render_, &channelMode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(AudioUtRenderTest, RenderRegCallbackIsInValid001, TestSize.Level1)
{
    int8_t cookie = 0;
    struct IAudioCallback *audioCallback = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->RegCallback(nullptr, audioCallback, cookie));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, render_->RegCallback(render_, nullptr, cookie));
}

HWTEST_F(AudioUtRenderTest, RenderRegCallbackIsValid001, TestSize.Level0)
{
    int8_t cookie = 0;
    struct IAudioCallback *audioCallback = nullptr;
    int32_t ret = render_->RegCallback(render_, audioCallback, cookie);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderTest, RenderDrainBufferIsInValid001, TestSize.Level1)
{
    enum AudioDrainNotifyType type = AUDIO_DRAIN_NORMAL_MODE;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->DrainBuffer(nullptr, &type));
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, render_->DrainBuffer(render_, nullptr));
}

HWTEST_F(AudioUtRenderTest, RenderDrainBufferIsValid001, TestSize.Level1)
{
    enum AudioDrainNotifyType type = AUDIO_DRAIN_NORMAL_MODE;
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, render_->DrainBuffer(render_, &type));
}

HWTEST_F(AudioUtRenderTest, RenderIsSupportsDrainIsInValid001, TestSize.Level1)
{
    bool support = false;
    int32_t ret = render_->IsSupportsDrain(nullptr, &support);
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);
    ret = render_->IsSupportsDrain(render_, nullptr);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderTest, RenderIsSupportsDrainIsValid001, TestSize.Level1)
{
    bool support = false;
    int32_t ret = render_->IsSupportsDrain(render_, &support);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_SUCCESS);
}

HWTEST_F(AudioUtRenderTest, RenderAddAudioEffectIsInValid001, TestSize.Level1)
{
    uint64_t effectId = 0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->AddAudioEffect(nullptr, effectId));
}

HWTEST_F(AudioUtRenderTest, RenderRemoveAudioEffectIsInValid001, TestSize.Level1)
{
    uint64_t effectId = 0;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, render_->RemoveAudioEffect(nullptr, effectId));
}

HWTEST_F(AudioUtRenderTest, RenderGetFrameBufferSizeIsInValid001, TestSize.Level1)
{
    uint64_t bufferSize = BUFFER_LENTH;
    int32_t ret = render_->GetFrameBufferSize(nullptr, &bufferSize);
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);

    ret = render_->GetFrameBufferSize(render_, nullptr);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderTest, RenderGetFrameBufferSizeIsValid001, TestSize.Level1)
{
    uint64_t bufferSize = BUFFER_LENTH;
    int32_t ret = render_->GetFrameBufferSize(render_, &bufferSize);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderTest, RenderIsSupportsPauseAndResumeIsInValid001, TestSize.Level1)
{
    bool supportPause = false;
    bool supportResume = false;
    int32_t ret = render_->IsSupportsPauseAndResume(nullptr, &supportPause, &supportResume);
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);

    ret = render_->IsSupportsPauseAndResume(render_, nullptr, &supportResume);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);

    ret = render_->IsSupportsPauseAndResume(render_, &supportPause, nullptr);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(AudioUtRenderTest, RenderIsSupportsPauseAndResumeIsValid001, TestSize.Level1)
{
    bool supportPause = false;
    bool supportResume = false;
    int32_t ret = render_->IsSupportsPauseAndResume(render_, &supportPause, &supportResume);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_INVALID_PARAM);
}

} // end of namespace
