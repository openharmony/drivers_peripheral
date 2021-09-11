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

#include "audio_render_test.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "audio_internal.h"

using namespace std;
using namespace testing::ext;
namespace {
const int FREAM_DATA = 4096;

class AudioRenderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void AudioRenderTest::SetUpTestCase()
{
}

void AudioRenderTest::TearDownTestCase()
{
}

HWTEST_F(AudioRenderTest, PcmBytesToFramesWhenFrameRenderModeIsNull, TestSize.Level0)
{
    const struct AudioFrameRenderMode *frameRenderMode = nullptr;
    uint64_t bytes = FREAM_DATA;
    uint32_t frameCount = 0;
    int32_t ret = PcmBytesToFrames(frameRenderMode, bytes, &frameCount);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioRenderTest, PcmBytesToFramesWhenFrameCountIsNull, TestSize.Level0)
{
    const struct AudioFrameRenderMode *frameRenderMode = new struct AudioFrameRenderMode;
    uint64_t bytes = FREAM_DATA;
    uint32_t *frameCount = nullptr;
    int32_t ret = PcmBytesToFrames(frameRenderMode, bytes, frameCount);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(frameRenderMode);
    frameRenderMode = nullptr;
}

HWTEST_F(AudioRenderTest, PcmBytesToFramesWhenParamIsNotSupport, TestSize.Level0)
{
    struct AudioFrameRenderMode *frameRenderMode = new struct AudioFrameRenderMode;
    frameRenderMode->attrs.format = AUDIO_FORMAT_AAC_MAIN;
    uint64_t bytes = FREAM_DATA;
    uint32_t frameCount = 0;
    int32_t ret = PcmBytesToFrames((const struct AudioFrameRenderMode *)frameRenderMode, bytes, &frameCount);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    delete(frameRenderMode);
    frameRenderMode = nullptr;
}

HWTEST_F(AudioRenderTest, PcmBytesToFramesWhenChannelCountIsZero, TestSize.Level0)
{
    struct AudioFrameRenderMode *frameRenderMode = new struct AudioFrameRenderMode;
    frameRenderMode->attrs.format = AUDIO_FORMAT_PCM_8_BIT;
    frameRenderMode->attrs.channelCount = 0;
    uint64_t bytes = FREAM_DATA;
    uint32_t frameCount = 0;
    int32_t ret = PcmBytesToFrames((const struct AudioFrameRenderMode *)frameRenderMode, bytes, &frameCount);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(frameRenderMode);
    frameRenderMode = nullptr;
}

HWTEST_F(AudioRenderTest, PcmBytesToFramesWhenParamIsVaild, TestSize.Level0)
{
    struct AudioFrameRenderMode *frameRenderMode = new struct AudioFrameRenderMode;
    frameRenderMode->attrs.format = AUDIO_FORMAT_PCM_8_BIT;
    frameRenderMode->attrs.channelCount = 1;
    uint64_t bytes = FREAM_DATA;
    uint32_t frameCount = 0;
    int32_t ret = PcmBytesToFrames((const struct AudioFrameRenderMode *)frameRenderMode, bytes, &frameCount);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(frameRenderMode);
    frameRenderMode = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderStartWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    int32_t ret = AudioRenderStart(handle);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderStopWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    int32_t ret = AudioRenderStop(handle);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderPauseWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    int32_t ret = AudioRenderPause(handle);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderResumeWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    int32_t ret = AudioRenderResume(handle);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderResumeWhenPauseIsFalse, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    hwRender->renderParam.renderMode.ctlParam.pause = false;
    int32_t ret = AudioRenderResume(handle);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderFlushWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    int32_t ret = AudioRenderFlush(handle);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderFlushWhenParamIsVaild, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    int32_t ret = AudioRenderFlush(handle);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetFrameSizeWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    uint64_t sizeTmp = FREAM_DATA;
    uint64_t *size = &sizeTmp;
    int32_t ret = AudioRenderGetFrameSize(handle, size);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderGetFrameSizeWhenSizeIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    uint64_t *size = nullptr;
    int32_t ret = AudioRenderGetFrameSize(handle, size);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetFrameSizeWhenParamIsNotSupport, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    hwRender->renderParam.frameRenderMode.attrs.format = AUDIO_FORMAT_AAC_MAIN;
    AudioHandle handle = (AudioHandle)hwRender;
    uint64_t sizeTmp = FREAM_DATA;
    uint64_t *size = &sizeTmp;
    int32_t ret = AudioRenderGetFrameSize(handle, size);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetFrameSizeWhenParamVaild, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    hwRender->renderParam.frameRenderMode.attrs.format = AUDIO_FORMAT_PCM_8_BIT;
    AudioHandle handle = (AudioHandle)hwRender;
    uint64_t sizeTmp = FREAM_DATA;
    uint64_t *size = &sizeTmp;
    int32_t ret = AudioRenderGetFrameSize(handle, size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetFrameCountWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    uint64_t countTmp = FREAM_DATA;
    uint64_t *count = &countTmp;
    int32_t ret = AudioRenderGetFrameCount(handle, count);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderGetFrameCountWhenCountIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    uint64_t *count = nullptr;
    int32_t ret = AudioRenderGetFrameCount(handle, count);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetFrameCountWhenParamIsVaild, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    uint64_t countTmp = FREAM_DATA;
    uint64_t *count = &countTmp;
    int32_t ret = AudioRenderGetFrameCount(handle, count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderSetSampleAttributesWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t ret = AudioRenderSetSampleAttributes(handle, attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderSetSampleAttributesWhenAttrsIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    AudioSampleAttributes *attrs = nullptr;
    int32_t ret = AudioRenderSetSampleAttributes(handle, attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetSampleAttributesWhenHandleIsNull, TestSize.Level0)
{
    AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t ret = AudioRenderGetSampleAttributes(nullptr, attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetSampleAttributesWhenAttrsIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    int32_t ret = AudioRenderGetSampleAttributes(handle, nullptr);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetSampleAttributesWhenParamIsVaild, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t ret = AudioRenderGetSampleAttributes(handle, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(hwRender);
    hwRender = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetCurrentChannelIdWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    uint32_t channelIdOne = 1;
    uint32_t *channelId = &channelIdOne;
    int32_t ret = AudioRenderGetCurrentChannelId(handle, channelId);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderGetCurrentChannelIdWhenChannelIdIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    uint32_t *channelId = nullptr;
    int32_t ret = AudioRenderGetCurrentChannelId(handle, channelId);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete hwRender;
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetCurrentChannelIdWhenParamIsVaild, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    uint32_t channelIdOne = 1;
    uint32_t *channelId = &channelIdOne;
    int32_t ret = AudioRenderGetCurrentChannelId(handle, channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete hwRender;
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderCheckSceneCapabilityWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    const struct AudioSceneDescriptor *scene = new struct AudioSceneDescriptor;
    bool supported = false;
    int32_t ret = AudioRenderCheckSceneCapability(handle, scene, &supported);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(scene);
    scene = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderCheckSceneCapabilityWhenSceneIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    const struct AudioSceneDescriptor *scene = nullptr;
    bool supported = false;
    int32_t ret = AudioRenderCheckSceneCapability(handle, scene, &supported);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderCheckSceneCapabilityWhenSupportedIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    const struct AudioSceneDescriptor *scene = new struct AudioSceneDescriptor;
    bool *supported = nullptr;
    int32_t ret = AudioRenderCheckSceneCapability(handle, scene, supported);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(hwRender);
    hwRender = nullptr;
    delete(scene);
    scene = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderSelectSceneWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    const struct AudioSceneDescriptor *scene = new struct AudioSceneDescriptor;
    int32_t ret = AudioRenderSelectScene(handle, scene);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(scene);
    scene = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderSelectSceneWhenSceneIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    const struct AudioSceneDescriptor *scene = nullptr;
    int32_t ret = AudioRenderSelectScene(handle, scene);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderSetMuteWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    bool mute = true;
    int32_t ret = AudioRenderSetMute(handle, mute);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderGetMuteWhenHandleIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = nullptr;
    AudioHandle handle = (AudioHandle)hwRender;
    bool mute = false;
    int32_t ret = AudioRenderGetMute(handle, &mute);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderGetMuteWhenMuteIsNull, TestSize.Level0)
{
    AudioHwRender *hwRender = new AudioHwRender;
    AudioHandle handle = (AudioHandle)hwRender;
    bool *mute = nullptr;
    int32_t ret = AudioRenderGetMute(handle, mute);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetLatencyWhenRenderIsNull, TestSize.Level0)
{
    struct AudioRender *render = nullptr;
    uint32_t msTmp = 96;
    uint32_t *ms = &msTmp;
    int32_t ret = AudioRenderGetLatency(render, ms);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderGetLatencyWhenMsIsNull, TestSize.Level0)
{
    struct AudioRender *render = new AudioRender;
    uint32_t *ms = nullptr;
    int32_t ret = AudioRenderGetLatency(render, ms);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(render);
    render = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderRenderFrameWhenRenderIsNull, TestSize.Level0)
{
    struct AudioRender *render = nullptr;
    void *frame = (void *)calloc(1, FREAM_DATA);
    uint64_t requestBytes = FREAM_DATA;
    uint64_t replyBytes;
    int32_t ret = AudioRenderRenderFrame(render, (const void*)frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    free(frame);
    frame = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderRenderFrameWhenFrameIsNull, TestSize.Level0)
{
    struct AudioRender *render = new AudioRender;
    const void *frame = nullptr;
    uint64_t requestBytes = FREAM_DATA;
    uint64_t replyBytes;
    int32_t ret = AudioRenderRenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(render);
    render = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderRenderFrameWhenReplyBytesIsNull, TestSize.Level0)
{
    struct AudioRender *render = new AudioRender;
    void *frame = (void *)calloc(1, FREAM_DATA);
    uint64_t requestBytes = FREAM_DATA;
    uint64_t *replyBytes = nullptr;
    int32_t ret = AudioRenderRenderFrame(render, (const void*)frame, requestBytes, replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(render);
    render = nullptr;
    free(frame);
    frame = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetRenderPositionWhenRenderIsNull, TestSize.Level0)
{
    struct AudioRender *render = nullptr;
    uint64_t frameTmp = 1024;
    uint64_t *frames = &frameTmp;
    struct AudioTimeStamp *time = new AudioTimeStamp;
    int32_t ret = AudioRenderGetRenderPosition(render, frames, time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(time);
    time = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetRenderPositionWhenFramesIsNull, TestSize.Level0)
{
    struct AudioRender *render = new AudioRender;
    uint64_t *frames = nullptr;
    struct AudioTimeStamp *time = new AudioTimeStamp;
    int32_t ret = AudioRenderGetRenderPosition(render, frames, time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(render);
    render = nullptr;
    delete(time);
    time = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetRenderPositionWhenTimeIsNull, TestSize.Level0)
{
    struct AudioRender *render = new AudioRender;
    uint64_t frameTmp = 1024;
    uint64_t *frames = &frameTmp;
    struct AudioTimeStamp *time = nullptr;
    int32_t ret = AudioRenderGetRenderPosition(render, frames, time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(render);
    render = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetRenderPositionWhenParamIsVaild, TestSize.Level0)
{
    struct AudioRender *render = new AudioRender;
    uint64_t frameTmp = 1024;
    uint64_t *frames = &frameTmp;
    struct AudioTimeStamp *time = new AudioTimeStamp;
    int32_t ret = AudioRenderGetRenderPosition(render, frames, time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(render);
    render = nullptr;
    delete(time);
    time = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetRenderSpeedWhenRenderIsNull, TestSize.Level0)
{
    struct AudioRender *render = nullptr;
    float speedTmp = 1.0;
    float *speed = &speedTmp;
    int32_t ret = AudioRenderGetRenderSpeed(render, speed);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioRenderTest, AudioRenderGetRenderSpeedWhenSpeedIsNull, TestSize.Level0)
{
    struct AudioRender *render = new AudioRender;
    float *speed = nullptr;
    int32_t ret = AudioRenderGetRenderSpeed(render, speed);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(render);
    render = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderGetRenderSpeedWhenParamIsVaild, TestSize.Level0)
{
    struct AudioRender *render = new AudioRender;
    float speedTmp = 1.0;
    float *speed = &speedTmp;
    int32_t ret = AudioRenderGetRenderSpeed(render, speed);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    delete(render);
    render = nullptr;
}
HWTEST_F(AudioRenderTest, AudioRenderDrainBufferWhenRenderIsNull, TestSize.Level0)
{
    AudioRender *render = nullptr;
    AudioDrainNotifyType *type = new AudioDrainNotifyType;
    int32_t ret = AudioRenderDrainBuffer(render, type);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(type);
    type = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderDrainBufferWhenTypeIsNull, TestSize.Level0)
{
    AudioRender *render = new AudioRender;
    AudioDrainNotifyType *type = nullptr;
    int32_t ret = AudioRenderDrainBuffer(render, type);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(render);
    render = nullptr;
}

HWTEST_F(AudioRenderTest, AudioRenderDrainBufferWhenParamIsNotSupport, TestSize.Level0)
{
    AudioRender *render = new AudioRender;
    AudioDrainNotifyType *type = new AudioDrainNotifyType;
    int32_t ret = AudioRenderDrainBuffer(render, type);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);
    delete(render);
    render = nullptr;
    delete(type);
    type = nullptr;
}
}
