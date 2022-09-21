/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "audio_proxy_common_fun_test.h"

using namespace std;
using namespace comfun;
using namespace testing::ext;
namespace {
class AudioProxyRenderTest : public testing::Test {
public:
    struct AudioManager *managerFuncs = nullptr;
    struct AudioManager *(*getAudioManager)(void) = NULL;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    void *clientHandle = nullptr;
    struct AudioDeviceDescriptor devDescRender = {};
    struct AudioSampleAttributes attrsRender = {};
    virtual void SetUp();
    virtual void TearDown();
};

void AudioProxyRenderTest::SetUp()
{
    clientHandle = GetDynamicLibHandle(RESOLVED_PATH);
    ASSERT_NE(clientHandle, nullptr);
    getAudioManager = (struct AudioManager *(*)())(dlsym(clientHandle, FUNCTION_NAME.c_str()));
    ASSERT_NE(getAudioManager, nullptr);
    managerFuncs = getAudioManager();
    ASSERT_NE(managerFuncs, nullptr);
    int32_t size = 0;
    ASSERT_EQ(HDF_SUCCESS, managerFuncs->GetAllAdapters(managerFuncs, &descs, &size));
    ASSERT_NE(descs, nullptr);
    desc = &descs[0];
    ASSERT_EQ(HDF_SUCCESS, managerFuncs->LoadAdapter(managerFuncs, desc, &adapter));
    ASSERT_NE(adapter, nullptr);
    ASSERT_EQ(HDF_SUCCESS, InitDevDesc(devDescRender));
    ASSERT_EQ(HDF_SUCCESS, InitAttrs(attrsRender));
    ASSERT_EQ(HDF_SUCCESS, adapter->CreateRender(adapter, &devDescRender, &attrsRender, &render));
}

void AudioProxyRenderTest::TearDown()
{
    if (adapter != nullptr) {
        adapter->DestroyRender(adapter, render);
        render = nullptr;
    }
    if (managerFuncs != nullptr) {
        managerFuncs->UnloadAdapter(managerFuncs, adapter);
        adapter = nullptr;
        managerFuncs->ReleaseAudioManagerObject(managerFuncs);
        managerFuncs = nullptr;
    }
    if (clientHandle != nullptr) {
        dlclose(clientHandle);
        clientHandle = nullptr;
    }
}

HWTEST_F(AudioProxyRenderTest, RenderStart_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderStart(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderStart_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderStart((AudioHandle)render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderStart_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyRenderStart((AudioHandle)render));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyRenderStop((AudioHandle)render));
}

HWTEST_F(AudioProxyRenderTest, RenderStop_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderStop(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderStop_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderStop((AudioHandle)render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderPause_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderPause(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderPause_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderPause((AudioHandle)render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderResume_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderResume(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderResume_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderResume((AudioHandle)render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderFlush_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderFlush(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderFlush_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, AudioProxyRenderFlush((AudioHandle)render));
}

HWTEST_F(AudioProxyRenderTest, RenderGetFrameSize_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t size = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetFrameSize(nullptr, &size));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetFrameSize((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetFrameSize_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t size = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetFrameSize((AudioHandle)render, &size));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetFrameCount_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t count = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetFrameCount(nullptr, &count));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetFrameCount((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetFrameCount_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t count = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetFrameCount((AudioHandle)render, &count));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetSampleAttributes_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetSampleAttributes(nullptr, &attrs));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetSampleAttributes((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderSetSampleAttributes_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSampleAttributes attrs;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetSampleAttributes((AudioHandle)render, &attrs));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetSampleAttributes_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetSampleAttributes(nullptr, &attrs));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetSampleAttributes((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetSampleAttributes_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSampleAttributes attrs;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetSampleAttributes((AudioHandle)render, &attrs));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetCurrentChannelId_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint32_t channelId = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetCurrentChannelId(nullptr, &channelId));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetCurrentChannelId((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetCurrentChannelId_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint32_t channelId = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetCurrentChannelId((AudioHandle)render, &channelId));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderCheckSceneCapability_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_SPEAKER;
    bool supported = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderCheckSceneCapability(nullptr, &scene, &supported));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderCheckSceneCapability((AudioHandle)render, nullptr,
                                                                                &supported));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderCheckSceneCapability((AudioHandle)render, &scene, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderCheckSceneCapability_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_SPEAKER;
    bool supported = false;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderCheckSceneCapability((AudioHandle)render, &scene,
                                                                                &supported));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSelectScene_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_SPEAKER;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSelectScene(nullptr, &scene));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSelectScene((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderSelectScene_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_SPEAKER;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSelectScene((AudioHandle)render, &scene));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSelectScene_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    AudioSceneDescriptor scene;
    scene.scene.id = 0; // 0 is Media
    scene.desc.pins = PIN_OUT_HEADSET;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyRenderSelectScene((AudioHandle)render, &scene));
    scene.desc.pins = PIN_OUT_SPEAKER;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyRenderSelectScene((AudioHandle)render, &scene));
}

HWTEST_F(AudioProxyRenderTest, RenderSetMute_001, TestSize.Level1)
{
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetMute(nullptr, mute));
}

HWTEST_F(AudioProxyRenderTest, RenderSetMute_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    bool mute = false;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetMute((AudioHandle)render, mute));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetMute_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetMute(nullptr, &mute));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetMute((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetMute_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    bool mute = false;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetMute((AudioHandle)render, &mute));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetVolume_001, TestSize.Level1)
{
    float volume = HALF_OF_NORMAL_VALUE; // Adjust the volume to half
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetVolume(nullptr, volume));
}

HWTEST_F(AudioProxyRenderTest, RenderSetVolume_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float volume = HALF_OF_NORMAL_VALUE; // Adjust the volume to half
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetVolume((AudioHandle)render, volume));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetVolume_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float volume = MIN_VALUE_OUT_OF_BOUNDS; // The volume value is not within the threshold range [0,1]
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetVolume((AudioHandle)render, volume));
    volume = MAX_VALUE_OUT_OF_BOUNDS; // The volume value is not within the threshold range [0,1]
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetVolume((AudioHandle)render, volume));
}

HWTEST_F(AudioProxyRenderTest, RenderGetVolume_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float volume = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetVolume(nullptr, &volume));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetVolume((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetVolume_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float volume = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetVolume((AudioHandle)render, &volume));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetGainThreshold_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float min = 0;
    float max = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetGainThreshold(nullptr, &min, &max));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetGainThreshold((AudioHandle)render, nullptr, &max));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetGainThreshold((AudioHandle)render, &min, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetGainThreshold_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float min = 0;
    float max = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetGainThreshold((AudioHandle)render, &min, &max));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetGain_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float gain = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetGain(nullptr, &gain));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetGain((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetGain_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float gain = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetGain((AudioHandle)render, &gain));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetGain_001, TestSize.Level1)
{
    float gain = HALF_OF_NORMAL_VALUE; // Adjust the gain to half
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetGain(nullptr, gain));
}

HWTEST_F(AudioProxyRenderTest, RenderSetGain_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float gain = HALF_OF_NORMAL_VALUE; // Adjust the gain to half
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetGain((AudioHandle)render, gain));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetGain_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float gain = MIN_VALUE_OUT_OF_BOUNDS; // The gain value is not within the threshold range [0,1]
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetGain((AudioHandle)render, gain));
}

HWTEST_F(AudioProxyRenderTest, RenderGetLatency_001, TestSize.Level1)
{
    uint32_t ms = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetLatency(nullptr, &ms));
}

HWTEST_F(AudioProxyRenderTest, RenderGetLatency_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint32_t ms = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetLatency(render, &ms));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetLatency_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint32_t ms = 0;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyRenderGetLatency(render, &ms));
}

HWTEST_F(AudioProxyRenderTest, RenderFrame_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    int8_t frame[AUDIO_RENDER_BUF_TEST];
    uint64_t frameLen = AUDIO_RENDER_BUF_TEST;
    uint64_t requestBytes = AUDIO_RENDER_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderRenderFrame(nullptr, &frame, frameLen, &requestBytes));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderRenderFrame(render, nullptr, frameLen, &requestBytes));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderRenderFrame(render, &frame, frameLen, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderFrame_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    int8_t frame[AUDIO_RENDER_BUF_TEST];
    uint64_t frameLen = AUDIO_RENDER_BUF_TEST;
    uint64_t requestBytes = AUDIO_RENDER_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderRenderFrame(render, &frame, frameLen, &requestBytes));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderFrame_003, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    int8_t frame[AUDIO_RENDER_BUF_TEST] = {0};
    uint64_t frameLen = AUDIO_RENDER_BUF_TEST;
    uint64_t requestBytes = AUDIO_RENDER_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyRenderStart((AudioHandle)render));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyRenderRenderFrame(render, &frame, frameLen, &requestBytes));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyRenderStop((AudioHandle)render));
}


HWTEST_F(AudioProxyRenderTest, RenderGetRenderPosition_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetRenderPosition(nullptr, &frames, &time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetRenderPosition(render, nullptr, &time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetRenderPosition(render, &frames, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetRenderPosition_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetRenderPosition(render, &frames, &time));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetRenderSpeed_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float speed = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetRenderSpeed(nullptr, speed));
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, AudioProxyRenderSetRenderSpeed(render, speed));
}

HWTEST_F(AudioProxyRenderTest, RenderGetRenderSpeed_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    float speed = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetRenderSpeed(nullptr, &speed));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetRenderSpeed(render, nullptr));
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, AudioProxyRenderGetRenderSpeed(render, &speed));
}

HWTEST_F(AudioProxyRenderTest, RenderSetChannelMode_001, TestSize.Level1)
{
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetChannelMode(nullptr, mode));
}

HWTEST_F(AudioProxyRenderTest, RenderSetChannelMode_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetChannelMode(render, mode));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetChannelMode_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetChannelMode(nullptr, &mode));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetChannelMode(render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetChannelMode_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetChannelMode(render, &mode));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderSetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetExtraParams(nullptr, keyValueList));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetExtraParams((AudioHandle)render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderSetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderSetExtraParams((AudioHandle)render, keyValueList));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    int32_t listLenth = AUDIO_RENDER_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetExtraParams(nullptr, keyValueList, listLenth));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetExtraParams((AudioHandle)render, nullptr, listLenth));
}

HWTEST_F(AudioProxyRenderTest, RenderGetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    char keyValueList[AUDIO_RENDER_BUF_TEST];
    int32_t listLenth = AUDIO_RENDER_BUF_TEST;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    int32_t ret = AudioProxyRenderGetExtraParams((AudioHandle)render, keyValueList, listLenth);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderReqMmapBuffer_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderReqMmapBuffer(nullptr, reqSize, &desc));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderReqMmapBuffer((AudioHandle)render, reqSize, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderReqMmapBuffer_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderReqMmapBuffer((AudioHandle)render, reqSize, &desc));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderGetMmapPosition_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t frames;
    struct AudioTimeStamp time;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetMmapPosition(nullptr, &frames, &time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetMmapPosition((AudioHandle)render, nullptr, &time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetMmapPosition((AudioHandle)render, &frames, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderGetMmapPosition_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t frames;
    struct AudioTimeStamp time;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderGetMmapPosition((AudioHandle)render, &frames, &time));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderTurnStandbyMode_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderTurnStandbyMode(nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderTurnStandbyMode_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderTurnStandbyMode((AudioHandle)render));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderAudioDevDump_001, TestSize.Level1)
{
    int32_t range = 0;
    int32_t fd = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderAudioDevDump(nullptr, range, fd));
}

HWTEST_F(AudioProxyRenderTest, RenderAudioDevDump_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    int32_t range = 0;
    int32_t fd = 0;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderAudioDevDump((AudioHandle)render, range, fd));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderRegCallback_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t tempAddr = 1;
    void *cookie = (void *)(uintptr_t)tempAddr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderRegCallback(nullptr, AudioRenderCallbackUtTest, cookie));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderRegCallback(render, nullptr, cookie));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderRegCallback(render, AudioRenderCallbackUtTest, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderRegCallback_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    uint64_t tempAddr = 1;
    void *cookie = (void *)(uintptr_t)tempAddr;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderRegCallback(render, AudioRenderCallbackUtTest, cookie));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyRenderTest, RenderDrainBuffer_001, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    AudioDrainNotifyType type = AUDIO_DRAIN_NORMAL_MODE;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderDrainBuffer(nullptr, &type));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderDrainBuffer(render, nullptr));
}

HWTEST_F(AudioProxyRenderTest, RenderDrainBuffer_002, TestSize.Level1)
{
    ASSERT_NE(render, nullptr);
    AudioDrainNotifyType type = AUDIO_DRAIN_NORMAL_MODE;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    struct HdfRemoteService *proxyRemoteHandle = hwRender->proxyRemoteHandle;
    hwRender->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyRenderDrainBuffer(render, &type));
    hwRender->proxyRemoteHandle = proxyRemoteHandle;
}
}
