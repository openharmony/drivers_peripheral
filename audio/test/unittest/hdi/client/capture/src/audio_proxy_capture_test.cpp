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

using namespace comfun;
using namespace testing::ext;
namespace {
class AudioProxyCaptureTest : public testing::Test {
public:
    struct AudioManager *managerFuncs = nullptr;
    struct AudioManager *(*getAudioManager)(void) = NULL;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioPort *audioPort = nullptr;
    void *clientHandle = nullptr;
    struct AudioDeviceDescriptor devDescCapture = {};
    struct AudioSampleAttributes attrsCapture = {};
    virtual void SetUp();
    virtual void TearDown();
};

void AudioProxyCaptureTest::SetUp()
{
    clientHandle = GetDynamicLibHandle(RESOLVED_PATH);
    ASSERT_NE(clientHandle, nullptr);
    getAudioManager = (struct AudioManager *(*)())(dlsym(clientHandle, FUNCTION_NAME.c_str()));
    ASSERT_NE(getAudioManager, nullptr);
    managerFuncs = getAudioManager();
    ASSERT_NE(managerFuncs, nullptr);
    int32_t size = 0;
    ASSERT_EQ(HDF_SUCCESS,  managerFuncs->GetAllAdapters(managerFuncs, &descs, &size));

    desc = &descs[0];
    ASSERT_EQ(HDF_SUCCESS, managerFuncs->LoadAdapter(managerFuncs, desc, &adapter));
    ASSERT_NE(adapter, nullptr);
    ASSERT_EQ(HDF_SUCCESS, InitDevDescCapture(devDescCapture));
    ASSERT_EQ(HDF_SUCCESS, InitAttrsCapture(attrsCapture));
    ASSERT_EQ(HDF_SUCCESS, adapter->CreateCapture(adapter, &devDescCapture, &attrsCapture, &capture));
}

void AudioProxyCaptureTest::TearDown()
{
    if (adapter != nullptr) {
        adapter->DestroyCapture(adapter, capture);
        capture = nullptr;
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

HWTEST_F(AudioProxyCaptureTest, CaptureStart_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureStart(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureStart_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureStart((AudioHandle)capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureStart_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureStart((AudioHandle)capture));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureStop((AudioHandle)capture));
}

HWTEST_F(AudioProxyCaptureTest, CaptureStop_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureStop(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureStop_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureStop((AudioHandle)capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CapturePause_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCapturePause(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CapturePause_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCapturePause((AudioHandle)capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureResume_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureResume(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureResume_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureResume((AudioHandle)capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureFlush_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureFlush(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureFlush_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, AudioProxyCaptureFlush((AudioHandle)capture));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameSize_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t size = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetFrameSize(nullptr, &size));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetFrameSize((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameSize_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint64_t size = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetFrameSize((AudioHandle)capture, &size));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameSize_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t size = 0;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureGetFrameSize((AudioHandle)capture, &size));
    EXPECT_NE(size, 0);
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameCount_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t count = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetFrameCount(nullptr, &count));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetFrameCount((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetFrameCount_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint64_t count = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetFrameCount((AudioHandle)capture, &count));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetSampleAttributes_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetSampleAttributes(nullptr, &attrsCapture));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetSampleAttributes_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetSampleAttributes((AudioHandle)capture, &attrsCapture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetSampleAttributes_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetSampleAttributes(nullptr, &attrsCapture));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetSampleAttributes_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetSampleAttributes((AudioHandle)capture, &attrsCapture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetCurrentChannelId_001, TestSize.Level1)
{
    uint32_t channelId = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetCurrentChannelId(nullptr, &channelId));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetCurrentChannelId((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetCurrentChannelId_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint32_t channelId = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetCurrentChannelId((AudioHandle)capture, &channelId));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureCheckSceneCapability_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_IN_MIC;
    bool supported = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureCheckSceneCapability(nullptr, &scene, &supported));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureCheckSceneCapability((AudioHandle)capture, nullptr,
                                                                                 &supported));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureCheckSceneCapability((AudioHandle)capture, &scene,
                                                                                 nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureCheckSceneCapability_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_IN_MIC;
    bool supported = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureCheckSceneCapability((AudioHandle)capture, &scene,
                                                                                 &supported));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSelectScene_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_IN_MIC;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSelectScene(nullptr, &scene));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSelectScene((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSelectScene_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    struct AudioSceneDescriptor scene;
    scene.scene.id = 0;
    scene.desc.pins = PIN_IN_MIC;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSelectScene((AudioHandle)capture, &scene));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSelectScene_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioSceneDescriptor *scene  = new AudioSceneDescriptor;
    scene->scene.id = 0; // 0 is Media
    scene->desc.pins = PIN_IN_HS_MIC;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureSelectScene((AudioHandle)capture, scene));
    scene->desc.pins = PIN_IN_MIC;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureSelectScene((AudioHandle)capture, scene));
    delete scene;
    scene = nullptr;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetMute_001, TestSize.Level1)
{
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetMute(nullptr, mute));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetMute_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetMute((AudioHandle)capture, mute));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetMute_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    bool mute;
    mute = true;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureSetMute((AudioHandle)capture, mute));
    mute = false;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureSetMute((AudioHandle)capture, mute));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetMute_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetMute(nullptr, &mute));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetMute((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetMute_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetMute((AudioHandle)capture, &mute));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetMute_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    bool mute = false;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureGetMute((AudioHandle)capture, &mute));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetVolume_001, TestSize.Level1)
{
    float volume = HALF_OF_NORMAL_VALUE; // Adjust the volume to half
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetVolume(nullptr, volume));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetVolume_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    float volume = HALF_OF_NORMAL_VALUE; // Adjust the volume to half
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetVolume((AudioHandle)capture, volume));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetVolume_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    float volume = MIN_VALUE_OUT_OF_BOUNDS; // The volume value is not within the threshold range [0,1]
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetVolume((AudioHandle)capture, volume));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetVolume_004, TestSize.Level1)
{
    float volume = MAX_VALUE_OUT_OF_BOUNDS; // The volume value is not within the threshold range [0,1]
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetVolume((AudioHandle)capture, volume));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetVolume_001, TestSize.Level1)
{
    float volume = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetVolume(nullptr, &volume));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetVolume_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    float volume = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetVolume((AudioHandle)capture, &volume));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetVolume_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    float volume = 0;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureGetVolume((AudioHandle)capture, &volume));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetGainThreshold_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    float min = 0;
    float max = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetGainThreshold(nullptr, &min, &max));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetGainThreshold((AudioHandle)capture, nullptr, &max));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetGainThreshold((AudioHandle)capture, &min, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetGainThreshold_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    float min = 0;
    float max = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetGainThreshold((AudioHandle)capture, &min, &max));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetGain_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    float gain = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetGain(nullptr, &gain));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetGain((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetGain_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    float gain = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetGain((AudioHandle)capture, &gain));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetGain_001, TestSize.Level1)
{
    float gain = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetGain(nullptr, gain));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetGain_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    float gain = HALF_OF_NORMAL_VALUE; // The parameter is adjusted to half the threshold of 1
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetGain((AudioHandle)capture, gain));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetGain_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    float gain = MIN_VALUE_OUT_OF_BOUNDS;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetGain((AudioHandle)capture, gain));
}

HWTEST_F(AudioProxyCaptureTest, CaptureFrame_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    int8_t frame[AUDIO_CAPTURE_BUF_TEST];
    uint64_t frameLen = AUDIO_CAPTURE_BUF_TEST;
    uint64_t requestBytes = AUDIO_CAPTURE_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureCaptureFrame(nullptr, &frame, frameLen, &requestBytes));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureCaptureFrame(capture, nullptr, frameLen, &requestBytes));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureCaptureFrame(capture, &frame, frameLen, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureFrame_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    int8_t frame[AUDIO_CAPTURE_BUF_TEST];
    uint64_t frameLen = AUDIO_CAPTURE_BUF_TEST;
    uint64_t requestBytes = AUDIO_CAPTURE_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureCaptureFrame(capture, &frame, frameLen, &requestBytes));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureFrame_003, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    int8_t frame[AUDIO_CAPTURE_BUF_TEST ];
    uint64_t frameLen = AUDIO_CAPTURE_BUF_TEST;
    uint64_t requestBytes = AUDIO_CAPTURE_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureStart((AudioHandle)capture));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureCaptureFrame(capture, &frame, frameLen, &requestBytes));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, AudioProxyCaptureStop((AudioHandle)capture));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetCapturePosition_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t frames;
    struct AudioTimeStamp time;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetCapturePosition(nullptr, &frames, &time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetCapturePosition(capture, nullptr, &time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetCapturePosition(capture, &frames, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetCapturePosition_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint64_t frames;
    struct AudioTimeStamp time;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetCapturePosition(capture, &frames, &time));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    char keyValueList[AUDIO_CAPTURE_BUF_TEST];
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetExtraParams(nullptr, keyValueList));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetExtraParams((AudioHandle)capture, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureSetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    char keyValueList[AUDIO_CAPTURE_BUF_TEST];
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureSetExtraParams((AudioHandle)capture, keyValueList));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetExtraParams_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    char keyValueList[AUDIO_CAPTURE_BUF_TEST];
    int32_t listLenth = AUDIO_CAPTURE_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetExtraParams(nullptr, keyValueList, listLenth));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetExtraParams((AudioHandle)capture, nullptr, listLenth));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetExtraParams((AudioHandle)capture, keyValueList, 0));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetExtraParams_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    char keyValueList[AUDIO_CAPTURE_BUF_TEST];
    int32_t listLenth = AUDIO_CAPTURE_BUF_TEST;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetExtraParams((AudioHandle)capture, keyValueList,
                                                                           listLenth));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureReqMmapBuffer_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureReqMmapBuffer(nullptr, reqSize, &desc));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureReqMmapBuffer((AudioHandle)capture, reqSize, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureReqMmapBuffer_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureReqMmapBuffer((AudioHandle)capture, reqSize, &desc));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetMmapPosition_001, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    uint64_t frames;
    struct AudioTimeStamp time;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetMmapPosition(nullptr, &frames, &time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetMmapPosition((AudioHandle)capture, nullptr, &time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetMmapPosition((AudioHandle)capture,  &frames, nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureGetMmapPosition_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    uint64_t frames;
    struct AudioTimeStamp time;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureGetMmapPosition((AudioHandle)capture, &frames, &time));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureTurnStandbyMode_001, TestSize.Level1)
{
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureTurnStandbyMode(nullptr));
}

HWTEST_F(AudioProxyCaptureTest, CaptureTurnStandbyMode_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureTurnStandbyMode((AudioHandle)capture));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}

HWTEST_F(AudioProxyCaptureTest, CaptureAudioDevDump_001, TestSize.Level1)
{
    int32_t range = 0;
    int32_t fd = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureAudioDevDump(nullptr, range, fd));
}

HWTEST_F(AudioProxyCaptureTest, CaptureAudioDevDump_002, TestSize.Level1)
{
    ASSERT_NE(capture, nullptr);
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    struct HdfRemoteService *proxyRemoteHandle = hwCapture->proxyRemoteHandle;
    hwCapture->proxyRemoteHandle = nullptr;
    int32_t range = 0;
    int32_t fd = 0;
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyCaptureAudioDevDump((AudioHandle)capture, range, fd));
    hwCapture->proxyRemoteHandle = proxyRemoteHandle;
}
}
