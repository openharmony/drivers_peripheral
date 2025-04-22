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

#include <gtest/gtest.h>
#include "hdi_service_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioIdlHdiCaptureSceneTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    static TestAudioManager *manager;
    uint32_t captureId_ = 0;
};

TestAudioManager *AudioIdlHdiCaptureSceneTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiCaptureSceneTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCaptureSceneTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiCaptureSceneTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture, &captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureSceneTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture, captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureCheckSceneCapability_001
* @tc.desc  Test AudioCaptureCheckSceneCapability interface,return 0 if check scene's capability successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureCheckSceneCapability_001, TestSize.Level0)
{
    int32_t ret = -1;
    bool supported = false;
    struct AudioSceneDescriptor scenes = {};
    ASSERT_NE(nullptr, capture);
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->CheckSceneCapability(capture, &scenes, &supported);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_TRUE(supported);
    free(scenes.desc.desc);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  AudioCaptureCheckSceneCapability_002
* @tc.desc  Test AudioCreateCapture interface,return -1 if the scene is not configured in the json.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureCheckSceneCapability_002, TestSize.Level0)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    ASSERT_NE(nullptr, capture);
    scenes.scene.id = 5; // invlalid id
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->CheckSceneCapability(capture, &scenes, &supported);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    free(scenes.desc.desc);
}
#endif
/**
* @tc.name  AudioCaptureCheckSceneCapabilityNull_003
* @tc.desc  Test AudioCreateCapture interface,return -3/-4 if the capture is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureCheckSceneCapabilityNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->CheckSceneCapability(captureNull, &scenes, &supported);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    capture->Stop(capture);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioCaptureCheckSceneCapabilityNull_004
* @tc.desc  Test AudioCreateCapture interface,return -3 if the scene is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureCheckSceneCapabilityNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor *scenes = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->CheckSceneCapability(capture, scenes, &supported);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    capture->Stop(capture);
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  AudioCaptureCheckSceneCapabilityNull_005
* @tc.desc  Test AudioCreateCapture interface,return -3 if the parameter supported is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureCheckSceneCapabilityNull_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    ASSERT_NE(nullptr, capture);
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->CheckSceneCapability(capture, &scenes, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    free(scenes.desc.desc);
}
#endif
/**
* @tc.name  AudioCaptureSelectScene_001
* @tc.desc  Test AudioCaptureSelectScene interface,return 0 if select capture's scene successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureSelectScene_001, TestSize.Level0)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    ASSERT_NE(nullptr, capture);
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->SelectScene(capture, &scenes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioCaptureSelectScene_002
* @tc.desc  Test AudioCaptureSelectScene, return 0 if select capture's scene successful after capture start.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureSelectScene_002, TestSize.Level0)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    ASSERT_NE(nullptr, capture);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->SelectScene(capture, &scenes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioCaptureSelectSceneNull_003
* @tc.desc  Test AudioCaptureSelectScene, return -3/-4 if the parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureSelectSceneNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->SelectScene(captureNull, &scenes);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioCaptureSelectSceneNull_004
* @tc.desc  Test AudioCaptureSelectScene, return -3 if the parameter scene is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureSelectSceneNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor *scenes = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->SelectScene(capture, scenes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  AudioCaptureSelectScene_005
* @tc.desc  Test AudioCaptureSelectScene, return -1 if the scene is not configured in the json.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, AudioCaptureSelectScene_005, TestSize.Level0)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    ASSERT_NE(nullptr, capture);

    scenes.scene.id = 99; // invlalid id
    scenes.desc.pins = PIN_OUT_HDMI;
    scenes.desc.desc = strdup("mic");
    ret = capture->SelectScene(capture, &scenes);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    free(scenes.desc.desc);
}
#endif
}
