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

#include "hdf_remote_adapter_if.h"
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
    static void *handle;
    static TestGetAudioManager getAudioManager;
    static TestAudioManager *manager;
    static TestAudioAdapterRelease adapterRelease;
    static TestAudioManagerRelease managerRelease;
    static TestAudioCaptureRelease captureRelease;
};

using THREAD_FUNC = void *(*)(void *);
void *AudioIdlHdiCaptureSceneTest::handle = nullptr;
TestGetAudioManager AudioIdlHdiCaptureSceneTest::getAudioManager = nullptr;
TestAudioManager *AudioIdlHdiCaptureSceneTest::manager = nullptr;
TestAudioManagerRelease AudioIdlHdiCaptureSceneTest::managerRelease = nullptr;
TestAudioAdapterRelease AudioIdlHdiCaptureSceneTest::adapterRelease = nullptr;
TestAudioCaptureRelease AudioIdlHdiCaptureSceneTest::captureRelease = nullptr;

void AudioIdlHdiCaptureSceneTest::SetUpTestCase(void)
{
    int32_t ret = LoadFuctionSymbol(handle, getAudioManager, managerRelease, adapterRelease);
    ASSERT_EQ(HDF_SUCCESS, ret);
    captureRelease = (TestAudioCaptureRelease)(dlsym(handle, "AudioCaptureRelease"));
    ASSERT_NE(nullptr, captureRelease);
    (void)HdfRemoteGetCallingPid();
    manager = getAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCaptureSceneTest::TearDownTestCase(void)
{
    if (managerRelease != nullptr && manager != nullptr) {
        (void)managerRelease(manager);
    }
    if (handle != nullptr) {
        (void)dlclose(handle);
    }
}

void AudioIdlHdiCaptureSceneTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureSceneTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture, adapterRelease, captureRelease);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name   Test AudioCaptureCheckSceneCapability API and check scene's capability
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_001
* @tc.desc  Test AudioCaptureCheckSceneCapability interface,return 0 if check scene's capability successful.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_001, TestSize.Level1)
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
* @tc.name   Test checking scene's capability where the scene is not configured in the json.
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_002
* @tc.desc  Test AudioCreateCapture interface,return -1 if the scene is not configured in the json.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    ASSERT_NE(nullptr, capture);
    scenes.scene.id = 5;
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->CheckSceneCapability(capture, &scenes, &supported);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(scenes.desc.desc);
}
#endif
/**
* @tc.name   Test checking scene's capability where the capture is nullptr
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_Null_003
* @tc.desc  Test AudioCreateCapture interface,return -3/-4 if the capture is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_Null_003, TestSize.Level1)
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
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    capture->Stop(capture);
    free(scenes.desc.desc);
}
/**
* @tc.name   Test checking scene's capability where the scene is nullptr
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_Null_004
* @tc.desc  Test AudioCreateCapture interface,return -3 if the scene is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_Null_004, TestSize.Level1)
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
* @tc.name   Test checking scene's capability where the parameter supported is nullptr.
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_Null_005
* @tc.desc  Test AudioCreateCapture interface,return -3 if the parameter supported is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_Null_005, TestSize.Level1)
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
* @tc.name  Test AudioCaptureSelectScene API via legal input
* @tc.number  SUB_Audio_HDI_CaptureSelectScene_001
* @tc.desc  Test AudioCaptureSelectScene interface,return 0 if select capture's scene successful.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureSelectScene_001, TestSize.Level1)
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
* @tc.name  Test AudioCaptureSelectScene API after capture start.
* @tc.number  SUB_Audio_HDI_CaptureSelectScene_002
* @tc.desc  Test AudioCaptureSelectScene, return 0 if select capture's scene successful after capture start.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureSelectScene_002, TestSize.Level1)
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
* @tc.name  Test AudioCaptureSelectScene API where the parameter handle is nullptr.
* @tc.number  SUB_Audio_HDI_CaptureSelectScene_Null_003
* @tc.desc  Test AudioCaptureSelectScene, return -3/-4 if the parameter handle is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureSelectScene_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    scenes.desc.desc = strdup("mic");
    ret = capture->SelectScene(captureNull, &scenes);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    free(scenes.desc.desc);
}
/**
* @tc.name  Test AudioCaptureSelectScene API where the parameter scene is nullptr.
* @tc.number  SUB_Audio_HDI_CaptureSelectScene_Null_004
* @tc.desc  Test AudioCaptureSelectScene, return -3 if the parameter scene is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureSelectScene_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor *scenes = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->SelectScene(capture, scenes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  Test AudioCaptureSelectScene API where the scene is not configured in the json.
* @tc.number  SUB_Audio_HDI_CaptureSelectScene_005
* @tc.desc  Test AudioCaptureSelectScene, return -1 if the scene is not configured in the json.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureSceneTest, SUB_Audio_HDI_CaptureSelectScene_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    ASSERT_NE(nullptr, capture);

    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_HDMI;
    scenes.desc.desc = strdup("mic");
    ret = capture->SelectScene(capture, &scenes);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(scenes.desc.desc);
}
#endif
}
