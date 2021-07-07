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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Defines audio-related APIs, including custom data types and functions for capture drivers funtion.
 * accessing a driver adapter, and capturing audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the capturing audio adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_hdicapture_scene_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string AUDIO_CAPTURE_FILE = "//bin/audiocapturetest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";

class AudioHdiCaptureSceneTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    int32_t GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
                           const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const;
    int32_t AudioCreateCapture(enum AudioPortPin pins, struct AudioManager manager,
                               struct AudioPort capturePort, struct AudioAdapter *adapter,
                               struct AudioCapture **capture) const;
    int32_t AudioCaptureStart(const string path, struct AudioCapture *capture) const;
};

void AudioHdiCaptureSceneTest::SetUpTestCase(void) {}

void AudioHdiCaptureSceneTest::TearDownTestCase(void) {}

void AudioHdiCaptureSceneTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libaudio_hdi_proxy_server.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (struct AudioManager *(*)())(dlsym(handleSo, "GetAudioProxyManagerFuncs"));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioHdiCaptureSceneTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioHdiCaptureSceneTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
    const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    if (adapter == nullptr) {
        return HDF_FAILURE;
    }
    ret = manager.GetAllAdapters(&manager, &descs, &size);
    if (ret < 0 || descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(descs, adapterName, portType, audioPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            desc = &descs[index];
        }
    }
    if (desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ret = manager.LoadAdapter(&manager, desc, adapter);
    }
    if (ret < 0 || adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureSceneTest::AudioCreateCapture(enum AudioPortPin pins, struct AudioManager manager,
    struct AudioPort capturePort, struct AudioAdapter *adapter, struct AudioCapture **capture) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (adapter == nullptr || adapter->CreateCapture == nullptr || capture == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, capture);
    if (ret < 0 || *capture == nullptr) {
        manager.UnloadAdapter(&manager, adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureSceneTest::AudioCaptureStart(const string path, struct AudioCapture *capture) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};

    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    FILE *file = fopen(path.c_str(), "wb+");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = FrameStartCapture(capture, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

/**
* @tc.name   Test AudioCaptureCheckSceneCapability API and check scene's capability
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_0001
* @tc.desc  Test AudioCaptureCheckSceneCapability interface,return 0 if check scene's capability successful.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = false;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSceneDescriptor scenes = {};

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = capture->scene.CheckSceneCapability(capture, &scenes, &supported);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_TRUE(supported);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name   Test checking scene's capability where the scene is not configed in the josn.
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_0002
* @tc.desc  Test AudioCreateCapture interface,return -1 if the scene is not configed in the josn.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSceneDescriptor scenes = {};

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    scenes.scene.id = 5;
    scenes.desc.pins = PIN_IN_MIC;
    ret = capture->scene.CheckSceneCapability(capture, &scenes, &supported);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name   Test checking scene's capability where the capture is empty
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_0003
* @tc.desc  Test AudioCreateCapture interface,return -1 if the capture is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_0003, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    struct AudioSceneDescriptor scenes = {};

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = capture->scene.CheckSceneCapability(captureNull, &scenes, &supported);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name   Test checking scene's capability where the scene is empty
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_0004
* @tc.desc  Test AudioCreateCapture interface,return -1 if the scene is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_0004, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSceneDescriptor *scenes = nullptr;

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->scene.CheckSceneCapability(capture, scenes, &supported);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name   Test checking scene's capability where the parameter supported is empty.
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_0005
* @tc.desc  Test AudioCreateCapture interface,return -1 if the parameter supported is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_CaptureCheckSceneCapability_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSceneDescriptor scenes = {};

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = capture->scene.CheckSceneCapability(capture, &scenes, nullptr);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSelectScene API via legal input
* @tc.number  SUB_Audio_HDI_AudioCaptureSelectScene_0001
* @tc.desc  Test AudioCaptureSelectScene interface,return 0 if select capture's scene successful.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_AudioCaptureSelectScene_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSceneDescriptor scenes = {};

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = capture->scene.SelectScene(capture, &scenes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSelectScene API after capture start.
* @tc.number  SUB_Audio_HDI_AudioCaptureSelectScene_0002
* @tc.desc  Test AudioCaptureSelectScene, return 0 if select capture's scene successful after capture start.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_AudioCaptureSelectScene_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSceneDescriptor scenes = {};

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = capture->scene.SelectScene(capture, &scenes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSelectScene API where the parameter handle is empty.
* @tc.number  SUB_Audio_HDI_AudioCaptureSelectScene_0003
* @tc.desc  Test AudioCaptureSelectScene, return -1 if the parameter handle is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_AudioCaptureSelectScene_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    struct AudioSceneDescriptor scenes = {};

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = capture->scene.SelectScene(captureNull, &scenes);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSelectScene API where the parameter scene is empty.
* @tc.number  SUB_Audio_HDI_AudioCaptureSelectScene_0004
* @tc.desc  Test AudioCaptureSelectScene, return -1 if the parameter scene is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_AudioCaptureSelectScene_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSceneDescriptor *scenes = nullptr;

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->scene.SelectScene(capture, scenes);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSelectScene API where the scene is not configed in the josn.
* @tc.number  SUB_Audio_HDI_AudioCaptureSelectScene_0005
* @tc.desc  Test AudioCaptureSelectScene, return -1 if the scene is not configed in the josn.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureSceneTest, SUB_Audio_HDI_AudioCaptureSelectScene_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSceneDescriptor scenes = {};

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_HDMI;
    ret = capture->scene.SelectScene(capture, &scenes);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
}