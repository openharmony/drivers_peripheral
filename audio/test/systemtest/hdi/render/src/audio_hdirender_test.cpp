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
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter, and rendering audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the audio render adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_hdirender_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string AUDIO_FILE = "//bin/audiorendertest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";

class AudioHdiRenderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    int32_t GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
                           const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const;
    int32_t AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager, struct AudioAdapter *adapter,
                              const struct AudioPort renderPort, struct AudioRender **render) const;
    int32_t AudioRenderStart(const string path, struct AudioRender *render) const;
    static int32_t GetLoadAdapterAudioPara(struct PrepareAudioPara& audiopara);
    static int32_t PlayAudioFile(struct PrepareAudioPara& audiopara);
};

using THREAD_FUNC = void *(*)(void *);

void AudioHdiRenderTest::SetUpTestCase(void) {}

void AudioHdiRenderTest::TearDownTestCase(void) {}

void AudioHdiRenderTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libaudio_hdi_proxy_server.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (struct AudioManager* (*)())(dlsym(handleSo, "GetAudioProxyManagerFuncs"));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioHdiRenderTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioHdiRenderTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
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

int32_t AudioHdiRenderTest::AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager,
    struct AudioAdapter *adapter, const struct AudioPort renderPort, struct AudioRender **render) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (adapter == nullptr || adapter->CreateRender == nullptr || render == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = InitDevDesc(devDesc, renderPort.portId, pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, render);
    if (ret < 0 || *render == nullptr) {
        manager.UnloadAdapter(&manager, adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderTest::AudioRenderStart(const string path, struct AudioRender *render) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioHeadInfo headInfo = {};
    if (render == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    char absPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), absPath) == nullptr) {
        printf("path is not exist");
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = WavHeadAnalysis(headInfo, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    ret = FrameStart(headInfo, render, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

struct PrepareAudioPara {
    struct AudioManager *manager;
    enum AudioPortDirection portType;
    const char *adapterName;
    struct AudioAdapter *adapter;
    struct AudioPort audioPort;
    void *self;
    enum AudioPortPin pins;
    const char *path;
    struct AudioRender *render;
    struct AudioCapture *capture;
    struct AudioHeadInfo headInfo;
    struct AudioAdapterDescriptor *desc;
    struct AudioAdapterDescriptor *descs;
    char *frame;
    uint64_t requestBytes;
    uint64_t replyBytes;
    uint64_t fileSize;
    struct AudioSampleAttributes attrs;
};

int32_t AudioHdiRenderTest::GetLoadAdapterAudioPara(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    int size = 0;
    auto *inst = (AudioHdiRenderTest *)audiopara.self;
    if (inst != nullptr && inst->GetAudioManager != nullptr) {
        audiopara.manager = inst->GetAudioManager();
    }
    if (audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = audiopara.manager->GetAllAdapters(audiopara.manager, &audiopara.descs, &size);
    if (ret < 0 || audiopara.descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(audiopara.descs, audiopara.adapterName,
            audiopara.portType, audiopara.audioPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            audiopara.desc = &audiopara.descs[index];
        }
    }
    if (audiopara.desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ret = audiopara.manager->LoadAdapter(audiopara.manager, audiopara.desc, &audiopara.adapter);
    }
    if (ret < 0 || audiopara.adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderTest::PlayAudioFile(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    struct AudioDeviceDescriptor devDesc = {};
    char absPath[PATH_MAX] = {0};
    if (realpath(audiopara.path, absPath) == nullptr) {
        printf("path is not exist");
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    if (audiopara.adapter == nullptr  || audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = HMOS::Audio::InitAttrs(audiopara.attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (WavHeadAnalysis(audiopara.headInfo, file, audiopara.attrs) < 0) {
        return HDF_FAILURE;
    }

    ret = HMOS::Audio::InitDevDesc(devDesc, (&audiopara.audioPort)->portId, audiopara.pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = audiopara.adapter->CreateRender(audiopara.adapter, &devDesc, &(audiopara.attrs), &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }
    ret = HMOS::Audio::FrameStart(audiopara.headInfo, audiopara.render, file, audiopara.attrs);
    if (ret == HDF_SUCCESS) {
        fclose(file);
    } else {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        fclose(file);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
* @tc.name  Test RenderGetLatency API via legal
* @tc.number  SUB_Audio_HDI_RenderGetLatency_0001
* @tc.desc  test RenderGetLatency interface, return 0 if GetLatency successful
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetLatency_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t latencyTime = 0;
    uint32_t hopeVolume = 0;
    struct AudioPort audioPort = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    enum AudioPortDirection audioPortType = PORT_OUT;

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, audioPortType, ADAPTER_NAME2, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(pins, manager, adapter, audioPort, &render);
    if (render == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(render, &latencyTime);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_LT(hopeVolume, latencyTime);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test RenderGetLatency API via Setting parameters render is empty
* @tc.number  SUB_Audio_HDI_AudioRenderGetLatency_0002
* @tc.desc  test RenderGetLatency interface, return -1 if Setting parameters render is empty
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetLatency_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t latencyTime = 0;
    struct AudioPort audioPort = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    enum AudioPortDirection audioPortType = PORT_OUT;

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, audioPortType, ADAPTER_NAME2, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(pins, manager, adapter, audioPort, &render);
    if (render == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(renderNull, &latencyTime);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test RenderGetLatency API via Setting parameters ms is empty
* @tc.number  SUB_Audio_HDI_AudioRenderGetLatency_0003
* @tc.desc  test RenderGetLatency interface,return -1 if Setting parameters ms is empty
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetLatency_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t *latencyTime = nullptr;
    struct AudioPort audioPort = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    enum AudioPortDirection audioPortType = PORT_OUT;

    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, audioPortType, ADAPTER_NAME2, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(pins, manager, adapter, audioPort, &render);
    if (render == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(render, latencyTime);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test SetRenderSpeed API via legal
    * @tc.number  SUB_Audio_HDI_AudioRenderSetRenderSpeed_0001
    * @tc.desc  Test SetRenderSpeed interface,return -2 if setting RenderSpeed
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderSetRenderSpeed_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    float speed = 100;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->SetRenderSpeed(render, speed);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test SetRenderSpeed API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderSetRenderSpeed_0002
    * @tc.desc  Test SetRenderSpeed interface,return -2 if the incoming parameter handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderSetRenderSpeed_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    float speed = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->SetRenderSpeed(renderNull, speed);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetRenderSpeed API via legal
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderSpeed_0001
    * @tc.desc  Test GetRenderSpeed interface,return -2 if getting RenderSpeed
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderSpeed_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    float speed = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderSpeed(render, &speed);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetRenderSpeed API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderSpeed_0002
    * @tc.desc  Test GetRenderSpeed interface,return -2 if the incoming parameter handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderSpeed_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    float speed = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderSpeed(renderNull, &speed);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetRenderSpeed API via setting the incoming parameter speed is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderSpeed_0002
    * @tc.desc  Test GetRenderSpeed interface,return -2 if the incoming parameter speed is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderSpeed_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    float *speedNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderSpeed(render, speedNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderFrame API via legal input
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0001
* @tc.desc  test AudioRenderFrame interface,Returns 0 if the data is written successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioPort renderPort = {};
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(pins, manager, adapter, renderPort, &render);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioRenderFrame API via setting the incoming parameter render is nullptr
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0002
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if the incoming parameter render is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioPort renderPort = {};
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(pins, manager, adapter, renderPort, &render);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(renderNull, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioRenderFrame API via setting the incoming parameter frame is nullptr
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0003
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if the incoming parameter frame is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioPort renderPort = {};
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(pins, manager, adapter, renderPort, &render);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->RenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderFrame API via setting the incoming parameter replyBytes is nullptr
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0004
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if the incoming parameter replyBytes is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    struct AudioPort renderPort = {};
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;
    uint64_t *replyBytes = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(pins, manager, adapter, renderPort, &render);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(render, frame, requestBytes, replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioRenderFrame API without calling interface renderstart
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0005
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if without calling interface renderstart
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioPort renderPort = {};
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(pins, manager, adapter, renderPort, &render);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
    * @tc.name  Test SetChannelMode API via setting channel mode to different enumeration values
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_0001
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode to different enumeration values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderSetChannelMode_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    enum AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    enum AudioChannelMode modeOne = AUDIO_CHANNEL_BOTH_LEFT;
    enum AudioChannelMode modeSec = AUDIO_CHANNEL_BOTH_RIGHT;
    enum AudioChannelMode modeTrd = AUDIO_CHANNEL_EXCHANGE;
    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_LEFT, modeOne);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_RIGHT, modeSec);
    ret = render->SetChannelMode(render, modeTrd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeTrd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_EXCHANGE, modeTrd);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test SetChannelMode API via setting channel mode to different values
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_0002
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode to different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderSetChannelMode_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    enum AudioChannelMode mode = AUDIO_CHANNEL_MIX;
    enum AudioChannelMode modeOne = AUDIO_CHANNEL_LEFT_MUTE;
    enum AudioChannelMode modeSec = AUDIO_CHANNEL_RIGHT_MUTE;
    enum AudioChannelMode modeTrd = AUDIO_CHANNEL_BOTH_MUTE;
    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_MIX, mode);
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_LEFT_MUTE, modeOne);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_RIGHT_MUTE, modeSec);
    ret = render->SetChannelMode(render, modeTrd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeTrd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_MUTE, modeTrd);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test SetChannelMode API via setting channel mode after render object is created
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_0003
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode after render object is created
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderSetChannelMode_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    enum AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test SetChannelMode API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_0004
    * @tc.desc  Test SetChannelMode interface,return -1 if set the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderSetChannelMode_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    enum AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetChannelMode(renderNull, mode);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetChannelMode API via getting the channel mode after setting
    * @tc.number  SUB_Audio_HDI_AudioRenderGetChannelMode_0001
    * @tc.desc  Test GetChannelMode interface,return 0 if getting the channel mode after setting
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetChannelMode_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    enum AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetChannelMode API via getting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetChannelMode_0002
    * @tc.desc  Test GetChannelMode interface,return -1 if getting the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetChannelMode_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    enum AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetChannelMode(renderNull, &mode);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetChannelMode API via getting the channel mode after the render object is created
    * @tc.number  SUB_Audio_HDI_AudioRenderGetChannelMode_0003
    * @tc.desc  Test GetChannelMode interface,return 0 if getting the channel mode after the object is created
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetChannelMode_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    enum AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test GetRenderPosition API via legal input
* @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0001
* @tc.desc  Test GetRenderPosition interface,Returns 0 if get RenderPosition during playing.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapterAudioPara(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(3);
    ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (int32_t)result;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Test AudioRenderGetRenderPosition API via get RenderPosition after the audio file is Paused and resumed
* @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0002
* @tc.desc   Test GetRenderPosition interface,Returns 0 if get RenderPosition after Pause and resume during playing
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapterAudioPara(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(3);
    ret = audiopara.render->control.Pause((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    sleep(5);
    ret = audiopara.render->control.Resume((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (int32_t)result;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Test GetRenderPosition API via get RenderPosition after the audio file is stopped
* @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0003
* @tc.desc  Test GetRenderPosition interface,Returns 0 if get RenderPosition after stop during playing
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapterAudioPara(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(3);
    ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (int32_t)result;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0004
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(time.tvSec, timeExp);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0005
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(renderNull, &frames, &time);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via setting the parameter frames is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0006
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter frames is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    uint64_t *framesNull = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0};

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(render, framesNull, &time);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via setting the parameter time is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0007
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter time is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp *timeNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, timeNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via get RenderPosition continuously
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0008
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return 0 if the GetRenderPosition was called twice
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetRenderPosition API via define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0009
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetRenderPosition API via define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0010
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetRenderPosition API via define sampleRate and channelCount to different value
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0011
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define channelCount  as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0011, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t channelCountExp = 1;
    uint32_t sampleRateExp = 48000;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetRenderPosition API via define sampleRate and channelCount to 1
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0012
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define channelCount to 1
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0012, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t channelCountExp = 1;
    uint32_t sampleRateExp = 48000;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
}