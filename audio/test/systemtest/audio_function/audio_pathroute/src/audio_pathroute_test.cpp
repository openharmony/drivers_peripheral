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
 * @brief Test audio route path function
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_pathroute_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string ADAPTER_USB = "usb";
const string ADAPTER_INTERNAL = "internal";
const int REGISTER_STATUS_ON = 1;
const int REGISTER_STATUS_OFF = 0;
static struct AudioCtlElemValue g_elemValues[4] = {
    {
        .id.cardServiceName = "hdf_audio_codec_dev0",
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_DAC,
        .id.itemName = "Dacl enable",
        .value[0] = 0,
    }, {
        .id.cardServiceName = "hdf_audio_codec_dev0",
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_DAC,
        .id.itemName = "Dacr enable",
        .value[0] = 0,
    }, {
        .id.cardServiceName = "hdf_audio_codec_dev0",
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_PGA,
        .id.itemName = "LPGA MIC Switch",
        .value[0] = 0,
    }, {
        .id.cardServiceName = "hdf_audio_codec_dev0",
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_PGA,
        .id.itemName = "RPGA MIC Switch",
        .value[0] = 0,
    }
};
class AudioPathRouteTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    int32_t GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
        const string adapterName, struct AudioAdapter **adapter, struct AudioPort& renderPort) const;
};

void AudioPathRouteTest::SetUpTestCase(void) {}

void AudioPathRouteTest::TearDownTestCase(void) {}

void AudioPathRouteTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libhdi_audio.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (struct AudioManager* (*)())(dlsym(handleSo, "GetAudioManagerFuncs"));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioPathRouteTest::TearDown(void)
{
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioPathRouteTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
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
    if (ret != 0 || descs == nullptr || size == 0) {
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
    if (ret != 0 || adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
* @tc.name  Test the audio path route selection funtion of palyback scene
* @tc.number  SUB_Audio_AudioPathRoute_0001
* @tc.desc  The audio path route can be opened sucessfuly,When it is set to
            palyback scene(attrs.type = AUDIO_IN_MEDIA,pins = PIN_OUT_SPEAKER)
* @tc.author: liweiming
*/
HWTEST_F(AudioPathRouteTest, SUB_Audio_AudioPathRoute_0001, TestSize.Level1)
{
    int32_t ret = -1;
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioPort renderPort = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_USB, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, renderPort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = CheckRegisterStatus(g_elemValues[0].id, g_elemValues[1].id, REGISTER_STATUS_ON, REGISTER_STATUS_ON);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test the audio path route selection funtion via switching device SPEAKER to HEADSET
* @tc.number  SUB_Audio_AudioPathRoute_0002
* @tc.desc  The audio path route can be opened sucessfuly,When switching
            device(attrs.type = AUDIO_IN_MEDIA,pins = PIN_OUT_HEADSET)
* @tc.author: liweiming
*/
HWTEST_F(AudioPathRouteTest, SUB_Audio_AudioPathRoute_0002, TestSize.Level1)
{
    int32_t ret = -1;
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioPort renderPort = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    g_elemValues[0].value[0] = 1;
    g_elemValues[1].value[0] = 1;
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_USB, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, renderPort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    struct AudioSceneDescriptor scene = {
        .scene.id = 0,
        .desc.pins = PIN_OUT_HEADSET,
    };
    ret = render->scene.SelectScene(AudioHandle(render), &scene);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[0].id, g_elemValues[1].id, REGISTER_STATUS_OFF, REGISTER_STATUS_OFF);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test the audio path route selection funtion of playback sence
            when the audio path route has been opened
* @tc.number  SUB_Audio_AudioPathRoute_0003
* @tc.desc  The audio path route of playback scene can be opened sucessfuly,When The current
            audio path route has been opened
* @tc.author: liweiming
*/
HWTEST_F(AudioPathRouteTest, SUB_Audio_AudioPathRoute_0003, TestSize.Level1)
{
    int32_t ret = -1;
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioPort renderPort = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *renderFirst = nullptr;
    struct AudioRender *renderSecond = nullptr;
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_INTERNAL, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, renderPort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &renderFirst);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &renderSecond);
    if (ret < 0) {
        adapter->DestroyRender(adapter, renderFirst);
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = CheckRegisterStatus(g_elemValues[0].id, g_elemValues[1].id, REGISTER_STATUS_ON, REGISTER_STATUS_ON);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, renderFirst);
    adapter->DestroyRender(adapter, renderSecond);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test the audio path route selection funtion of recording scene
* @tc.number  SUB_Audio_AudioPathRoute_0004
* @tc.desc  The audio path route can be opened sucessfuly,When it is set to
            recording scene(attrs.type = AUDIO_IN_MEDIA,pins = PIN_IN_MIC)
* @tc.author: liweiming
*/
HWTEST_F(AudioPathRouteTest, SUB_Audio_AudioPathRoute_0004, TestSize.Level1)
{
    int32_t ret = -1;
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioPort capturePort = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    g_elemValues[3].value[0] = 1;
    ret = PowerOff(g_elemValues[2], g_elemValues[3]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_INTERNAL, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = CheckRegisterStatus(g_elemValues[2].id, g_elemValues[3].id, REGISTER_STATUS_ON, REGISTER_STATUS_OFF);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test the audio path route selection funtion via switching device MIC to HS_MIC
* @tc.number  SUB_Audio_AudioPathRoute_0005
* @tc.desc  The audio path route can be opened sucessfuly,When it is set to
            recording scene(attrs.type = AUDIO_IN_MEDIA,pins = PIN_IN_HS_MIC)
* @tc.author: liweiming
*/
HWTEST_F(AudioPathRouteTest, SUB_Audio_AudioPathRoute_0005, TestSize.Level1)
{
    int32_t ret = -1;
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioPort capturePort = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    g_elemValues[2].value[0] = 1;
    g_elemValues[3].value[0] = 1;
    ret = PowerOff(g_elemValues[2], g_elemValues[3]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_INTERNAL, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    struct AudioSceneDescriptor scene = {
        .scene.id = 0,
        .desc.pins = PIN_IN_HS_MIC,
    };
    ret = capture->scene.SelectScene(AudioHandle(capture), &scene);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[2].id, g_elemValues[3].id, REGISTER_STATUS_OFF, REGISTER_STATUS_OFF);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test the audio path route selection funtion of recording sence
            when the audio path route has been opened
* @tc.number  SUB_Audio_AudioPathRoute_0006
* @tc.desc  The audio path route of recording scene can be opened sucessfuly,When The current
            audio path route has been opened
* @tc.author: liweiming
*/
HWTEST_F(AudioPathRouteTest, SUB_Audio_AudioPathRoute_0006, TestSize.Level1)
{
    int32_t ret = -1;
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioPort capturePort = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *captureFirst = nullptr;
    struct AudioCapture *captureSecond = nullptr;
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_INTERNAL, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &captureFirst);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &captureSecond);
    if (ret < 0) {
        adapter->DestroyCapture(adapter, captureFirst);
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = CheckRegisterStatus(g_elemValues[2].id, g_elemValues[3].id, REGISTER_STATUS_ON, REGISTER_STATUS_OFF);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, captureFirst);
    adapter->DestroyCapture(adapter, captureSecond);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test the audio path route selection funtion via runing multi service scenarios
* @tc.number  SUB_Audio_AudioPathRoute_0007
* @tc.desc  The audio path route can be opened sucessfuly,When runing multi service scenarios
* @tc.author: liweiming
*/
HWTEST_F(AudioPathRouteTest, SUB_Audio_AudioPathRoute_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioPort renderPort = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor captureDesc = {};
    struct AudioDeviceDescriptor renderDesc = {};
    struct AudioAdapter *captureAdapter = nullptr;
    struct AudioAdapter *renderAdapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioRender *render = nullptr;
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = PowerOff(g_elemValues[2], g_elemValues[3]);
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_INTERNAL, &captureAdapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_USB, &renderAdapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(captureDesc, capturePort.portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(renderDesc, renderPort.portId, PIN_OUT_SPEAKER);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = captureAdapter->CreateCapture(captureAdapter, &captureDesc, &attrs, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, captureAdapter);
        manager.UnloadAdapter(&manager, renderAdapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = CheckRegisterStatus(g_elemValues[2].id, g_elemValues[3].id, REGISTER_STATUS_ON, REGISTER_STATUS_OFF);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = renderAdapter->CreateRender(renderAdapter, &renderDesc, &attrs, &render);
    if (ret < 0) {
        captureAdapter->DestroyCapture(captureAdapter, capture);
        manager.UnloadAdapter(&manager, captureAdapter);
        manager.UnloadAdapter(&manager, renderAdapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = CheckRegisterStatus(g_elemValues[0].id, g_elemValues[1].id, REGISTER_STATUS_ON, REGISTER_STATUS_ON);
    EXPECT_EQ(HDF_SUCCESS, ret);
    captureAdapter->DestroyCapture(captureAdapter, capture);
    manager.UnloadAdapter(&manager, captureAdapter);
    renderAdapter->DestroyRender(renderAdapter, render);
    manager.UnloadAdapter(&manager, renderAdapter);
}
}