/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <thread>
#include <chrono>

#include "audio_adapter_interface_impl_test.h"
#include "daudio_constants.h"

using namespace testing::ext;
using namespace OHOS::DistributedHardware;
namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
static constexpr int32_t DEFAULT_CAPTURE_ID = 1 << 27 | 1 << 0;

void AudioAdapterInterfaceImpTest::SetUpTestCase(void) {}

void AudioAdapterInterfaceImpTest::TearDownTestCase(void) {}

void AudioAdapterInterfaceImpTest::SetUp(void) {}

void AudioAdapterInterfaceImpTest::TearDown(void)
{
    AdapterTest_ = nullptr;
}

/**
 * @tc.name: InitAllPorts_001
 * @tc.desc: Verify the InitAllPorts function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, InitAllPorts_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    sptr<IDAudioCallback> speakerCallback = nullptr;
    int32_t dhId = 1;
    AdapterTest_->SetSpeakerCallback(dhId, speakerCallback);
    AdapterTest_->extCallbackMap_.erase(dhId);
    speakerCallback = new MockIDAudioCallback();
    AdapterTest_->SetSpeakerCallback(dhId, speakerCallback);

    dhId = DEFAULT_CAPTURE_ID;
    sptr<IDAudioCallback> micCallback = nullptr;
    AdapterTest_->SetMicCallback(dhId, micCallback);
    AdapterTest_->extCallbackMap_.erase(dhId);
    micCallback = new MockIDAudioCallback();
    AdapterTest_->SetMicCallback(dhId, micCallback);

    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->InitAllPorts());
}

/**
 * @tc.name: CreateRender_001
 * @tc.desc: Verify the CreateRender function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, CreateRender_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    AudioSampleAttributes attrs;
    sptr<IAudioRender> render = nullptr;
    uint32_t renderId = 0;
    int32_t dhId = 1;
    AdapterTest_->extCallbackMap_[dhId] = new MockIDAudioCallback();
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->CreateRender(devDesc, attrs, render, renderId));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->DestroyRender(renderId));

    AdapterTest_->mapAudioDevice_.insert(std::make_pair(PIN_OUT_DAUDIO_DEFAULT, "hello"));
    devDesc.pins = PIN_OUT_DAUDIO_DEFAULT;
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->CreateRender(devDesc, attrs, render, renderId));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->DestroyRender(renderId));
}

/**
 * @tc.name: DestroyRender_001
 * @tc.desc: Verify the DestroyRender function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, DestroyRender_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    AudioSampleAttributes attrs;
    std::string adpterName = "adbcef";
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();
    AdapterTest_->extCallbackMap_[dhId] = new MockRevertIDAudioCallback();

    devDesc.pins = PIN_OUT_DAUDIO_DEFAULT;
    uint32_t renderId = 0;
    AdapterTest_->renderDevs_[renderId] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, devDesc, attrs, callback, renderId));
    AdapterTest_->spkPinInUse_ = 0;

    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->DestroyRender(renderId));
    renderId = 10;
    EXPECT_EQ(HDF_FAILURE, AdapterTest_->DestroyRender(renderId));
    renderId = 1;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->DestroyRender(renderId));
}

/**
 * @tc.name: CreateCapture_001
 * @tc.desc: Verify the CreateCapture function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, CreateCapture_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    AudioSampleAttributes attrs;
    sptr<IAudioCapture> capture = nullptr;
    uint32_t capId = 0;
    int32_t dhId = DEFAULT_CAPTURE_ID;
    AdapterTest_->extCallbackMap_[dhId] = new MockIDAudioCallback();
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->CreateCapture(devDesc, attrs, capture, capId));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->DestroyCapture(capId));

    AdapterTest_->mapAudioDevice_.insert(std::make_pair(PIN_OUT_DAUDIO_DEFAULT, "hello"));
    devDesc.pins = PIN_OUT_DAUDIO_DEFAULT;
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->CreateCapture(devDesc, attrs, capture, capId));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->DestroyCapture(capId));
}

/**
 * @tc.name: CreateRender_001
 * @tc.desc: Verify the DestroyCapture function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, DestroyCapture_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    AudioSampleAttributes attrs;
    std::string adpterName = "adbcef";
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();
    int32_t dhId = DEFAULT_CAPTURE_ID;
    AdapterTest_->extCallbackMap_[dhId] = new MockRevertIDAudioCallback();

    devDesc.pins = PIN_OUT_DAUDIO_DEFAULT;
    uint32_t capId = 0;
    AdapterTest_->captureDevs_[capId] = std::make_pair(dhId,
        new AudioCaptureInterfaceImpl(adpterName, devDesc, attrs, callback));

    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->DestroyCapture(capId));
    capId = 10;
    EXPECT_EQ(HDF_FAILURE, AdapterTest_->DestroyCapture(capId));
    capId = 1;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->DestroyCapture(capId));
}

/**
 * @tc.name: GetPortCapability_001
 * @tc.desc: Verify the GetPortCapability function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetPortCapability_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioPort port;
    AudioPortCapability capability;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetPortCapability(port, capability));
}

/**
 * @tc.name: SetPassthroughMode_001
 * @tc.desc: Verify the SetPassthroughMode function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, SetPassthroughMode_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioPort port;
    AudioPortPassthroughMode mode = AudioPortPassthroughMode::PORT_PASSTHROUGH_LPCM;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetPassthroughMode(port, mode));
}

/**
 * @tc.name: GetPassthroughMode_001
 * @tc.desc: Verify the GetPassthroughMode function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetPassthroughMode_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioPort port;
    AudioPortPassthroughMode mode = AudioPortPassthroughMode::PORT_PASSTHROUGH_LPCM;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetPassthroughMode(port, mode));
}

/**
 * @tc.name: GetDeviceStatus_001
 * @tc.desc: Verify the GetDeviceStatus function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetDeviceStatus_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceStatus sta;

    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetDeviceStatus(sta));
}

/**
 * @tc.name: SetMicMute_001
 * @tc.desc: Verify the SetMicMute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, SetMicMute_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    bool muteTmp = true;
    bool muteGetted;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetMicMute(muteTmp));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetMicMute(muteGetted));
}

/**
 * @tc.name: SetVoiceVolume_001
 * @tc.desc: Verify the SetVoiceVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, SetVoiceVolume_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    float vol = 1.0f;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetVoiceVolume(vol));
}

/**
 * @tc.name: UpdateAudioRoute_001
 * @tc.desc: Verify the UpdateAudioRoute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, UpdateAudioRoute_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioRoute route;
    int32_t handle = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->UpdateAudioRoute(route, handle));
}

/**
 * @tc.name: ReleaseAudioRoute_001
 * @tc.desc: Verify the ReleaseAudioRoute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, ReleaseAudioRoute_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    int32_t handle = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->ReleaseAudioRoute(handle));
}

/**
 * @tc.name: SetExtraParams_001
 * @tc.desc: Verify the SetExtraParams function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, SetExtraParams_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_NONE;
    std::string condition = "{\"dhId\":\"1\"}";
    std::string value = "world";
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AdapterTest_->SetExtraParams(key, condition, value));
    key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetExtraParams(key, condition, value));
    key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_LOWPOWER;
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->SetExtraParams(key, condition, value));
}

/**
 * @tc.name: GetExtraParams_001
 * @tc.desc: Verify the GetExtraParams function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetExtraParams_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_NONE;
    std::string condition = "hello";
    std::string value = "world";
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AdapterTest_->GetExtraParams(key, condition, value));
}

/**
 * @tc.name: GetExtraParams_002
 * @tc.desc: Verify the GetExtraParams function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetExtraParams_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME;
    std::string condition = "hello";
    std::string value = "1";
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->GetExtraParams(key, condition, value));
}

/**
 * @tc.name: GetExtraParams_003
 * @tc.desc: Verify the GetExtraParams function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetExtraParams_003, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_VOLUME;
    std::string condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    std::string value = "1";
    EXPECT_EQ(HDF_FAILURE, AdapterTest_->GetExtraParams(key, condition, value));
}

/**
 * @tc.name: GetExtraParams_004
 * @tc.desc: Verify the GetExtraParams function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetExtraParams_004, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioExtParamKey key = AudioExtParamKey::AUDIO_EXT_PARAM_KEY_STATUS;
    std::string condition = "hello";
    std::string value = "world";
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AdapterTest_->GetExtraParams(key, condition, value));
}

/**
 * @tc.name: RegExtraParamObserver_001
 * @tc.desc: Verify the RegExtraParamObserver function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, RegExtraParamObserver_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    sptr<IAudioCallback> cbObj = nullptr;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->RegExtraParamObserver(cbObj, 0));
}

/**
 * @tc.name: RegExtraParamObserver_002
 * @tc.desc: Verify the RegExtraParamObserver function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, RegExtraParamObserver_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AdapterTest_->paramCallback_ = new MockIAudioParamCallback();
    sptr<IAudioCallback> cbObj = new MockIAudioParamCallback();
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->RegExtraParamObserver(cbObj, 0));
}

/**
 * @tc.name: GetAdapterDesc_002
 * @tc.desc: Verify the GetAdapterDesc function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetAdapterDesc_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AdapterTest_->mapAudioDevice_.insert(std::make_pair(64, "hello"));
    AudioPort port;
    port.dir = PORT_OUT_IN;
    port.portId = 64;
    port.portName = "";
    AdapterTest_->GetAdapterDesc();
    EXPECT_EQ(PORT_OUT_IN, AdapterTest_->adpDescriptor_.ports[0].dir);
}

/**
 * @tc.name: GetDeviceCapabilitys_001
 * @tc.desc: Verify the GetDeviceCapabilitys function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetDeviceCapabilitys_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    uint32_t devId = 88;
    std::string caps = "worldcup";
    AdapterTest_->AddAudioDevice(devId, caps);

    EXPECT_EQ(caps, AdapterTest_->GetDeviceCapabilitys(devId));
}

/**
 * @tc.name: GetDeviceCapabilitys_002
 * @tc.desc: Verify the GetDeviceCapabilitys function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetDeviceCapabilitys_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    uint32_t devId = 88;
    std::string caps = "worldcup";
    AdapterTest_->RemoveAudioDevice(devId);

    EXPECT_EQ("", AdapterTest_->GetDeviceCapabilitys(devId));
}

/**
 * @tc.name: AdapterLoad_001
 * @tc.desc: Verify the AdapterLoad function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, AdapterLoad_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->AdapterLoad());
}

/**
 * @tc.name: AdapterUnload_001
 * @tc.desc: Verify the AdapterUnload function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, AdapterUnload_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->AdapterUnload());

    std::string adpterName = "adbcef";
    AudioDeviceDescriptor descSpk;
    AudioSampleAttributes attrsSpk;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callbackSpk = new MockIDAudioCallback();
    AdapterTest_->SetSpeakerCallback(dhId, callbackSpk);
    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, descSpk, attrsSpk, callbackSpk, 0));
    EXPECT_EQ(HDF_ERR_DEVICE_BUSY, AdapterTest_->AdapterUnload());

    AudioDeviceDescriptor devDescMic;
    AudioSampleAttributes attrsMic;
    dhId = DEFAULT_CAPTURE_ID;
    sptr<IDAudioCallback> callbackMic = new MockIDAudioCallback();
    AdapterTest_->SetMicCallback(dhId, callbackMic);
    AdapterTest_->captureDevs_[0] = std::make_pair(dhId,
        new AudioCaptureInterfaceImpl(adpterName, devDescMic, attrsMic, callbackMic));
    EXPECT_EQ(HDF_ERR_DEVICE_BUSY, AdapterTest_->AdapterUnload());

    AdapterTest_->renderDevs_[0].first = 0;
    AdapterTest_->renderDevs_[0].second = nullptr;
    EXPECT_EQ(HDF_ERR_DEVICE_BUSY, AdapterTest_->AdapterUnload());

    AdapterTest_->captureDevs_[0].first = 0;
    AdapterTest_->captureDevs_[0].second = nullptr;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->AdapterUnload());
}

/**
 * @tc.name: Notify_001
 * @tc.desc: Verify the Notify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, Notify_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event;
    event.type = 3;
    event.content = "VOLUME_LEVEL";
    uint32_t devId = 64;
    uint32_t streamId = 0;
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
}

/**
 * @tc.name: Notify_002
 * @tc.desc: Verify the Notify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, Notify_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event;
    event.type = 10;
    event.content = "FOCUS_CHANGE";
    uint32_t devId = 64;
    uint32_t streamId = 0;
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
    event.type = 11;
    event.content = "RENDER_STATE_CHANG";
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
    event.type = 7;
    event.content = "CLOSE_MIC_RESULT";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
    event.type = 9;
    event.content = "MIC_CLOSED_STATE";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
}

/**
 * @tc.name: Notify_003
 * @tc.desc: Verify the Notify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, Notify_003, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event;
    event.type = 4;
    event.content = "OPEN_SPK_RESULT";
    uint32_t devId = 64;
    uint32_t streamId = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
    event.type = 5;
    event.content = "CLOSE_SPK_RESULT";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
    event.type = 6;
    event.content = "OPEN_MIC_RESULT";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
    event.type = 8;
    event.content = "SPK_CLOSED";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->Notify(devId, streamId, event));
}

/**
 * @tc.name: AddAudioDevice_001
 * @tc.desc: Verify the AddAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, AddAudioDevice_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    uint32_t devId = 64;
    std::string caps;
    AdapterTest_->mapAudioDevice_.insert(std::make_pair(64, "hello"));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->AddAudioDevice(devId, caps));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->RemoveAudioDevice(devId));
}

/**
 * @tc.name: AddAudioDevice_002
 * @tc.desc: Verify the AddAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, AddAudioDevice_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    uint32_t devId = 64;
    std::string caps = "hello";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->AddAudioDevice(devId, caps));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->RemoveAudioDevice(devId));
}

/**
 * @tc.name: RemoveAudioDevice_001
 * @tc.desc: Verify the RemoveAudioDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, RemoveAudioDevice_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    uint32_t devId = 64;
    std::string caps;
    AdapterTest_->mapAudioDevice_.insert(std::make_pair(64, "hello"));
    AdapterTest_->spkPinInUse_ = 64;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->RemoveAudioDevice(devId));
    AdapterTest_->mapAudioDevice_.insert(std::make_pair(64, "hello"));
    AdapterTest_->spkPinInUse_ = 0;
    AdapterTest_->micPinInUse_ = 64;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->RemoveAudioDevice(devId));
}

/**
 * @tc.name: OpenRenderDevice_001
 * @tc.desc: Verify the OpenRenderDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, OpenRenderDevice_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    uint32_t renderId = 0;
    AdapterTest_->extCallbackMap_[dhId] = new MockIDAudioCallback();
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->OpenRenderDevice(devDesc, attrs,
        AdapterTest_->extCallbackMap_[dhId], dhId, renderId));
    AdapterTest_->spkStatus_[renderId] = true;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->OpenRenderDevice(devDesc, attrs,
        AdapterTest_->extCallbackMap_[dhId], dhId, renderId));
}
/**
 * @tc.name: OpenRenderDevice_002
 * @tc.desc: Verify the OpenRenderDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, OpenRenderDevice_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    uint32_t renderId = 0;
    AdapterTest_->extCallbackMap_[dhId] = new MockRevertIDAudioCallback();
    AdapterTest_->spkStatus_[renderId] = false;
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->OpenRenderDevice(devDesc, attrs,
        AdapterTest_->extCallbackMap_[dhId], dhId, renderId));
}

/**
 * @tc.name: CloseRenderDevice_001
 * @tc.desc: Verify the CloseRenderDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, CloseRenderDevice_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback(nullptr);
    AdapterTest_->spkPinInUse_  = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->CloseRenderDevice(devDesc, callback, dhId));
    AdapterTest_->spkPinInUse_  = 1;
    callback = new MockIDAudioCallback();
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->CloseRenderDevice(devDesc, callback, dhId));
    callback = new MockRevertIDAudioCallback();
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->CloseRenderDevice(devDesc, callback, dhId));
}

/**
 * @tc.name: OpenCaptureDevice_001
 * @tc.desc: Verify the OpenCaptureDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, OpenCaptureDevice_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    AudioSampleAttributes attrs;
    int32_t dhId = DEFAULT_CAPTURE_ID;
    sptr<IDAudioCallback> callback(new MockIDAudioCallback());
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->OpenCaptureDevice(devDesc, attrs, callback, dhId));
    AdapterTest_->isMicOpened_ = true;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->OpenCaptureDevice(devDesc, attrs, callback, dhId));
}

/**
 * @tc.name: CloseCaptureDevice_001
 * @tc.desc: Verify the CloseCaptureDevice function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, CloseCaptureDevice_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceDescriptor devDesc;
    int32_t dhId = DEFAULT_CAPTURE_ID;
    sptr<IDAudioCallback> callback(new MockIDAudioCallback());
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->CloseCaptureDevice(devDesc, callback, dhId));
    AdapterTest_->micPinInUse_  = 1;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->CloseCaptureDevice(devDesc, callback, dhId));
}

/**
 * @tc.name: GetVolumeGroup_001
 * @tc.desc: Verify the GetVolumeGroup function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetVolumeGroup_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    uint32_t devId = 88;
    int32_t dhId = DEFAULT_CAPTURE_ID;
    AdapterTest_->extCallbackMap_[dhId] = new MockIDAudioCallback();
    EXPECT_EQ(0, AdapterTest_->GetVolumeGroup(devId));
}

/**
 * @tc.name: GetInterruptGroup_001
 * @tc.desc: Verify the GetInterruptGroup function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetInterruptGroup_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    uint32_t devId = 88;
    int32_t dhId = 1;

    AdapterTest_->extCallbackMap_[dhId] = new MockIDAudioCallback();
    EXPECT_EQ(0, AdapterTest_->GetInterruptGroup(devId));
}

/**
 * @tc.name: SetAudioVolume_001
 * @tc.desc: Verify the SetAudioVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, SetAudioVolume_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string condition = "EVENT_TYPE=4;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    std::string param = "1";
    int32_t dhId = 1;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetAudioVolume(condition, param));
    AdapterTest_->extCallbackMap_[dhId] = new MockIDAudioCallback();
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetAudioVolume(condition, param));
    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetAudioVolume(condition, param));
    param = "0";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetAudioVolume(condition, param));
    param = "-66";
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->SetAudioVolume(condition, param));
    condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->SetAudioVolume(condition, param));
}

/**
 * @tc.name: GetAudioVolume_001
 * @tc.desc: Verify the GetAudioVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetAudioVolume_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));

    std::string condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    std::string param = "1";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetAudioVolume(condition, param));
}

/**
 * @tc.name: GetAudioVolume_002
 * @tc.desc: Verify the GetAudioVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetAudioVolume_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));

    std::string condition = "EVENT_TYPE=3;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    std::string param = "1";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetAudioVolume(condition, param));
}

/**
 * @tc.name: GetAudioVolume_003
 * @tc.desc: Verify the GetAudioVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetAudioVolume_003, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));

    std::string condition = "EVENT_TYPE=2;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    std::string param = "1";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetAudioVolume(condition, param));
}

/**
 * @tc.name: GetAudioVolume_004
 * @tc.desc: Verify the GetAudioVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetAudioVolume_004, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));

    std::string condition = "EVENT_TYPE=4;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    std::string param = "1";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetAudioVolume(condition, param));
}


/**
 * @tc.name: GetAudioVolume_005
 * @tc.desc: Verify the GetAudioVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetAudioVolume_005, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    int32_t dhId = 0;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));

    std::string condition = "EVENT_TYPE=66;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    std::string param = "1";
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->GetAudioVolume(condition, param));
    EXPECT_EQ("0", param);
}

/**
 * @tc.name: GetAudioVolume_006
 * @tc.desc: Verify the GetAudioVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetAudioVolume_006, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AdapterTest_->renderDevs_[0] = std::make_pair(1, nullptr);

    std::string condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    std::string param = "1";
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->GetAudioVolume(condition, param));
    EXPECT_EQ("1", param);
}

/**
 * @tc.name: getEventTypeFromCondition_001
 * @tc.desc: Verify the getEventTypeFromCondition function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, getEventTypeFromCondition_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string condition = "EVENT_TYPE=1;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    auto actualValue = AdapterTest_->getEventTypeFromCondition(condition);
    EXPECT_EQ(1, actualValue);
}

/**
 * @tc.name: getEventTypeFromCondition_002
 * @tc.desc: Verify the getEventTypeFromCondition function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, getEventTypeFromCondition_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string condition = "EVENT_TYPE=12;VOLUME_GROUP_ID=2;AUDIO_VOLUME_TYPE=1;";
    auto actualValue = AdapterTest_->getEventTypeFromCondition(condition);
    EXPECT_EQ(12, actualValue);
}

/**
 * @tc.name: ParseDhIdFromJson_001
 * @tc.desc: Verify the ParseDhIdFromJson function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, ParseDhIdFromJson_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string jsonArgs = "";
    EXPECT_EQ(-1, AdapterTest_->ParseDhIdFromJson(jsonArgs));
}

/**
 * @tc.name: ConvertString2Int_001
 * @tc.desc: Verify the ConvertString2Int function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, ConvertString2Int_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string valueStr = "";
    int value = 0;

    for (int i = 1; i < 10; i++) {
        valueStr += std::to_string(i);
        value = value * 10 + i;
        EXPECT_EQ(value, AdapterTest_->ConvertString2Int(valueStr));
    }
    valueStr = "1ab";
    value = -1;
    EXPECT_EQ(value, AdapterTest_->ConvertString2Int(valueStr));
}

/**
 * @tc.name: GetRenderImpl_001
 * @tc.desc: Verify the GetRenderImpl function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, GetRenderImpl_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    std::string content = "";
    EXPECT_EQ(nullptr, AdapterTest_->GetRenderImpl(content));

    content = "{\"dhId\":\"1\"}";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    const int dhId = 1;
    const std::string adpName = "abc";
    auto audioRender = new AudioRenderInterfaceImpl(adpName, desc, attrs, nullptr, 0);
    AdapterTest_->renderDevs_[0] = std::make_pair(dhId, audioRender);
    EXPECT_NE(nullptr, AdapterTest_->GetRenderImpl(content));
}

/**
 * @tc.name: HandleVolumeChangeEvent_001
 * @tc.desc: Verify the HandleVolumeChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleVolumeChangeEvent_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_VOLUME_CHANGE,
        "VOLUME_CHANAGE;AUDIO_STREAM_TYPE=1;VOLUME_LEVEL=1;IS_UPDATEUI=1;VOLUME_GROUP_ID=1;"};
    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId, nullptr);
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleVolumeChangeEvent(event));

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleVolumeChangeEvent(event));
    AdapterTest_->paramCallback_ = new MockIAudioParamCallback();
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleVolumeChangeEvent(event));
}

/**
 * @tc.name: HandleVolumeChangeEvent_002
 * @tc.desc: Verify the HandleVolumeChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleVolumeChangeEvent_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_VOLUME_CHANGE, "V"};
    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));
    EXPECT_EQ(ERR_DH_AUDIO_HDF_NULLPTR, AdapterTest_->HandleVolumeChangeEvent(event));
}

/**
 * @tc.name: HandleVolumeChangeEvent_003
 * @tc.desc: Verify the HandleVolumeChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleVolumeChangeEvent_003, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_VOLUME_CHANGE, "V"};
    std::string adpterName = "adbcef";
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    int32_t dhId = 1;
    sptr<IDAudioCallback> callback = new MockIDAudioCallback();

    AdapterTest_->renderDevs_[0] = std::make_pair(dhId,
        new AudioRenderInterfaceImpl(adpterName, desc, attrs, callback, 0));
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleVolumeChangeEvent(event));
}

/**
 * @tc.name: HandleFocusChangeEvent_001
 * @tc.desc: Verify the HandleFocusChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleFocusChangeEvent_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_FOCUS_CHANGE,
        "INTERRUPT_EVENT;EVENT_TYPE=1;VOLUME_LEVEL=1;FORCE_TYPE=1;HINT_TYPE=1;"};

    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleFocusChangeEvent(event));
    AdapterTest_->paramCallback_ = new MockIAudioParamCallback();
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleFocusChangeEvent(event));
}

/**
 * @tc.name: HandleFocusChangeEvent_002
 * @tc.desc: Verify the HandleFocusChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleFocusChangeEvent_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_FOCUS_CHANGE,
        "INTERRUPT_EVENT;EVENT_TYPE=1;VOLUME_LEVEL=1;FORCE_TYPE=1;HINT_TYPE=1;"};

    AdapterTest_->paramCallback_ = new MockRevertIAudioParamCallback();
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleFocusChangeEvent(event));
}

/**
 * @tc.name: HandleRenderStateChangeEvent_001
 * @tc.desc: Verify the HandleRenderStateChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleRenderStateChangeEvent_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_RENDER_STATE_CHANGE,
        "RENDER_STATE_CHANGE_EVENT;STATE=0;"};

    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleRenderStateChangeEvent(event));
    AdapterTest_->paramCallback_ = new MockIAudioParamCallback();
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleRenderStateChangeEvent(event));
}

/**
 * @tc.name: HandleRenderStateChangeEvent_002
 * @tc.desc: Verify the HandleRenderStateChangeEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleRenderStateChangeEvent_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_RENDER_STATE_CHANGE,
        "RENDER_STATE_CHANGE_EVENT;STATE=0;"};

    AdapterTest_->paramCallback_ = new MockRevertIAudioParamCallback();
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleRenderStateChangeEvent(event));
}

/**
 * @tc.name: HandleSANotifyEvent_001
 * @tc.desc: Verify the HandleSANotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleSANotifyEvent_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_OPEN_SPK_RESULT, "RENDER_STATE_CHANGE_EVENT"};
    uint32_t streamId = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event));
}

/**
 * @tc.name: HandleSANotifyEvent_002
 * @tc.desc: Verify the HandleSANotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleSANotifyEvent_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_OPEN_SPK_RESULT, HDF_EVENT_RESULT_SUCCESS};
    uint32_t streamId = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event));
}

/**
 * @tc.name: HandleSANotifyEvent_003
 * @tc.desc: Verify the HandleSANotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleSANotifyEvent_003, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_CLOSE_SPK_RESULT,
        HDF_EVENT_RESULT_SUCCESS};
    uint32_t streamId = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event));
    DAudioEvent event1 = {HDF_AUDIO_EVENT_CLOSE_SPK_RESULT, "RENDER_STATE_CHANGE"};
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event1));
}

/**
 * @tc.name: HandleSANotifyEvent_004
 * @tc.desc: Verify the HandleSANotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleSANotifyEvent_004, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_OPEN_MIC_RESULT,
        HDF_EVENT_RESULT_SUCCESS};
    uint32_t streamId = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event));
    DAudioEvent event1 = {HDF_AUDIO_EVENT_OPEN_MIC_RESULT, "RENDER_STATE_CHANGE"};
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event1));
}

/**
 * @tc.name: HandleSANotifyEvent_005
 * @tc.desc: Verify the HandleSANotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleSANotifyEvent_005, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_CLOSE_MIC_RESULT, HDF_EVENT_RESULT_SUCCESS};
    uint32_t streamId = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event));
    DAudioEvent event1 = {HDF_AUDIO_EVENT_CLOSE_MIC_RESULT, "RENDER_STATE_CHANGE"};
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event1));
}

/**
 * @tc.name: HandleSANotifyEvent_006
 * @tc.desc: Verify the HandleSANotifyEvent function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleSANotifyEvent_006, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    using namespace DistributedHardware;
    DAudioEvent event = {-1, "ddd"};
    uint32_t streamId = 0;
    EXPECT_NE(HDF_SUCCESS, AdapterTest_->HandleSANotifyEvent(streamId, event));
}

/**
 * @tc.name: WaitForSANotify_001
 * @tc.desc: Verify the WaitForSANotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, WaitForSANotify_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    int flag = 1;
    uint32_t streamId = 0;
    std::thread th([&]() {
        while (flag) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            AdapterTest_->spkNotifyFlag_ = true;
            AdapterTest_->spkWaitCond_.notify_one();
        }});
    AudioDeviceEvent  event = EVENT_OPEN_SPK;
    AdapterTest_->spkStatus_[streamId] = true;
    EXPECT_EQ(DH_SUCCESS, AdapterTest_->WaitForSANotify(streamId, event));
    AudioDeviceEvent event1 = EVENT_CLOSE_SPK ;
    AdapterTest_->spkStatus_[streamId] = false;
    EXPECT_EQ(DH_SUCCESS, AdapterTest_->WaitForSANotify(streamId, event1));
    flag = 0;
    if (th.joinable()) {
        th.join();
    }
}

/**
 * @tc.name: WaitForSANotify_002
 * @tc.desc: Verify the WaitForSANotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, WaitForSANotify_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    int flag = 1;
    std::thread th([&]() {
        while (flag) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            AdapterTest_->spkNotifyFlag_ = true;
            AdapterTest_->spkWaitCond_.notify_one();
        }});
    AudioDeviceEvent  event = EVENT_OPEN_SPK;
    uint32_t streamId = 0;
    AdapterTest_->spkStatus_[streamId] = true;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->WaitForSANotify(streamId, event));
    flag = 0;
    if (th.joinable()) {
        th.join();
    }
}

/**
 * @tc.name: WaitForSANotify_003
 * @tc.desc: Verify the WaitForSANotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, WaitForSANotify_003, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    int flag = 1;
    uint32_t captureId = 0;
    std::thread th([&]() {
        while (flag) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            AdapterTest_->micNotifyFlag_ = true;
            AdapterTest_->micWaitCond_.notify_one();
        }});
    AudioDeviceEvent  event = EVENT_OPEN_MIC;
    AdapterTest_->isMicOpened_ = true;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->WaitForSANotify(captureId, event));

    AudioDeviceEvent  event1 = EVENT_CLOSE_MIC;
    AdapterTest_->isMicOpened_ = false;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->WaitForSANotify(captureId, event1));
    flag = 0;
    if (th.joinable()) {
        th.join();
    }
}

/**
 * @tc.name: WaitForSANotify_004
 * @tc.desc: Verify the WaitForSANotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, WaitForSANotify_004, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    int flag = 1;
    uint32_t captureId = 0;
    std::thread th([&]() {
        while (flag) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
                AdapterTest_->micNotifyFlag_ = true;
            AdapterTest_->micWaitCond_.notify_one();
        }});
    AudioDeviceEvent  event = EVENT_OPEN_MIC;
    AdapterTest_->isMicOpened_ = true;;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->WaitForSANotify(captureId, event));
    flag = 0;
    if (th.joinable()) {
        th.join();
    }
}

/**
 * @tc.name: WaitForSANotify_005
 * @tc.desc: Verify the WaitForSANotify function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, WaitForSANotify_005, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    AudioDeviceEvent  event = EVENT_DEV_CLOSED;
    uint32_t captureId = 0;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->WaitForSANotify(captureId, event));
}

/**
 * @tc.name: HandleDeviceClosed_001
 * @tc.desc: Verify the HandleDeviceClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleDeviceClosed_001, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_SPK_CLOSED, "gtest"};
    uint32_t streamId = 0;

    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleDeviceClosed(streamId, event));
    AdapterTest_->paramCallback_ = new MockIAudioParamCallback();
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleDeviceClosed(streamId, event));
}

/**
 * @tc.name: HandleDeviceClosed_002
 * @tc.desc: Verify the HandleDeviceClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleDeviceClosed_002, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_SPK_CLOSED, "gtest"};
    DAudioEvent event1 = {HDF_AUDIO_EVENT_MIC_CLOSED, "gmock"};
    uint32_t streamId = 0;
    AdapterTest_->paramCallback_ = nullptr;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleDeviceClosed(streamId, event));

    AdapterTest_->spkStatus_[streamId] = true;
    AdapterTest_->isMicOpened_ = true;
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleDeviceClosed(streamId, event));
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleDeviceClosed(streamId, event1));
}

/**
 * @tc.name: HandleDeviceClosed_001
 * @tc.desc: Verify the HandleDeviceClosed function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioAdapterInterfaceImpTest, HandleDeviceClosed_003, TestSize.Level1)
{
    AudioAdapterDescriptor adaDesc;
    AdapterTest_ = std::make_shared<AudioAdapterInterfaceImpl>(adaDesc);

    DAudioEvent event = {HDF_AUDIO_EVENT_SPK_CLOSED, "gtest"};
    uint32_t streamId = 0;

    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleDeviceClosed(streamId, event));
    AdapterTest_->paramCallback_ = new MockRevertIAudioParamCallback();
    EXPECT_EQ(HDF_SUCCESS, AdapterTest_->HandleDeviceClosed(streamId, event));
}
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS