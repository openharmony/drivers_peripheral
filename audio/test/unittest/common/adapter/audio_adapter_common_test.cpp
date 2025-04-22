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

#include <climits>
#include <cstring>
#include <gtest/gtest.h>
#include "hdf_dlist.h"
#include "osal_mem.h"
#include "v4_0/audio_types.h"
#include "v4_0/iaudio_adapter.h"
#include "v4_0/iaudio_manager.h"

using namespace std;
using namespace testing::ext;

#define AUDIO_CHANNELCOUNT             2
#define AUDIO_SAMPLE_RATE_48K          48000
#define DEEP_BUFFER_RENDER_PERIOD_SIZE 4096
#define INT_32_MAX                     0x7fffffff
#define PCM_16_BIT                     16
#define PCM_8_BIT                      8
#define AUDIO_STREAM_NUM_MAX           10
namespace {
static const uint32_t g_audioAdapterNumMax = 5;
const int32_t AUDIO_ADAPTER_BUF_TEST = 1024;

class HdfAudioUtAdapterTest : public testing::Test {
public:
    struct IAudioManager *manager_ = nullptr;
    struct IAudioAdapter *adapter_ = nullptr;
    struct AudioAdapterDescriptor *adapterDescs_ = nullptr;
    uint32_t renderId_ = 0;
    uint32_t captureId_ = 0;
    virtual void SetUp();
    virtual void TearDown();
    void InitAttrs(struct AudioSampleAttributes &attrs);
    void InitDevDesc(struct AudioDeviceDescriptor &devDesc);
    void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen);
};

void HdfAudioUtAdapterTest::AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == nullptr) {
        return;
    }

    if (dataBlock->adapterName != nullptr) {
        OsalMemFree(dataBlock->adapterName);
        dataBlock->adapterName = nullptr;
    }

    if (dataBlock->ports != nullptr) {
        OsalMemFree(dataBlock->ports);
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void HdfAudioUtAdapterTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if ((descsLen > 0) && (descs != nullptr) && ((*descs) != nullptr)) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = nullptr;
    }
}

void HdfAudioUtAdapterTest::InitAttrs(struct AudioSampleAttributes &attrs)
{
    attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs.channelCount = AUDIO_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs.interleaved = 1;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = PCM_16_BIT * attrs.channelCount / PCM_8_BIT;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.frameSize);
    attrs.stopThreshold = INT_32_MAX;
}

void HdfAudioUtAdapterTest::InitDevDesc(struct AudioDeviceDescriptor &devDesc)
{
    ASSERT_NE(adapterDescs_, nullptr);
    ASSERT_NE(adapterDescs_->ports, nullptr);
    for (uint32_t index = 0; index < adapterDescs_->portsLen; index++) {
        if (adapterDescs_->ports[index].dir == PORT_OUT) {
            devDesc.portId = adapterDescs_->ports[index].portId;
            return;
        }
    }
}

void HdfAudioUtAdapterTest::SetUp()
{
    uint32_t size = g_audioAdapterNumMax;
    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);

    adapterDescs_ = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(adapterDescs_, nullptr);

    ASSERT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, adapterDescs_, &size));
    if (size > g_audioAdapterNumMax) {
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_LT(size, g_audioAdapterNumMax);
    }

    if (manager_->LoadAdapter(manager_, &adapterDescs_[0], &adapter_) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_TRUE(false);
    }
    if (adapter_ == nullptr) {
        ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
        ASSERT_TRUE(false);
    }
}

void HdfAudioUtAdapterTest::TearDown()
{
    ASSERT_NE(manager_, nullptr);
    ASSERT_NE(adapter_, nullptr);

    manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName);
    ReleaseAdapterDescs(&adapterDescs_, g_audioAdapterNumMax);
    adapter_ = nullptr;
    IAudioManagerRelease(manager_, false);
    manager_ = nullptr;
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterInitAllPortsNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->InitAllPorts(nullptr));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterInitAllPortsParaIsvalid001, TestSize.Level1)
{
    EXPECT_EQ(HDF_SUCCESS, adapter_->InitAllPorts(adapter_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateRenderNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->CreateRender(nullptr, nullptr, nullptr, nullptr, &renderId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateRenderNull002, TestSize.Level1)
{
    struct IAudioRender *render = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    EXPECT_NE(HDF_SUCCESS, adapter_->CreateRender(nullptr, &devicedesc, &attrs, &render, &renderId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateRenderInvalid001, TestSize.Level1)
{
    struct IAudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->CreateRender(adapter_, nullptr, &attrs, &render, &renderId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateRenderInvalid002, TestSize.Level1)
{
    struct IAudioRender *render = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->CreateRender(adapter_, &devicedesc, nullptr, &render, &renderId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateRenderIsvalid001, TestSize.Level0)
{
    struct IAudioRender *render = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_OUT_SPEAKER;
    InitAttrs(attrs);
    attrs.silenceThreshold = 0;
    attrs.streamId = 0;
    int32_t ret = adapter_->CreateRender(adapter_, &devicedesc, &attrs, &render, &renderId_);
    if (ret != HDF_SUCCESS) {
        attrs.format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
        ASSERT_EQ(HDF_SUCCESS, adapter_->CreateRender(adapter_, &devicedesc, &attrs, &render, &renderId_));
    }
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyRender(adapter_, renderId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterDestroyRenderNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->DestroyRender(nullptr, renderId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterDestroyRenderNull002, TestSize.Level1)
{
    uint32_t renderId = AUDIO_STREAM_NUM_MAX - 1;
    int32_t ret = adapter_->DestroyRender(adapter_, renderId);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterDestroyRenderInvalid001, TestSize.Level1)
{
    uint32_t renderId = AUDIO_STREAM_NUM_MAX;
    int32_t ret = adapter_->DestroyRender(adapter_, renderId);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->CreateCapture(nullptr, nullptr, nullptr, nullptr, &captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureNull002, TestSize.Level1)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    EXPECT_NE(HDF_SUCCESS, adapter_->CreateCapture(nullptr, &devicedesc, &attrs, &capture, &captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureInvalid001, TestSize.Level1)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->CreateCapture(adapter_, nullptr, &attrs, &capture, &captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureInvalid002, TestSize.Level1)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->CreateCapture(adapter_, &devicedesc, nullptr, &capture, &captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureIsvalid001, TestSize.Level0)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_IN_MIC;
    InitAttrs(attrs);
    attrs.silenceThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    EXPECT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_));
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyCapture(adapter_, captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureIsvalid002, TestSize.Level0)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_IN_MIC;
    InitAttrs(attrs);
    attrs.sourceType = AUDIO_INPUT_VOICE_UPLINK_TYPE;
    attrs.silenceThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    EXPECT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_));
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyCapture(adapter_, captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureIsvalid003, TestSize.Level0)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_IN_MIC;
    InitAttrs(attrs);
    attrs.sourceType = AUDIO_INPUT_VOICE_DOWNLINK_TYPE;
    attrs.silenceThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    EXPECT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_));
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyCapture(adapter_, captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureIsvalid004, TestSize.Level0)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_IN_MIC;
    InitAttrs(attrs);
    attrs.sourceType = AUDIO_INPUT_VOICE_CALL_TYPE;
    attrs.silenceThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    EXPECT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_));
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyCapture(adapter_, captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureIsvalid005, TestSize.Level0)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_IN_MIC;
    InitAttrs(attrs);
    attrs.sourceType = AUDIO_INPUT_CAMCORDER_TYPE;
    attrs.silenceThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    EXPECT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_));
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyCapture(adapter_, captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureIsvalid006, TestSize.Level0)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_IN_MIC;
    InitAttrs(attrs);
    attrs.sourceType = AUDIO_INPUT_EC_TYPE;
    attrs.silenceThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    EXPECT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_));
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyCapture(adapter_, captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterCreateCaptureIsvalid007, TestSize.Level0)
{
    struct IAudioCapture *capture = nullptr;
    struct AudioDeviceDescriptor devicedesc = {};
    struct AudioSampleAttributes attrs = {};
    InitDevDesc(devicedesc);
    devicedesc.desc = const_cast<char*>("primary");
    devicedesc.pins = PIN_IN_MIC;
    InitAttrs(attrs);
    attrs.sourceType = AUDIO_INPUT_NOISE_REDUCTION_TYPE;
    attrs.silenceThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    EXPECT_EQ(HDF_SUCCESS, adapter_->CreateCapture(adapter_, &devicedesc, &attrs, &capture, &captureId_));
    EXPECT_EQ(HDF_SUCCESS, adapter_->DestroyCapture(adapter_, captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterDestroyCaptureNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->DestroyCapture(nullptr, captureId_));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterDestroyCaptureInvalid001, TestSize.Level1)
{
    uint32_t captureId = AUDIO_STREAM_NUM_MAX;
    int32_t ret = adapter_->DestroyCapture(adapter_, captureId);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPortCapabilityNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->GetPortCapability(nullptr, nullptr, nullptr));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPortCapabilityNull002, TestSize.Level1)
{
    struct AudioPort port = {};
    struct AudioPortCapability capability = {};
    EXPECT_NE(HDF_SUCCESS, adapter_->GetPortCapability(nullptr, &port, &capability));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPortCapabilityInvalid001, TestSize.Level1)
{
    struct AudioPortCapability capability = {};
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->GetPortCapability(adapter_, nullptr, &capability));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPortCapabilityInvalid002, TestSize.Level1)
{
    struct AudioPort port = {};
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->GetPortCapability(adapter_, &port, nullptr));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPortCapabilityInvalid003, TestSize.Level0)
{
    struct AudioPort port = {};
    struct AudioPortCapability capability = {};
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = const_cast<char*>("primary");
    int32_t ret = adapter_->GetPortCapability(adapter_, &port, &capability);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPortCapabilityIsvalid001, TestSize.Level1)
{
    struct AudioPort port = adapterDescs_[0].ports[0];
    struct AudioPortCapability capability = {};
    int32_t ret = adapter_->GetPortCapability(adapter_, &port, &capability);
    ASSERT_TRUE(ret == HDF_SUCCESS);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetPassthroughModeNull001, TestSize.Level1)
{
    enum AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    EXPECT_NE(HDF_SUCCESS, adapter_->SetPassthroughMode(nullptr, nullptr, mode));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetPassthroughModeNull002, TestSize.Level1)
{
    struct AudioPort port = {};
    enum AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    EXPECT_NE(HDF_SUCCESS, adapter_->SetPassthroughMode(nullptr, &port, mode));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetPassthroughModeInvalid001, TestSize.Level1)
{
    enum AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->SetPassthroughMode(adapter_, nullptr, mode));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetPassthroughModeIsvalid001, TestSize.Level0)
{
    struct AudioPort port = {};
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = const_cast<char*>("primary");
    enum AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    int32_t ret = adapter_->SetPassthroughMode(adapter_, &port, mode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPassthroughModeNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->GetPassthroughMode(nullptr, nullptr, nullptr));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPassthroughModeNull002, TestSize.Level1)
{
    struct AudioPort port = {};
    enum AudioPortPassthroughMode mode;
    EXPECT_NE(HDF_SUCCESS, adapter_->GetPassthroughMode(nullptr, &port, &mode));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPassthroughModeInvalid001, TestSize.Level1)
{
    enum AudioPortPassthroughMode mode;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->GetPassthroughMode(adapter_, nullptr, &mode));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetPassthroughModeIsvalid001, TestSize.Level0)
{
    struct AudioPort port = {};
    port.dir = PORT_OUT;
    port.portId = 0;
    port.portName = const_cast<char*>("primary");
    enum AudioPortPassthroughMode mode;
    int32_t ret = adapter_->GetPassthroughMode(adapter_, &port, &mode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetDeviceStatusNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->GetDeviceStatus(nullptr, nullptr));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetDeviceStatusNull002, TestSize.Level1)
{
    struct AudioDeviceStatus status = {};
    EXPECT_NE(HDF_SUCCESS, adapter_->GetDeviceStatus(nullptr, &status));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetDeviceStatusInvalid001, TestSize.Level0)
{
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, adapter_->GetDeviceStatus(adapter_, nullptr));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetDeviceStatusIsvalid001, TestSize.Level0)
{
    struct AudioDeviceStatus status = {};
    EXPECT_EQ(HDF_SUCCESS, adapter_->GetDeviceStatus(adapter_, &status));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetMicMuteNull001, TestSize.Level1)
{
    bool mute = false;
    EXPECT_NE(HDF_SUCCESS, adapter_->SetMicMute(nullptr, mute));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetMicMuteIsvalid001, TestSize.Level0)
{
    bool mute = false;
    int32_t ret = adapter_->SetMicMute(adapter_, mute);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetMicMuteNull001, TestSize.Level1)
{
    EXPECT_NE(HDF_SUCCESS, adapter_->GetMicMute(nullptr, nullptr));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetMicMuteNull002, TestSize.Level1)
{
    bool mute = false;
    EXPECT_NE(HDF_SUCCESS, adapter_->GetMicMute(nullptr, &mute));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetMicMuteIsvalid001, TestSize.Level0)
{
    bool mute = false;
    int32_t ret = adapter_->GetMicMute(adapter_, &mute);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetVoiceVolumeNull001, TestSize.Level1)
{
    float volume = 0;
    EXPECT_NE(HDF_SUCCESS, adapter_->SetVoiceVolume(nullptr, volume));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetVoiceVolumeIsvalid001, TestSize.Level0)
{
    float volume = 0;
    int32_t ret = adapter_->SetVoiceVolume(adapter_, volume);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetExtraParamsNull001, TestSize.Level1)
{
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    EXPECT_NE(HDF_SUCCESS, adapter_->SetExtraParams(nullptr, key, nullptr, nullptr));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetExtraParamsNull002, TestSize.Level1)
{
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    char condition[AUDIO_ADAPTER_BUF_TEST];
    char value[AUDIO_ADAPTER_BUF_TEST];
    EXPECT_NE(HDF_SUCCESS, adapter_->SetExtraParams(nullptr, key, condition, value));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterSetExtraParamsIsvalid001, TestSize.Level0)
{
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_LOWPOWER;
    char condition[AUDIO_ADAPTER_BUF_TEST];
    const char *value = "sup_sampling_rates=4800;sup_channels=1;sup_formats=2;";
    int32_t ret = adapter_->SetExtraParams(adapter_, key, condition, value);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetExtraParamsNull001, TestSize.Level1)
{
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    uint32_t valueLen = AUDIO_ADAPTER_BUF_TEST;
    EXPECT_NE(HDF_SUCCESS, adapter_->GetExtraParams(nullptr, key, nullptr, nullptr, valueLen));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetExtraParamsNull002, TestSize.Level1)
{
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    char condition[AUDIO_ADAPTER_BUF_TEST];
    char value[AUDIO_ADAPTER_BUF_TEST];
    uint32_t valueLen = AUDIO_ADAPTER_BUF_TEST;
    EXPECT_NE(HDF_SUCCESS, adapter_->GetExtraParams(nullptr, key, condition, value, valueLen));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetExtraParamsIsvalid001, TestSize.Level1)
{
    enum AudioExtParamKey key = AUDIO_EXT_PARAM_KEY_NONE;
    char condition[AUDIO_ADAPTER_BUF_TEST];
    char value[AUDIO_ADAPTER_BUF_TEST] = "sup_sampling_rates=4800;sup_channels=1;sup_formats=2;";
    uint32_t valueLen = AUDIO_ADAPTER_BUF_TEST;

    int32_t ret = adapter_->GetExtraParams(adapter_, key, condition, value, valueLen);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_FAILURE);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterUpdateAudioRouteNull001, TestSize.Level1)
{
    struct AudioRoute route = {};
    int32_t routeHandle = 0;
    EXPECT_NE(HDF_SUCCESS, adapter_->UpdateAudioRoute(nullptr, &route, &routeHandle));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterUpdateAudioRouteIsvalid001, TestSize.Level1)
{
    struct AudioRoute route = {};
    int32_t routeHandle = 0;
    int32_t ret = adapter_->UpdateAudioRoute(adapter_, &route, &routeHandle);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_FAILURE);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterReleaseAudioRouteNull001, TestSize.Level1)
{
    int32_t routeHandle = 0;
    EXPECT_NE(HDF_SUCCESS, adapter_->ReleaseAudioRoute(nullptr, routeHandle));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterReleaseAudioRouteIsvalid001, TestSize.Level0)
{
    int32_t routeHandle = 0;
    int32_t ret = adapter_->ReleaseAudioRoute(adapter_, routeHandle);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_FAILURE);
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetVersionNull001, TestSize.Level1)
{
    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    EXPECT_NE(HDF_SUCCESS, adapter_->GetVersion(nullptr, &majorVer, &minorVer));
}

HWTEST_F(HdfAudioUtAdapterTest, HdfAudioAdapterGetVersionIsvalid001, TestSize.Level0)
{
    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    int32_t ret = adapter_->GetVersion(adapter_, &majorVer, &minorVer);
    ASSERT_TRUE(ret == HDF_ERR_NOT_SUPPORT || ret == HDF_SUCCESS);
}
}
