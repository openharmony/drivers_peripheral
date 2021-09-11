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

#include "audio_adapter_test.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "audio_internal.h"

using namespace std;
using namespace testing::ext;
namespace {
const int PORTNUM = 1;
const int AUDIO_CHANNELCOUNT = 2;
const int AUDIO_PORT_ID = 2; // portId
const int AUDIO_SAMPLE_RATE_48K = 48000;
const int DEEP_BUFFER_RENDER_PERIOD_SIZE = 4096;
const int INT_32_MAX = 0x7fffffff;
const int DEFAULT_RENDER_SAMPLING_RATE = 48000;
const int DEEP_BUFFER_RENDER_PERIOD_COUNT = 8;

static int32_t InitPort(struct AudioPort &portIndex)
{
    portIndex.dir = PORT_OUT;
    portIndex.portId = 1;
    portIndex.portName = "usb";
    return HDF_SUCCESS;
}

static int32_t InitHwRender(struct AudioHwRender &hwRender,
    const struct AudioDeviceDescriptor &desc, const struct AudioSampleAttributes &attrs)
{
    hwRender.renderParam.renderMode.hwInfo.deviceDescript = desc;
    hwRender.renderParam.frameRenderMode.attrs = attrs;
    hwRender.renderParam.renderMode.ctlParam.audioGain.gainMax = 15; // gainMax 15
    hwRender.renderParam.renderMode.ctlParam.audioGain.gainMin = 0;
    hwRender.renderParam.frameRenderMode.frames = 0;
    hwRender.renderParam.frameRenderMode.time.tvNSec = 0;
    hwRender.renderParam.frameRenderMode.time.tvSec = 0;
    hwRender.renderParam.frameRenderMode.byteRate = DEFAULT_RENDER_SAMPLING_RATE;
    hwRender.renderParam.frameRenderMode.periodSize = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    hwRender.renderParam.frameRenderMode.periodCount = DEEP_BUFFER_RENDER_PERIOD_COUNT;
    hwRender.renderParam.frameRenderMode.attrs.period = attrs.period;
    hwRender.renderParam.frameRenderMode.attrs.frameSize = attrs.frameSize;
    hwRender.renderParam.frameRenderMode.attrs.startThreshold = attrs.startThreshold;
    hwRender.renderParam.frameRenderMode.attrs.stopThreshold = attrs.stopThreshold;
    hwRender.renderParam.frameRenderMode.attrs.silenceThreshold = attrs.silenceThreshold;
    hwRender.renderParam.frameRenderMode.attrs.isBigEndian = attrs.isBigEndian;
    hwRender.renderParam.frameRenderMode.attrs.isSignedData = attrs.isSignedData;
    return HDF_SUCCESS;
}

static int32_t InitHwCapture(struct AudioHwCapture &hwCapture, const struct AudioDeviceDescriptor &desc,
    const struct AudioSampleAttributes &attrs)
{
    hwCapture.captureParam.captureMode.hwInfo.deviceDescript = desc;
    hwCapture.captureParam.frameCaptureMode.attrs = attrs;
    hwCapture.captureParam.captureMode.ctlParam.audioGain.gainMax = 15; // gainMax 15
    hwCapture.captureParam.captureMode.ctlParam.audioGain.gainMin = 0;
    hwCapture.captureParam.frameCaptureMode.frames = 0;
    hwCapture.captureParam.frameCaptureMode.time.tvNSec = 0;
    hwCapture.captureParam.frameCaptureMode.time.tvSec = 0;
    hwCapture.captureParam.frameCaptureMode.byteRate = DEFAULT_RENDER_SAMPLING_RATE;
    hwCapture.captureParam.frameCaptureMode.periodSize = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    hwCapture.captureParam.frameCaptureMode.periodCount = DEEP_BUFFER_RENDER_PERIOD_COUNT;
    hwCapture.captureParam.frameCaptureMode.attrs.period = attrs.period;
    hwCapture.captureParam.frameCaptureMode.attrs.frameSize = attrs.frameSize;
    hwCapture.captureParam.frameCaptureMode.attrs.startThreshold = attrs.startThreshold;
    hwCapture.captureParam.frameCaptureMode.attrs.stopThreshold = attrs.stopThreshold;
    hwCapture.captureParam.frameCaptureMode.attrs.silenceThreshold = attrs.silenceThreshold;
    hwCapture.captureParam.frameCaptureMode.attrs.isBigEndian = attrs.isBigEndian;
    hwCapture.captureParam.frameCaptureMode.attrs.isSignedData = attrs.isSignedData;
    return HDF_SUCCESS;
}

static int32_t InitAttrs(struct AudioSampleAttributes &attrs)
{
    /* Initialization of audio parameters for playback */
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.channelCount = AUDIO_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs.interleaved = 0;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    /* PERIOD_SIZE * 16 * attrs.channelCount / 8 */
    attrs.frameSize = 16 * attrs.channelCount / 8;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    /* DEEP_BUFFER_RENDER_PERIOD_SIZE / (16 * attrs->channelCount / 8) */
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (16 * attrs.channelCount / 8);
    attrs.stopThreshold = INT_32_MAX;
    attrs.silenceThreshold = 0;
    return HDF_SUCCESS;
}

static int32_t InitDevDesc(struct AudioDeviceDescriptor &devDesc)
{
    /* Initialization of audio parameters for playback */
    devDesc.portId = 0;
    devDesc.pins = PIN_OUT_SPEAKER;
    devDesc.desc = NULL;
    return HDF_SUCCESS;
}

static int32_t InitAttrsCapture(struct AudioSampleAttributes &attrs)
{
    /* Initialization of audio parameters for playback */
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.channelCount = AUDIO_CHANNELCOUNT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs.interleaved = 0;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
     /* PERIOD_SIZE * 16 * attrs.channelCount / 8,Byte */
    attrs.frameSize = 16 * attrs.channelCount / 8;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    /* DEEP_BUFFER_RENDER_PERIOD_SIZE / (16 * attrs.channelCount / 8) */
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (16 * attrs.channelCount / 8);
    attrs.stopThreshold = INT_32_MAX;
    /* 16 * 1024 */
    attrs.silenceThreshold = 16 * 1024;
    return HDF_SUCCESS;
}

static int32_t InitDevDescCapture(struct AudioDeviceDescriptor &devDesc)
{
    /* Initialization of audio parameters for playback */
    devDesc.portId = 0;
    devDesc.pins = PIN_IN_MIC;
    devDesc.desc = NULL;
    return HDF_SUCCESS;
}

class AudioAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void AudioAdapterTest::SetUpTestCase()
{
}

void AudioAdapterTest::TearDownTestCase()
{
}

HWTEST_F(AudioAdapterTest, GetAudioRenderFuncWhenHwRenderIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = nullptr;
    int32_t ret = GetAudioRenderFunc(hwRender);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, GetAudioRenderFuncWhenParamIsVaild, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    int32_t ret = GetAudioRenderFunc(hwRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioAdapterTest, CheckParaDescWhenDescIsNull, TestSize.Level0)
{
    const struct AudioDeviceDescriptor *desc = nullptr;
    const char *type = "Render";
    int32_t ret = CheckParaDesc(desc, type);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, CheckParaDescWhenTypeIsNull, TestSize.Level0)
{
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const char *type = nullptr;
    int32_t ret = CheckParaDesc(desc, type);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(desc);
    desc = nullptr;
}

HWTEST_F(AudioAdapterTest, CheckParaDescWhenPortIdLessThanZero, TestSize.Level0)
{
    struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const char *type = "Render";
    desc->portId = AUDIO_HAL_ERR_NOT_SUPPORT;
    int32_t ret = CheckParaDesc((const struct AudioDeviceDescriptor *)desc, type);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    delete(desc);
    desc = nullptr;
}

HWTEST_F(AudioAdapterTest, CheckParaDescWhenPinsIsPinNone, TestSize.Level0)
{
    struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const char *type = "Render";
    desc->pins = PIN_NONE;
    int32_t ret = CheckParaDesc((const struct AudioDeviceDescriptor *)desc, type);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    delete(desc);
    desc = nullptr;
}

HWTEST_F(AudioAdapterTest, CheckParaDescWhenTypeIsError, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDesc(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    const char *type = "123";
    ret = CheckParaDesc(&desc, type);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, CheckParaDescWhenParamIsVaild, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDesc(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    const char *type = "Render";
    ret = CheckParaDesc(&desc, type);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAdapterTest, CheckParaAttrWhenAttrsIsNull, TestSize.Level0)
{
    const struct AudioSampleAttributes *attrs = nullptr;
    int32_t ret = CheckParaAttr(attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, CheckParaAttrWhenPeriodLessThanZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.period = AUDIO_HAL_ERR_NOT_SUPPORT;
    ret = CheckParaAttr(&attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, CheckParaAttrWhenTypeIsNotSupport, TestSize.Level0)
{
    int32_t ret;
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.type = (enum AudioCategory)AUDIO_HAL_ERR_NOT_SUPPORT;
    ret = CheckParaAttr(&attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, CheckParaAttrWhenFormatIsNotSupport, TestSize.Level0)
{
    int32_t ret;
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.format = AUDIO_FORMAT_G726;
    ret = CheckParaAttr(&attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, CheckParaAttrWhenParamIsVaild, TestSize.Level0)
{
    int32_t ret;
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CheckParaAttr(&attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAdapterTest, AttrFormatToBitWhenAttrsIsNull, TestSize.Level0)
{
    const struct AudioSampleAttributes *attrs = nullptr;
    int32_t formatTmp = -1;
    int32_t *format = &formatTmp;
    int32_t ret = AttrFormatToBit(attrs, format);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, AttrFormatToBitWhenFormatIsNull, TestSize.Level0)
{
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t *format = nullptr;
    int32_t ret = AttrFormatToBit(attrs, format);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AttrFormatToBitWhenAttrsIsNotSupport, TestSize.Level0)
{
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t formatTmp = -1;
    int32_t *format = &formatTmp;
    int32_t ret = AttrFormatToBit(attrs, format);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AttrFormatToBitWhenParamIsVaild, TestSize.Level0)
{
    int32_t ret;
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t formatTmp = -1;
    int32_t *format = &formatTmp;
    ret = AttrFormatToBit(&attrs, format);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAdapterTest, InitHwRenderParamWhenHwRenderIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = nullptr;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t ret = InitHwRenderParam(hwRender, desc, attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, InitHwRenderParamWhenDescIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    const struct AudioDeviceDescriptor *desc = nullptr;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t ret = InitHwRenderParam(hwRender, desc, attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwRender);
    hwRender = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, InitHwRenderParamWhenAttrsIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = nullptr;
    int32_t ret = InitHwRenderParam(hwRender, desc, attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwRender);
    hwRender = nullptr;
    delete(desc);
    desc = nullptr;
}

HWTEST_F(AudioAdapterTest, InitHwRenderParamWhenPortIdLessThanZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDesc(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    desc.portId = AUDIO_HAL_ERR_NOT_SUPPORT;
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioHwRender hwRender;
    ret = InitHwRender(hwRender, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwRenderParam(&hwRender, &desc, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, InitHwRenderParamWhenPeriodLessThanZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDesc(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.period = AUDIO_HAL_ERR_NOT_SUPPORT;
    struct AudioHwRender hwRender;
    ret = InitHwRender(hwRender, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwRenderParam(&hwRender, &desc, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, InitHwRenderParamWhenFormatIsNotSupport, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDesc(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.format = AUDIO_FORMAT_AAC_MAIN;
    struct AudioHwRender hwRender;
    ret = InitHwRender(hwRender, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwRenderParam(&hwRender, &desc, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, InitHwRenderParamWhenChannelCountIsZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDesc(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.channelCount = 0;
    struct AudioHwRender hwRender;
    ret = InitHwRender(hwRender, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwRenderParam(&hwRender, &desc, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, InitHwRenderParamWhenParamIsVaild, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDesc(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioHwRender hwRender;
    ret = InitHwRender(hwRender, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwRenderParam(&hwRender, &desc, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAdapterTest, InitForGetPortCapabilityWhenCapabilityIndexIsNull, TestSize.Level0)
{
    int32_t ret;
    struct AudioPort portIndex;
    ret = InitPort(portIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioPortCapability *capabilityIndex = nullptr;
    ret = InitForGetPortCapability(portIndex, capabilityIndex);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, InitForGetPortCapabilityWhenDirIsPortIn, TestSize.Level0)
{
    int32_t ret;
    struct AudioPort portIndex;
    ret = InitPort(portIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    portIndex.dir = PORT_IN;
    struct AudioPortCapability *capabilityIndex = new AudioPortCapability;
    ret = InitForGetPortCapability(portIndex, capabilityIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(capabilityIndex);
    capabilityIndex = nullptr;
}

HWTEST_F(AudioAdapterTest, InitForGetPortCapabilityWhenPortIdIsZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioPort portIndex;
    ret = InitPort(portIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    portIndex.portId = 0;
    struct AudioPortCapability *capabilityIndex = new AudioPortCapability;
    ret = InitForGetPortCapability(portIndex, capabilityIndex);
    if (HDF_SUCCESS != ret) {
        delete(capabilityIndex);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    EXPECT_NE(capabilityIndex->subPorts, nullptr);
    if (capabilityIndex->subPorts != nullptr) {
        EXPECT_EQ(capabilityIndex->subPorts->portId, portIndex.portId);
        EXPECT_EQ(capabilityIndex->subPorts->desc, portIndex.portName);
        EXPECT_EQ(capabilityIndex->subPorts->mask, PORT_PASSTHROUGH_LPCM);
    }
    if (capabilityIndex->subPorts != nullptr) {
        free(capabilityIndex->subPorts);
        capabilityIndex->subPorts = nullptr;
    }
    delete(capabilityIndex);
    capabilityIndex = nullptr;
}

HWTEST_F(AudioAdapterTest, InitForGetPortCapabilityWhenPortIdIsOne, TestSize.Level0)
{
    int32_t ret;
    struct AudioPort portIndex;
    ret = InitPort(portIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    portIndex.portId = 1;
    struct AudioPortCapability *capabilityIndex = new AudioPortCapability;
    ret = InitForGetPortCapability(portIndex, capabilityIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(capabilityIndex);
    capabilityIndex = nullptr;
}

HWTEST_F(AudioAdapterTest, InitForGetPortCapabilityWhenPortIdIsHdmiPortId, TestSize.Level0)
{
    int32_t ret;
    struct AudioPort portIndex;
    ret = InitPort(portIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    portIndex.portId = HDMI_PORT_ID;
    struct AudioPortCapability *capabilityIndex = new AudioPortCapability;
    ret = InitForGetPortCapability(portIndex, capabilityIndex);
    if (HDF_SUCCESS != ret) {
        delete(capabilityIndex);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    EXPECT_NE(capabilityIndex->subPorts, nullptr);
    if (capabilityIndex->subPorts != nullptr) {
        EXPECT_EQ(capabilityIndex->subPorts->portId, portIndex.portId);
        EXPECT_EQ(capabilityIndex->subPorts->desc, portIndex.portName);
        EXPECT_EQ(capabilityIndex->subPorts->mask, PORT_PASSTHROUGH_LPCM);
    }
    if (capabilityIndex->subPorts != nullptr) {
        free(capabilityIndex->subPorts);
        capabilityIndex->subPorts = nullptr;
    }
    delete(capabilityIndex);
    capabilityIndex = nullptr;
}

HWTEST_F(AudioAdapterTest, InitForGetPortCapabilityWhenPortIdIsTwo, TestSize.Level0)
{
    int32_t ret;
    struct AudioPort portIndex;
    ret = InitPort(portIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    portIndex.dir = PORT_OUT;
    portIndex.portId = AUDIO_PORT_ID;
    struct AudioPortCapability *capabilityIndex = new AudioPortCapability;
    ret = InitForGetPortCapability(portIndex, capabilityIndex);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(capabilityIndex);
    capabilityIndex = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterReleaseCapSubPortsWhenPortCapabilitysIsNull, TestSize.Level0)
{
    const struct AudioPortAndCapability *portCapabilitys = nullptr;
    int32_t num = PORTNUM;
    AudioAdapterReleaseCapSubPorts(portCapabilitys, num);
    EXPECT_EQ(nullptr, portCapabilitys);
}

HWTEST_F(AudioAdapterTest, AudioAdapterReleaseCapSubPortsWhenParamIsVaild, TestSize.Level0)
{
    struct AudioPortAndCapability *portCapabilitys = new AudioPortAndCapability;
    struct AudioSubPortCapability *subPorts =
        (struct AudioSubPortCapability *)calloc(1, sizeof(struct AudioSubPortCapability));
    portCapabilitys->capability.subPorts = subPorts;
    int32_t num = PORTNUM;
    AudioAdapterReleaseCapSubPorts((const struct AudioPortAndCapability *)portCapabilitys, num);
    EXPECT_EQ(nullptr, portCapabilitys->capability.subPorts);
    EXPECT_NE(nullptr, portCapabilitys);
    delete(portCapabilitys);
    portCapabilitys = nullptr;
    subPorts = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterInitAllPortsWhenAdapterIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = nullptr;
    int32_t ret = AudioAdapterInitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioAdapterTest, AudioAdapterInitAllPortsWhenPortCapabilitysIsNotNull, TestSize.Level0)
{
    struct AudioHwAdapter *hwAdapter = new AudioHwAdapter;
    struct AudioPortAndCapability *portCapabilitys = new AudioPortAndCapability;
    EXPECT_NE(nullptr, portCapabilitys);
    hwAdapter->portCapabilitys = portCapabilitys;
    int32_t ret = AudioAdapterInitAllPorts((struct AudioAdapter *)hwAdapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    delete(hwAdapter);
    hwAdapter = nullptr;
    delete(portCapabilitys);
    portCapabilitys = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterInitAllPortsWhenPortsIsNull, TestSize.Level0)
{
    struct AudioHwAdapter *hwAdapter = new AudioHwAdapter;
    hwAdapter->portCapabilitys = nullptr;
    hwAdapter->adapterDescriptor.ports = nullptr;
    int32_t ret = AudioAdapterInitAllPorts((struct AudioAdapter *)hwAdapter);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    delete(hwAdapter);
    hwAdapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterInitAllPortsWhenPortNumIsZero, TestSize.Level0)
{
    struct AudioHwAdapter *hwAdapter = new AudioHwAdapter;
    hwAdapter->portCapabilitys = nullptr;
    hwAdapter->adapterDescriptor.portNum = 0;
    struct AudioPort *ports = new AudioPort;
    hwAdapter->adapterDescriptor.ports = ports;
    int32_t ret = AudioAdapterInitAllPorts((struct AudioAdapter *)hwAdapter);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    delete(hwAdapter);
    hwAdapter = nullptr;
    delete(ports);
    ports = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioReleaseRenderHandleWhenHwRenderIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = nullptr;
    AudioReleaseRenderHandle(hwRender);
    EXPECT_EQ(nullptr, hwRender);
}

HWTEST_F(AudioAdapterTest, AudioSetAcodeModeRenderWhenHwRenderIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = nullptr;
    InterfaceLibModeRenderSo *pInterfaceLibModeRender = new InterfaceLibModeRenderSo;
    int32_t ret = AudioSetAcodeModeRender(hwRender, pInterfaceLibModeRender);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(pInterfaceLibModeRender);
    pInterfaceLibModeRender = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioSetAcodeModeRenderWhenpInterfaceLibModeRenderIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    InterfaceLibModeRenderSo *pInterfaceLibModeRender = nullptr;
    int32_t ret = AudioSetAcodeModeRender(hwRender, pInterfaceLibModeRender);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwRender);
    hwRender = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioSetAcodeModeRenderWhenpDevCtlHandleIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    InterfaceLibModeRenderSo *pInterfaceLibModeRender = new InterfaceLibModeRenderSo;
    hwRender->devCtlHandle = nullptr;
    int32_t ret = AudioSetAcodeModeRender(hwRender, pInterfaceLibModeRender);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwRender);
    hwRender = nullptr;
    delete(pInterfaceLibModeRender);
    pInterfaceLibModeRender = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderPreWhenHwRenderIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = nullptr;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioHwAdapter *hwadapter = new AudioHwAdapter;
    int32_t ret = AudioAdapterCreateRenderPre(hwRender, desc, attrs, hwadapter);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
    delete(hwadapter);
    hwadapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderPreWhenDescIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    const struct AudioDeviceDescriptor *desc = nullptr;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioHwAdapter *hwadapter = new AudioHwAdapter;
    int32_t ret = AudioAdapterCreateRenderPre(hwRender, desc, attrs, hwadapter);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwRender);
    hwRender = nullptr;
    delete(attrs);
    attrs = nullptr;
    delete(hwadapter);
    hwadapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderPreWhenAttrsIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = nullptr;
    struct AudioHwAdapter *hwadapter = new AudioHwAdapter;
    int32_t ret = AudioAdapterCreateRenderPre(hwRender, desc, attrs, hwadapter);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwRender);
    hwRender = nullptr;
    delete(desc);
    desc = nullptr;
    delete(hwadapter);
    hwadapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderPreWhenAdapterIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = new AudioHwRender;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioHwAdapter *hwadapter = nullptr;
    int32_t ret = AudioAdapterCreateRenderPre(hwRender, desc, attrs, hwadapter);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwRender);
    hwRender = nullptr;
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderPreWhenPortIdLessThanZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioManager *managerFuncs = GetAudioManagerFuncs();
    int32_t size = 0;
    struct AudioAdapterDescriptor *descs;
    ret = managerFuncs->GetAllAdapters(managerFuncs, &descs, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);

    struct AudioPort *ports = new AudioPort;
    struct AudioAdapterDescriptor *desc = new AudioAdapterDescriptor;
    desc->adapterName = "usb";
    desc->ports = ports;
    struct AudioAdapter *adapter;
    ret = managerFuncs->LoadAdapter(managerFuncs, desc, &adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);

    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    EXPECT_NE(hwRender, nullptr);
    struct AudioDeviceDescriptor devDesc;
    ret = InitDevDesc(devDesc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    devDesc.portId = AUDIO_HAL_ERR_NOT_SUPPORT;
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioAdapterCreateRenderPre(hwRender, &devDesc, &attrs, (struct AudioHwAdapter *)adapter);
    EXPECT_EQ(HDF_FAILURE, ret);

    delete(ports);
    ports = nullptr;
    delete(desc);
    desc = nullptr;
    free(hwRender);
    hwRender = nullptr;
    managerFuncs->UnloadAdapter(managerFuncs, adapter);
    adapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderPreWhenAdapterNameIsNull, TestSize.Level0)
{
    int32_t ret;
    struct AudioManager *managerFuncs = GetAudioManagerFuncs();
    int32_t size = 0;
    struct AudioAdapterDescriptor *descs;
    ret = managerFuncs->GetAllAdapters(managerFuncs, &descs, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);

    struct AudioPort *ports = new AudioPort;
    struct AudioAdapterDescriptor *desc = new AudioAdapterDescriptor;
    desc->adapterName = "usb";
    desc->ports = ports;
    struct AudioAdapter *adapter;
    ret = managerFuncs->LoadAdapter(managerFuncs, desc, &adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);

    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    EXPECT_NE(hwRender, nullptr);
    struct AudioDeviceDescriptor devDesc;
    ret = InitDevDesc(devDesc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioHwAdapter *hwAdapter = reinterpret_cast<AudioHwAdapter *>(adapter);
    hwAdapter->adapterDescriptor.adapterName = nullptr;
    ret = AudioAdapterCreateRenderPre(hwRender, &devDesc, &attrs, hwAdapter);
    EXPECT_EQ(HDF_FAILURE, ret);

    delete(ports);
    ports = nullptr;
    delete(desc);
    desc = nullptr;
    free(hwRender);
    hwRender = nullptr;
    managerFuncs->UnloadAdapter(managerFuncs, adapter);
    adapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderPreWhenParamIsVaild, TestSize.Level0)
{
    int32_t ret;
    struct AudioManager *managerFuncs = GetAudioManagerFuncs();
    int32_t size = 0;
    struct AudioAdapterDescriptor *descs;
    ret = managerFuncs->GetAllAdapters(managerFuncs, &descs, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);

    struct AudioPort *ports = new AudioPort;
    struct AudioAdapterDescriptor *desc = new AudioAdapterDescriptor;
    desc->adapterName = "usb";
    desc->ports = ports;
    struct AudioAdapter *adapter;
    ret = managerFuncs->LoadAdapter(managerFuncs, desc, &adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);

    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    EXPECT_NE(hwRender, nullptr);
    struct AudioDeviceDescriptor devDesc;
    ret = InitDevDesc(devDesc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioAdapterCreateRenderPre(hwRender, &devDesc, &attrs, (struct AudioHwAdapter *)adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);

    delete(ports);
    ports = nullptr;
    delete(desc);
    desc = nullptr;
    free(hwRender);
    hwRender = nullptr;
    managerFuncs->UnloadAdapter(managerFuncs, adapter);
    adapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterBindServiceRenderWhenHwRenderIsNull, TestSize.Level0)
{
    struct AudioHwRender *hwRender = nullptr;
    int32_t ret = AudioAdapterBindServiceRender(hwRender);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderWhenAdapterIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = nullptr;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioRender *render;
    int32_t ret = AudioAdapterCreateRender(adapter, desc, attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderWhenDescIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = new AudioAdapter;
    const struct AudioDeviceDescriptor *desc = nullptr;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioRender *render;
    int32_t ret = AudioAdapterCreateRender(adapter, desc, attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(adapter);
    adapter = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderWhenAttrsIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = new AudioAdapter;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = nullptr;
    struct AudioRender *render;
    int32_t ret = AudioAdapterCreateRender(adapter, desc, attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(adapter);
    adapter = nullptr;
    delete(desc);
    desc = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateRenderWhenRenderIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = new AudioAdapter;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioRender **render = nullptr;
    int32_t ret = AudioAdapterCreateRender(adapter, desc, attrs, render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(adapter);
    adapter = nullptr;
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterDestroyRenderWhenAdapterIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = new AudioRender;
    int32_t ret = AudioAdapterDestroyRender(adapter, render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(render);
    render = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterDestroyRenderWhenRenderIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = new AudioAdapter;
    struct AudioRender *render = nullptr;
    int32_t ret = AudioAdapterDestroyRender(adapter, render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(adapter);
    adapter = nullptr;
}

HWTEST_F(AudioAdapterTest, GetAudioCaptureFuncWhenHwCaptureIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = nullptr;
    int32_t ret = GetAudioCaptureFunc(hwCapture);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, GetAudioCaptureFuncWhenParamIsVaild, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = new AudioHwCapture;
    int32_t ret = GetAudioCaptureFunc(hwCapture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(hwCapture);
    hwCapture = nullptr;
}

HWTEST_F(AudioAdapterTest, InitHwCaptureParamWhenHwCaptureIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = nullptr;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t ret = InitHwCaptureParam(hwCapture, desc, attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, InitHwCaptureParamWhenDescIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = new AudioHwCapture;
    const struct AudioDeviceDescriptor *desc = nullptr;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    int32_t ret = InitHwCaptureParam(hwCapture, desc, attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwCapture);
    hwCapture = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, InitHwCaptureParamWhenAttrsIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = new AudioHwCapture;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = nullptr;
    int32_t ret = InitHwCaptureParam(hwCapture, desc, attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwCapture);
    hwCapture = nullptr;
    delete(desc);
    desc = nullptr;
}

HWTEST_F(AudioAdapterTest, InitHwCaptureParamWhenPortIdLessThanZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDescCapture(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    desc.portId = AUDIO_HAL_ERR_NOT_SUPPORT;
    struct AudioSampleAttributes attrs;
    ret = InitAttrsCapture(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioHwCapture hwCapture;
    ret = InitHwCapture(hwCapture, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwCaptureParam(&hwCapture, &desc, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, InitHwCaptureParamWhenPeriodLessThanZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDescCapture(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrsCapture(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.period = AUDIO_HAL_ERR_NOT_SUPPORT;
    struct AudioHwCapture hwCapture;
    ret = InitHwCapture(hwCapture, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwCaptureParam(&hwCapture, &desc, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, InitHwCaptureParamWhenFormatIsNotSupport, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDescCapture(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrsCapture(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.format = AUDIO_FORMAT_AAC_MAIN;
    struct AudioHwCapture hwCapture;
    ret = InitHwCapture(hwCapture, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwCaptureParam(&hwCapture, &desc, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

HWTEST_F(AudioAdapterTest, InitHwCaptureParamWhenChannelCountIsZero, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDescCapture(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrsCapture(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    attrs.channelCount = 0;
    struct AudioHwCapture hwCapture;
    ret = InitHwCapture(hwCapture, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwCaptureParam(&hwCapture, &desc, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, InitHwCaptureParamWhenParamIsVaild, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor desc;
    ret = InitDevDescCapture(desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrs;
    ret = InitAttrsCapture(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioHwCapture hwCapture;
    ret = InitHwCapture(hwCapture, desc, attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitHwCaptureParam(&hwCapture, &desc, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAdapterTest, AudioReleaseCaptureHandleWhenHwRenderIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = nullptr;
    AudioReleaseCaptureHandle(hwCapture);
    EXPECT_EQ(nullptr, hwCapture);
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateCapturePreWhenHwRenderIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = nullptr;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioHwAdapter *hwadapter = new AudioHwAdapter;
    int32_t ret = AudioAdapterCreateCapturePre(hwCapture, desc, attrs, hwadapter);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
    delete(hwadapter);
    hwadapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateCapturePreWhenDescIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = new AudioHwCapture;
    const struct AudioDeviceDescriptor *desc = nullptr;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioHwAdapter *hwadapter = new AudioHwAdapter;
    int32_t ret = AudioAdapterCreateCapturePre(hwCapture, desc, attrs, hwadapter);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwCapture);
    hwCapture = nullptr;
    delete(attrs);
    attrs = nullptr;
    delete(hwadapter);
    hwadapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateCapturePreWhenAttrsIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = new AudioHwCapture;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = nullptr;
    struct AudioHwAdapter *hwadapter = new AudioHwAdapter;
    int32_t ret = AudioAdapterCreateCapturePre(hwCapture, desc, attrs, hwadapter);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwCapture);
    hwCapture = nullptr;
    delete(desc);
    desc = nullptr;
    delete(hwadapter);
    hwadapter = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateCapturePreWhenAdapterIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = new AudioHwCapture;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioHwAdapter *hwadapter = nullptr;
    int32_t ret = AudioAdapterCreateCapturePre(hwCapture, desc, attrs, hwadapter);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(hwCapture);
    hwCapture = nullptr;
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterInterfaceLibModeCaptureWhenHwCaptureIsNull, TestSize.Level0)
{
    struct AudioHwCapture *hwCapture = nullptr;
    int32_t ret = AudioAdapterInterfaceLibModeCapture(hwCapture);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateCaptureWhenAdapterIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = nullptr;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioCapture *capture;
    int32_t ret = AudioAdapterCreateCapture(adapter, desc, attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateCaptureWhenDescIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = new AudioAdapter;
    const struct AudioDeviceDescriptor *desc = nullptr;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioCapture *capture;
    int32_t ret = AudioAdapterCreateCapture(adapter, desc, attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(adapter);
    adapter = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateCaptureWhenAttrsIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = new AudioAdapter;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = nullptr;
    struct AudioCapture *capture;
    int32_t ret = AudioAdapterCreateCapture(adapter, desc, attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(adapter);
    adapter = nullptr;
    delete(desc);
    desc = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterCreateCaptureWhenCaptureIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = new AudioAdapter;
    const struct AudioDeviceDescriptor *desc = new AudioDeviceDescriptor;
    const struct AudioSampleAttributes *attrs = new AudioSampleAttributes;
    struct AudioCapture **capture = nullptr;
    int32_t ret = AudioAdapterCreateCapture(adapter, desc, attrs, capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(adapter);
    adapter = nullptr;
    delete(desc);
    desc = nullptr;
    delete(attrs);
    attrs = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterDestroyCaptureWhenAdapterIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = new AudioCapture;
    int32_t ret = AudioAdapterDestroyCapture(adapter, capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(capture);
    capture = nullptr;
}

HWTEST_F(AudioAdapterTest, AudioAdapterDestroyCaptureWhenCaptureIsNull, TestSize.Level0)
{
    struct AudioAdapter *adapter = new AudioAdapter;
    struct AudioCapture *capture = nullptr;
    int32_t ret = AudioAdapterDestroyCapture(adapter, capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    delete(adapter);
    adapter = nullptr;
}
}
