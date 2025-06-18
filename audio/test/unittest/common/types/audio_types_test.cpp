/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "v5_0/audio_types.h"

using namespace std;
using namespace testing::ext;

namespace {
class HdfAudioUtTypesTest : public testing::Test {
public:
    virtual void SetUp();
    virtual void TearDown();
};

void HdfAudioUtTypesTest::SetUp()
{
}

void HdfAudioUtTypesTest::TearDown()
{
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioPortDirection001, TestSize.Level0)
{
    EXPECT_EQ(PORT_OUT, (AudioPortDirection)(1));
    EXPECT_EQ(PORT_IN, (AudioPortDirection)(2));
    EXPECT_EQ(PORT_OUT_IN, (AudioPortDirection)(3));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioPortPin001, TestSize.Level0)
{
    EXPECT_EQ(PIN_NONE, (AudioPortPin)(0));
    EXPECT_EQ(PIN_OUT_SPEAKER, (AudioPortPin)(1 << 0));
    EXPECT_EQ(PIN_OUT_HEADSET, (AudioPortPin)(1 << 1));
    EXPECT_EQ(PIN_OUT_LINEOUT, (AudioPortPin)(1 << 2));
    EXPECT_EQ(PIN_OUT_HDMI, (AudioPortPin)(1 << 3));
    EXPECT_EQ(PIN_OUT_USB, (AudioPortPin)(1 << 4));
    EXPECT_EQ(PIN_OUT_USB_EXT, (AudioPortPin)(1 << 5));
    EXPECT_EQ(PIN_OUT_EARPIECE, (AudioPortPin)(1 << 5 | 1 << 4));
    EXPECT_EQ(PIN_OUT_BLUETOOTH_SCO, (AudioPortPin)(1 << 6));
    EXPECT_EQ(PIN_OUT_DAUDIO_DEFAULT, (AudioPortPin)(1 << 7));
    EXPECT_EQ(PIN_OUT_HEADPHONE, (AudioPortPin)(1 << 8));
    EXPECT_EQ(PIN_OUT_USB_HEADSET, (AudioPortPin)(1 << 9));
    EXPECT_EQ(PIN_OUT_BLUETOOTH_A2DP, (AudioPortPin)(1 << 10));
    EXPECT_EQ(PIN_OUT_DP, (AudioPortPin)(1 << 11));
    EXPECT_EQ(PIN_OUT_NEARLINK_SCO, (AudioPortPin)(1 << 12));
    EXPECT_EQ(PIN_OUT_NEARLINK, (AudioPortPin)(1 << 13));
    EXPECT_EQ(PIN_IN_MIC, (AudioPortPin)(1 << 27 | 1 << 0));
    EXPECT_EQ(PIN_IN_HS_MIC, (AudioPortPin)(1 << 27 | 1 << 1));
    EXPECT_EQ(PIN_IN_LINEIN, (AudioPortPin)(1 << 27 | 1 << 2));
    EXPECT_EQ(PIN_IN_USB_EXT, (AudioPortPin)(1 << 27 | 1 << 3));
    EXPECT_EQ(PIN_IN_BLUETOOTH_SCO_HEADSET, (AudioPortPin)(1 << 27 | 1 << 4));
    EXPECT_EQ(PIN_IN_DAUDIO_DEFAULT, (AudioPortPin)(1 << 27 | 1 << 5));
    EXPECT_EQ(PIN_IN_USB_HEADSET, (AudioPortPin)(1 << 27 | 1 << 6));
    EXPECT_EQ(PIN_IN_PENCIL, (AudioPortPin)(1 << 27 | 1 << 7));
    EXPECT_EQ(PIN_IN_UWB, (AudioPortPin)(1 << 27 | 1 << 8));
    EXPECT_EQ(PIN_IN_NEARLINK, (AudioPortPin)(1 << 27 | 1 << 9));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioCategory001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_IN_MEDIA, (AudioCategory)(0));
    EXPECT_EQ(AUDIO_IN_COMMUNICATION, (AudioCategory)(1));
    EXPECT_EQ(AUDIO_IN_RINGTONE, (AudioCategory)(2));
    EXPECT_EQ(AUDIO_IN_CALL, (AudioCategory)(3));
    EXPECT_EQ(AUDIO_MMAP_NOIRQ, (AudioCategory)(4));
    EXPECT_EQ(AUDIO_OFFLOAD, (AudioCategory)(5));
    EXPECT_EQ(AUDIO_MULTI_CHANNEL, (AudioCategory)(6));
    EXPECT_EQ(AUDIO_DP, (AudioCategory)(7));
    EXPECT_EQ(AUDIO_MMAP_VOIP, (AudioCategory)(8));
    EXPECT_EQ(AUDIO_IN_NAVIGATION, (AudioCategory)(9));
    EXPECT_EQ(AUDIO_DIRECT, (AudioCategory)(10));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioFormat001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_8_BIT, (AudioFormat)(1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_16_BIT, (AudioFormat)(1 << 1));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_24_BIT, (AudioFormat)(1 << 1 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_32_BIT, (AudioFormat)(1 << 2));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_FLOAT, (AudioFormat)(1 << 2 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_MP3, (AudioFormat)(1 << 24));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_MAIN, (AudioFormat)(1 << 24 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_LC, (AudioFormat)(1 << 24 | 1 << 1));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_LD, (AudioFormat)(1 << 24 | 1 << 1 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_ELD, (AudioFormat)(1 << 24 | 1 << 2));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_HE_V1, (AudioFormat)(1 << 24 | 1 << 2 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_AAC_HE_V2, (AudioFormat)(1 << 24 | 1 << 2 | 1 << 1));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_EAC3, (AudioFormat)(1 << 24 | 1 << 2 | 1 << 1 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_G711A, (AudioFormat)(1 << 25 | 1 << 0));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_G711U, (AudioFormat)(1 << 25 | 1 << 1));
    EXPECT_EQ(AUDIO_FORMAT_TYPE_G726, (AudioFormat)(1 << 25 | 1 << 1 | 1 << 0));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioSampleRatesMask001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_8000, (AudioSampleRatesMask)(1 << 0));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_12000, (AudioSampleRatesMask)(1 << 1));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_11025, (AudioSampleRatesMask)(1 << 2));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_16000, (AudioSampleRatesMask)(1 << 3));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_22050, (AudioSampleRatesMask)(1 << 4));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_24000, (AudioSampleRatesMask)(1 << 5));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_32000, (AudioSampleRatesMask)(1 << 6));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_44100, (AudioSampleRatesMask)(1 << 7));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_48000, (AudioSampleRatesMask)(1 << 8));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_64000, (AudioSampleRatesMask)(1 << 9));
    EXPECT_EQ(AUDIO_SAMPLE_RATE_MASK_96000, (AudioSampleRatesMask)(1 << 10));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioPortPassthroughMode001, TestSize.Level0)
{
    EXPECT_EQ(PORT_PASSTHROUGH_LPCM, (AudioPortPassthroughMode)(1 << 0));
    EXPECT_EQ(PORT_PASSTHROUGH_RAW, (AudioPortPassthroughMode)(1 << 1));
    EXPECT_EQ(PORT_PASSTHROUGH_HBR2LBR, (AudioPortPassthroughMode)(1 << 2));
    EXPECT_EQ(PORT_PASSTHROUGH_AUTO, (AudioPortPassthroughMode)(1 << 3));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioSampleFormat001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S8, (AudioSampleFormat)(0));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S8P, (AudioSampleFormat)(1));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U8, (AudioSampleFormat)(2));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U8P, (AudioSampleFormat)(3));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S16, (AudioSampleFormat)(4));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S16P, (AudioSampleFormat)(5));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U16, (AudioSampleFormat)(6));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U16P, (AudioSampleFormat)(7));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S24, (AudioSampleFormat)(8));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S24P, (AudioSampleFormat)(9));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U24, (AudioSampleFormat)(10));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U24P, (AudioSampleFormat)(11));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S32, (AudioSampleFormat)(12));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S32P, (AudioSampleFormat)(13));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U32, (AudioSampleFormat)(14));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U32P, (AudioSampleFormat)(15));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S64, (AudioSampleFormat)(16));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_S64P, (AudioSampleFormat)(17));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U64, (AudioSampleFormat)(18));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_U64P, (AudioSampleFormat)(19));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_F32, (AudioSampleFormat)(20));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_F32P, (AudioSampleFormat)(21));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_F64, (AudioSampleFormat)(22));
    EXPECT_EQ(AUDIO_SAMPLE_FORMAT_F64P, (AudioSampleFormat)(23));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioChannelMode001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, (AudioChannelMode)(0));
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_LEFT, (AudioChannelMode)(1));
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_RIGHT, (AudioChannelMode)(2));
    EXPECT_EQ(AUDIO_CHANNEL_EXCHANGE, (AudioChannelMode)(3));
    EXPECT_EQ(AUDIO_CHANNEL_MIX, (AudioChannelMode)(4));
    EXPECT_EQ(AUDIO_CHANNEL_LEFT_MUTE, (AudioChannelMode)(5));
    EXPECT_EQ(AUDIO_CHANNEL_RIGHT_MUTE, (AudioChannelMode)(6));
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_MUTE, (AudioChannelMode)(7));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioDrainNotifyType001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_DRAIN_NORMAL_MODE, (AudioDrainNotifyType)(0));
    EXPECT_EQ(AUDIO_DRAIN_EARLY_MODE, (AudioDrainNotifyType)(1));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioCallbackType001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_NONBLOCK_WRITE_COMPLETED, (AudioCallbackType)(0));
    EXPECT_EQ(AUDIO_DRAIN_COMPLETED, (AudioCallbackType)(1));
    EXPECT_EQ(AUDIO_FLUSH_COMPLETED, (AudioCallbackType)(2));
    EXPECT_EQ(AUDIO_RENDER_FULL, (AudioCallbackType)(3));
    EXPECT_EQ(AUDIO_ERROR_OCCUR, (AudioCallbackType)(4));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioPortRole001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_PORT_UNASSIGNED_ROLE, (AudioPortRole)(0));
    EXPECT_EQ(AUDIO_PORT_SOURCE_ROLE, (AudioPortRole)(1));
    EXPECT_EQ(AUDIO_PORT_SINK_ROLE, (AudioPortRole)(2));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioPortType001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_PORT_UNASSIGNED_TYPE, (AudioPortType)(0));
    EXPECT_EQ(AUDIO_PORT_DEVICE_TYPE, (AudioPortType)(1));
    EXPECT_EQ(AUDIO_PORT_MIX_TYPE, (AudioPortType)(2));
    EXPECT_EQ(AUDIO_PORT_SESSION_TYPE, (AudioPortType)(3));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioSessionType001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_OUTPUT_STAGE_SESSION, (AudioSessionType)(0));
    EXPECT_EQ(AUDIO_OUTPUT_MIX_SESSION, (AudioSessionType)(1));
    EXPECT_EQ(AUDIO_ALLOCATE_SESSION, (AudioSessionType)(2));
    EXPECT_EQ(AUDIO_INVALID_SESSION, (AudioSessionType)(3));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioDeviceType001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_LINEOUT, (AudioDeviceType)(1 << 0));
    EXPECT_EQ(AUDIO_HEADPHONE, (AudioDeviceType)(1 << 1));
    EXPECT_EQ(AUDIO_HEADSET, (AudioDeviceType)(1 << 2));
    EXPECT_EQ(AUDIO_USB_HEADSET, (AudioDeviceType)(1 << 3));
    EXPECT_EQ(AUDIO_USB_HEADPHONE, (AudioDeviceType)(1 << 4));
    EXPECT_EQ(AUDIO_USBA_HEADSET, (AudioDeviceType)(1 << 5));
    EXPECT_EQ(AUDIO_USBA_HEADPHONE, (AudioDeviceType)(1 << 6));
    EXPECT_EQ(AUDIO_PRIMARY_DEVICE, (AudioDeviceType)(1 << 7));
    EXPECT_EQ(AUDIO_USB_DEVICE, (AudioDeviceType)(1 << 8));
    EXPECT_EQ(AUDIO_A2DP_DEVICE, (AudioDeviceType)(1 << 9));
    EXPECT_EQ(AUDIO_HDMI_DEVICE, (AudioDeviceType)(1 << 10));
    EXPECT_EQ(AUDIO_ADAPTER_DEVICE, (AudioDeviceType)(1 << 11));
    EXPECT_EQ(AUDIO_DP_DEVICE, (AudioDeviceType)(1 << 12));
    EXPECT_EQ(AUDIO_ACCESSORY_DEVICE, (AudioDeviceType)(1 << 13));
    EXPECT_EQ(AUDIO_REMOTE_DEVICE, (AudioDeviceType)(1 << 14));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioEventType001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_DEVICE_ADD, (AudioEventType)(1));
    EXPECT_EQ(AUDIO_DEVICE_REMOVE, (AudioEventType)(2));
    EXPECT_EQ(AUDIO_LOAD_SUCCESS, (AudioEventType)(3));
    EXPECT_EQ(AUDIO_LOAD_FAILURE, (AudioEventType)(4));
    EXPECT_EQ(AUDIO_UNLOAD, (AudioEventType)(5));
    EXPECT_EQ(AUDIO_SERVICE_VALID, (AudioEventType)(7));
    EXPECT_EQ(AUDIO_SERVICE_INVALID, (AudioEventType)(8));
    EXPECT_EQ(AUDIO_CAPTURE_THRESHOLD, (AudioEventType)(9));
    EXPECT_EQ(AUDIO_EVENT_UNKNOWN, (AudioEventType)(10));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioExtParamKey001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_NONE, (AudioExtParamKey)(0));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_VOLUME, (AudioExtParamKey)(1));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_FOCUS, (AudioExtParamKey)(2));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_BUTTON, (AudioExtParamKey)(3));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_EFFECT, (AudioExtParamKey)(4));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_STATUS, (AudioExtParamKey)(5));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_USB_DEVICE, (AudioExtParamKey)(101));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_PERF_INFO, (AudioExtParamKey)(201));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_MMI, (AudioExtParamKey)(301));
    EXPECT_EQ(AUDIO_EXT_PARAM_KEY_LOWPOWER, (AudioExtParamKey)(1000));
}

HWTEST_F(HdfAudioUtTypesTest, HdfAudioTypesAudioInputType001, TestSize.Level0)
{
    EXPECT_EQ(AUDIO_INPUT_DEFAULT_TYPE, (AudioInputType)(0));
    EXPECT_EQ(AUDIO_INPUT_MIC_TYPE, (AudioInputType)(1 << 0));
    EXPECT_EQ(AUDIO_INPUT_SPEECH_WAKEUP_TYPE, (AudioInputType)(1 << 1));
    EXPECT_EQ(AUDIO_INPUT_VOICE_COMMUNICATION_TYPE, (AudioInputType)(1 << 2));
    EXPECT_EQ(AUDIO_INPUT_VOICE_RECOGNITION_TYPE, (AudioInputType)(1 << 3));
    EXPECT_EQ(AUDIO_INPUT_VOICE_UPLINK_TYPE, (AudioInputType)(1 << 4));
    EXPECT_EQ(AUDIO_INPUT_VOICE_DOWNLINK_TYPE, (AudioInputType)(1 << 5));
    EXPECT_EQ(AUDIO_INPUT_VOICE_CALL_TYPE, (AudioInputType)(1 << 6));
    EXPECT_EQ(AUDIO_INPUT_CAMCORDER_TYPE, (AudioInputType)(1 << 7));
    EXPECT_EQ(AUDIO_INPUT_EC_TYPE, (AudioInputType)(1 << 8));
    EXPECT_EQ(AUDIO_INPUT_NOISE_REDUCTION_TYPE, (AudioInputType)(1 << 9));
    EXPECT_EQ(AUDIO_INPUT_RAW_TYPE, (AudioInputType)(1 << 10));
    EXPECT_EQ(AUDIO_INPUT_LIVE_TYPE, (AudioInputType)(1 << 11));
}
}