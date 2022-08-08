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
#include "audio_internal.h"
#include "alsa_lib_render.h"

using namespace std;
using namespace testing::ext;
namespace {
constexpr int32_t channel = 2;
constexpr int32_t sampleRate = 48000;
constexpr int32_t volMin = 0;
constexpr int32_t volMax = 100;
constexpr int32_t frameData = 16 * 1024;
constexpr int32_t mmapFrameData = 256 * 1024;

const string BIND_CONTROL = "control";
const string BIND_RENDER = "render";

class AudioAlsaIfLibRenderTest : public testing::Test {
public:
    static struct DevHandle *handle;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t AudioInterfaceRenderInit(struct AudioHwRenderParam *&handleData);
    int32_t AudioInitHwParams(struct AudioHwRenderParam *&handleData);
    int32_t AudioResourceRelease(struct AudioHwRenderParam *&handleData);
};

struct DevHandle *AudioAlsaIfLibRenderTest::handle = nullptr;

void AudioAlsaIfLibRenderTest::SetUpTestCase()
{
}

void AudioAlsaIfLibRenderTest::TearDownTestCase()
{
}

void AudioAlsaIfLibRenderTest::SetUp()
{
    handle = AudioBindServiceRender(BIND_RENDER.c_str());
}

void AudioAlsaIfLibRenderTest::TearDown()
{
    AudioCloseServiceRender(handle);
}

int32_t AudioAlsaIfLibRenderTest::AudioInterfaceRenderInit(struct AudioHwRenderParam *&handleData)
{
    int32_t ret;
    if (handleData == nullptr) {
        return HDF_FAILURE;
    }
    ret = AudioOutputRenderOpen(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, handleData);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ret = AudioOutputRenderHwParams(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, handleData);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ret = AudioOutputRenderPrepare(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, handleData);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}


int32_t AudioAlsaIfLibRenderTest::AudioInitHwParams(struct AudioHwRenderParam * &handleData)
{
    if (handleData == nullptr) {
        return HDF_FAILURE;
    }
    (void)memcpy_s(handleData->renderMode.hwInfo.adapterName, NAME_LEN, "primary", strlen("primary"));
    handleData->frameRenderMode.attrs.channelCount = channel;
    handleData->frameRenderMode.attrs.sampleRate = sampleRate;
    handleData->frameRenderMode.attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    handleData->frameRenderMode.attrs.isBigEndian = false;
    handleData->frameRenderMode.attrs.isSignedData = true;
    return HDF_SUCCESS;
}

int32_t AudioAlsaIfLibRenderTest::AudioResourceRelease(struct AudioHwRenderParam *&handleData)
{
    if (handleData == nullptr) {
        return HDF_FAILURE;
    }

    int32_t ret = AudioOutputRenderClose(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(handleData);
    handleData = nullptr;
    return HDF_SUCCESS;
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderOpen_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioOutputRenderOpen(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderOpen_002, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    (void)memcpy_s(handleData->renderMode.hwInfo.adapterName, NAME_LEN, "primary", strlen("primary"));
    int32_t ret = AudioOutputRenderOpen(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, SetHwParams_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioOutputRenderHwParams(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, SetHwParams_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputRenderOpen(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputRenderHwParams(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderPrepare_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioOutputRenderPrepare(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderPrepare_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputRenderOpen(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputRenderHwParams(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputRenderPrepare(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetVolThreshold_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetVolThreshold(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetVolThreshold_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderGetVolThreshold(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t volumeMin = handleData->renderMode.ctlParam.volThreshold.volMin;
    int32_t volumeMax = handleData->renderMode.ctlParam.volThreshold.volMax;
    EXPECT_EQ(volMin, volumeMin);
    EXPECT_EQ(volMax, volumeMax);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetVolume_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetVolume_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderGetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t vol = (int32_t)handleData->renderMode.ctlParam.volume;
    EXPECT_GE(vol, volMin);
    EXPECT_LE(vol, volMax);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetVolume_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetVolume_002, TestSize.Level1)
{
    int32_t ret;
    float setVol = 0.0;
    float getVol = 0.0;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    setVol = 80.0;
    handleData->renderMode.ctlParam.volume = setVol;
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderSetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderGetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    getVol = handleData->renderMode.ctlParam.volume;
    EXPECT_EQ(setVol, getVol);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetMuteStu_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetMuteStu_002, TestSize.Level1)
{
    int32_t ret;
    bool mute = true;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderGetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    mute = handleData->renderMode.ctlParam.mute;
    EXPECT_EQ(false, mute);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetMuteStu_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetMuteStu_002, TestSize.Level1)
{
    int32_t ret;
    bool mute = false;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    handleData->renderMode.ctlParam.mute = true;
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderSetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderGetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    mute = handleData->renderMode.ctlParam.mute;
    EXPECT_EQ(true, mute);
    handleData->renderMode.ctlParam.mute = false;
    ret = AudioCtlRenderSetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderGetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    mute = handleData->renderMode.ctlParam.mute;
    EXPECT_EQ(false, mute);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetPauseStu_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetPauseStu(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetPauseStu_002, TestSize.Level1)
{
    int32_t ret;
    bool pause = true;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    handleData->renderMode.ctlParam.pause = false;
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCtlRenderSetPauseStu(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    pause = handleData->renderMode.ctlParam.pause;
    EXPECT_EQ(false, pause);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetPauseStu_003, TestSize.Level1)
{
    int32_t ret;
    bool pause = false;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    handleData->renderMode.ctlParam.pause = true;
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCtlRenderSetPauseStu(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    pause = handleData->renderMode.ctlParam.pause;
    EXPECT_EQ(true, pause);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetChannelMode_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetChannelMode(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetChannelMode_002, TestSize.Level1)
{
    struct AudioHwRenderParam handleData;
    int32_t ret = AudioCtlRenderSetChannelMode(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE, &handleData);
    /* alsa_lib not support AudioCtlRenderSetChannelMode, Therefore, success is returned directly */
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetChannelMode_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetChannelMode(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetChannelMode_002, TestSize.Level1)
{
    struct AudioHwRenderParam handleData;
    int32_t ret = AudioCtlRenderGetChannelMode(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ, &handleData);
    /* alsa_lib not support AudioCtlRenderGetChannelMode, Therefore, success is returned directly */
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetGainStu_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetGainStu(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSetGainStu_002, TestSize.Level1)
{
    struct AudioHwRenderParam handleData;
    int32_t ret = AudioCtlRenderSetGainStu(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &handleData);
    /* alsa_lib not support AudioCtlRenderSetGainStu, Therefore, success is returned directly */
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetGainStu_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetGainStu(handle, AUDIODRV_CTL_IOCTL_GAIN_READ, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderGetGainStu_002, TestSize.Level1)
{
    struct AudioHwRenderParam handleData;
    int32_t ret = AudioCtlRenderGetGainStu(handle, AUDIODRV_CTL_IOCTL_GAIN_READ, &handleData);
    /* alsa_lib not support AudioCtlRenderGetGainStu, Therefore, success is returned directly */
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSceneSelect_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSceneSelect(handle, AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSceneSelect_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    handleData->renderMode.hwInfo.deviceDescript.pins = PIN_OUT_SPEAKER;
    handleData->frameRenderMode.attrs.type = AUDIO_IN_MEDIA;
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderSceneSelect(handle, AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioCtlRenderSceneSelect_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    handleData->renderMode.hwInfo.deviceDescript.pins = PIN_OUT_HEADSET;
    handleData->frameRenderMode.attrs.type = AUDIO_IN_MEDIA;
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlRenderSceneSelect(handle, AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderStart_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioOutputRenderStart(handle, AUDIO_DRV_PCM_IOCTRL_START, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderStart_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputRenderStart(handle, AUDIO_DRV_PCM_IOCTRL_START, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderStop_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioOutputRenderStop(handle, AUDIO_DRV_PCM_IOCTRL_STOP, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderStop_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputRenderStop(handle, AUDIO_DRV_PCM_IOCTRL_STOP, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderWrite_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioOutputRenderWrite(handle, AUDIO_DRV_PCM_IOCTL_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderWrite_002, TestSize.Level1)
{
    int32_t ret;
    char buffer[frameData];
    for (int i = 0; i < sizeof(buffer); i++) {
        buffer[i] = random() & 0xff;
    }
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t frameSize = channel * 2; /* 2 is for AUDIO_FORMAT_PCM_16_BIT to byte */
    ASSERT_NE(frameSize, 0);
    handleData->frameRenderMode.bufferFrameSize = frameData / frameSize;
    char *bufferFrame = new char[frameData];
    handleData->frameRenderMode.buffer = bufferFrame;
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    (void)memcpy_s(handleData->frameRenderMode.buffer, frameData, buffer, frameData);
    ret = AudioOutputRenderWrite(handle, AUDIO_DRV_PCM_IOCTL_WRITE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete[] bufferFrame;
    bufferFrame = NULL;
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderReqMmapBuffer_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioOutputRenderReqMmapBuffer(handle, AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderReqMmapBuffer_002, TestSize.Level1)
{
    int32_t ret;
    char mmapBuffer[mmapFrameData];
    for (int i = 0; i < sizeof(mmapBuffer); i++) {
        mmapBuffer[i] = random() & 0xff;
    }
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t frameSize = channel * 2; /* 2 is for AUDIO_FORMAT_PCM_16_BIT to byte */
    ASSERT_NE(frameSize, 0);
    handleData->frameRenderMode.mmapBufDesc.totalBufferFrames = mmapFrameData / frameSize;
    char *mmapBufferFrames = new char[mmapFrameData];
    handleData->frameRenderMode.mmapBufDesc.memoryAddress = mmapBufferFrames ;
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    (void)memcpy_s(handleData->frameRenderMode.mmapBufDesc.memoryAddress, mmapFrameData, mmapBuffer, mmapFrameData);
    ret = AudioOutputRenderReqMmapBuffer(handle, AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete[] mmapBufferFrames;
    mmapBufferFrames = NULL;
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderGetMmapPosition_001, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioOutputRenderGetMmapPosition(handle, AUDIO_DRV_PCM_IOCTL_MMAP_POSITION, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibRenderTest, AudioOutputRenderGetMmapPosition_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    memset_s(handleData, sizeof(AudioHwRenderParam), 0, sizeof(AudioHwRenderParam));
    ret = AudioInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t mmapFrameSize = channel * 2; /* 2 is for AUDIO_FORMAT_PCM_16_BIT to byte */
    ASSERT_NE(mmapFrameSize, 0);
    handleData->frameRenderMode.mmapBufDesc.totalBufferFrames = mmapFrameData / mmapFrameSize;
    char mmapBuffer[mmapFrameData];
    for (int i = 0; i < sizeof(mmapBuffer); i++) {
        mmapBuffer[i] = random() & 0xff;
    }
    handleData->frameRenderMode.mmapBufDesc.memoryAddress = mmapBuffer ;
    ret = AudioInterfaceRenderInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    (void)memcpy_s(handleData->frameRenderMode.mmapBufDesc.memoryAddress, mmapFrameData, mmapBuffer, mmapFrameData);
    ret = AudioOutputRenderReqMmapBuffer(handle, AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputRenderGetMmapPosition(handle, AUDIO_DRV_PCM_IOCTL_MMAP_POSITION, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(handleData->frameRenderMode.frames, mmapFrameData / mmapFrameSize);
    ret = AudioResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
}
