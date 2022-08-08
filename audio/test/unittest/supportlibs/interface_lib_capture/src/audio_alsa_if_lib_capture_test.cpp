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
#include "alsa_lib_capture.h"

using namespace std;
using namespace testing::ext;
namespace {
constexpr int32_t capChannel = 2;
constexpr int32_t capSampleRate = 48000;
constexpr int32_t capVolMin = 0;
constexpr int32_t capVolMax = 100;
constexpr int32_t capFrameData = 16 * 1024;
constexpr int32_t capMmapFrameData = 256 * 1024;
const string BIND_CAPTURE = "capture";

class AudioAlsaIfLibCaptureTest : public testing::Test {
public:
    static struct DevHandleCapture *handle;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t AudioInterfaceCaptureInit(struct AudioHwCaptureParam *&handleData);
    int32_t AudioCapInitHwParams(struct AudioHwCaptureParam *&handleData);
    int32_t AudioCapResourceRelease(struct AudioHwCaptureParam *&handleData);
};

struct DevHandleCapture *AudioAlsaIfLibCaptureTest::handle = nullptr;

void AudioAlsaIfLibCaptureTest::SetUpTestCase()
{
}

void AudioAlsaIfLibCaptureTest::TearDownTestCase()
{
}

void AudioAlsaIfLibCaptureTest::SetUp()
{
    handle = AudioBindServiceCapture(BIND_CAPTURE.c_str());
}

void AudioAlsaIfLibCaptureTest::TearDown()
{
    AudioCloseServiceCapture(handle);
}

int32_t AudioAlsaIfLibCaptureTest::AudioInterfaceCaptureInit(struct AudioHwCaptureParam *&handleData)
{
    int32_t ret;
    if (handleData == nullptr) {
        return HDF_FAILURE;
    }
    ret = AudioOutputCaptureOpen(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, handleData);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ret = AudioOutputCaptureHwParams(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, handleData);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ret = AudioOutputCapturePrepare(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, handleData);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioAlsaIfLibCaptureTest::AudioCapInitHwParams(struct AudioHwCaptureParam *&handleData)
{
    if (handleData == nullptr) {
        return HDF_FAILURE;
    }
    (void)memcpy_s(handleData->captureMode.hwInfo.adapterName, NAME_LEN, "primary", strlen("primary"));
    handleData->frameCaptureMode.attrs.channelCount = capChannel;
    handleData->frameCaptureMode.attrs.sampleRate = capSampleRate;
    handleData->frameCaptureMode.attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    handleData->frameCaptureMode.attrs.isBigEndian = false;
    handleData->frameCaptureMode.attrs.isSignedData = true;
    return HDF_SUCCESS;
}

int32_t AudioAlsaIfLibCaptureTest::AudioCapResourceRelease(struct AudioHwCaptureParam *&handleData)
{
    if (handleData == nullptr) {
        return HDF_FAILURE;
    }

    int32_t ret = AudioOutputCaptureClose(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(handleData);
    handleData = nullptr;
    return HDF_SUCCESS;
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureOpen_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioOutputCaptureOpen(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureOpen_002, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    (void)memcpy_s(handleData->captureMode.hwInfo.adapterName, NAME_LEN, "primary", strlen("primary"));
    int32_t ret = AudioOutputCaptureOpen(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, SetHwParams_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioOutputCaptureHwParams(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, SetHwParams_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureOpen(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureHwParams(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCapturePrepare_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioOutputCapturePrepare(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCapturePrepare_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureOpen(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureHwParams(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCapturePrepare(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureGetVolThresholds_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureGetVolThreshold(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureGetVolThresholds_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlCaptureGetVolThreshold(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t volumeMin = handleData->captureMode.ctlParam.volThreshold.volMin;
    int32_t volumeMax = handleData->captureMode.ctlParam.volThreshold.volMax;
    EXPECT_EQ(capVolMin, volumeMin);
    EXPECT_EQ(capVolMax, volumeMax);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlRenderGetVolume_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureGetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlRenderGetVolume_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlCaptureGetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t vol = (int32_t)handleData->captureMode.ctlParam.volume;
    EXPECT_GE(vol, capVolMin);
    EXPECT_LE(vol, capVolMax);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetVolume_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetVolume_002, TestSize.Level1)
{
    int32_t ret;
    float setVol;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    setVol = 60.0;
    handleData->captureMode.ctlParam.volume = setVol;
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlCaptureSetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlCaptureGetVolume(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    float getVol = handleData->captureMode.ctlParam.volume;
    EXPECT_EQ(setVol, getVol);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureGetMuteStu_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureGetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureGetMuteStu_002, TestSize.Level1)
{
    int32_t ret;
    bool mute = true;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlCaptureGetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    mute = handleData->captureMode.ctlParam.mute;
    EXPECT_EQ(false, mute);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetMuteStu_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSetMuteStu(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetMuteStu_002, TestSize.Level1)
{
    int32_t ret;
    bool mute = false;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    handleData->captureMode.ctlParam.mute = true;
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlCaptureSetMuteStu(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlCaptureGetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    mute = handleData->captureMode.ctlParam.mute;
    EXPECT_EQ(true, mute);
    handleData->captureMode.ctlParam.mute = false;
    ret = AudioCtlCaptureSetMuteStu(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCtlCaptureGetMuteStu(handle, AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    mute = handleData->captureMode.ctlParam.mute;
    EXPECT_EQ(false, mute);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetPauseStu_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSetPauseStu(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetPauseStu_002, TestSize.Level1)
{
    int32_t ret;
    bool pause = true;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    handleData->captureMode.ctlParam.pause = false;
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCtlCaptureSetPauseStu(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    pause = handleData->captureMode.ctlParam.pause;
    EXPECT_EQ(false, pause);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetPauseStu_003, TestSize.Level1)
{
    int32_t ret;
    bool pause = false;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    handleData->captureMode.ctlParam.pause = true;
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCtlCaptureSetPauseStu(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    pause = handleData->captureMode.ctlParam.pause;
    EXPECT_EQ(true, pause);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetGainStu_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSetGainStu(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSetGainStu_002, TestSize.Level1)
{
    struct AudioHwCaptureParam handleData;
    int32_t ret = AudioCtlCaptureSetGainStu(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &handleData);
    /* alsa_lib not support AudioCtlCaptureSetGainStu, Therefore, success is returned directly */
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureGetGainStu_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureGetGainStu(handle, AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureGetGainStu_002, TestSize.Level1)
{
    struct AudioHwCaptureParam handleData;
    int32_t ret = AudioCtlCaptureGetGainStu(handle, AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE, &handleData);
    /* alsa_lib not support AudioCtlCaptureGetGainStu, Therefore, success is returned directly */
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSceneSelect_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSceneSelect(handle, AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioCtlCaptureSceneSelect_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam handleData;
    /* alsa_lib not support AudioCtlCaptureSceneSelect, Therefore, success is returned directly */
    handleData.captureMode.hwInfo.pathSelect.deviceInfo.deviceNum = AUDIO_MIN_CARD_NUM;
    ret = AudioCtlCaptureSceneSelect(handle, AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE, &handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureStart_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioOutputCaptureStart(handle, AUDIO_DRV_PCM_IOCTRL_START_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureStart_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureStart(handle, AUDIO_DRV_PCM_IOCTRL_START_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureStop_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioOutputCaptureStop(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureStop_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureStop(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureRead_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioOutputCaptureRead(handle, AUDIO_DRV_PCM_IOCTL_READ, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureRead_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t frameSize = capChannel * 2; /* 2 is for AUDIO_FORMAT_PCM_16_BIT to byte */
    ASSERT_NE(frameSize, 0);
    char *bufferFrameSize = new char[capFrameData];
    memset_s(bufferFrameSize, capFrameData, 0, capFrameData);
    handleData->frameCaptureMode.buffer = bufferFrameSize;
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureRead(handle, AUDIO_DRV_PCM_IOCTL_READ, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete[] bufferFrameSize;
    bufferFrameSize = nullptr;
    handleData->frameCaptureMode.buffer = nullptr;
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureReqMmapBuffer_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioOutputCaptureReqMmapBuffer(handle, AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureReqMmapBuffer_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t capFrameSize = capChannel * 2; /* 2 is for AUDIO_FORMAT_PCM_16_BIT to byte */
    ASSERT_NE(capFrameSize, 0);
    handleData->frameCaptureMode.mmapBufDesc.totalBufferFrames = capMmapFrameData / capFrameSize;
    char *mmapBufferFrameSize = new char[capMmapFrameData];
    handleData->frameCaptureMode.mmapBufDesc.memoryAddress = mmapBufferFrameSize ;
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureReqMmapBuffer(handle, AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete[] mmapBufferFrameSize;
    mmapBufferFrameSize = nullptr;
    handleData->frameCaptureMode.mmapBufDesc.memoryAddress = nullptr;
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureGetMmapPosition_001, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioOutputCaptureGetMmapPosition(handle, AUDIO_DRV_PCM_IOCTL_MMAP_POSITION_CAPTURE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAlsaIfLibCaptureTest, AudioOutputCaptureGetMmapPosition_002, TestSize.Level1)
{
    int32_t ret;
    char mmapBuffer[capMmapFrameData];
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    memset_s(handleData, sizeof(AudioHwCaptureParam), 0, sizeof(AudioHwCaptureParam));
    ret = AudioCapInitHwParams(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int32_t mmapFrameSize = capChannel * 2; /* 2 is for AUDIO_FORMAT_PCM_16_BIT to byte */
    ASSERT_NE(mmapFrameSize, 0);
    handleData->frameCaptureMode.mmapBufDesc.totalBufferFrames = capMmapFrameData / mmapFrameSize;
    handleData->frameCaptureMode.mmapBufDesc.memoryAddress = mmapBuffer ;
    ret = AudioInterfaceCaptureInit(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioOutputCaptureReqMmapBuffer(handle, AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    handleData->frameCaptureMode.frames = 0;
    ret = AudioOutputCaptureGetMmapPosition(handle, AUDIO_DRV_PCM_IOCTL_MMAP_POSITION_CAPTURE, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    uint64_t getFramePosition = handleData->frameCaptureMode.frames;
    EXPECT_EQ(getFramePosition, capMmapFrameData / mmapFrameSize);
    ret = AudioCapResourceRelease(handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
}
