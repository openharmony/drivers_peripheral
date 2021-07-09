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
 * @brief Test audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver ADM interface lib,and rendering audios
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_lib_common.h
 *
 * @brief Declares APIs for operations related to the audio ADM interface lib.
 *
 * @since 1.0
 * @version 1.0
 */
#include "audio_lib_common.h"
#include "audio_librender_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string BIND_CONTROL = "control";
const string BIND_RENDER = "render";
const string BIND_NAME_ERROR = "rendeo";
const string AUDIO_FILE_PATH = "//bin/audiorendertest.wav";
const int G_BUFFERSIZE = 256;
const string ADAPTER_NAME_HDIMI = "hdmi";
const string ADAPTER_NAME_USB = "usb";
const string ADAPTER_NAME3 = "internal";

class AudioLibRenderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct DevHandle *(*BindServiceRenderSo)(const char *) = nullptr;
    int32_t (*InterfaceLibOutputRender)(struct DevHandle *, int, struct AudioHwRenderParam *) = nullptr;
    int32_t (*InterfaceLibCtlRender)(struct DevHandle *, int, struct AudioHwRenderParam *) = nullptr;
    void (*CloseServiceRenderSo)(struct DevHandle *) = nullptr;
    void *PtrHandle = nullptr;
    uint32_t PcmFormatToBits(enum AudioFormat format) const;
    uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs) const;
    uint32_t PcmBytesToFrames(const struct AudioFrameRenderMode &frameRenderMode, uint64_t bytes) const;
    uint32_t FormatToBits(enum AudioFormat format) const;
    uint32_t FrameLibStart(FILE *file, struct AudioSampleAttributes attrs,
        struct AudioHeadInfo wavHeadInfo, struct AudioHwRender *hwRender) const;
    uint32_t LibStartAndStream(const std::string path, struct AudioSampleAttributes attrs,
        struct DevHandle *handle, struct AudioHwRender *hwRender, struct AudioHeadInfo wavHeadInfo) const;
    uint32_t InitHwRender(struct AudioHwRender *hwRender, struct AudioSampleAttributes attrs,
        const std::string adapterNameCase) const;
};

void AudioLibRenderTest::SetUpTestCase(void)
{
}

void AudioLibRenderTest::TearDownTestCase(void)
{
}

void AudioLibRenderTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libhdi_audio_interface_lib_render.z.so";
    PtrHandle = dlopen(resolvedPath, RTLD_LAZY);
    if (PtrHandle == nullptr) {
        return;
    }
    BindServiceRenderSo = (struct DevHandle* (*)(const char *))dlsym(PtrHandle, "AudioBindServiceRender");
    InterfaceLibOutputRender = (int32_t (*)(struct DevHandle *, int,
        struct AudioHwRenderParam *))dlsym(PtrHandle, "AudioInterfaceLibOutputRender");
    InterfaceLibCtlRender = (int32_t (*)(struct DevHandle *, int,
        struct AudioHwRenderParam *))dlsym(PtrHandle, "AudioInterfaceLibCtlRender");
    CloseServiceRenderSo = (void (*)(struct DevHandle *))dlsym(PtrHandle, "AudioCloseServiceRender");
    if (BindServiceRenderSo == nullptr || CloseServiceRenderSo == nullptr ||
        InterfaceLibCtlRender == nullptr || InterfaceLibOutputRender == nullptr) {
        dlclose(PtrHandle);
        return;
    }
}

void AudioLibRenderTest::TearDown(void)
{
    if (PtrHandle != nullptr) {
        dlclose(PtrHandle);
        PtrHandle = nullptr;
    }
    if (BindServiceRenderSo != nullptr) {
        BindServiceRenderSo = nullptr;
    } else if (CloseServiceRenderSo != nullptr) {
        CloseServiceRenderSo = nullptr;
    } else if (InterfaceLibOutputRender != nullptr) {
        InterfaceLibOutputRender = nullptr;
    } else {
        InterfaceLibCtlRender = nullptr;
    }
}

uint32_t AudioLibRenderTest::PcmFormatToBits(enum AudioFormat format) const
{
    switch (format) {
        case AUDIO_FORMAT_PCM_16_BIT:
            return G_PCM16BIT;
        case AUDIO_FORMAT_PCM_8_BIT:
            return G_PCM8BIT;
        default:
            return G_PCM16BIT;
    };
}

uint32_t AudioLibRenderTest::PcmFramesToBytes(const struct AudioSampleAttributes attrs) const
{
    uint32_t ret = 1024 * attrs.channelCount * (PcmFormatToBits(attrs.format) >> 3);
    return ret;
}
uint32_t AudioLibRenderTest::FormatToBits(enum AudioFormat format) const
{
    switch (format) {
        case AUDIO_FORMAT_PCM_16_BIT:
            return G_PCM16BIT;
        case AUDIO_FORMAT_PCM_8_BIT:
            return G_PCM8BIT;
        default:
            return G_PCM16BIT;
    }
}

uint32_t AudioLibRenderTest::PcmBytesToFrames(const struct AudioFrameRenderMode &frameRenderMode, uint64_t bytes) const
{
    return bytes / (frameRenderMode.attrs.channelCount * (FormatToBits(frameRenderMode.attrs.format) >> 3));
}

/**
 * @brief Reading audio file frame.
 *
 * @param file audio file path
 * @param AudioSampleAttributes
 * @param struct AudioHeadInfo wavHeadInfo
 * @param struct AudioHwRender *hwRender
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
uint32_t AudioLibRenderTest::FrameLibStart(FILE *file, struct AudioSampleAttributes attrs,
    struct AudioHeadInfo wavHeadInfo, struct AudioHwRender *hwRender) const
{
    int bufferSize = G_BUFFERSIZE;
    int readSize = 0;
    int remainingDataSize = 0;
    int numRead = 0;
    uint64_t *replyBytes = nullptr;
    remainingDataSize = wavHeadInfo.dataSize;
    bufferSize = PcmFramesToBytes(attrs);
    char *frame = nullptr;
    frame = (char *)calloc(1, bufferSize);
    if (frame == nullptr) {
        return HDF_FAILURE;
    }
    replyBytes = (uint64_t *)calloc(1, bufferSize);
    if (replyBytes == nullptr) {
        free(frame);
        return HDF_FAILURE;
    }
    do {
        readSize = (remainingDataSize > bufferSize) ? bufferSize : remainingDataSize;
        numRead = fread(frame, 1, readSize, file);
        if (numRead > 0) {
            hwRender->renderParam.frameRenderMode.buffer = (char *)frame;
            hwRender->renderParam.frameRenderMode.bufferSize = numRead;
            hwRender->renderParam.frameRenderMode.bufferFrameSize =
                PcmBytesToFrames(hwRender->renderParam.frameRenderMode, numRead);
            remainingDataSize -= numRead;
        }
    } while (0);
    free(frame);
    free(replyBytes);
    return HDF_SUCCESS;
}

uint32_t AudioLibRenderTest::LibStartAndStream(const std::string path, struct AudioSampleAttributes attrs,
    struct DevHandle *handle, struct AudioHwRender *hwRender, struct AudioHeadInfo wavHeadInfo) const
{
    int ret = -1;
    if (InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam) ||
        InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam) ||
        InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_START, &hwRender->renderParam)) {
        return HDF_FAILURE;
    }
    char absPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), absPath) == nullptr) {
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    if (WavHeadAnalysis(wavHeadInfo, file, attrs)) {
        fclose(file);
        return HDF_FAILURE;
    }
    ret = FrameLibStart(file, attrs, wavHeadInfo, hwRender);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, &hwRender->renderParam);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

uint32_t AudioLibRenderTest::InitHwRender(struct AudioHwRender *hwRender, struct AudioSampleAttributes attrs,
    const std::string adapterNameCase) const
{
    int ret = -1;
    if (hwRender == nullptr) {
        return HDF_FAILURE;
    }
    if (InitHwRenderMode(hwRender->renderParam.renderMode) or
        InitRenderFramepara(hwRender->renderParam.frameRenderMode)) {
        return HDF_FAILURE;
    }
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, adapterNameCase.c_str());
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (InitAttrs(attrs)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
/**
* @tc.name  test BindServiceRenderSo API via legal input.
* @tc.number  SUB_Audio_InterfaceLib_BindServiceRender_0001
* @tc.desc  test Binding succeeded Service which service Name is control_service and close Service.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLib_BindServiceRender_0001, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    CloseServiceRenderSo(handle);
}
/**
* @tc.name  test BindServiceRenderSo API via invalid input.
* @tc.number  SUB_Audio_InterfaceLib_BindServiceRender_0002
* @tc.desc  test Binding failed Service which invalid service Name is rendeo.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLib_BindServiceRender_0002, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_NAME_ERROR.c_str());
    if (handle != nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(nullptr, handle);
    }
    EXPECT_EQ(nullptr, handle);
}
/**
* @tc.name  test BindServiceRenderSo API via nullptr input.
* @tc.number  SUB_Audio_InterfaceLib_BindServiceRender_0003
* @tc.desc  test Binding failed Service, nullptr pointer passed in.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLib_BindServiceRender_0003, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    char *bindNameNull = nullptr;
    handle = BindServiceRenderSo(bindNameNull);
    if (handle != nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(nullptr, handle);
    }
    EXPECT_EQ(nullptr, handle);
}
/**
* @tc.name  test BindServiceRenderSo API via binding service name lens is 25.
* @tc.number  SUB_Audio_InterfaceLib_BindServiceRender_0004
* @tc.desc  test Binding failed Service, Log printing 'service name not support!' and 'Failed to get service!'.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLib_BindServiceRender_0004, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    string bindNameLen = "renderrenderedededededede";
    handle = BindServiceRenderSo(bindNameLen.c_str());
    if (handle != nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(nullptr, handle);
    }
    EXPECT_EQ(nullptr, handle);
}
/**
* @tc.name  test BindServiceRenderSo API via binding service name lens is 26.
* @tc.number  SUB_Audio_InterfaceLib_BindServiceRender_0005
* @tc.desc  test Binding failed Service, Log printing 'Failed to snprintf_s'.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLib_BindServiceRender_0005, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    string bindNameLen = "renderrenderededededededer";
    handle = BindServiceRenderSo(bindNameLen.c_str());
    if (handle != nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(nullptr, handle);
    }
    EXPECT_EQ(nullptr, handle);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value of AcodecIn is normal value and reading
*    this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volum_AcodecIn_Write_Read_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volum_AcodecIn_Write_Read_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumevalue = 0;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax-1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(126, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin+1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(41, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = 127.9;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(127, volumevalue);

    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value of AcodecIn is boundary value and reading
*    this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volum_AcodecIn_Write_Read_0002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volum_AcodecIn_Write_Read_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumevalue = 0;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(127, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(40, volumevalue);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value is invalid value of AcodecIn.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volum_AcodecIn_Write_Read_0003
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volum_AcodecIn_Write_Read_0003, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax + 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin - 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value of smartpa is normal value and reading
*    this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volum_AcodecOut_Write_Read_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volum_AcodecOut_Write_Read_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumevalue = 0;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_OUT;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_HDIMI.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax-1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(187, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin+1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(1, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = 127.9;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(127, volumevalue);

    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value of smartpa is boundary value and reading
*    this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volum_AcodecOut_Write_Read_0002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volum_AcodecOut_Write_Read_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumevalue = 0;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_OUT;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_HDIMI.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(188, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(0, volumevalue);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value of smartpa is invalid value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volum_AcodecOut_Write_Read_0003
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volum_AcodecOut_Write_Read_0003, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_OUT;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_HDIMI.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax + 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin - 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing GetVolthreshold value that
*    Hardware equipment of Acodec_ChangeOut.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GetVolthresholdRead_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GetVolthresholdRead_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float expMax = 188;
    float expMix = 0;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }

    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_OUT;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_HDIMI.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_OUT, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;
    EXPECT_EQ(expMax, volumeThresholdValueMax);
    EXPECT_EQ(expMix, volumeThresholdValueMin);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing GetVolthreshold value that
*    Hardware equipment of Acodec_ChangeIn.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GetVolthresholdRead_0002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GetVolthresholdRead_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float expMax = 127;
    float expMix = 40;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;
    EXPECT_EQ(expMax, volumeThresholdValueMax);
    EXPECT_EQ(expMix, volumeThresholdValueMin);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing ChannelMode value is normal value and reading this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_ChannelMode_Write_Read_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE
*    and AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_ChannelMode_Write_Read_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float channelModeExc = 1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *impl = (struct AudioHwRender *)calloc(1, sizeof(struct AudioHwRender));
    if (impl == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(impl->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = strcpy_s(impl->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitRenderFramepara(impl->renderParam.frameRenderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);

    impl->renderParam.frameRenderMode.mode = AUDIO_CHANNEL_BOTH_RIGHT;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE, &impl->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ, &impl->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    channelModeExc = impl->renderParam.frameRenderMode.mode;
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_RIGHT, channelModeExc);

    impl->renderParam.frameRenderMode.mode = AUDIO_CHANNEL_RIGHT_MUTE;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE, &impl->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ, &impl->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    channelModeExc = impl->renderParam.frameRenderMode.mode;
    EXPECT_EQ(AUDIO_CHANNEL_RIGHT_MUTE, channelModeExc);

    CloseServiceRenderSo(handle);
    free(impl);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing ChannelMode value is boundary value and reading this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_ChannelMode_Write_Read_0002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE
*    and AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_ChannelMode_Write_Read_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float channelModeExc = 1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *impl = (struct AudioHwRender *)calloc(1, sizeof(struct AudioHwRender));
    if (impl == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(impl->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = strcpy_s(impl->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitRenderFramepara(impl->renderParam.frameRenderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);

    impl->renderParam.frameRenderMode.mode = AUDIO_CHANNEL_NORMAL;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE, &impl->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ, &impl->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    channelModeExc = impl->renderParam.frameRenderMode.mode;
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, channelModeExc);

    impl->renderParam.frameRenderMode.mode = AUDIO_CHANNEL_BOTH_MUTE;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE, &impl->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ, &impl->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    channelModeExc = impl->renderParam.frameRenderMode.mode;
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_MUTE, channelModeExc);

    CloseServiceRenderSo(handle);
    free(impl);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing mute value that include 1 and 0 and reading mute value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_MuteWrite_Read_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_MUTE_WRITE and AUDIODRV_CTL_IOCTL_MUTE_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_MuteWrite_Read_0001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteValue = 1;
    bool wishValue = 0;
    bool expectedValue = 1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.mute = 0;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    muteValue = hwRender->renderParam.renderMode.ctlParam.mute;
    EXPECT_EQ(wishValue, muteValue);
    hwRender->renderParam.renderMode.ctlParam.mute = 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    muteValue = hwRender->renderParam.renderMode.ctlParam.mute;
    EXPECT_EQ(expectedValue, muteValue);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing mute value that include 2 and reading mute value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_MuteWrite_Read_0002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_MUTE_WRITE and AUDIODRV_CTL_IOCTL_MUTE_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_MuteWrite_Read_0002, TestSize.Level1)
{
    int32_t ret = -1;
    bool mutevalue = 0;
    bool expectedValue = 1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.mute = 2;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    mutevalue = hwRender->renderParam.renderMode.ctlParam.mute;
    EXPECT_EQ(expectedValue, mutevalue);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via selecting scene.
* @tc.number  SUB_Audio_InterfaceLib_CtlRender_SelectScene_0001
* @tc.desc  test InterfaceLibCtlRender,cmdId is AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLib_CtlRender_SelectScene_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);

    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitRenderFramepara(hwRender->renderParam.frameRenderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);

    struct AudioSceneDescriptor scene = {
        .scene.id = 0,
        .desc.pins = PIN_OUT_HEADSET,
    };
    hwRender->renderParam.renderMode.hwInfo.pathSelect.deviceInfo.deviceNum = 1;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[0].deviceSwitch,
        PATHPLAN_COUNT, "Dacl enable");
    hwRender->renderParam.renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[0].value = 0;
    hwRender->renderParam.frameRenderMode.attrs.type = (enum AudioCategory)(scene.scene.id);
    hwRender->renderParam.renderMode.hwInfo.deviceDescript.pins = scene.desc.pins;

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing normal gain value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE and AUDIODRV_CTL_IOCTL_GAIN_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float gainValue = 0;
    struct DevHandle *handle = nullptr;
    float gainThresholdValueMax, gainThresholdValueMin;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.audioGain.gainMax;
    gainThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.audioGain.gainMin;
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.audioGain.gain = gainThresholdValueMax - 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwRender->renderParam.renderMode.ctlParam.audioGain.gain;
    EXPECT_EQ(gainThresholdValueMax - 1, gainValue);
    hwRender->renderParam.renderMode.ctlParam.audioGain.gain = gainThresholdValueMin + 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwRender->renderParam.renderMode.ctlParam.audioGain.gain;
    EXPECT_EQ(gainThresholdValueMin + 1, gainValue);
    hwRender->renderParam.renderMode.ctlParam.audioGain.gain = 2.3;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwRender->renderParam.renderMode.ctlParam.audioGain.gain;
    EXPECT_EQ(2, gainValue);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing boundary value of gain and reading gain value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_0002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE and AUDIODRV_CTL_IOCTL_GAIN_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float gainValue = 0;
    struct DevHandle *handle = nullptr;
    float gainThresholdValueMax, gainThresholdValueMin;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.audioGain.gainMax;
    gainThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.audioGain.gainMin;
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.audioGain.gain = gainThresholdValueMin;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwRender->renderParam.renderMode.ctlParam.audioGain.gain;
    EXPECT_EQ(gainThresholdValueMin, gainValue);
    hwRender->renderParam.renderMode.ctlParam.audioGain.gain = gainThresholdValueMax;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwRender->renderParam.renderMode.ctlParam.audioGain.gain;
    EXPECT_EQ(gainThresholdValueMax, gainValue);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing gain invalid value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_0003
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE and AUDIODRV_CTL_IOCTL_GAIN_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    float gainThresholdValueMax, gainThresholdValueMin;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.audioGain.gainMax;
    gainThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.audioGain.gainMin;
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.audioGain.gain = gainThresholdValueMax + 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    hwRender->renderParam.renderMode.ctlParam.audioGain.gain = gainThresholdValueMin - 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via getting gainthreshold value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GetGainthresholdRead_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GetGainthresholdRead_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float gainThresholdValueMax, gainThresholdValueMin;
    float expMax = 10;
    float expMix = 0;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.audioGain.gainMax;
    gainThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.audioGain.gainMin;
    EXPECT_LT(expMax, gainThresholdValueMax);
    EXPECT_EQ(expMix, gainThresholdValueMin);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via using Acodec_ChangeIn.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Acodec_ChangeIn_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Acodec_ChangeIn_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via using smartpa.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Acodec_ChangeOut_0001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_OUT.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Acodec_ChangeOut_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_OUT;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_HDIMI.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_OUT, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via inputting invalid cmdid.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Abnormal_0001
* @tc.desc  test InterfaceLibCtlRender, cmdId is invalid eg 50,so return -1.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Abnormal_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, ADAPTER_NAME_USB.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, 50, &hwRender->renderParam);
    if (ret == 0) {
        CloseServiceRenderSo(handle);
        free(hwRender);
        ASSERT_EQ(HDF_FAILURE, ret);
    }
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibCtlRender API via inputting handleData invalid.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Abnormal_0002
* @tc.desc  test InterfaceLibCtlRender, handleData is nullptr,so return -1.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Abnormal_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    struct AudioHwRenderParam *handleData = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, handleData);
    if (ret == 0) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(HDF_FAILURE, ret);
    }
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
}
/**
* @tc.name  test InterfaceLibCtlRender API via don't binding control service.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Abnormal_0003
* @tc.desc  test Audio lib Interface CtlRender, but there isn't binding control service,so Interface return -1.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Abnormal_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_HW_PARAMS.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_HwParams_0001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_HwParams_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    struct AudioSampleAttributes attrs = {};
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRender(hwRender, attrs, ADAPTER_NAME_USB);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_PREPARE.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Prepare_0001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Prepare_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    struct AudioSampleAttributes attrs = {};
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRender(hwRender, attrs, ADAPTER_NAME_USB);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTRL_START.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Start_0001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Start_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    struct AudioSampleAttributes attrs = {};
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRender(hwRender, attrs, ADAPTER_NAME_USB);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_START, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_WRITE and AUDIO_DRV_PCM_IOCTRL_STOP.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Write_Stop_0001
* @tc.desc  test Audio lib Interface OutputRender and Normal data flow distribution.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Write_Stop_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioHeadInfo wavHeadInfo = {};
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitHwRender(hwRender, attrs, ADAPTER_NAME_USB);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_START, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    char absPath[PATH_MAX] = {0};
    if (realpath(AUDIO_FILE_PATH.c_str(), absPath) == nullptr) {
        cout << "path is not exist!" << endl;
        free(hwRender);
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, absPath);
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        cout << "failed to open!" << endl;
        free(hwRender);
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, file);
    }
    if (WavHeadAnalysis(wavHeadInfo, file, attrs) < 0) {
        free(hwRender);
        fclose(file);
        CloseServiceRenderSo(handle);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = FrameLibStart(file, attrs, wavHeadInfo, hwRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
    fclose(file);
}
/**
* @tc.name  test InterfaceLibCtlRender and InterfaceLibOutputRender API via Serial
    transmission of data flow and control flow.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Write_0001
* @tc.desc  test Audio lib Interface CtlRender and OutputRender, Data stream and control stream send successful.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Write_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float muteValue = 1;
    float expectedValue = 0;
    struct DevHandle *handler = nullptr;
    struct DevHandle *handlec = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioHeadInfo wavHeadInfo = {};
    handler = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handler);
    handlec = BindServiceRenderSo(BIND_CONTROL.c_str());
    if (handlec == nullptr) {
        CloseServiceRenderSo(handler);
        ASSERT_NE(nullptr, handlec);
    }
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handler);
        CloseServiceRenderSo(handlec);
        ASSERT_NE(nullptr, hwRender);
    }
    ret = InitHwRender(hwRender, attrs, ADAPTER_NAME_USB);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.mute = muteValue;
    ret = InterfaceLibCtlRender(handlec, AUDIODRV_CTL_IOCTL_MUTE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handlec, AUDIODRV_CTL_IOCTL_MUTE_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    expectedValue = hwRender->renderParam.renderMode.ctlParam.mute;
    EXPECT_EQ(expectedValue, muteValue);
    ret = LibStartAndStream(AUDIO_FILE_PATH, attrs, handler, hwRender, wavHeadInfo);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handler, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handler);
    CloseServiceRenderSo(handlec);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibOutputRender API via pause.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Pause_0001
* @tc.desc  test InterfaceLibOutputRender,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Pause_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.pause = 1;
    ret = InterfaceLibOutputRender(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibOutputRender API via resuming.
* @tc.number  SUB_Audio_InterfaceLib_CtlRender_Resume_0001
* @tc.desc  test InterfaceLibOutputRender,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Resume_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = InitHwRenderMode(hwRender->renderParam.renderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.pause = 0;
    ret = InterfaceLibOutputRender(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibOutputRender API via setting the cmdId is invalid.
* @tc.number  SUB_Audio_InterfaceLibOutputRender__Abnormal_0001
* @tc.desc  test Audio lib Interface OutputRender via cmdid is invalid and cmdid is 30,so Interface return -1.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Abnormal_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitRenderFramepara(hwRender->renderParam.frameRenderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, 30, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
/**
* @tc.name  test InterfaceLibOutputRender API via inputting handleData is nullptr.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Abnormal_0002
* @tc.desc  test Audio lib Interface OutputRender, handleData is nullptr.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Abnormal_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    struct AudioHwRenderParam *handleData = nullptr;
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
}
/**
* @tc.name  test InterfaceLibOutputRender via don't binding render service.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Abnormal_0003
* @tc.desc  test Audio lib Interface OutputRender, but there isn't binding render service,so Interface return -1.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Abnormal_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct DevHandle *handle = nullptr;
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, handle);
    }
    ret = InitRenderFramepara(hwRender->renderParam.frameRenderMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
}
}