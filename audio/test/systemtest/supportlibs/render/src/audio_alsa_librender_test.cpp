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

#include "audio_lib_common.h"
#include "audio_librender_test.h"
using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const string BIND_CONTROL = "control";

class AudioAlsaLibRenderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static int32_t (*InterfaceLibOutputRender)(struct DevHandle *handle, int cmdId,
                                               struct AudioHwRenderParam *handleData);
    static int32_t (*InterfaceLibCtlRender)(struct DevHandle *handle, int cmdId,
                                            struct AudioHwRenderParam *handleData);
    static void *ptrHandle;
    static struct DevHandle *handle;
    static struct DevHandle *(*BindServiceRender)(const char *serverName);
    static void (*CloseServiceRender)(struct DevHandle *handle);
    uint32_t PcmBytesToFrames(const struct AudioFrameRenderMode &frameRenderMode, uint64_t bytes) const;
    int32_t FrameLibStart(FILE *file, struct AudioSampleAttributes attrs,
        struct AudioHeadInfo wavHeadInfo, struct AudioHwRender *hwRender) const;
    int32_t LibRenderStart(struct AudioHwRender *hwRender, struct DevHandle *handlerender) const;
    int32_t CreatHwRender(struct AudioHwRender *&hwRender, const std::string adapterNameCase) const;
};

int32_t (*AudioAlsaLibRenderTest::InterfaceLibOutputRender)(struct DevHandle *handle, int cmdId,
                                                            struct AudioHwRenderParam *handleData) = nullptr;
int32_t (*AudioAlsaLibRenderTest::InterfaceLibCtlRender)(struct DevHandle *handle, int cmdId,
                                                         struct AudioHwRenderParam *handleData) = nullptr;
void *AudioAlsaLibRenderTest::ptrHandle = nullptr;
struct DevHandle *AudioAlsaLibRenderTest::handle = nullptr;
struct DevHandle *(*AudioAlsaLibRenderTest::BindServiceRender)(const char *serverName) = nullptr;
void (*AudioAlsaLibRenderTest::CloseServiceRender)(struct DevHandle *handle) = nullptr;
void AudioAlsaLibRenderTest::SetUpTestCase(void)
{
    char resolvedPath[] = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_render");
    ptrHandle = dlopen(resolvedPath, RTLD_LAZY);
    ASSERT_NE(nullptr, ptrHandle);
    InterfaceLibOutputRender = (int32_t (*)(struct DevHandle *, int,
        struct AudioHwRenderParam *))dlsym(ptrHandle, "AudioInterfaceLibOutputRender");
    ASSERT_NE(nullptr, InterfaceLibOutputRender);
    InterfaceLibCtlRender = (int32_t (*)(struct DevHandle *, int,
        struct AudioHwRenderParam *))dlsym(ptrHandle, "AudioInterfaceLibCtlRender");
    ASSERT_NE(nullptr, InterfaceLibCtlRender);
    BindServiceRender = (struct DevHandle* (*)(const char *))dlsym(ptrHandle, "AudioBindServiceRender");
    ASSERT_NE(nullptr, BindServiceRender);
    CloseServiceRender = (void (*)(struct DevHandle *))dlsym(ptrHandle, "AudioCloseServiceRender");
    ASSERT_NE(nullptr, CloseServiceRender);
}

void AudioAlsaLibRenderTest::TearDownTestCase(void)
{
    if (InterfaceLibOutputRender != nullptr) {
        InterfaceLibOutputRender = nullptr;
    }
    if (InterfaceLibCtlRender != nullptr) {
        InterfaceLibCtlRender = nullptr;
    }
    if (ptrHandle != nullptr) {
        dlclose(ptrHandle);
        ptrHandle = nullptr;
    }
}

void AudioAlsaLibRenderTest::SetUp(void)
{
    handle = BindServiceRender(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
}

void AudioAlsaLibRenderTest::TearDown(void)
{
    CloseServiceRender(handle);
}

uint32_t AudioAlsaLibRenderTest::PcmBytesToFrames(const struct AudioFrameRenderMode &frameRenderMode,
                                                  uint64_t bytes) const
{
    uint32_t replyByte = static_cast<uint32_t>(bytes);
    return replyByte / (frameRenderMode.attrs.channelCount * (PcmFormatToBits(frameRenderMode.attrs.format) >>
                        MOVE_RIGHT_NUM));
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
int32_t AudioAlsaLibRenderTest::FrameLibStart(FILE *file, struct AudioSampleAttributes attrs,
    struct AudioHeadInfo wavHeadInfo, struct AudioHwRender *hwRender) const
{
    if (hwRender == nullptr) {
        return HDF_FAILURE;
    }
    size_t numRead = 0;
    uint32_t remainingDataSize = wavHeadInfo.dataSize;
    uint32_t bufferSize = PcmFramesToBytes(attrs);
    if (bufferSize <= 0) {
        return HDF_FAILURE;
    }
    hwRender->renderParam.frameRenderMode.buffer = (char *)calloc(1, bufferSize);
    if (hwRender->renderParam.frameRenderMode.buffer == nullptr) {
        return HDF_FAILURE;
    }

    uint32_t readSize = (remainingDataSize > bufferSize) ? bufferSize : remainingDataSize;
    numRead = fread(hwRender->renderParam.frameRenderMode.buffer, readSize, 1, file);
    if (numRead < 1) {
        free(hwRender->renderParam.frameRenderMode.buffer);
        hwRender->renderParam.frameRenderMode.buffer = nullptr;
        return HDF_FAILURE;
    }
    hwRender->renderParam.frameRenderMode.bufferSize = readSize;
    hwRender->renderParam.frameRenderMode.bufferFrameSize =
        PcmBytesToFrames(hwRender->renderParam.frameRenderMode, readSize);
    return HDF_SUCCESS;
}

int32_t AudioAlsaLibRenderTest::LibRenderStart(struct AudioHwRender *hwRender, struct DevHandle *handlerender) const
{
    if (hwRender == nullptr) {
        return HDF_FAILURE;
    }

    if (InterfaceLibOutputRender(handlerender, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam) ||
        InterfaceLibOutputRender(handlerender, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam) ||
        InterfaceLibOutputRender(handlerender, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam) ||
        InterfaceLibOutputRender(handlerender, AUDIO_DRV_PCM_IOCTRL_START, &hwRender->renderParam)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioAlsaLibRenderTest::CreatHwRender(struct AudioHwRender *&hwRender, const std::string adapterNameCase) const
{
    int32_t ret = HDF_FAILURE;
    hwRender = (struct AudioHwRender *)calloc(1, sizeof(*hwRender));
    if (hwRender == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitHwRender(hwRender, adapterNameCase;
    if (ret != HDF_SUCCESS) {
        free(hwRender);
        hwRender = nullptr;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_RENDER_OPEN/
            AUDIO_DRV_PCM_IOCTL_RENDER_CLOSE.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Open_001
* @tc.desc  test Audio Alsalib Interface OutputRender.return 0 if the Interface call successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Open_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via stting cmdid is AUDIO_DRV_PCM_IOCTL_RENDER_OPEN twins.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Open_002
* @tc.desc  test Audio lib Interface OutputRender.return -1 if stting cmdid is AUDIO_DRV_PCM_IOCTL_RENDER_OPEN twins.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Open_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_ERR_DEVICE_BUSY, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_RENDER_CLOSE without opning.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Close_001
* @tc.desc  test Audio lib Interface OutputRender.return -1 if without opning.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Close_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via stting cmdid is AUDIO_DRV_PCM_IOCTL_RENDER_CLOSE twins.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Close_002
* @tc.desc  test Audio lib Interface OutputRender.return -1 if stting cmdid is AUDIO_DRV_PCM_IOCTL_RENDER_CLOSE twins.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Close_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_HW_PARAMS.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_HwParams_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_HwParams_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_HW_PARAMS but without opening.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_HwParams_002
* @tc.desc  test Audio lib Interface OutputRender.return -1 if without opening.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_HwParams_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via stting cmdid is AUDIO_DRV_PCM_IOCTL_HW_PARAMS twins.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_HwParams_003
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_HwParams_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_PREPARE.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Prepare_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Prepare_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_PREPARE but without setting params.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Prepare_002
* @tc.desc  test Audio lib Interface OutputRender.return -1 if without setting params.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Prepare_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_PREPARE twice.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Prepare_003
* @tc.desc  test Audio lib Interface OutputRender.return -1 if the Interface call twice.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Prepare_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}

/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTRL_START/AUDIO_DRV_PCM_IOCTRL_STOP.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Start_Stop_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Start_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_START, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}

/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTRL_START/AUDIO_DRV_PCM_IOCTRL_STOP
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Start_Stop_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if without opening.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Stop_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_START, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputCapture API via cmdid is AUDIO_DRV_PCM_IOCTRL_STOP.
* @tc.number  SUB_Audio_InterfaceLibOutputCapture_Stop_002
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if the Interface call unsuccessful.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Stop_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTRL_STOP twice
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Start_Stop_001
* @tc.desc  test Audio lib Interface OutputRender.return -1 if the Interface call twice.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Stop_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_START, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}

/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_WRITE.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Write_001
* @tc.desc  test Audio lib Interface OutputRender and Normal data flow distribution.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Write_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHeadInfo wavHeadInfo = {};
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    char absPath[PATH_MAX] = {0};
    if (realpath(AUDIO_FILE.c_str(), absPath) == nullptr) {
        free(hwRender);
        ASSERT_NE(nullptr, realpath(AUDIO_FILE.c_str(), absPath));
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        free(hwRender);
        ASSERT_NE(nullptr, file);
    }
    ret = LibRenderStart(hwRender, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WavHeadAnalysis(wavHeadInfo, file, hwRender->renderParam.frameRenderMode.attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = FrameLibStart(file, hwRender->renderParam.frameRenderMode.attrs, wavHeadInfo, hwRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    if (hwRender->renderParam.frameRenderMode.buffer != nullptr) {
        free(hwRender->renderParam.frameRenderMode.buffer);
    }
    free(hwRender);
    fclose(file);
}
/**
* @tc.name  test InterfaceLibOutputRender API via cmdid is AUDIO_DRV_PCM_IOCTL_WRITE without starting.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Write_002
* @tc.desc  test Audio lib Interface OutputRender ，return -1 if without starting.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Write_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHeadInfo wavHeadInfo = {};
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    char absPath[PATH_MAX] = {0};
    if (realpath(AUDIO_FILE.c_str(), absPath) == nullptr) {
        free(hwRender);
        ASSERT_NE(nullptr, realpath(AUDIO_FILE.c_str(), absPath));
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        free(hwRender);
        ASSERT_NE(nullptr, file);
    }
    ret = WavHeadAnalysis(wavHeadInfo, file, hwRender->renderParam.frameRenderMode.attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = FrameLibStart(file, hwRender->renderParam.frameRenderMode.attrs, wavHeadInfo, hwRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    if (hwRender->renderParam.frameRenderMode.buffer != nullptr) {
        free(hwRender->renderParam.frameRenderMode.buffer);
    }
    free(hwRender);
    fclose(file);
}

/**
* @tc.name  test InterfaceLibOutputRender API via setting the cmdId is invalid.
* @tc.number  SUB_Audio_InterfaceLibOutputRender__Abnormal_001
* @tc.desc  test Audio lib Interface OutputRender via cmdid is invalid and cmdid is 30,so Interface return -1.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Abnormal_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, 30, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via inputting handleData is nullptr.
* @tc.number  SUB_Audio_InterfaceLibOutputRender_Abnormal_002
* @tc.desc  test Audio lib Interface OutputRender, handleData is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Abnormal_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    ASSERT_NE(nullptr, handle);
    struct AudioHwRenderParam *handleData = nullptr;
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing GetVolthreshold value
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GetVolthresholdRead_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GetVolthresholdRead_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float expMax = 100;
    float expMin = 0;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;
    EXPECT_EQ(expMax, volumeThresholdValueMax);
    EXPECT_EQ(expMin, volumeThresholdValueMin);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value is normal value and reading
*    this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volume_AcodecIn_Write_Read_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volume_Write_Read_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float volumeValue = 0;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float volumeBoundaryValue = 99.9;
    float expectVolumeValue = 99;
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = nullptr;
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax - 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(volumeThresholdValueMax - 1, volumeValue);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin + 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(volumeThresholdValueMin + 1, volumeValue);
    hwRender->renderParam.renderMode.ctlParam.volume = volumeBoundaryValue;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(expectVolumeValue, volumeValue);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value is boundary value and reading
*    this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volume_AcodecIn_Write_Read_002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volume_Write_Read_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float volumeValue = 0;

    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(volumeThresholdValueMin, volumeValue);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(volumeThresholdValueMax, volumeValue);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing volume value is invalid value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Volume_AcodecIn_Write_Read_003
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_Volume_Write_Read_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;

    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax + 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin - 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing mute value that include 1 and 0 and reading mute value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_MuteWrite_Read_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_MUTE_WRITE and AUDIODRV_CTL_IOCTL_MUTE_READ.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_MuteWrite_Read_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    bool muteValue = 1;
    bool wishValue = 0;
    bool expectedValue = 1;

    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = nullptr;
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    hwRender->renderParam.renderMode.ctlParam.mute = 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    muteValue = hwRender->renderParam.renderMode.ctlParam.mute;
    EXPECT_EQ(expectedValue, muteValue);

    hwRender->renderParam.renderMode.ctlParam.mute = 0;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_MUTE_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    muteValue = hwRender->renderParam.renderMode.ctlParam.mute;
    EXPECT_EQ(wishValue, muteValue);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibOutputRender API via pause.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_Pause_001
* @tc.desc  test InterfaceLibOutputRender,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Pause_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;

    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = nullptr;
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = LibRenderStart(hwRender, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.pause = 1;
    ret = InterfaceLibOutputRender(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}

/**
* @tc.name  test InterfaceLibOutputRender API via resuming.
* @tc.number  SUB_Audio_InterfaceLib_CtlRender_Resume_001
* @tc.desc  test InterfaceLibOutputRender,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibOutputRender_Resume_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = nullptr;
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = LibRenderStart(hwRender, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.pause = 0;
    ret = InterfaceLibOutputRender(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibCtlRender API via reading  gain threshold.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE and AUDIODRV_CTL_IOCTL_GAIN_READ.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GainThreshold_Read_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibCtlRender API via writting and reading  gain value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE and AUDIODRV_CTL_IOCTL_GAIN_READ.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_GainWrite_Read_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = nullptr;
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    hwRender->renderParam.renderMode.ctlParam.audioGain.gain = 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_GAIN_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibCtlRender API via writing ChannelMode value is normal value and reading this value.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_ChannelMode_Write_Read_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE
*    and AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_ChannelMode_Write_Read_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = nullptr;
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    hwRender->renderParam.frameRenderMode.mode = AUDIO_CHANNEL_BOTH_RIGHT;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  test InterfaceLibCtlRender API via selecting scene.
* @tc.number  SUB_Audio_InterfaceLib_CtlRender_SelectScene_001
* @tc.desc  test InterfaceLibCtlRender,cmdId is AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLib_CtlRender_SelectScene_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = nullptr;
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = LibRenderStart(hwRender, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);

    struct AudioSceneDescriptor scene = {};
    scene.scene.id = 0;
    scene.desc.pins = PIN_OUT_HEADSET;

    hwRender->renderParam.renderMode.hwInfo.pathSelect.deviceInfo.deviceNum = 1;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[0].deviceSwitch,
        PATHPLAN_COUNT, "Dacl enable");
    hwRender->renderParam.renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[0].value = 0;
    hwRender->renderParam.frameRenderMode.attrs.type = (enum AudioCategory)(scene.scene.id);
    hwRender->renderParam.renderMode.hwInfo.deviceDescript.pins = scene.desc.pins;

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwRender);
    hwRender = nullptr;
}

/**
* @tc.name  test InterfaceLibCtlRender API via cmdId is AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER.
* @tc.number  SUB_Audio_InterfaceLibCtlRender_MuteWrite_Read_001
* @tc.desc  test InterfaceLibCtlRender ,return 0 if the Interface call successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioAlsaLibRenderTest, SUB_Audio_InterfaceLibCtlRender_ReqMmpbuffer_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    int64_t fileSize = 0;

    ASSERT_NE(nullptr, handle);
    struct AudioHwRender *hwRender = nullptr;
    ret = CreatHwRender(hwRender, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = LibRenderStart(hwRender, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = RenderReqMmapBufferInit(hwRender->renderParam.frameRenderMode, LOW_LATENCY_AUDIO_FILE, fileSize);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    munmap(hwRender->renderParam.frameRenderMode.mmapBufDesc.memoryAddress, fileSize);
    free(hwRender);
    hwRender = nullptr;
}
}