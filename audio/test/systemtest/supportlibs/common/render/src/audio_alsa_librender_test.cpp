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
    BindServiceRender = reinterpret_cast<struct DevHandle* (*)(const char *)>(dlsym(ptrHandle,
        "AudioBindServiceRender"));
    ASSERT_NE(nullptr, BindServiceRender);
    CloseServiceRender = (void (*)(static_cast<struct DevHandle *>))dlsym(ptrHandle, "AudioCloseServiceRender");
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
    uint32_t frameCount = (frameRenderMode.attrs.channelCount * (PcmFormatToBits(frameRenderMode.attrs.format) >>
        MOVE_RIGHT_NUM));
    if (frameCount == 0) {
        return 0;
    }
    return replyByte / frameCount;
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
    hwRender->renderParam.frameRenderMode.buffer = static_cast<char *>(calloc(1, bufferSize));
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
    uint32_t bufferFrameSize = PcmBytesToFrames(hwRender->renderParam.frameRenderMode, readSize);
    if (bufferFrameSize <= 0) {
        return HDF_FAILURE;
    }
    hwRender->renderParam.frameRenderMode.bufferFrameSize = bufferFrameSize;
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
    hwRender = static_cast<struct AudioHwRender *>(calloc(1, sizeof(*hwRender)));
    if (hwRender == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitHwRender(hwRender, adapterNameCase);
    if (ret != HDF_SUCCESS) {
        free(hwRender);
        hwRender = nullptr;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
/**
* @tc.name  AudioInterfaceLibOutputRenderOpen_001
* @tc.desc  test Audio Alsalib Interface OutputRender.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderOpen_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderOpen_002
* @tc.desc  test Audio lib Interface OutputRender.return -1 if stting cmdid is AUDIO_DRV_PCM_IOCTL_RENDER_OPEN twins.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderOpen_002, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderClose_001
* @tc.desc  test Audio lib Interface OutputRender.return -1 if without opning.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderClose_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderClose_002
* @tc.desc  test Audio lib Interface OutputRender.return -1 if stting cmdid is AUDIO_DRV_PCM_IOCTL_RENDER_CLOSE twins.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderClose_002, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderHwParams_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderHwParams_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderHwParams_002
* @tc.desc  test Audio lib Interface OutputRender.return -1 if without opening.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderHwParams_002, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderHwParams_003
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderHwParams_003, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderPrepare_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderPrepare_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderPrepare_002
* @tc.desc  test Audio lib Interface OutputRender.return -1 if without setting params.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderPrepare_002, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderPrepare_003
* @tc.desc  test Audio lib Interface OutputRender.return -1 if the Interface call twice.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderPrepare_003, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderStart_Stop_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderStart_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderStart_Stop_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if without opening.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderStop_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputCaptureStop_002
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if the Interface call unsuccessful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderStop_002, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderStart_Stop_001
* @tc.desc  test Audio lib Interface OutputRender.return -1 if the Interface call twice.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderStop_003, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderWrite_001
* @tc.desc  test Audio lib Interface OutputRender and Normal data flow distribution.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderWrite_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderWrite_002
* @tc.desc  test Audio lib Interface OutputRender ，return -1 if without starting.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderWrite_002, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRender_Abnormal_001
* @tc.desc  test Audio lib Interface OutputRender via cmdid is invalid and cmdid is 30,so Interface return -1.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderAbnormal_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderAbnormal_002
* @tc.desc  test Audio lib Interface OutputRender, handleData is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderAbnormal_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    ASSERT_NE(nullptr, handle);
    struct AudioHwRenderParam *handleData = nullptr;
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioInterfaceLibCtlRenderGetVolthresholdRead_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderGetVolthresholdRead_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderVolumeWriteRead_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderVolumeWriteRead_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderVolumeWriteRead_002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderVolumeWriteRead_002, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderVolumeWriteRead_003
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderVolumeWriteRead_003, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderMuteWriteRead_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_MUTE_WRITE and AUDIODRV_CTL_IOCTL_MUTE_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderMuteWriteRead_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderPause_001
* @tc.desc  test InterfaceLibOutputRender,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderPause_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibOutputRenderResume_001
* @tc.desc  test InterfaceLibOutputRender,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibOutputRenderResume_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderGainThresholdRead_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE and AUDIODRV_CTL_IOCTL_GAIN_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderGainThresholdRead_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderGainWriteRead_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE and AUDIODRV_CTL_IOCTL_GAIN_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderGainWriteRead_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderChannelModeWriteRead_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE
*    and AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderChannelModeWriteRead_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderSelectScene_001
* @tc.desc  test InterfaceLibCtlRender,cmdId is AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderSelectScene_001, TestSize.Level1)
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
* @tc.name  AudioInterfaceLibCtlRenderReqMmpbuffer_001
* @tc.desc  test InterfaceLibCtlRender ,return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibRenderTest, AudioInterfaceLibCtlRenderReqMmpbuffer_001, TestSize.Level1)
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