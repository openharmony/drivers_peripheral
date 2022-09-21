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
const string BIND_RENDER = "render";
const string BIND_NAME_ERROR = "rendor";
class AudioLibRenderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static struct DevHandle *(*BindServiceRenderSo)(const char *serverName);
    static int32_t (*InterfaceLibOutputRender)(struct DevHandle *handle, int cmdId,
        struct AudioHwRenderParam *handleData);
    static int32_t (*InterfaceLibCtlRender)(struct DevHandle *handle, int cmdId,
        struct AudioHwRenderParam *handleData);
    static void (*CloseServiceRenderSo)(struct DevHandle *handle);
    static void *ptrHandle;
    uint32_t PcmBytesToFrames(const struct AudioFrameRenderMode &frameRenderMode, uint64_t bytes) const;
    int32_t FrameLibStart(FILE *file, struct AudioSampleAttributes attrs,
        struct AudioHeadInfo wavHeadInfo, struct AudioHwRender *hwRender) const;
    int32_t LibStartAndStream(const std::string path, struct AudioSampleAttributes attrs,
        struct DevHandle *handle, struct AudioHwRender *hwRender, struct AudioHeadInfo wavHeadInfo) const;
    int32_t LibHwOutputRender(struct AudioHwRender *hwRender, struct DevHandle *handlerender) const;
    int32_t BindServiceAndHwRender(struct AudioHwRender *&hwRender,
        const std::string BindName, const std::string adapterNameCase, struct DevHandle *&handle) const;
};

struct DevHandle *(*AudioLibRenderTest::BindServiceRenderSo)(const char *serverName) = nullptr;
int32_t (*AudioLibRenderTest::InterfaceLibOutputRender)(struct DevHandle *handle, int cmdId,
    struct AudioHwRenderParam *handleData) = nullptr;
int32_t (*AudioLibRenderTest::InterfaceLibCtlRender)(struct DevHandle *handle, int cmdId,
    struct AudioHwRenderParam *handleData) = nullptr;
void (*AudioLibRenderTest::CloseServiceRenderSo)(struct DevHandle *handle) = nullptr;
void *AudioLibRenderTest::ptrHandle = nullptr;

void AudioLibRenderTest::SetUpTestCase(void)
{
    char resolvedPath[] = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_render");
    ptrHandle = dlopen(resolvedPath, RTLD_LAZY);
    if (ptrHandle == nullptr) {
        return;
    }
    BindServiceRenderSo = reinterpret_cast<struct DevHandle* (*)(const char *serverName)>(dlsym(ptrHandle,
        "AudioBindServiceRender"));
    InterfaceLibOutputRender = (int32_t (*)(struct DevHandle *, int cmdId,
        struct AudioHwRenderParam *handleData))dlsym(ptrHandle, "AudioInterfaceLibOutputRender");
    InterfaceLibCtlRender = (int32_t (*)(struct DevHandle *, int cmdId,
        struct AudioHwRenderParam *handleData))dlsym(ptrHandle, "AudioInterfaceLibCtlRender");
    CloseServiceRenderSo = reinterpret_cast<void (*)(struct DevHandle *)>(dlsym(ptrHandle, "AudioCloseServiceRender"));
    if (BindServiceRenderSo == nullptr || CloseServiceRenderSo == nullptr ||
        InterfaceLibCtlRender == nullptr || InterfaceLibOutputRender == nullptr) {
        dlclose(ptrHandle);
        return;
    }
}

void AudioLibRenderTest::TearDownTestCase(void)
{
    if (BindServiceRenderSo != nullptr) {
        BindServiceRenderSo = nullptr;
    }
    if (CloseServiceRenderSo != nullptr) {
        CloseServiceRenderSo = nullptr;
    }
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

void AudioLibRenderTest::SetUp(void) {}

void AudioLibRenderTest::TearDown(void) {}

uint32_t AudioLibRenderTest::PcmBytesToFrames(const struct AudioFrameRenderMode &frameRenderMode, uint64_t bytes) const
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
int32_t AudioLibRenderTest::FrameLibStart(FILE *file, struct AudioSampleAttributes attrs,
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
    hwRender->renderParam.frameRenderMode.bufferFrameSize =
        PcmBytesToFrames(hwRender->renderParam.frameRenderMode, readSize);
    return HDF_SUCCESS;
}

int32_t AudioLibRenderTest::LibStartAndStream(const std::string path, struct AudioSampleAttributes attrs,
    struct DevHandle *handle, struct AudioHwRender *hwRender, struct AudioHeadInfo wavHeadInfo) const
{
    int ret = HDF_FAILURE;
    if (handle == nullptr || hwRender == nullptr || InterfaceLibOutputRender == nullptr) {
        return HDF_FAILURE;
    }
    if (InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam) ||
        InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam) ||
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
        (void)fclose(file);
        return HDF_FAILURE;
    }
    ret = FrameLibStart(file, attrs, wavHeadInfo, hwRender);
    if (ret < 0) {
        (void)fclose(file);
        return HDF_FAILURE;
    }
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, &hwRender->renderParam);
    if (ret < 0) {
        (void)fclose(file);
        free(hwRender->renderParam.frameRenderMode.buffer);
        hwRender->renderParam.frameRenderMode.buffer = nullptr;
        return HDF_FAILURE;
    }
    (void)fclose(file);
    free(hwRender->renderParam.frameRenderMode.buffer);
    hwRender->renderParam.frameRenderMode.buffer = nullptr;
    return HDF_SUCCESS;
}

int32_t AudioLibRenderTest::LibHwOutputRender(struct AudioHwRender *hwRender, struct DevHandle *handlerender) const
{
    if (hwRender == nullptr || handlerender == nullptr || InterfaceLibOutputRender == nullptr) {
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

int32_t AudioLibRenderTest::BindServiceAndHwRender(struct AudioHwRender *&hwRender,
    const std::string BindName, const std::string adapterNameCase, struct DevHandle *&handle) const
{
    if (BindServiceRenderSo == nullptr || CloseServiceRenderSo == nullptr) {
        return HDF_FAILURE;
    }
    int32_t ret = HDF_FAILURE;
    handle = BindServiceRenderSo(BindName.c_str());
    if (handle == nullptr) {
        return HDF_FAILURE;
    }
    hwRender = static_cast<struct AudioHwRender *>(calloc(1, sizeof(*hwRender)));
    if (hwRender == nullptr) {
        CloseServiceRenderSo(handle);
        return HDF_FAILURE;
    }
    ret = InitHwRender(hwRender, adapterNameCase);
    if (ret != HDF_SUCCESS) {
        CloseServiceRenderSo(handle);
        free(hwRender);
        hwRender = nullptr;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
/**
* @tc.name  AudioInterfaceLibBindServiceRender_001
* @tc.desc  test Binding succeeded Service which service Name is control_service and close Service.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibBindServiceRender_001, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    ASSERT_TRUE((BindServiceRenderSo != nullptr && CloseServiceRenderSo != nullptr));
    handle = BindServiceRenderSo(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
    CloseServiceRenderSo(handle);
}
/**
* @tc.name  AudioInterfaceLibBindServiceRender_002
* @tc.desc  test Binding failed service, where the service name is wrong.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibBindServiceRender_002, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    ASSERT_TRUE((BindServiceRenderSo != nullptr && CloseServiceRenderSo != nullptr));
    handle = BindServiceRenderSo(BIND_NAME_ERROR.c_str());
    if (handle != nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(nullptr, handle);
    }
    EXPECT_EQ(nullptr, handle);
}
/**
* @tc.name  AudioInterfaceLibBindServiceRender_003
* @tc.desc  test Binding failed Service, nullptr pointer passed in.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibBindServiceRender_003, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    char *bindNameNull = nullptr;
    ASSERT_TRUE((BindServiceRenderSo != nullptr && CloseServiceRenderSo != nullptr));
    handle = BindServiceRenderSo(bindNameNull);
    if (handle != nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(nullptr, handle);
    }
    EXPECT_EQ(nullptr, handle);
}
/**
* @tc.name  AudioInterfaceLibBindServiceRender_004
* @tc.desc  test Binding failed Service, Log printing 'service name not support!' and 'Failed to get service!'.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibBindServiceRender_004, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    string bindNameOverLen = "renderrenderedededededede";
    ASSERT_TRUE((BindServiceRenderSo != nullptr && CloseServiceRenderSo != nullptr));
    handle = BindServiceRenderSo(bindNameOverLen.c_str());
    if (handle != nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(nullptr, handle);
    }
    EXPECT_EQ(nullptr, handle);
}
/**
* @tc.name  AudioInterfaceLibBindServiceRender_005
* @tc.desc  test Binding failed Service, Log printing 'Failed to snprintf_s'.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibBindServiceRender_005, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    string bindNameOverLen = "renderrenderededededededer";
    ASSERT_TRUE((BindServiceRenderSo != nullptr && CloseServiceRenderSo != nullptr));
    handle = BindServiceRenderSo(bindNameOverLen.c_str());
    if (handle != nullptr) {
        CloseServiceRenderSo(handle);
        ASSERT_EQ(nullptr, handle);
    }
    EXPECT_EQ(nullptr, handle);
}
/**
* @tc.name  AudioInterfaceLibCtlRenderMuteWriteRead_001
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_MUTE_WRITE and AUDIODRV_CTL_IOCTL_MUTE_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibCtlRenderMuteWriteRead_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    bool muteValue = 1;
    bool wishValue = 0;
    bool expectedValue = 1;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibCtlRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

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
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlRenderMuteWriteRead_002
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_MUTE_WRITE and AUDIODRV_CTL_IOCTL_MUTE_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibCtlRenderMuteWriteRead_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    bool muteValue = 0;
    bool wishValue = 0;
    bool expectedValue = 1;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibCtlRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    hwRender->renderParam.renderMode.ctlParam.mute = 2;
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
    CloseServiceRenderSo(handle);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlRenderAbnormal_001
* @tc.desc  test InterfaceLibCtlRender, cmdId is invalid eg 50,so return -1.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibCtlRenderAbnormal_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibCtlRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, 50, &hwRender->renderParam);
    if (ret == 0) {
        CloseServiceRenderSo(handle);
        free(hwRender);
        hwRender = nullptr;
        ASSERT_EQ(HDF_FAILURE, ret);
    }
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlRenderAbnormal_002
* @tc.desc  test InterfaceLibCtlRender, handleData is nullptr,so return -1.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibCtlRenderAbnormal_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwRenderParam *handleData = nullptr;
    ASSERT_TRUE((InterfaceLibCtlRender != nullptr && BindServiceRenderSo != nullptr &&
        CloseServiceRenderSo != nullptr));
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
* @tc.name  AudioInterfaceLibOutputRenderHwParams_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderHwParams_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_RENDER.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputRenderPrepare_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderPrepare_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioHwRender *hwRender = nullptr;
    struct DevHandle *handle = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_RENDER.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_PREPARE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputRenderStart_001
* @tc.desc  test Audio lib Interface OutputRender.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderStart_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_RENDER.c_str(), ADAPTER_NAME, handle);
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
    CloseServiceRenderSo(handle);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputRenderWriteStop_001
* @tc.desc  test Audio lib Interface OutputRender and Normal data flow distribution.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderWriteStop_001, TestSize.Level1)
{
    struct DevHandle *handle = nullptr;
    struct AudioHeadInfo wavHeadInfo = {};
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr));
    int32_t ret = BindServiceAndHwRender(hwRender, BIND_RENDER.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = LibHwOutputRender(hwRender, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    char absPath[PATH_MAX] = {0};
    if (realpath(AUDIO_FILE.c_str(), absPath) == nullptr) {
        free(hwRender);
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, realpath(AUDIO_FILE.c_str(), absPath));
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        free(hwRender);
        CloseServiceRenderSo(handle);
        ASSERT_NE(nullptr, file);
    }
    if (hwRender != nullptr) {
        ret = WavHeadAnalysis(wavHeadInfo, file, hwRender->renderParam.frameRenderMode.attrs);
        if (ret < 0) {
            free(hwRender);
            fclose(file);
            CloseServiceRenderSo(handle);
            ASSERT_EQ(HDF_SUCCESS, ret);
        }
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
    }
    CloseServiceRenderSo(handle);
    fclose(file);
}
/**
    transmission of data flow and control flow.
* @tc.name  AudioInterfaceLibOutputRenderWrite_001
* @tc.desc  test Audio lib Interface CtlRender and OutputRender, Data stream and control stream send successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderWrite_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float muteValue = 0;
    float expectedValue = 0;
    struct DevHandle *handler = nullptr;
    struct DevHandle *handlec = nullptr;
    struct AudioHeadInfo wavHeadInfo = {};
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr &&
        InterfaceLibCtlRender != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_RENDER.c_str(), ADAPTER_NAME, handler);
    ASSERT_EQ(HDF_SUCCESS, ret);
    handlec = BindServiceRenderSo(BIND_CONTROL.c_str());
    if (handlec == nullptr) {
        CloseServiceRenderSo(handler);
        free(hwRender);
        hwRender = nullptr;
        ASSERT_NE(nullptr, handlec);
    }
    if (hwRender != nullptr) {
        hwRender->renderParam.renderMode.ctlParam.mute = muteValue;
        ret = InterfaceLibCtlRender(handlec, AUDIODRV_CTL_IOCTL_MUTE_WRITE, &hwRender->renderParam);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = InterfaceLibCtlRender(handlec, AUDIODRV_CTL_IOCTL_MUTE_READ, &hwRender->renderParam);
        EXPECT_EQ(HDF_SUCCESS, ret);
        expectedValue = hwRender->renderParam.renderMode.ctlParam.mute;
        EXPECT_EQ(expectedValue, muteValue);

        ret = LibStartAndStream(AUDIO_FILE, hwRender->renderParam.frameRenderMode.attrs,
            handler, hwRender, wavHeadInfo);
        if (ret < 0) {
            CloseServiceRenderSo(handler);
            CloseServiceRenderSo(handlec);
            free(hwRender);
            ASSERT_EQ(HDF_SUCCESS, ret);
        }
    ret = InterfaceLibOutputRender(handler, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handler, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    }
    CloseServiceRenderSo(handler);
    CloseServiceRenderSo(handlec);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlRenderPause_001
* @tc.desc  test InterfaceLibOutputRender,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderPause_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_RENDER.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = LibHwOutputRender(hwRender, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.pause = 1;
    ret = InterfaceLibOutputRender(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  Audio_InterfaceLib_CtlRender_Resume_001
* @tc.desc  test InterfaceLibOutputRender,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderResume_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_RENDER.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = LibHwOutputRender(hwRender, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwRender->renderParam.renderMode.ctlParam.pause = 0;
    ret = InterfaceLibOutputRender(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_STOP, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputRender_Abnormal_001
* @tc.desc  test Audio lib Interface OutputRender via cmdid is invalid and cmdid is 30,so Interface return -1.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderAbnormal_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr));
    ret = BindServiceAndHwRender(hwRender, BIND_RENDER.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputRender(handle, 30, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
    free(hwRender);
    hwRender = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputRenderAbnormal_002
* @tc.desc  test Audio lib Interface OutputRender, handleData is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibRenderTest, AudioInterfaceLibOutputRenderAbnormal_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwRenderParam *handleData = nullptr;
    ASSERT_TRUE((InterfaceLibOutputRender != nullptr && CloseServiceRenderSo != nullptr &&
        InterfaceLibCtlRender != nullptr));
    handle = BindServiceRenderSo(BIND_RENDER.c_str());
    ASSERT_NE(nullptr, handle);
    ret = InterfaceLibOutputRender(handle, AUDIO_DRV_PCM_IOCTL_WRITE, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceRenderSo(handle);
}
}
