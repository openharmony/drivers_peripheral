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
#include "audio_libcapture_test.h"
using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const string BIND_CONTROL = "control";

class AudioAlsaLibCaptureTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static int32_t (*InterfaceLibOutputCapture)(struct DevHandle *, int, struct AudioHwCaptureParam *);
    static int32_t (*InterfaceLibCtlCapture)(struct DevHandle *, int, struct AudioHwCaptureParam *);
    static void *ptrHandle;
    static struct DevHandle *handle;
    static struct DevHandle *(*BindServiceCapture)(const char *);
    static void (*CloseServiceCapture)(struct DevHandle *);
    int32_t CreatHwCapture(struct AudioHwCapture *&hwCapture, const std::string adapterNameCase) const;
    int32_t LibCaptureStart(struct AudioHwCapture *hwCapture, struct DevHandle *handleCapture) const;
};

int32_t (*AudioAlsaLibCaptureTest::InterfaceLibOutputCapture)(struct DevHandle *, int,
    struct AudioHwCaptureParam *) = nullptr;
int32_t (*AudioAlsaLibCaptureTest::InterfaceLibCtlCapture)(struct DevHandle *, int,
    struct AudioHwCaptureParam *) = nullptr;
void *AudioAlsaLibCaptureTest::ptrHandle = nullptr;
struct DevHandle *AudioAlsaLibCaptureTest::handle = nullptr;
struct DevHandle *(*AudioAlsaLibCaptureTest::BindServiceCapture)(const char *) = nullptr;
void (*AudioAlsaLibCaptureTest::CloseServiceCapture)(struct DevHandle *) = nullptr;
void AudioAlsaLibCaptureTest::SetUpTestCase(void)
{
    char resolvedPath[] = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_capture");
    ptrHandle = dlopen(resolvedPath, RTLD_LAZY);
    ASSERT_NE(nullptr, ptrHandle);
    InterfaceLibOutputCapture = (int32_t (*)(struct DevHandle *, int,
                                 struct AudioHwCaptureParam *))dlsym(ptrHandle, "AudioInterfaceLibOutputCapture");
    ASSERT_NE(nullptr, InterfaceLibOutputCapture);
    InterfaceLibCtlCapture = (int32_t (*)(struct DevHandle *, int,
                                          struct AudioHwCaptureParam *))dlsym(ptrHandle, "AudioInterfaceLibCtlCapture");
    ASSERT_NE(nullptr, InterfaceLibCtlCapture);
    BindServiceCapture = reinterpret_cast<struct DevHandle* (*)(const char *)>(dlsym(ptrHandle,
        "AudioBindServiceCapture"));
    ASSERT_NE(nullptr, BindServiceCapture);
    CloseServiceCapture = (void (*)(struct DevHandle *))dlsym(ptrHandle, "AudioCloseServiceCapture");
    ASSERT_NE(nullptr, CloseServiceCapture);
}

void AudioAlsaLibCaptureTest::TearDownTestCase(void)
{
    if (InterfaceLibCtlCapture != nullptr) {
        InterfaceLibCtlCapture = nullptr;
    }
    if (InterfaceLibOutputCapture != nullptr) {
        InterfaceLibOutputCapture = nullptr;
    }
    if (ptrHandle != nullptr) {
        dlclose(ptrHandle);
        ptrHandle = nullptr;
    }
}

void AudioAlsaLibCaptureTest::SetUp(void)
{
    handle = BindServiceCapture(BIND_CONTROL.c_str());
    ASSERT_NE(nullptr, handle);
}

void AudioAlsaLibCaptureTest::TearDown(void)
{
    CloseServiceCapture(handle);
    handle = nullptr;
}

int32_t AudioAlsaLibCaptureTest::CreatHwCapture(struct AudioHwCapture *&hwCapture,
    const std::string adapterNameCase) const
{
    hwCapture = static_cast<struct AudioHwCapture *>(calloc(1, sizeof(*hwCapture)));
    if (hwCapture == nullptr) {
        return HDF_FAILURE;
    }
    if (InitHwCapture(hwCapture, adapterNameCase)) {
        free(hwCapture);
        hwCapture = nullptr;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
int32_t AudioAlsaLibCaptureTest::LibCaptureStart(struct AudioHwCapture *hwCapture,
    struct DevHandle *handleCapture) const
{
    if (hwCapture == nullptr) {
        return HDF_FAILURE;
    }

    if (InterfaceLibOutputCapture(handleCapture, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam) ||
        InterfaceLibOutputCapture(handleCapture, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam) ||
        InterfaceLibOutputCapture(handleCapture, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, &hwCapture->captureParam) ||
        InterfaceLibOutputCapture(handleCapture, AUDIO_DRV_PCM_IOCTRL_START_CAPTURE, &hwCapture->captureParam)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureOpen_001
* @tc.desc  test Audio lib Interface OutputCapture.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureOpen_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureOpen_002
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if seting cmdid is AUDIO_DRV_PCM_IOCTL_Capture_OPEN twins.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureOpen_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_ERR_DEVICE_BUSY, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureClose_001
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if without opening.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureClose_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureClose_002
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if seting cmdid is AUDIO_DRV_PCM_IOCTL_Capture_CLOSE twins.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureClose_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(hwCapture);
    hwCapture = nullptr;
}

/**
* @tc.name  AudioInterfaceLibOutputCaptureHwParams_001
* @tc.desc  test Audio lib Interface OutputCapture.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureHwParams_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureHwParams_002
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if without opening.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureHwParams_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureHwParams_003
* @tc.desc  test Audio lib Interface OutputCapture.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureHwParams_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCapturePrepare_001
* @tc.desc  test Audio lib Interface OutputCapture.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCapturePrepare_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCapturePrepare_002
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if without setting params.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCapturePrepare_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCapturePrepare_003
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if the Interface call twice.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCapturePrepare_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}

/**
* @tc.name  AudioInterfaceLibOutputCaptureStart_001
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if the Interface call unsuccessful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureStart_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_START_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureStop_001
* @tc.desc  test Audio lib Interface OutputCapture.return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureStop_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_START_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureStop_002
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if the Interface call unsuccessful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureStop_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureStop_003
* @tc.desc  test Audio lib Interface OutputCapture.return -1 if the Interface call twice.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureStop_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_HW_PARAMS, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_START_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}

/**
* @tc.name  AudioInterfaceLibOutputCaptureRead_001
* @tc.desc  test Audio lib Interface OutputCapture and Normal data flow distribution.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureRead_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = LibCaptureStart(hwCapture, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwCapture->captureParam.frameCaptureMode.buffer = (char *)calloc(1, BUFFER_LENTH);
    if (hwCapture->captureParam.frameCaptureMode.buffer == nullptr) {
        free(hwCapture);
        hwCapture = nullptr;
        ASSERT_NE(nullptr, hwCapture);
    }
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_READ, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture->captureParam.frameCaptureMode.buffer);
    hwCapture->captureParam.frameCaptureMode.buffer = nullptr;
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureRead_002
* @tc.desc  test Audio lib Interface OutputCapture,return -1 if without starting.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureRead_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    hwCapture->captureParam.frameCaptureMode.buffer = (char *)calloc(1, BUFFER_LENTH);
    if (hwCapture->captureParam.frameCaptureMode.buffer == nullptr) {
        free(hwCapture);
        hwCapture = nullptr;
        ASSERT_NE(nullptr, hwCapture);
    }
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_READ, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(hwCapture->captureParam.frameCaptureMode.buffer);
    hwCapture->captureParam.frameCaptureMode.buffer = nullptr;
    free(hwCapture);
    hwCapture = nullptr;
}

/**
* @tc.name  AudioInterfaceLibOutputCaptureAbnormal_001
* @tc.desc  test OutputCapture interface, return -1 if the cmdId is invalid.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureAbnormal_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibOutputCapture(handle, 30, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureAbnormal_002
* @tc.desc   Test Outputcapture interface, return -1 if the incoming parameter handleData is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureAbnormal_002, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, handle);
    struct AudioHwCaptureParam *handleData = nullptr;
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_READ, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureGetVolthresholdRead_001
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureGetVolthresholdRead_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float expMax = 100;
    float expMin = 0;
    struct AudioHwCapture *hwCapture = nullptr;
    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;
    EXPECT_EQ(expMax, volumeThresholdValueMax);
    EXPECT_EQ(expMin, volumeThresholdValueMin);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureVolumeWriteRead_001
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureVolumeWriteRead_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeValue = 0;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float volumeBoundaryValue = 99.9;
    float expectVolumeValue = 99;
    ASSERT_NE(nullptr, handle);
    struct AudioHwCapture *hwCapture = nullptr;
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);


    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMax - 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwCapture->captureParam.captureMode.ctlParam.volume;
    EXPECT_EQ(volumeThresholdValueMax - 1, volumeValue);

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMin + 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwCapture->captureParam.captureMode.ctlParam.volume;
    EXPECT_EQ(volumeThresholdValueMin + 1, volumeValue);
    hwCapture->captureParam.captureMode.ctlParam.volume = volumeBoundaryValue;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwCapture->captureParam.captureMode.ctlParam.volume;
    EXPECT_EQ(expectVolumeValue, volumeValue);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureVolumeWriteRead_002
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureVolumeWriteRead_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float volumeValue = 0;

    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMin;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwCapture->captureParam.captureMode.ctlParam.volume;
    EXPECT_EQ(volumeThresholdValueMin, volumeValue);

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMax;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwCapture->captureParam.captureMode.ctlParam.volume;
    EXPECT_EQ(volumeThresholdValueMax, volumeValue);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureVolume_AcodecIn_Write_Read_003
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureVolumeWriteRead_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioHwCapture *hwCapture = nullptr;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    float volumeValue = 0;

    ASSERT_NE(nullptr, handle);
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMax + 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMin - 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    volumeValue = hwCapture->captureParam.captureMode.ctlParam.volume;
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureMuteWriteRead_001
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_MUTE_WRITE and AUDIODRV_CTL_IOCTL_MUTE_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureMuteWriteRead_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteValue = 1;
    bool wishValue = 0;
    bool expectedValue = 1;

    ASSERT_NE(nullptr, handle);
    struct AudioHwCapture *hwCapture = nullptr;
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    hwCapture->captureParam.captureMode.ctlParam.mute = 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    muteValue = hwCapture->captureParam.captureMode.ctlParam.mute;
    EXPECT_EQ(expectedValue, muteValue);

    hwCapture->captureParam.captureMode.ctlParam.mute = 0;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    muteValue = hwCapture->captureParam.captureMode.ctlParam.mute;
    EXPECT_EQ(wishValue, muteValue);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCapturePause_001
* @tc.desc  test InterfaceLibOutputCapture,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCapturePause_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, handle);
    struct AudioHwCapture *hwCapture = nullptr;
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = LibCaptureStart(hwCapture, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);

    hwCapture->captureParam.captureMode.ctlParam.pause = 1;
    ret = InterfaceLibOutputCapture(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibOutputCaptureResume_001
* @tc.desc  test InterfaceLibOutputCapture,cmdId is AUDIODRV_CTL_IOCTL_PAUSE_WRITE.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibOutputCaptureResume_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, handle);
    struct AudioHwCapture *hwCapture = nullptr;
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = LibCaptureStart(hwCapture, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);

    hwCapture->captureParam.captureMode.ctlParam.pause = 0;
    ret = InterfaceLibOutputCapture(handle, AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureGetGainthresholdRead_001
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE(23).
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureGetGainthresholdRead_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, handle);
    struct AudioHwCapture *hwCapture = nullptr;
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureGainWriteRead_001
* @tc.desc  test InterfaceLibCtlCapture,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE and
*    AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureGainWriteRead_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, handle);
    struct AudioHwCapture *hwCapture = nullptr;
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    hwCapture->captureParam.captureMode.ctlParam.audioGain.gain = 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureSelectScene_001
* @tc.desc  test InterfaceLibCtlCapture,cmdId is AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureSelectScene_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, handle);
    struct AudioHwCapture *hwCapture = nullptr;
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);

    struct AudioSceneDescriptor scene = {
        .scene.id = 0,
        .desc.pins = PIN_IN_HS_MIC,
    };
    hwCapture->captureParam.captureMode.hwInfo.pathSelect.deviceInfo.deviceNum = 1;
    ret = strcpy_s(hwCapture->captureParam.captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[0].deviceSwitch,
        PATHPLAN_COUNT, "LPGA MIC Switch");
    hwCapture->captureParam.captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[0].value = 0;
    hwCapture->captureParam.frameCaptureMode.attrs.type = (enum AudioCategory)(scene.scene.id);
    hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = scene.desc.pins;

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);

    free(hwCapture);
    hwCapture = nullptr;
}

/**
* @tc.name  AudioInterfaceLibCtlCaptureReqMmpbuffer_001
* @tc.desc  test InterfaceLibCtlCapture ,return 0 if the Interface call successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioAlsaLibCaptureTest, AudioInterfaceLibCtlCaptureReqMmpbuffer_001, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, handle);
    struct AudioHwCapture *hwCapture = nullptr;
    ret = CreatHwCapture(hwCapture, ADAPTER_NAME);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = LibCaptureStart(hwCapture, handle);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CaptureReqMmapBufferInit(hwCapture->captureParam.frameCaptureMode,
                                   AUDIO_LOW_LATENCY_CAPTURE_FILE, FILE_CAPTURE_SIZE);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibOutputCapture(handle, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    munmap(hwCapture->captureParam.frameCaptureMode.mmapBufDesc.memoryAddress, FILE_CAPTURE_SIZE);
    free(hwCapture);
    hwCapture = nullptr;
}
}
