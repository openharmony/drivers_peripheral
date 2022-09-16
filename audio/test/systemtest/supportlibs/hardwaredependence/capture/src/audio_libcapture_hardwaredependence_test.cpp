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
#include "audio_libcapture_hardwaredependence_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const string BIND_CONTROL = "control";

#ifdef PRODUCT_RK3568
    constexpr int MAX_VOLUME = 255;
    constexpr int MIN_VOLUME = 0;
    constexpr int BELOW_MAX_VOLUME = 254;
    constexpr int OVER_MIN_VOLUME = 1;
#else
    constexpr int MAX_VOLUME = 87;
    constexpr int MIN_VOLUME = 0;
    constexpr int BELOW_MAX_VOLUME = 86;
    constexpr int OVER_MIN_VOLUME = 1;
#endif
    constexpr float MAX_GAIN = 15;
    constexpr float MIN_GAIN = 0;
class AudioLibCaptureHardwareDependenceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static struct DevHandle *(*BindServiceCaptureSo)(const char *serverName);
    static int32_t (*InterfaceLibOutputCapture)(struct DevHandle *handle, int cmdId,
                                                struct AudioHwCaptureParam *handleData);
    static int32_t (*InterfaceLibCtlCapture)(struct DevHandle *handle, int cmdId,
                                             struct AudioHwCaptureParam *handleData);
    static void (*CloseServiceCaptureSo)(struct DevHandle *handle);
    static void *ptrHandle;
    int32_t BindServiceAndHwCapture(struct AudioHwCapture *&hwCapture, const std::string BindName,
                                    const std::string adapterNameCase, struct DevHandle *&handle) const;
};

struct DevHandle *(*AudioLibCaptureHardwareDependenceTest::BindServiceCaptureSo)(const char *serverName) = nullptr;
int32_t (*AudioLibCaptureHardwareDependenceTest::InterfaceLibOutputCapture)(struct DevHandle *handle, int cmdId,
    struct AudioHwCaptureParam *) = nullptr;
int32_t (*AudioLibCaptureHardwareDependenceTest::InterfaceLibCtlCapture)(struct DevHandle *handle, int cmdId,
    struct AudioHwCaptureParam *handleData) = nullptr;
void (*AudioLibCaptureHardwareDependenceTest::CloseServiceCaptureSo)(struct DevHandle *handle) = nullptr;
void *AudioLibCaptureHardwareDependenceTest::ptrHandle = nullptr;

void AudioLibCaptureHardwareDependenceTest::SetUpTestCase(void)
{
    char resolvedPath[] = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_capture");
    ptrHandle = dlopen(resolvedPath, RTLD_LAZY);
    if (ptrHandle == nullptr) {
        return;
    }
    BindServiceCaptureSo = reinterpret_cast<struct DevHandle* (*)(const char *)>(dlsym(ptrHandle,
        "AudioBindServiceCapture"));
    InterfaceLibOutputCapture = (int32_t (*)(struct DevHandle *handle, int cmdId,
        struct AudioHwCaptureParam *handleData))dlsym(ptrHandle, "AudioInterfaceLibOutputCapture");
    InterfaceLibCtlCapture = (int32_t (*)(struct DevHandle *handle, int cmdId,
        struct AudioHwCaptureParam *handleData))dlsym(ptrHandle, "AudioInterfaceLibCtlCapture");
    CloseServiceCaptureSo = (void (*)(struct DevHandle *))dlsym(ptrHandle, "AudioCloseServiceCapture");
    if (BindServiceCaptureSo == nullptr || CloseServiceCaptureSo == nullptr ||
        InterfaceLibCtlCapture == nullptr || InterfaceLibOutputCapture == nullptr) {
        dlclose(ptrHandle);
        return;
    }
}

void AudioLibCaptureHardwareDependenceTest::TearDownTestCase(void)
{
    if (BindServiceCaptureSo != nullptr) {
        BindServiceCaptureSo = nullptr;
    }
    if (CloseServiceCaptureSo != nullptr) {
        CloseServiceCaptureSo = nullptr;
    }
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

void AudioLibCaptureHardwareDependenceTest::SetUp(void) {}

void AudioLibCaptureHardwareDependenceTest::TearDown(void) {}

int32_t AudioLibCaptureHardwareDependenceTest::BindServiceAndHwCapture(struct AudioHwCapture *&hwCapture,
    const std::string BindName, const std::string adapterNameCase, struct DevHandle *&handle) const
{
    int32_t ret = HDF_FAILURE;
    handle = BindServiceCaptureSo(BindName.c_str());
    if (handle == nullptr) {
        return HDF_FAILURE;
    }
    hwCapture = static_cast<struct AudioHwCapture *>(calloc(1, sizeof(*hwCapture)));
    if (hwCapture == nullptr) {
        CloseServiceCaptureSo(handle);
        return HDF_FAILURE;
    }
    ret = InitHwCapture(hwCapture, adapterNameCase);
    if (ret != HDF_SUCCESS) {
        free(hwCapture);
        hwCapture = nullptr;
        CloseServiceCaptureSo(handle);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureVolumeWriteRead_001
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE and
*    AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureVolumeWriteRead_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float volumeValue;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    struct AudioHwCapture *hwCapture = nullptr;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

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
    EXPECT_EQ(BELOW_MAX_VOLUME, volumeValue);

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMin + 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwCapture->captureParam.captureMode.ctlParam.volume;
    EXPECT_EQ(OVER_MIN_VOLUME, volumeValue);

    free(hwCapture);
    hwCapture = nullptr;
    CloseServiceCaptureSo(handle);
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureVolumeWriteRead_002
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE and
*    AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureVolumeWriteRead_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwCapture *hwCapture = nullptr;
    float volumeValue = 0;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

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
    EXPECT_EQ(MIN_VOLUME, volumeValue);

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMax;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeValue = hwCapture->captureParam.captureMode.ctlParam.volume;
    EXPECT_EQ(MAX_VOLUME, volumeValue);

    free(hwCapture);
    hwCapture = nullptr;
    CloseServiceCaptureSo(handle);
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureVolumeWriteRead_003
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE and
*    AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureVolumeWriteRead_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float volumeThresholdValueMax = 0;
    struct AudioHwCapture *hwCapture = nullptr;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;

    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMax + 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    hwCapture->captureParam.captureMode.ctlParam.volume = volumeThresholdValueMin - 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(hwCapture);
    hwCapture = nullptr;
    CloseServiceCaptureSo(handle);
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureGetVolthresholdRead_001
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureGetVolthresholdRead_001,
         TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    struct AudioHwCapture *hwCapture = nullptr;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;
    EXPECT_EQ(MAX_VOLUME, volumeThresholdValueMax);
    EXPECT_EQ(MIN_VOLUME, volumeThresholdValueMin);
    CloseServiceCaptureSo(handle);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureSelectScene_001
* @tc.desc  test InterfaceLibCtlCapture,cmdId is AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureSelectScene_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle* handle = nullptr;
    struct AudioHwCapture *hwCapture = nullptr;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
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

    CloseServiceCaptureSo(handle);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureGainWriteRead_001
* @tc.desc  test InterfaceLibCtlCapture,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE and
*    AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureGainWriteRead_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float gainValue = 0;
    float gainThresholdValueMax = 0;
    float gainThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    struct AudioHwCapture *hwCapture = nullptr;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMax;
    gainThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMin;
    ret = InitHwCaptureMode(hwCapture->captureParam.captureMode);
    EXPECT_EQ(HDF_SUCCESS, ret);

    hwCapture->captureParam.captureMode.ctlParam.audioGain.gain = gainThresholdValueMax - 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwCapture->captureParam.captureMode.ctlParam.audioGain.gain;
    EXPECT_EQ(gainThresholdValueMax - 1, gainValue);
    hwCapture->captureParam.captureMode.ctlParam.audioGain.gain = gainThresholdValueMin + 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwCapture->captureParam.captureMode.ctlParam.audioGain.gain;
    EXPECT_EQ(gainThresholdValueMin + 1, gainValue);
    hwCapture->captureParam.captureMode.ctlParam.audioGain.gain = 2.3;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwCapture->captureParam.captureMode.ctlParam.audioGain.gain;
    EXPECT_EQ(2, gainValue);
    CloseServiceCaptureSo(handle);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureGainWriteRead_002
* @tc.desc  test InterfaceLibCtlCapture,cmdId is AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE and
*    AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureGainWriteRead_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct DevHandle *handle = nullptr;
    struct AudioHwCapture *hwCapture = nullptr;
    float gainValue = 0;
    float gainThresholdValueMax = 0;
    float gainThresholdValueMin = 0;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMax;
    gainThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMin;
    ret = InitHwCaptureMode(hwCapture->captureParam.captureMode);
    EXPECT_EQ(HDF_SUCCESS, ret);

    hwCapture->captureParam.captureMode.ctlParam.audioGain.gain = gainThresholdValueMax;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwCapture->captureParam.captureMode.ctlParam.audioGain.gain;
    EXPECT_EQ(gainThresholdValueMax, gainValue);
    hwCapture->captureParam.captureMode.ctlParam.audioGain.gain = gainThresholdValueMin;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainValue = hwCapture->captureParam.captureMode.ctlParam.audioGain.gain;
    EXPECT_EQ(gainThresholdValueMin, gainValue);
    CloseServiceCaptureSo(handle);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureGainWriteRead_003
* @tc.desc  test InterfaceLibCtlCapture ,return -1,If the threshold is invalid.
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureGainWriteRead_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float gainThresholdValueMax = 0;
    float gainThresholdValueMin = 0;
    struct AudioHwCapture *hwCapture = nullptr;
    struct DevHandle *handle = nullptr;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMax;
    gainThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMin;
    ret = InitHwCaptureMode(hwCapture->captureParam.captureMode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    hwCapture->captureParam.captureMode.ctlParam.audioGain.gain = gainThresholdValueMax + 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    hwCapture->captureParam.captureMode.ctlParam.audioGain.gain = gainThresholdValueMin - 1;
    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_FAILURE, ret);
    CloseServiceCaptureSo(handle);
    free(hwCapture);
    hwCapture = nullptr;
}
/**
* @tc.name  AudioInterfaceLibCtlCaptureGetGainthresholdRead_001
* @tc.desc  test InterfaceLibCtlCapture ,cmdId is AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE(23).
* @tc.type: FUNC
*/
HWTEST_F(AudioLibCaptureHardwareDependenceTest, AudioInterfaceLibCtlCaptureGetGainthresholdRead_001,
         TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    float gainThresholdValueMax, gainThresholdValueMin;
    struct DevHandle *handle = nullptr;
    struct AudioHwCapture *hwCapture = nullptr;
    ret = BindServiceAndHwCapture(hwCapture, BIND_CONTROL.c_str(), ADAPTER_NAME, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlCapture(handle, AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE, &hwCapture->captureParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    gainThresholdValueMax = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMax;
    gainThresholdValueMin = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMin;
    EXPECT_EQ(MAX_GAIN, gainThresholdValueMax);
    EXPECT_EQ(MIN_GAIN, gainThresholdValueMin);
    CloseServiceCaptureSo(handle);
    free(hwCapture);
    hwCapture = nullptr;
}
}
