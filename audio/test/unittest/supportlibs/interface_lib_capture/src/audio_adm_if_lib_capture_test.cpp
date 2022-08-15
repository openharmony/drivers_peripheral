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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "audio_interface_lib_capture.h"

using namespace std;
using namespace testing::ext;
namespace {
extern "C" {
struct HdfSBuf *AudioObtainHdfSBuf();
int32_t SetHwParamsCapture(const struct AudioHwCaptureParam * const handleData);
int32_t AudioServiceCaptureDispatch(struct HdfIoService *service,
    int cmdId, struct HdfSBuf *sBuf, struct HdfSBuf *reply);
int32_t AudioCtlCaptureSetPauseBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetPauseStu(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetVolumeSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetVolume(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetVolumeSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetVolume(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetMuteSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetMuteStu(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetMuteSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetMuteStu(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetGainSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetGainStu(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetGainSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetGainStu(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSceneSelectSBuf(struct HdfSBuf *sBuf,
    struct AudioHwCaptureParam *handleData, int32_t deviceIndex);
int32_t AudioCtlCaptureSceneSelect(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetGainThresholdSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetGainThreshold(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioInterfaceLibCtlCapture(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureHwParams(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureRead(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureStop(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioInterfaceLibOutputCapture(const struct DevHandleCapture *handle, int cmdId,
    struct AudioHwCaptureParam *handleData);
}

class AudioAdmIfLibCaptureTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void AudioAdmIfLibCaptureTest::SetUpTestCase()
{
}

void AudioAdmIfLibCaptureTest::TearDownTestCase()
{
}

HWTEST_F(AudioAdmIfLibCaptureTest, SetHwParamsCapture_001, TestSize.Level1)
{
    const struct AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = SetHwParamsCapture(handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdmIfLibCaptureTest, SetHwParamsCapture_002, TestSize.Level1)
{
    struct AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = SetHwParamsCapture((const struct AudioHwCaptureParam *)handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetPauseBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t ret = AudioCtlCaptureSetPauseBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetPauseBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSetPauseBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetPauseBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlCaptureSetPauseBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetVolumeSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t ret = AudioCtlCaptureGetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetVolumeSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureGetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetVolumeSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlCaptureGetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetVolumeSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t ret = AudioCtlCaptureSetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetVolumeSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetVolumeSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlCaptureSetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetMuteSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t ret = AudioCtlCaptureSetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetMuteSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetMuteSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlCaptureSetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetMuteSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t ret = AudioCtlCaptureGetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetMuteSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureGetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetMuteSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlCaptureGetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetGainSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t ret = AudioCtlCaptureSetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetGainSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureSetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSetGainSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlCaptureSetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetGainSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t ret = AudioCtlCaptureGetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetGainSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureGetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetGainSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlCaptureGetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSceneSelectSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t deviceIndex = 0;
    int32_t ret = AudioCtlCaptureSceneSelectSBuf(sBuf, handleData, deviceIndex);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSceneSelectSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t deviceIndex = 0;
    int32_t ret = AudioCtlCaptureSceneSelectSBuf(sBuf, handleData, deviceIndex);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureSceneSelectSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t deviceIndex = 0;
    int32_t ret = AudioCtlCaptureSceneSelectSBuf(sBuf, handleData, deviceIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetGainThresholdSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    int32_t ret = AudioCtlCaptureGetGainThresholdSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetGainThresholdSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = nullptr;
    int32_t ret = AudioCtlCaptureGetGainThresholdSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibCaptureTest, AudioCtlCaptureGetGainThresholdSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwCaptureParam *handleData = new AudioHwCaptureParam;
    handleData->captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlCaptureGetGainThresholdSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}
}
