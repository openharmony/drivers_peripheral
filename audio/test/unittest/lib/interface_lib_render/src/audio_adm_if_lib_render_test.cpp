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
#include "audio_interface_lib_render.h"

using namespace std;
using namespace testing::ext;
namespace {
extern "C" {
struct HdfSBuf *AudioObtainHdfSBuf();
int32_t IoctlWrite(const struct AudioHwRenderParam *handleData);
int32_t AudioServiceRenderDispatch(struct HdfIoService *service, int cmdId,
    struct HdfSBuf *sBuf, struct HdfSBuf *reply);
int32_t SetHwParams(const struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetVolumeSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderGetVolumeSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetVolume(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderGetVolume(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData);
int32_t AudioOutputRenderSetSpeed(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetPauseBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetPauseStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetMuteBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetMuteStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderGetMuteSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderGetMuteStu(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetGainBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetGainStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderGetGainSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderGetGainStu(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSceneSelectSBuf(struct HdfSBuf *sBuf,
    struct AudioHwRenderParam *handleData, int32_t deviceIndex);
int32_t AudioCtlRenderSceneSelect(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSceneGetGainThresholdSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSceneGetGainThreshold(const struct DevHandle *handle,
    int cmdId, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetChannelModeBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderSetChannelMode(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderGetChannelModeSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData);
int32_t AudioCtlRenderGetChannelMode(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData);
int32_t AudioInterfaceLibCtlRender(const struct DevHandle *handle,
    int cmdId, struct AudioHwRenderParam *handleData);
int32_t FrameSbufWriteBuffer(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData);
int32_t AudioOutputRenderHwParams(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioOutputRenderWrite(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioOutputRenderStop(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData);
int32_t AudioInterfaceLibOutputRender(const struct DevHandle *handle, int cmdId,
    struct AudioHwRenderParam *handleData);
struct HdfIoService *HdfIoServiceBindName(const char *serviceName);
}

class AudioAdmIfLibRenderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void AudioAdmIfLibRenderTest::SetUpTestCase()
{
}

void AudioAdmIfLibRenderTest::TearDownTestCase()
{
}

HWTEST_F(AudioAdmIfLibRenderTest, SetHwParams_001, TestSize.Level1)
{
    const struct AudioHwRenderParam *handleData = nullptr;
    int32_t ret = SetHwParams(handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
}

HWTEST_F(AudioAdmIfLibRenderTest, SetHwParams_002, TestSize.Level1)
{
    struct AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = SetHwParams((const struct AudioHwRenderParam *)handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetVolumeSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderSetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetVolumeSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetVolumeSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderSetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetVolumeSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderGetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetVolumeSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetVolumeSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderGetVolumeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetPauseBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderSetPauseBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetPauseBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetPauseBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetPauseBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderSetPauseBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetMuteBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderSetMuteBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetMuteBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetMuteBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetMuteBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderSetMuteBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetMuteSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderGetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetMuteSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetMuteSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderGetMuteSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetGainBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderSetGainBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetGainBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetGainBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetGainBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderSetGainBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetGainSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderGetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetGainSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetGainSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderGetGainSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSceneSelectSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t deviceIndex = 0;
    int32_t ret = AudioCtlRenderSceneSelectSBuf(sBuf, handleData, deviceIndex);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSceneSelectSBuf_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t deviceIndex = 0;
    int32_t ret = AudioCtlRenderSceneSelectSBuf(sBuf, handleData, deviceIndex);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSceneSelectSBuf_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t deviceIndex = 0;
    int32_t ret = AudioCtlRenderSceneSelectSBuf(sBuf, handleData, deviceIndex);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSceneGetGainThreshold_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderSceneGetGainThresholdSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSceneGetGainThreshold_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSceneGetGainThresholdSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSceneGetGainThreshold_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderSceneGetGainThresholdSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetChannelMode_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderSetChannelModeBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetChannelMode_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderSetChannelModeBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderSetChannelMode_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderSetChannelModeBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetChannelMode_001, TestSize.Level1)
{
    struct HdfSBuf *sBuf = nullptr;
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    int32_t ret = AudioCtlRenderGetChannelModeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    delete(handleData);
    handleData = nullptr;
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetChannelMode_002, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = nullptr;
    int32_t ret = AudioCtlRenderGetChannelModeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_FAILURE, ret);
    HdfSbufRecycle(sBuf);
}

HWTEST_F(AudioAdmIfLibRenderTest, AudioCtlRenderGetChannelMode_003, TestSize.Level1)
{
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    AudioHwRenderParam *handleData = new AudioHwRenderParam;
    handleData->renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    int32_t ret = AudioCtlRenderGetChannelModeSBuf(sBuf, handleData);
    EXPECT_EQ(HDF_SUCCESS, ret);
    HdfSbufRecycle(sBuf);
    delete(handleData);
    handleData = nullptr;
}
}
