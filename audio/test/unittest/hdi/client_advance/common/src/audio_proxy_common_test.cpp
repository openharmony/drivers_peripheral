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

#include <unistd.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "audio_proxy_common.h"
#include "audio_proxy_common_fun_test.h"
#include "hdf_remote_service.h"
#include "hdf_sbuf.h"

using namespace std;
using namespace testing::ext;
namespace {
class AudioProxyCommonTest : public testing::Test {
public:
    virtual void SetUp();
    virtual void TearDown();
};

void AudioProxyCommonTest::SetUp() {}

void AudioProxyCommonTest::TearDown() {}

HWTEST_F(AudioProxyCommonTest, AudioProxyObtainHdfSBufWhenNormal, TestSize.Level1)
{
    struct HdfSBuf *data = AudioProxyObtainHdfSBuf();
    EXPECT_NE(nullptr, data);
    HdfSbufRecycle(data);
    data = nullptr;
}

HWTEST_F(AudioProxyCommonTest, AudioProxyObtainHdfSBuf_001, TestSize.Level1)
{
    struct HdfSBuf *data = nullptr;
    struct HdfSBuf *reply = nullptr;
    EXPECT_EQ(HDF_FAILURE, AudioProxyPreprocessSBuf(nullptr, &reply));
    EXPECT_EQ(HDF_FAILURE, AudioProxyPreprocessSBuf(&data, nullptr));
}

HWTEST_F(AudioProxyCommonTest, AudioProxyDispatchCall_001, TestSize.Level1)
{
    int32_t id = 0;
    struct HdfSBuf *data = AudioProxyObtainHdfSBuf();
    struct HdfSBuf *reply = AudioProxyObtainHdfSBuf();
    struct HdfRemoteService self;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyDispatchCall(nullptr, id, data, reply));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyDispatchCall(&self, id, nullptr, reply));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyDispatchCall(&self, id, data, nullptr));
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
}

HWTEST_F(AudioProxyCommonTest, AudioProxyDispatchCall_002, TestSize.Level1)
{
    int32_t id = 0;
    struct HdfSBuf *data = AudioProxyObtainHdfSBuf();
    struct HdfSBuf *reply = AudioProxyObtainHdfSBuf();
    struct HdfRemoteService self;
    self.dispatcher = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyDispatchCall(nullptr, id, data, reply));
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
}

HWTEST_F(AudioProxyCommonTest, AdapterGetRemoteHandle_001, TestSize.Level1)
{
    char adapterName[NAME_LEN];
    struct AudioHwAdapter hwAdapter;
    struct AudioProxyManager proxyManager;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyAdapterGetRemoteHandle(nullptr, &hwAdapter, adapterName));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyAdapterGetRemoteHandle(&proxyManager, nullptr, adapterName));
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyAdapterGetRemoteHandle(&proxyManager, &hwAdapter, nullptr));
}

HWTEST_F(AudioProxyCommonTest, AdapterGetRemoteHandle_002, TestSize.Level1)
{
    const char *adapterName = "abc";
    struct AudioHwAdapter hwAdapter;
    struct AudioProxyManager proxyManager;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyAdapterGetRemoteHandle(&proxyManager, &hwAdapter, adapterName));
}

HWTEST_F(AudioProxyCommonTest, AudioProxyPreprocessRender_001, TestSize.Level1)
{
    struct HdfSBuf *data = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct AudioHwRender render;
    EXPECT_EQ(HDF_FAILURE, AudioProxyPreprocessRender(nullptr, &data, &reply));
    EXPECT_EQ(HDF_FAILURE, AudioProxyPreprocessRender(&render, nullptr, &reply));
    EXPECT_EQ(HDF_FAILURE, AudioProxyPreprocessRender(&render, &data, nullptr));
}

HWTEST_F(AudioProxyCommonTest, AudioProxyPreprocessCapture_001, TestSize.Level1)
{
    struct HdfSBuf *data = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct AudioHwCapture capture;
    EXPECT_EQ(HDF_FAILURE, AudioProxyPreprocessCapture(nullptr, &data, &reply));
    EXPECT_EQ(HDF_FAILURE, AudioProxyPreprocessCapture(&capture, nullptr, &reply));
    EXPECT_EQ(HDF_FAILURE, AudioProxyPreprocessCapture(&capture, &data, nullptr));
}

HWTEST_F(AudioProxyCommonTest, AudioProxyWriteSampleAttributes_001, TestSize.Level1)
{
    struct HdfSBuf *data = AudioProxyObtainHdfSBuf();
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_FAILURE, AudioProxyWriteSampleAttributes(nullptr, &attrs));
    EXPECT_EQ(HDF_FAILURE, AudioProxyWriteSampleAttributes(data, nullptr));
    HdfSbufRecycle(data);
}

HWTEST_F(AudioProxyCommonTest, AudioProxyReadSapmleAttrbutes_001, TestSize.Level1)
{
    struct HdfSBuf *data = AudioProxyObtainHdfSBuf();
    struct AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_FAILURE, AudioProxyReadSapmleAttrbutes(nullptr, &attrs));
    EXPECT_EQ(HDF_FAILURE, AudioProxyReadSapmleAttrbutes(data, nullptr));
    HdfSbufRecycle(data);
}

HWTEST_F(AudioProxyCommonTest, SetRenderCtrlParam_001, TestSize.Level1)
{
    int cmId = AUDIO_HDI_RENDER_SET_VOLUME;
    float param = commonfun::HALF_OF_NORMAL_VALUE; // normal value
    struct AudioHwRender hwRender;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyCommonSetRenderCtrlParam(cmId, nullptr, param));

    hwRender.proxyRemoteHandle = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyCommonSetRenderCtrlParam(cmId, (AudioHandle)(&hwRender), param));
}

HWTEST_F(AudioProxyCommonTest, SetRenderCtrlParam_002, TestSize.Level1)
{
    int cmId = AUDIO_HDI_RENDER_SET_VOLUME;
    float volume = commonfun::MIN_VALUE_OUT_OF_BOUNDS; // The volume value is not within the threshold range [0,1]
    struct AudioHwRender hwRender;
    struct HdfRemoteService remoteHandle;
    hwRender.proxyRemoteHandle = &remoteHandle;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyCommonSetRenderCtrlParam(cmId, (AudioHandle)(&hwRender), volume));
    volume = commonfun::MAX_VALUE_OUT_OF_BOUNDS; // The volume value is not within the threshold range [0,1]
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyCommonSetRenderCtrlParam(cmId, (AudioHandle)(&hwRender), volume));
}

HWTEST_F(AudioProxyCommonTest, GetRenderCtrlParam_001, TestSize.Level1)
{
    int cmId = AUDIO_HDI_RENDER_SET_VOLUME;
    float param = commonfun::HALF_OF_NORMAL_VALUE; // normal value
    struct AudioHwRender hwRender;
    int32_t ret  = AudioProxyCommonGetRenderCtrlParam(cmId, nullptr, &param);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = AudioProxyCommonGetRenderCtrlParam(cmId, (AudioHandle)(&hwRender), nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    hwRender.proxyRemoteHandle = nullptr;
    ret = AudioProxyCommonGetRenderCtrlParam(cmId, (AudioHandle)(&hwRender), &param);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}


HWTEST_F(AudioProxyCommonTest, SetCaptureCtrlParam_001, TestSize.Level1)
{
    int cmId = AUDIO_HDI_RENDER_SET_VOLUME;
    float param = commonfun::HALF_OF_NORMAL_VALUE; // normal value
    struct AudioHwCapture hwCapture;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyCommonSetCaptureCtrlParam(cmId, nullptr, param));

    hwCapture.proxyRemoteHandle = nullptr;
    int32_t ret = AudioProxyCommonSetCaptureCtrlParam(cmId, (AudioHandle)(&hwCapture), param);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioProxyCommonTest, SetCaptureCtrlParam_002, TestSize.Level1)
{
    int cmId = AUDIO_HDI_CAPTURE_SET_VOLUME;
    float volume = commonfun::MIN_VALUE_OUT_OF_BOUNDS; // The volume value is not within the threshold range [0,1].
    struct AudioHwCapture hwCapture;
    struct HdfRemoteService remoteHandle;
    hwCapture.proxyRemoteHandle = &remoteHandle;
    int32_t ret = AudioProxyCommonSetCaptureCtrlParam(cmId, (AudioHandle)(&hwCapture), volume);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = AudioProxyCommonSetCaptureCtrlParam(cmId, (AudioHandle)(&hwCapture), volume);
    volume = commonfun::MAX_VALUE_OUT_OF_BOUNDS; // The volume value is not within the threshold range [0,1].
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioProxyCommonTest, GetCaptureCtrlParam_001, TestSize.Level1)
{
    int cmId = AUDIO_HDI_CAPTURE_SET_VOLUME;
    float param = commonfun::HALF_OF_NORMAL_VALUE; // normal value
    struct AudioHwCapture hwCapture;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, AudioProxyCommonGetCaptureCtrlParam(cmId, nullptr, &param));
    int32_t ret = AudioProxyCommonGetCaptureCtrlParam(cmId, (AudioHandle)(&hwCapture), nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    hwCapture.proxyRemoteHandle = nullptr;
    ret = AudioProxyCommonGetCaptureCtrlParam(cmId, (AudioHandle)(&hwCapture), &param);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

HWTEST_F(AudioProxyCommonTest, GetMmapPositionRead_001, TestSize.Level1)
{
    uint64_t frames = 0;
    struct HdfSBuf *reply = AudioProxyObtainHdfSBuf();
    struct AudioTimeStamp time;
    EXPECT_EQ(HDF_FAILURE, AudioProxyGetMmapPositionRead(nullptr, &frames, &time));
    EXPECT_EQ(HDF_FAILURE, AudioProxyGetMmapPositionRead(reply, nullptr, &time));
    EXPECT_EQ(HDF_FAILURE, AudioProxyGetMmapPositionRead(reply, &frames, nullptr));
    HdfSbufRecycle(reply);
}

HWTEST_F(AudioProxyCommonTest, ReqMmapBufferWrite_001, TestSize.Level1)
{
    int32_t reqSize = 0;
    struct HdfSBuf *data = AudioProxyObtainHdfSBuf();
    struct AudioMmapBufferDescripter desc;
    EXPECT_EQ(HDF_FAILURE, AudioProxyReqMmapBufferWrite(nullptr, reqSize, &desc));
    EXPECT_EQ(HDF_FAILURE, AudioProxyReqMmapBufferWrite(data, reqSize, nullptr));
    HdfSbufRecycle(data);
}
}
