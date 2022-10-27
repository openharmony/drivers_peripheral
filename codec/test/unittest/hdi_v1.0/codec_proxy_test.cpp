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

#include <gtest/gtest.h>
#include <osal_mem.h>
#include <securec.h>
#include <unistd.h>
#include "codec_callback_stub.h"
#include "hdf_log.h"
#include "hdi_mpp_ext_param_keys.h"
#include "icodec.h"
#include "share_mem.h"

#define HDF_LOG_TAG codec_hdi_uinttest

using namespace std;
using namespace testing::ext;

namespace {
constexpr const char *TEST_SERVICE_NAME = "codec_hdi_service";
constexpr const int TEST_PACKET_BUFFER_SIZE = 4096;
constexpr const int TEST_FRAME_BUFFER_SIZE = 640 * 480 * 3 / 2;
constexpr const uint32_t QUEUE_TIME_OUT = 10;
constexpr const int CAPABILITY_COUNT = 9;
constexpr int32_t INT_TO_STR_LEN = 32;
constexpr int32_t ARRAY_TO_STR_LEN = 1000;
struct ICodec *g_codecObj = nullptr;
ShareMemory g_inputBuffer;
ShareMemory g_outputBuffer;
CodecBuffer *g_inputInfoData = nullptr;
CodecBuffer *g_outputInfoData = nullptr;
CODEC_HANDLETYPE g_handle = NULL;

class CodecProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

static char arrayStr[ARRAY_TO_STR_LEN];
static char *GetArrayStr(int32_t *array, int32_t arrayLen, int32_t endValue)
{
    int32_t len = 0;
    int32_t totalLen = 0;
    int32_t ret;
    char value[INT_TO_STR_LEN];
    ret = memset_s(arrayStr, sizeof(arrayStr), 0, sizeof(arrayStr));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memset_s arrayStr failed, error code: %{public}d", __func__, ret);
        return arrayStr;
    }
    for (int32_t i = 0; i < arrayLen; i++) {
        if (array[i] == endValue) {
            break;
        }
        ret = memset_s(value, sizeof(value), 0, sizeof(value));
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memset_s value failed, error code: %{public}d", __func__, ret);
            return arrayStr;
        }
        ret = sprintf_s(value, sizeof(value) - 1, "0x0%X, ", array[i]);
        if (ret < 0) {
            HDF_LOGE("%{public}s: sprintf_s value failed, error code: %{public}d", __func__, ret);
            return arrayStr;
        }
        len = strlen(value);
        ret = memcpy_s(arrayStr + totalLen, len, value, len);
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memcpy_s arrayStr failed, error code: %{public}d", __func__, ret);
            return arrayStr;
        }
        totalLen += len;
    }
    return arrayStr;
}

static void PrintCapability(CodecCapability *cap, int index)
{
    int32_t mime = 0;
    if (cap == NULL) {
        HDF_LOGE("null capability!");
        return;
    }
    mime = (int32_t)cap->mime;
    if (mime < 0) {
        HDF_LOGE("print invalid capability!");
        return;
    }
    HDF_LOGI("-------------------------- capability %{public}d ---------------------------", index + 1);
    HDF_LOGI("mime:%{public}d", cap->mime);
    HDF_LOGI("type:%{public}d", cap->type);
    HDF_LOGI("name:%{public}s", cap->name);
    HDF_LOGI("supportProfiles:%{public}s", GetArrayStr(cap->supportProfiles, PROFILE_NUM, INVALID_PROFILE));
    HDF_LOGI("isSoftwareCodec:%{public}d", cap->isSoftwareCodec);
    HDF_LOGI("processModeMask:0x0%{public}x", cap->processModeMask);
    HDF_LOGI("capsMask:0x0%{public}x", cap->capsMask);
    HDF_LOGI("allocateMask:0x0%{public}x", cap->allocateMask);
    HDF_LOGI("inputBufferNum.min:%{public}d", cap->inputBufferNum.min);
    HDF_LOGI("inputBufferNum.max:%{public}d", cap->inputBufferNum.max);
    HDF_LOGI("outputBufferNum.min:%{public}d", cap->outputBufferNum.min);
    HDF_LOGI("outputBufferNum.max:%{public}d", cap->outputBufferNum.max);
    HDF_LOGI("bitRate.min:%{public}d", cap->bitRate.min);
    HDF_LOGI("bitRate.max:%{public}d", cap->bitRate.max);
    HDF_LOGI("inputBufferSize:%{public}d", cap->inputBufferSize);
    HDF_LOGI("outputBufferSize:%{public}d", cap->outputBufferSize);
    if (cap->mime < MEDIA_MIMETYPE_AUDIO_FIRST) {
        HDF_LOGI("minSize.width:%{public}d", cap->port.video.minSize.width);
        HDF_LOGI("minSize.height:%{public}d", cap->port.video.minSize.height);
        HDF_LOGI("maxSize.width:%{public}d", cap->port.video.maxSize.width);
        HDF_LOGI("maxSize.height:%{public}d", cap->port.video.maxSize.height);
        HDF_LOGI("widthAlignment:%{public}d", cap->port.video.whAlignment.widthAlignment);
        HDF_LOGI("heightAlignment:%{public}d", cap->port.video.whAlignment.heightAlignment);
        HDF_LOGI("supportPixFmts:%{public}s", GetArrayStr(cap->port.video.supportPixFmts, PIX_FMT_NUM, 0));
    } else {
        HDF_LOGI(":%{public}s", GetArrayStr(cap->port.audio.sampleFormats, SAMPLE_FORMAT_NUM, 0));
        HDF_LOGI(":%{public}s", GetArrayStr(cap->port.audio.sampleRate, SAMPLE_RATE_NUM, 0));
        HDF_LOGI(":%{public}s", GetArrayStr(cap->port.audio.channelLayouts, CHANNEL_NUM, -1));
    }
    HDF_LOGI("-------------------------------------------------------------------");
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1GetCodecObjTest_001, TestSize.Level1)
{
    g_codecObj = HdiCodecGet(TEST_SERVICE_NAME);
    ASSERT_TRUE(g_codecObj != nullptr);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1EnumerateCapabilityTest_001, TestSize.Level1)
{
    int32_t ret = HDF_SUCCESS;
    for (int index = 0; index < CAPABILITY_COUNT; index++) {
        CodecCapability cap;
        ret = g_codecObj->CodecEnumerateCapability(g_codecObj, index, &cap);
        ASSERT_EQ(ret, HDF_SUCCESS);
        PrintCapability(&cap, index);
    }
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1GetCapabilityTest_001, TestSize.Level1)
{
    CodecCapability cap;
    int32_t ret = g_codecObj->CodecGetCapability(g_codecObj, MEDIA_MIMETYPE_IMAGE_JPEG, VIDEO_DECODER, 0, &cap);
    ASSERT_EQ(ret, HDF_SUCCESS);
    PrintCapability(&cap, 0);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1GetCapabilityTest_002, TestSize.Level1)
{
    CodecCapability cap;
    int32_t ret = g_codecObj->CodecGetCapability(g_codecObj, MEDIA_MIMETYPE_VIDEO_HEVC, VIDEO_DECODER, 0, &cap);
    ASSERT_EQ(ret, HDF_SUCCESS);
    PrintCapability(&cap, 0);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1GetCapabilityTest_003, TestSize.Level1)
{
    CodecCapability cap;
    int32_t ret = g_codecObj->CodecGetCapability(g_codecObj, MEDIA_MIMETYPE_VIDEO_AVC, VIDEO_DECODER, 0, &cap);
    ASSERT_EQ(ret, HDF_SUCCESS);
    PrintCapability(&cap, 0);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1InitCodecTest_001, TestSize.Level1)
{
    ASSERT_TRUE(g_codecObj != nullptr);
    int32_t errorCode = g_codecObj->CodecInit(g_codecObj);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1CreateCodecTest_001, TestSize.Level1)
{
    const char* name = "codec.avc.hardware.decoder";
    int32_t errorCode = g_codecObj->CodecCreate(g_codecObj, name, &g_handle);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_TRUE(g_handle != nullptr);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1CreateCodecByTypeTest_001, TestSize.Level1)
{
    CodecType type = VIDEO_DECODER;
    AvCodecMime mime = MEDIA_MIMETYPE_VIDEO_AVC;
    int32_t errorCode = g_codecObj->CodecCreateByType(g_codecObj, type, mime, &g_handle);
    ASSERT_EQ(errorCode, HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1SetPortModeTest_001, TestSize.Level1)
{
    DirectionType direct = OUTPUT_TYPE;
    AllocateBufferMode mode = ALLOCATE_INPUT_BUFFER_CODEC_PRESET;
    BufferType type = BUFFER_TYPE_FD;
    int32_t errorCode = g_codecObj->CodecSetPortMode(g_codecObj, g_handle, direct, mode, type);
    ASSERT_EQ(errorCode, HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1GetPortModeTest_001, TestSize.Level1)
{
    DirectionType direct = OUTPUT_TYPE;
    AllocateBufferMode mode;
    BufferType type;
    int32_t errorCode = g_codecObj->CodecGetPortMode(g_codecObj, g_handle, direct, &mode, &type);
    ASSERT_EQ(errorCode, HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1SetCodecTypeTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = KEY_CODEC_TYPE;
    CodecType type = VIDEO_DECODER;
    params->val = (void *)&type;
    params->size = sizeof(type);

    int32_t errorCode = g_codecObj->CodecSetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1SetGopModeTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = KEY_VIDEO_GOP_MODE;
    VideoCodecGopMode mode = VID_CODEC_GOPMODE_NORMALP;
    params->val = (void *)&mode;
    params->size = sizeof(mode);

    int32_t errorCode = g_codecObj->CodecSetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1SetMimeTypeTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = KEY_MIMETYPE;
    AvCodecMime mime = MEDIA_MIMETYPE_IMAGE_JPEG;
    params->val = (void *)&mime;
    params->size = sizeof(mime);

    int32_t errorCode = g_codecObj->CodecSetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1SetPixelFormatTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = KEY_PIXEL_FORMAT;
    CodecPixelFormat format = PIXEL_FORMAT_YUV_422_I;
    params->val = (void *)&format;
    params->size = sizeof(format);

    int32_t errorCode = g_codecObj->CodecSetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1GetDefaultCfgTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = (ParamKey)ParamExtKey::KEY_EXT_DEFAULT_CFG_RK;
    params->val = nullptr;
    params->size = 0;

    int32_t errorCode = g_codecObj->CodecGetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1SetSplitModeTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = (ParamKey)ParamExtKey::KEY_EXT_SPLIT_PARSE_RK;
    int32_t needSplit = 1;
    params->val = (void *)&needSplit;
    params->size = sizeof(needSplit);

    int32_t errorCode = g_codecObj->CodecSetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1GetSplitParseTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = (ParamKey)ParamExtKey::KEY_EXT_SPLIT_PARSE_RK;
    params->val = nullptr;
    params->size = 0;

    int32_t errorCode = g_codecObj->CodecGetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1SetDecFrameNumTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = (ParamKey)ParamExtKey::KEY_EXT_DEC_FRAME_NUM_RK;
    int32_t frameNum = 1;
    params->val = (void *)&frameNum;
    params->size = sizeof(frameNum);

    int32_t errorCode = g_codecObj->CodecSetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1GetDecFrameTest_001, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = (ParamKey)ParamExtKey::KEY_EXT_DEC_FRAME_NUM_RK;
    params->val = nullptr;
    params->size = 0;

    int32_t errorCode = g_codecObj->CodecGetParameter(g_codecObj, g_handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}


HWTEST_F(CodecProxyTest, HdfCodecHdiV1QueueInputTest_001, TestSize.Level1)
{
    g_inputBuffer.id = 0;
    g_inputBuffer.size = TEST_PACKET_BUFFER_SIZE;
    int32_t ret = CreateFdShareMemory(&g_inputBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);

    g_inputInfoData = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * 1);
    g_inputInfoData->bufferId = 0;
    g_inputInfoData->bufferCnt = 1;
    g_inputInfoData->flag = 1;
    g_inputInfoData->timeStamp = 1;
    g_inputInfoData->buffer[0].type = BUFFER_TYPE_FD;
    g_inputInfoData->buffer[0].offset = 1;
    g_inputInfoData->buffer[0].length = 1;
    g_inputInfoData->buffer[0].capacity = TEST_PACKET_BUFFER_SIZE;
    g_inputInfoData->buffer[0].buf = (intptr_t)g_inputBuffer.fd;

    int32_t errorCode = g_codecObj->CodecQueueInput(g_codecObj, g_handle, g_inputInfoData,
        (uint32_t)QUEUE_TIME_OUT, -1);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1DequeInputTest_001, TestSize.Level1)
{
    int32_t acquireFd;
    CodecBuffer *inputInfo = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * 1);
    inputInfo->bufferCnt = 1;

    int32_t errorCode = g_codecObj->CodecDequeueInput(g_codecObj, g_handle, QUEUE_TIME_OUT, &acquireFd, inputInfo);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_EQ(inputInfo->bufferId, g_inputInfoData->bufferId);
    ASSERT_EQ(inputInfo->bufferCnt, g_inputInfoData->bufferCnt);
    ASSERT_EQ(inputInfo->buffer[0].type, g_inputInfoData->buffer[0].type);
    ASSERT_EQ(inputInfo->buffer[0].offset, g_inputInfoData->buffer[0].offset);
    ASSERT_EQ(inputInfo->buffer[0].length, g_inputInfoData->buffer[0].length);
    ASSERT_EQ(inputInfo->buffer[0].capacity, g_inputInfoData->buffer[0].capacity);
    OsalMemFree(inputInfo);
    OsalMemFree(g_inputInfoData);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1StartCodecTest_001, TestSize.Level1)
{
    int32_t  errorCode = g_codecObj->CodecStart(g_codecObj, g_handle);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1StopCodecTest_001, TestSize.Level1)
{
    int32_t errorCode = g_codecObj->CodecStop(g_codecObj, g_handle);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1ResetCodecTest_001, TestSize.Level1)
{
    int32_t errorCode = g_codecObj->CodecReset(g_codecObj, g_handle);
    ASSERT_EQ(errorCode, HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1QueueOutputTest_001, TestSize.Level1)
{
    g_outputBuffer.id = 1;
    g_outputBuffer.size = TEST_FRAME_BUFFER_SIZE;
    int32_t ret = CreateFdShareMemory(&g_outputBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);

    g_outputInfoData = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * 1);
    g_outputInfoData->bufferId = 1;
    g_outputInfoData->bufferCnt = 1;
    g_outputInfoData->flag = 1;
    g_outputInfoData->timeStamp = 1;
    g_outputInfoData->buffer[0].type = BUFFER_TYPE_FD;
    g_outputInfoData->buffer[0].offset = 1;
    g_outputInfoData->buffer[0].length = 1;
    g_outputInfoData->buffer[0].capacity = TEST_FRAME_BUFFER_SIZE;
    g_outputInfoData->buffer[0].buf = (intptr_t)g_outputBuffer.fd;

    int32_t errorCode = g_codecObj->CodecQueueOutput(g_codecObj, g_handle, g_outputInfoData, (uint32_t)0, -1);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1DequeueOutputTest_001, TestSize.Level1)
{
    int32_t errorCode = 0;
    int32_t acquireFd;
    CodecBuffer *outInfo = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * 1);
    outInfo->bufferCnt = 1;

    errorCode = g_codecObj->CodecDequeueOutput(g_codecObj, g_handle, QUEUE_TIME_OUT, &acquireFd, outInfo);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_EQ(outInfo->bufferId, g_outputInfoData->bufferId);
    ASSERT_EQ(outInfo->bufferCnt, g_outputInfoData->bufferCnt);
    ASSERT_EQ(outInfo->buffer[0].type, g_outputInfoData->buffer[0].type);
    ASSERT_EQ(outInfo->buffer[0].offset, g_outputInfoData->buffer[0].offset);
    ASSERT_EQ(outInfo->buffer[0].length, g_outputInfoData->buffer[0].length);
    ASSERT_EQ(outInfo->buffer[0].capacity, g_outputInfoData->buffer[0].capacity);
    OsalMemFree(outInfo);
    OsalMemFree(g_outputInfoData);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1FlushTest_001, TestSize.Level1)
{
    DirectionType directType = OUTPUT_TYPE;

    int32_t errorCode = g_codecObj->CodecFlush(g_codecObj, g_handle, directType);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_EQ(directType, OUTPUT_TYPE);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1FlushTest_002, TestSize.Level1)
{
    DirectionType directType = INPUT_TYPE;

    int32_t errorCode = g_codecObj->CodecFlush(g_codecObj, g_handle, directType);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_EQ(directType, INPUT_TYPE);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1FlushTest_003, TestSize.Level1)
{
    DirectionType directType = ALL_TYPE;

    int32_t errorCode = g_codecObj->CodecFlush(g_codecObj, g_handle, directType);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_EQ(directType, ALL_TYPE);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1SetCallbackTest_001, TestSize.Level1)
{
    UINTPTR instance = 0;
    ICodecCallback *callback = CodecCallbackStubObtain();
    ASSERT_TRUE(callback != nullptr);

    int32_t errorCode = g_codecObj->CodecSetCallback(g_codecObj, g_handle, callback, instance);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1DestroyCodecTest_001, TestSize.Level1)
{
    int32_t errorCode = g_codecObj->CodecDestroy(g_codecObj, g_handle);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, HdfCodecHdiV1DeinitTest_001, TestSize.Level1)
{
    int32_t errorCode = g_codecObj->CodecDeinit(g_codecObj);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    HdiCodecRelease(g_codecObj);
}
}