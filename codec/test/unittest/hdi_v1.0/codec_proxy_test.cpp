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
#include <unistd.h>
#include "codec_callback_stub.h"
#include "codec_config_reader.h"
#include "codec_utils.h"
#include "icodec.h"
#include "share_mem.h"

using namespace std;
using namespace testing::ext;

namespace {
enum class ParamExtKeys {
    KEY_START = 0xF000,
    KEY_DEFAULT_CFG_RK,             /**< Default config. Used for RK codec. */
    KEY_SPLIT_PARSE_RK,             /**< Split parse. Used for RK codec. */
    KEY_DEC_FRAME_NUM_RK,           /**< Decode frame number. Used for RK codec. */
    KEY_EXT_SETUP_DROP_MODE_RK,     /**< Drop mode setup. Used for RK codec. */
    KEY_EXT_ENC_VALIDATE_SETUP_RK,  /**< Validate config setup. Used for RK codec. */
    KEY_ENC_SETUP_AVC_RK,           /**< AVC config setup. Used for RK codec. */
    KEY_ENC_FRAME_NUM_RK,           /**< Frame num setup. Used for RK codec. */
    KEY_END = 0xFFFF,
};

constexpr const char *TEST_SERVICE_NAME = "codec_hdi_service";
constexpr const int TEST_PACKET_BUFFER_SIZE = 4096;
constexpr const int TEST_FRAME_BUFFER_SIZE = 640 * 480 * 3 / 2;
constexpr const int QUEUE_TIME_OUT = 10;
struct ICodec *codecObj = nullptr;
ShareMemory inputBuffer;
ShareMemory outputBuffer;
InputInfo inputInfoData = {0};
CodecBufferInfo inputCodecBufferInfo = {BUFFER_TYPE_FD};
OutputInfo outputInfoData = {0};
CodecBufferInfo outputCodecBufferInfo = {BUFFER_TYPE_FD};
CODEC_HANDLETYPE handle = NULL;

class CodecProxyTest : public testing::Test {
public:
    ICodecCallback *g_callback = nullptr;
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(CodecProxyTest, CodecHdiGetCodecObj, TestSize.Level1)
{
    codecObj = HdiCodecGet(TEST_SERVICE_NAME);
    ASSERT_TRUE(codecObj != nullptr);
}

HWTEST_F(CodecProxyTest, CodecHdiEnumerateCapbility, TestSize.Level1)
{
    struct HdfRemoteService *remote = GetConfigService();
    ASSERT_TRUE(remote != nullptr);

    int32_t ret = HDF_SUCCESS;
    for (int32_t index = 0; index < 8; index++) {
        CodecCapbility cap;
        ret = EnumrateCapability(remote, index, &cap);
        ASSERT_EQ(ret, HDF_SUCCESS);
        PrintCapability("codec_config_utest", &cap);
    }
}

HWTEST_F(CodecProxyTest, CodecHdiGetCapbility, TestSize.Level1)
{
    struct HdfRemoteService *remote = GetConfigService();
    ASSERT_TRUE(remote != nullptr);

    CodecCapbility cap;
    int32_t ret = GetCapability(remote, MEDIA_MIMETYPE_VIDEO_HEVC, VIDEO_ENCODER, 0, &cap);
    ASSERT_EQ(ret, HDF_SUCCESS);
    PrintCapability("codec_config_utest", &cap);
}

HWTEST_F(CodecProxyTest, CodecHdiInitCodec, TestSize.Level1)
{
    ASSERT_TRUE(codecObj != nullptr);
    int32_t errorCode = codecObj->CodecInit(codecObj);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiCreateCodec, TestSize.Level1)
{
    const char* name = "codec.avc.hardware.decoder";
    Param params;
    params.key = KEY_CODEC_TYPE;
    CodecType ct = VIDEO_DECODER;
    params.val = (void *)&ct;
    params.size = sizeof(ct);
    int len = 1;

    int32_t errorCode = codecObj->CodecCreate(codecObj, name, &params, len, &handle);

    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_TRUE(handle != nullptr);
}

HWTEST_F(CodecProxyTest, CodecHdiSetPortMode, TestSize.Level1)
{
    DirectionType type = OUTPUT_TYPE;
    BufferMode mode = EXTERNAL;

    int32_t errorCode = codecObj->CodecSetPortMode(codecObj, handle, type, mode);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiSetCodecType, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = KEY_CODEC_TYPE;
    CodecType ct = VIDEO_DECODER;
    params->val = (void *)&ct;
    params->size = sizeof(ct);

    int32_t errorCode = codecObj->CodecSetParameter(codecObj, handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiGetDefaultCfg, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = (ParamKey)ParamExtKeys::KEY_DEFAULT_CFG_RK;
    params->val = nullptr;
    params->size = 0;

    int32_t errorCode = codecObj->CodecGetParameter(codecObj, handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiSetSplitMode, TestSize.Level1)
{
    Param *params;
    int paramCnt = 1;
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    ASSERT_TRUE(params != nullptr);
    params->key = (ParamKey)ParamExtKeys::KEY_SPLIT_PARSE_RK;
    int32_t needSplit = 1;
    params->val = (void *)&needSplit;
    params->size = sizeof(needSplit);

    int32_t errorCode = codecObj->CodecSetParameter(codecObj, handle, params, paramCnt);
    OsalMemFree(params);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiQueueInput, TestSize.Level1)
{
    inputBuffer.id = 0;
    inputBuffer.size = TEST_PACKET_BUFFER_SIZE;
    int32_t ret = CreateShareMemory(&inputBuffer);
    ASSERT_EQ(ret, HDF_SUCCESS);
    inputInfoData.bufferCnt = 1;
    inputInfoData.flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    inputInfoData.buffers = &inputCodecBufferInfo;
    if (inputInfoData.buffers != NULL) {
        inputInfoData.buffers->type = BUFFER_TYPE_FD;
        inputInfoData.buffers->fd = inputBuffer.fd;
        inputInfoData.buffers->offset = inputBuffer.id;
        inputInfoData.buffers->size = TEST_PACKET_BUFFER_SIZE;
    }
    int32_t errorCode = codecObj->CodecQueueInput(codecObj, handle, &inputInfoData, (uint32_t)0);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiDequeInput, TestSize.Level1)
{
    InputInfo inputInfo = {0};
    CodecBufferInfo codecBufferInfo = {BUFFER_TYPE_FD};

    inputInfo.bufferCnt = 1;
    inputInfo.buffers = &codecBufferInfo;
    int32_t errorCode = codecObj->CodecDequeInput(codecObj, handle, QUEUE_TIME_OUT, &inputInfo);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_EQ(inputInfo.buffers->type, inputInfoData.buffers->type);
    ASSERT_EQ(inputInfo.buffers->size, inputInfoData.buffers->size);
    ASSERT_EQ(inputInfo.buffers->offset, inputInfoData.buffers->offset);
}

HWTEST_F(CodecProxyTest, CodecHdiStartCodec, TestSize.Level1)
{
    int32_t  errorCode = codecObj->CodecStart(codecObj, handle);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiStopCodec, TestSize.Level1)
{
    int32_t errorCode = codecObj->CodecStop(codecObj, handle);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiQueueOutput, TestSize.Level1)
{
    outputBuffer.id = 1;
    outputBuffer.size = TEST_FRAME_BUFFER_SIZE;
    CreateShareMemory(&outputBuffer);
    outputInfoData.bufferCnt = 1;
    outputInfoData.flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    outputInfoData.buffers = &outputCodecBufferInfo;
    if (outputInfoData.buffers != NULL) {
        outputInfoData.buffers->type = BUFFER_TYPE_FD;
        outputInfoData.buffers->fd = outputBuffer.fd;
        outputInfoData.buffers->offset = outputBuffer.id;
        outputInfoData.buffers->size = TEST_FRAME_BUFFER_SIZE;
    }
    int32_t errorCode = codecObj->CodecQueueOutput(codecObj, handle, &outputInfoData, (uint32_t)0, 1);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiDequeueOutput, TestSize.Level1)
{
    int32_t errorCode = 0;
    int32_t acquireFd;
    OutputInfo outInfo = {0};
    CodecBufferInfo codecBufferInfo = {BUFFER_TYPE_FD};
    outInfo.bufferCnt = 1;
    outInfo.buffers = &codecBufferInfo;
    errorCode = codecObj->CodecDequeueOutput(codecObj, handle, QUEUE_TIME_OUT, &acquireFd, &outInfo);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_EQ(outInfo.buffers->type, outputInfoData.buffers->type);
    ASSERT_EQ(outInfo.buffers->size, outputInfoData.buffers->size);
    ASSERT_EQ(outInfo.buffers->offset, outputInfoData.buffers->offset);
}

HWTEST_F(CodecProxyTest, CodecHdiFlush, TestSize.Level1)
{
    DirectionType directType = OUTPUT_TYPE;

    int32_t errorCode = codecObj->CodecFlush(codecObj, handle, directType);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    ASSERT_EQ(directType, OUTPUT_TYPE);
}

HWTEST_F(CodecProxyTest, CodecHdiSetCallback, TestSize.Level1)
{
    UINTPTR instance = 0;
    g_callback = CodecCallbackStubObtain();
    ASSERT_TRUE(g_callback != nullptr);

    int32_t errorCode = codecObj->CodecSetCallback(codecObj, handle, g_callback, instance);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiDestroyCodec, TestSize.Level1)
{
    int32_t errorCode = codecObj->CodecDestroy(codecObj, handle);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
}

HWTEST_F(CodecProxyTest, CodecHdiDeinit, TestSize.Level1)
{
    int32_t errorCode = codecObj->CodecDeinit(codecObj);
    ASSERT_EQ(errorCode, HDF_SUCCESS);
    HdiCodecRelease(codecObj);
}
}
