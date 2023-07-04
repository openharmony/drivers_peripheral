/*
 * Copyright (c) 2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <securec.h>
#include <string.h>
#include <sys/stat.h>
#include "codec_callback_stub.h"
#include "codec_type.h"
#include "codec_utils.h"
#include "codec_gralloc_wrapper.h"
#include "hdf_log.h"
#include "icodec.h"
#include "share_mem.h"

#define HDF_LOG_TAG codec_hdi_demo_encode
#define TEST_SERVICE_NAME   "codec_hdi_service"
#define QUEUE_TIME_OUT                      10
#define USLEEP_TIME_OUT                     10000
#define FRAME_SIZE_MULTI                    3
#define FRAME_SIZE_OPERATOR                 2
#define ENC_DEFAULT_FRAME_RATE              24
#define PARAM_ARRAY_LEN                     20
#define YUV_ALIGNMENT                       16
#define BUF_COUNT                           1
#define TIME_OUTMS                          0
#define RELEASE_FENCEFD                     (-1)
#define FOUR_BYTE_PIX_BUF_SIZE_OPERATOR     4
#define ENC_GET_PARAM_COUNT                 3

static struct ICodec *g_codecProxy = NULL;
static CODEC_HANDLETYPE g_handle = NULL;
ShareMemory *g_inputBuffers = NULL;
ShareMemory *g_outputBuffers = NULL;
CodecBuffer **g_inputInfosData = NULL;
CodecBuffer **g_outputInfosData = NULL;

CodecCmd g_cmd = {0};
CodecEnvData g_data = {0};

bool g_pktEos = false;
int32_t g_srcFileSize = 0;
int32_t g_totalSrcSize = 0;
int32_t g_totalDstSize = 0;
int32_t g_frameCount = 0;
int32_t g_frameStride = 0;
int32_t g_frameSize = 0;
CodecCallback g_callback;

static uint32_t inline AlignUp(uint32_t width, uint32_t alignment)
{
    if (alignment < 1) {
        return width;
    }
    return (((width) + alignment - 1) & (~(alignment - 1)));
}

static int32_t GetFrameSize(void)
{
    int32_t frameSize = 0;
    int32_t wStride = AlignUp(g_cmd.width, YUV_ALIGNMENT);
    switch (g_cmd.pixFmt) {
        case PIXEL_FMT_YCBCR_420_SP:
        case PIXEL_FMT_YCBCR_420_P:
            frameSize = (wStride * g_cmd.height * FRAME_SIZE_MULTI) / FRAME_SIZE_OPERATOR;
            break;
        case PIXEL_FMT_BGRA_8888:
        case PIXEL_FMT_RGBA_8888:
            frameSize = wStride * g_cmd.height * FOUR_BYTE_PIX_BUF_SIZE_OPERATOR;
            break;
        default:
            break;
    }
    return frameSize;
}

static void DumpOutputToFile(FILE *fp, uint8_t *addr, uint32_t len)
{
    if (fp == NULL || addr == NULL) {
        HDF_LOGE("%{public}s: invalid param!", __func__);
        return;
    }
    size_t ret = fwrite(addr, 1, len, fp);
    if (ret != len) {
        HDF_LOGE("%{public}s: Dump packet failed, ret: %{public}zu", __func__, ret);
    }
}

static int32_t ReadInputFromFile(FILE *fp, uint8_t *addr)
{
    if (fp == NULL || addr == NULL) {
        HDF_LOGE("%{public}s: invalid param!", __func__);
        return 0;
    }
    return fread(addr, 1, g_frameSize, fp);
}

static ShareMemory* GetShareMemoryById(int32_t id)
{
    uint32_t i;
    for (i = 0; i < g_data.inputBufferCount; i++) {
        if (g_inputBuffers[i].id == id) {
            return &g_inputBuffers[i];
        }
    }
    for (i = 0; i < g_data.outputBufferCount; i++) {
        if (g_outputBuffers[i].id == id) {
            return &g_outputBuffers[i];
        }
    }
    return NULL;
}

static void ReleaseShm(void)
{
    uint32_t i;
    if (g_inputBuffers != NULL) {
        for (i = 0; i < g_data.inputBufferCount; i++) {
            CodecBuffer *info = g_inputInfosData[i];
            ReleaseGrShareMemory((BufferHandle *)info->buffer[0].buf, &g_inputBuffers[i]);
        }
    }
    if (g_outputBuffers != NULL) {
        for (i = 0; i < g_data.outputBufferCount; i++) {
            ReleaseFdShareMemory(&g_outputBuffers[i]);
        }
    }
}

void ReleaseCodecBuffer(CodecBuffer *info)
{
    if (info == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    for (uint32_t i = 0; i < info->bufferCnt; i++) {
        if (info->buffer[i].type == BUFFER_TYPE_HANDLE) {
            DestroyGrShareMemory((BufferHandle *)info->buffer[i].buf);
        }
    }
    OsalMemFree(info);
}

static void ReleaseCodecBuffers(void)
{
    uint32_t i;
    if (g_inputInfosData != NULL) {
        for (i = 0; i < g_data.inputBufferCount; i++) {
            ReleaseCodecBuffer(g_inputInfosData[i]);
            g_inputInfosData[i] = NULL;
        }
    }
    if (g_outputInfosData != NULL) {
        for (i = 0; i < g_data.outputBufferCount; i++) {
            ReleaseCodecBuffer(g_outputInfosData[i]);
            g_outputInfosData[i] = NULL;
        }
    }
}

static int32_t CalcFrameParams(void)
{
    g_frameSize = GetFrameSize();
    g_frameStride = AlignUp(g_cmd.width, YUV_ALIGNMENT);
    if (g_frameSize <= 0 || g_frameStride <= 0) {
        HDF_LOGI("%{public}s: g_frameSize or g_frameStride invalid!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static bool AllocateBuffer(int32_t inputBufferNum, int32_t outputBufferNum)
{
    g_inputBuffers = (ShareMemory *)OsalMemCalloc(sizeof(ShareMemory) * inputBufferNum);
    g_outputBuffers = (ShareMemory *)OsalMemCalloc(sizeof(ShareMemory) * outputBufferNum);
    g_inputInfosData = (CodecBuffer **)OsalMemCalloc(sizeof(CodecBuffer*) * inputBufferNum);
    g_outputInfosData = (CodecBuffer **)OsalMemCalloc(sizeof(CodecBuffer*) * outputBufferNum);
    if (g_inputBuffers != NULL && g_outputBuffers != NULL && g_inputInfosData != NULL && g_outputInfosData != NULL) {
        return true;
    }

    HDF_LOGE("%{public}s: alloc buffers failed!", __func__);
    OsalMemFree(g_inputBuffers);
    OsalMemFree(g_outputBuffers);
    OsalMemFree(g_inputInfosData);
    OsalMemFree(g_outputInfosData);
    g_inputBuffers = NULL;
    g_outputBuffers = NULL;
    g_inputInfosData = NULL;
    g_outputInfosData = NULL;

    return false;
}

static void FreeInfosData(CodecBuffer **g_InfosData, int32_t num)
{
    if (g_InfosData == NULL) {
        HDF_LOGE("%{public}s: invalid param!", __func__);
        return;
    }
    for (int32_t n = 0; n < num; n++) {
        OsalMemFree(g_InfosData[n]);
    }
}

static bool InitInputInfosData(int32_t num)
{
    BufferHandle *bufferHandle = NULL;
    if (CreateGrShareMemory(&bufferHandle, g_cmd, &g_inputBuffers[num]) != HDF_SUCCESS) {
        return false;
    }
    g_inputInfosData[num] = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * BUF_COUNT);
    if (g_inputInfosData[num] == NULL) {
        FreeInfosData(g_inputInfosData, num);
        HDF_LOGE("%{public}s: g_inputInfosData[%{public}d] is NULL!", __func__, num);
        return false;
    }
    g_inputInfosData[num]->bufferCnt = BUF_COUNT;
    g_inputInfosData[num]->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    g_inputInfosData[num]->bufferId = g_inputBuffers[num].id;
    g_inputInfosData[num]->buffer[0].type = BUFFER_TYPE_HANDLE;
    g_inputInfosData[num]->buffer[0].buf = (intptr_t)bufferHandle;
    g_inputInfosData[num]->buffer[0].capacity = bufferHandle->size;
    return true;
}

static bool InitOutputInfosData(int32_t outputBufferSize, int32_t num)
{
    g_outputInfosData[num] = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * BUF_COUNT);
    if (g_outputInfosData[num] == NULL) {
        FreeInfosData(g_outputInfosData, num);
        HDF_LOGE("%{public}s: g_outputInfosData[%{public}d] is NULL!", __func__, num);
        return false;
    }
    g_outputInfosData[num]->bufferCnt = BUF_COUNT;
    g_outputInfosData[num]->bufferId = g_outputBuffers[num].id;
    g_outputInfosData[num]->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    g_outputInfosData[num]->buffer[0].type = BUFFER_TYPE_FD;
    g_outputInfosData[num]->buffer[0].buf = (intptr_t)g_outputBuffers[num].fd;
    g_outputInfosData[num]->buffer[0].capacity = outputBufferSize;
    return true;
}

static bool InitBuffer(int32_t inputBufferNum, int32_t inputBufferSize,
    int32_t outputBufferNum, int32_t outputBufferSize)
{
    int32_t queueRet;
    if (!AllocateBuffer(inputBufferNum, outputBufferNum)) {
        return false;
    }

    for (int32_t i = 0; i < inputBufferNum; i++) {
        g_inputBuffers[i].id = i;
        g_inputBuffers[i].type = BUFFER_TYPE_HANDLE;
        bool ret = InitInputInfosData(i);
        if (!ret) {
            HDF_LOGE("%{public}s: InitInputInfosData[%{public}d] failed!", __func__, i);
            return false;
        }
        queueRet = g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
        g_inputInfosData[i], TIME_OUTMS, RELEASE_FENCEFD);
        if (queueRet != HDF_SUCCESS) {
            FreeInfosData(g_inputInfosData, i);
            HDF_LOGE("%{public}s: CodecQueueInput g_inputInfosData[%{public}d] initial failed!", __func__, i);
            return false;
        }
    }

    for (int32_t j = 0; j < outputBufferNum; j++) {
        g_outputBuffers[j].id = inputBufferNum + j;
        g_outputBuffers[j].size = outputBufferSize;
        if (CreateFdShareMemory(&g_outputBuffers[j]) != HDF_SUCCESS) {
            return false;
        }
        bool ret = InitOutputInfosData(outputBufferSize, j);
        if (!ret) {
            FreeInfosData(g_inputInfosData, inputBufferNum);
            HDF_LOGE("%{public}s: InitOutputInfosData[%{public}d] failed!", __func__, j);
            return false;
        }
        queueRet = g_codecProxy->CodecQueueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
        g_outputInfosData[j], TIME_OUTMS, RELEASE_FENCEFD);
        if (queueRet != HDF_SUCCESS) {
            FreeInfosData(g_inputInfosData, inputBufferNum);
            FreeInfosData(g_outputInfosData, j);
            HDF_LOGE("%{public}s: CodecQueueInput g_outputInfosData[%{public}d] initial failed!", __func__, j);
            return false;
        }
    }
    return true;
}

static void CheckEncSetup(Param *setParams, Param *getParams, int32_t paramCnt)
{
    if (setParams == NULL || getParams == NULL || paramCnt <= 0) {
        HDF_LOGE("%{public}s: params is null or invalid count!", __func__);
        return;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (setParams[i].size != getParams[i].size) {
            HDF_LOGE("%{public}s: params size incorrect!", __func__);
            return;
        }
        if (memcmp(setParams[i].val, getParams[i].val, setParams[i].size) != 0) {
            HDF_LOGE("%{public}s: params val incorrect! index:%{public}d", __func__, i);
            return;
        }
    }
    
    HDF_LOGI("%{public}s: get all params correctly!", __func__);
}

static int32_t GetSetupParams(Param *setParams, int32_t paramCnt)
{
    Param *getParams = (Param *)OsalMemCalloc(sizeof(Param) * paramCnt);
    if (getParams == NULL) {
        HDF_LOGE("%{public}s: getParams is NULL!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    for (int32_t i = 0; i < paramCnt; i++) {
        getParams[i].key = setParams[i].key;
    }
    int32_t ret = g_codecProxy->CodecGetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, getParams, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecGetParameter failed, ret:%{public}d", __func__, ret);
        FreeParams(getParams, paramCnt);
        return HDF_FAILURE;
    }
    CheckEncSetup(setParams, getParams, paramCnt);
    FreeParams(getParams, paramCnt);
    return HDF_SUCCESS;
}

static int32_t SetupBasicEncParams(Param *params)
{
    if (params == NULL) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return 0;
    }
    Param *param = NULL;
    int32_t paramCount = 0;

    param = &params[paramCount++];
    param->key = KEY_VIDEO_WIDTH;
    param->val = &g_cmd.width;
    param->size = sizeof(g_cmd.width);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_HEIGHT;
    param->val = &g_cmd.height;
    param->size = sizeof(g_cmd.height);

    param = &params[paramCount++];
    param->key = KEY_CODEC_TYPE;
    param->val = &g_cmd.type;
    param->size = sizeof(g_cmd.type);

    param = &params[paramCount++];
    param->key = KEY_PIXEL_FORMAT;
    param->val = &g_cmd.pixFmt;
    param->size = sizeof(g_cmd.pixFmt);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_STRIDE;
    param->val = &g_frameStride;
    param->size = sizeof(g_frameStride);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_FRAME_RATE;
    param->val = &g_cmd.fps;
    param->size = sizeof(g_cmd.fps);

    return paramCount;
}

static int32_t SetupEncParams(void)
{
    Param params[PARAM_ARRAY_LEN] = {0};
    Param *param = NULL;
    int32_t paramCount = 0;

    paramCount = SetupBasicEncParams(params);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_RC_MODE;
    int32_t rcMode = VID_CODEC_RC_VBR;
    param->val = &rcMode;
    param->size = sizeof(rcMode);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_GOP_MODE;
    int32_t gopMode = VID_CODEC_GOPMODE_NORMALP;
    param->val = &gopMode;
    param->size = sizeof(gopMode);

    int32_t ret = g_codecProxy->CodecSetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, params, paramCount);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    ret = GetSetupParams(params, paramCount);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetSetupParams failed", __func__);
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t GetEncParameter(void)
{
    int32_t paramIndex = 0;
    int32_t ret;

    // get buffer size and count
    Param *param = (Param *)OsalMemCalloc(sizeof(Param) * ENC_GET_PARAM_COUNT);
    if (param == NULL) {
        HDF_LOGE("%{public}s: param malloc failed!", __func__);
        return HDF_FAILURE;
    }
    param[paramIndex++].key = KEY_BUFFERSIZE;
    param[paramIndex++].key = KEY_INPUT_BUFFER_COUNT;
    param[paramIndex++].key = KEY_OUTPUT_BUFFER_COUNT;
    ret = g_codecProxy->CodecGetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, param, ENC_GET_PARAM_COUNT);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecGetParameter failed", __func__);
        FreeParams(param, ENC_GET_PARAM_COUNT);
        return HDF_FAILURE;
    }
    paramIndex = 0;
    g_data.bufferSize = *(uint32_t *)param[paramIndex++].val;
    g_data.inputBufferCount = *(uint32_t *)param[paramIndex++].val;
    g_data.outputBufferCount = *(uint32_t *)param[paramIndex++].val;

    FreeParams(param, ENC_GET_PARAM_COUNT);
    return HDF_SUCCESS;
}

static int32_t CodecCallbackOnEvent(UINTPTR userData, EventType event, uint32_t length, int32_t eventData[])
{
    HDF_LOGI("%{public}s: userData: %{public}d, event: %{public}d!", __func__, userData, event);
    return HDF_SUCCESS;
}

static int32_t CodecCallbackInputBufferAvailable(UINTPTR userData, CodecBuffer *inBuf, int32_t *acquireFd)
{
    if (inBuf == NULL) {
        HDF_LOGE("%{public}s: invalid input buffer!", __func__);
        return HDF_FAILURE;
    }
    ShareMemory *sm = GetShareMemoryById(inBuf->bufferId);
    g_frameCount++;
    int32_t readSize = ReadInputFromFile(g_data.fpInput, sm->virAddr);
    g_totalSrcSize += readSize;
    g_pktEos = (g_totalSrcSize >= g_srcFileSize);
    if (g_pktEos) {
        HDF_LOGI("%{public}s: client inputData reach STREAM_FLAG_EOS, g_frameCount:%{public}d",
            __func__, g_frameCount);
        inBuf->flag = STREAM_FLAG_EOS;
    }
    
    inBuf->buffer[0].length = readSize;
    g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, inBuf, QUEUE_TIME_OUT, -1);
    return HDF_SUCCESS;
}

static int32_t CodecCallbackOutputBufferAvailable(UINTPTR userData, CodecBuffer *outBuf, int32_t *acquireFd)
{
    if (outBuf == NULL) {
        HDF_LOGE("%{public}s: invalid output buffer!", __func__);
        return HDF_FAILURE;
    }
    g_totalDstSize += outBuf->buffer[0].length;
    ShareMemory *sm = GetShareMemoryById(outBuf->bufferId);
    DumpOutputToFile(g_data.fpOutput, sm->virAddr, outBuf->buffer[0].length);
    
    outBuf->buffer[0].length = 0;
    g_codecProxy->CodecQueueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, outBuf, QUEUE_TIME_OUT, -1);
    if (outBuf->flag & STREAM_FLAG_EOS) {
        HDF_LOGI("%{public}s: client reach STREAM_FLAG_EOS, CodecEncode loopEnd", __func__);
        g_data.loopEnd = 1;
    }
    return HDF_SUCCESS;
}

static int32_t CodecCallbackServiceConstruct(CodecCallback *service)
{
    if (service == NULL) {
        HDF_LOGE("%{public}s: invalid output buffer!", __func__);
        return HDF_FAILURE;
    }
    service->OnEvent = CodecCallbackOnEvent;
    service->InputBufferAvailable = CodecCallbackInputBufferAvailable;
    service->OutputBufferAvailable = CodecCallbackOutputBufferAvailable;
    return HDF_SUCCESS;
}

static void RevertEncodeStep1(void)
{
    if (g_data.fpInput) {
        fclose(g_data.fpInput);
        g_data.fpInput = NULL;
    }
    if (g_data.fpOutput) {
        fclose(g_data.fpOutput);
        g_data.fpOutput = NULL;
    }
}

static void RevertEncodeStep2(void)
{
    int32_t ret = g_codecProxy->CodecDeinit(g_codecProxy);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to CodecDeinit %{public}d", __func__, ret);
    }
    RevertEncodeStep1();
}

static void RevertEncodeStep3(void)
{
    ReleaseShm();
    ReleaseCodecBuffers();

    if (g_inputBuffers != NULL) {
        OsalMemFree(g_inputBuffers);
    }
    if (g_outputBuffers != NULL) {
        OsalMemFree(g_outputBuffers);
    }
    if (g_inputInfosData != NULL) {
        OsalMemFree(g_inputInfosData);
    }
    if (g_outputInfosData != NULL) {
        OsalMemFree(g_outputInfosData);
    }
    int32_t ret = g_codecProxy->CodecDestroy(g_codecProxy, (CODEC_HANDLETYPE)g_handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to CodecDestroy %{public}d", __func__, ret);
    }
    RevertEncodeStep2();
}

static int32_t OpenFile(void)
{
    struct stat fileStat = {0};
    stat(g_cmd.fileInput, &fileStat);
    g_srcFileSize = fileStat.st_size;
    HDF_LOGI("%{public}s: input file size %{public}d", __func__, g_srcFileSize);

    g_data.fpInput = fopen(g_cmd.fileInput, "rb");
    if (g_data.fpInput == NULL) {
        HDF_LOGE("%{public}s: failed to open input file %{public}s", __func__, g_cmd.fileInput);
        RevertEncodeStep1();
        return HDF_FAILURE;
    }

    g_data.fpOutput = fopen(g_cmd.fileOutput, "w+b");
    if (g_data.fpOutput == NULL) {
        HDF_LOGE("%{public}s: failed to open output file %{public}s", __func__, g_cmd.fileOutput);
        RevertEncodeStep1();
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void EncodeEnd(void)
{
    DirectionType directType = ALL_TYPE;
    int32_t ret = g_codecProxy->CodecFlush(g_codecProxy, (CODEC_HANDLETYPE)g_handle, directType);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecFlush failed", __func__);
    }

    ret = g_codecProxy->CodecStop(g_codecProxy, (CODEC_HANDLETYPE)g_handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to CodecStop %{public}d", __func__, ret);
    }

    RevertEncodeStep3();
}

static int32_t Encode(void)
{
    int32_t ret = 0;

    if (OpenFile() != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    ret = g_codecProxy->CodecInit(g_codecProxy);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecInit failed", __func__);
        RevertEncodeStep1();
        return HDF_FAILURE;
    }

    ret = g_codecProxy->CodecCreate(g_codecProxy, g_data.codecName, &g_handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecCreate failed, ret:%{public}d", __func__, ret);
        RevertEncodeStep2();
        return HDF_FAILURE;
    }

    if (CalcFrameParams() != HDF_SUCCESS || SetupEncParams() != HDF_SUCCESS || GetEncParameter() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: params handling failed", __func__);
        RevertEncodeStep3();
        return HDF_FAILURE;
    }

    if (!InitBuffer(g_data.inputBufferCount, g_frameSize, g_data.outputBufferCount, g_data.bufferSize)) {
        HDF_LOGE("%{public}s: InitBuffer failed", __func__);
        RevertEncodeStep3();
        return HDF_FAILURE;
    }

    if (CodecCallbackServiceConstruct(&g_callback) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecCallbackStubObtain failed", __func__);
        RevertEncodeStep3();
        return HDF_FAILURE;
    }
    struct CodecCallbackStub *cb = CodecCallbackStubObtain(&g_callback);
    if (cb == NULL) {
        HDF_LOGE("%{public}s: CodecCallbackStubObtain failed", __func__);
        RevertEncodeStep3();
        return HDF_FAILURE;
    }
    if (g_codecProxy->CodecSetCallback(g_codecProxy, g_handle, &cb->service, 0) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetCallback failed", __func__);
        RevertEncodeStep3();
        return HDF_FAILURE;
    }

    g_codecProxy->CodecStart(g_codecProxy, (CODEC_HANDLETYPE)g_handle);

    while (g_data.loopEnd != 1) {
        usleep(USLEEP_TIME_OUT);
    }
    EncodeEnd();
    CodecCallbackStubRelease(cb);

    return HDF_SUCCESS;
}

int32_t main(int32_t argc, char **argv)
{
    if (GrAllocatorInit() != HDF_SUCCESS) {
        HDF_LOGE("GrAllocatorInit failed!");
        return HDF_FAILURE;
    }

    g_cmd.fps = ENC_DEFAULT_FRAME_RATE;
    g_cmd.pixFmt = PIXEL_FMT_YCBCR_420_SP;
    g_cmd.type = VIDEO_ENCODER;
    int32_t ret = ParseArguments(&g_cmd, argc, argv);
    HDF_LOGI("%{public}s: ParseArguments width:%{public}d", __func__, g_cmd.width);
    HDF_LOGI("%{public}s: ParseArguments height:%{public}d", __func__, g_cmd.height);
    HDF_LOGI("%{public}s: ParseArguments codecName:%{public}s", __func__, g_cmd.codecName);
    HDF_LOGI("%{public}s: ParseArguments input:%{public}s", __func__, g_cmd.fileInput);
    HDF_LOGI("%{public}s: ParseArguments output:%{public}s", __func__, g_cmd.fileOutput);
    HDF_LOGI("%{public}s: ParseArguments fps:%{public}d", __func__, g_cmd.fps);
    HDF_LOGI("%{public}s: ParseArguments pixFmt:%{public}d", __func__, g_cmd.pixFmt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ParseArguments failed", __func__);
        return ret;
    }

    ret = memset_s(&g_data, sizeof(g_data), 0, sizeof(g_data));
    if (ret != EOK) {
        HDF_LOGE("%{public}s, memset_s g_data failed!", __func__);
        return HDF_FAILURE;
    }
    g_codecProxy = HdiCodecGet(TEST_SERVICE_NAME);

    g_data.codecName = g_cmd.codecName;

    ret = Encode();
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: test success", __func__);
    } else {
        HDF_LOGE("%{public}s: test failed ret %{public}d", __func__, ret);
    }

    HdiCodecRelease(g_codecProxy);
    HDF_LOGI("%{public}s: test exit", __func__);
    return ret;
}

