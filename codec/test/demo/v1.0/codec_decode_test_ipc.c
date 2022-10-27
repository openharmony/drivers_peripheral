/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <securec.h>
#include <sys/stat.h>
#include "codec_callback_stub.h"
#include "codec_utils.h"
#include "codec_gralloc_wrapper.h"
#include "hdf_log.h"
#include "hdi_mpp.h"
#include "icodec.h"
#include "osal_mem.h"
#include "share_mem.h"

#define HDF_LOG_TAG codec_hdi_demo_decode
#define TEST_SERVICE_NAME           "codec_hdi_service"
#define INPUT_BUFFER_NUM            4
#define OUTPUT_BUFFER_NUM           10
#define STREAM_PACKET_BUFFER_SIZE   (4 * 1024)
#define QUEUE_TIME_OUT              10
#define HEIGHT_OPERATOR             2
#define FRAME_SIZE_OPERATOR         2
#define START_CODE_OFFSET_ONE       (-1)
#define START_CODE_OFFSET_SEC       (-2)
#define START_CODE_OFFSET_THIRD     (-3)
#define START_CODE_SIZE_FRAME       4
#define START_CODE_SIZE_SLICE       3
#define START_CODE                  0x1

typedef struct {
    char            *codecName;
    /* end of stream flag when set quit the loop */
    unsigned int    loopEnd;
    /* input and output */
    FILE            *fpInput;
    FILE            *fpOutput;
    int32_t         frameNum;
    CodecCallback   cb;
} MpiDecLoopData;

static struct ICodec *g_codecProxy = NULL;
static CODEC_HANDLETYPE g_handle = NULL;
ShareMemory *g_inputBuffers = NULL;
ShareMemory *g_outputBuffers = NULL;
CodecBuffer **g_inputInfosData = NULL;
CodecBuffer **g_outputInfosData = NULL;

CodecCmd g_cmd = {0};
MpiDecLoopData g_data = {0};
uint32_t g_autoSplit = 0;
bool g_pktEos = false;
uint8_t *g_readFileBuf;
int32_t g_srcFileSize = 0;
int32_t g_totalSrcSize = 0;
int32_t g_totalFrames = 0;

static void DumpOutputToFile(FILE *fp, uint8_t *addr)
{
    uint32_t width = g_cmd.width;
    uint32_t height = g_cmd.height;
    uint32_t horStride = g_cmd.width;
    uint32_t verStride = g_cmd.height;
    uint8_t *base = addr;
    size_t ret = 0;

    // MPP_FMT_YUV420SP
    uint32_t i;
    uint8_t *baseY = base;
    uint8_t *baseC = base + horStride * verStride;

    for (i = 0; i < height; i++, baseY += horStride) {
        ret = fwrite(baseY, 1, width, fp);
        if (ret != width) {
            HDF_LOGE("%{public}s: DumpOutputToFile failed", __func__);
            continue;
        }
    }
    for (i = 0; i < height / HEIGHT_OPERATOR; i++, baseC += horStride) {
        ret = fwrite(baseC, 1, width, fp);
        if (ret != width) {
            HDF_LOGE("%{public}s: DumpOutputToFile failed", __func__);
            continue;
        }
    }
}

static int32_t ReadInputFromFile(FILE *fp, uint8_t *buf)
{
    return fread(buf, 1, STREAM_PACKET_BUFFER_SIZE, fp);
}

static int32_t ReadOneFrameFromFile(FILE *fp, uint8_t *buf)
{
    int32_t readSize = 0;
    // read start code first
    size_t t = fread(buf, 1, START_CODE_SIZE_FRAME, fp);
    if (t < START_CODE_SIZE_FRAME) {
        return readSize;
    }
    uint8_t *temp = buf;
    temp += START_CODE_SIZE_FRAME;
    while (!feof(fp)) {
        t = fread(temp, 1, 1, fp);
        if (t != 1) {
            continue;
        }

        if (*temp == START_CODE) {
            // check start code
            if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0) &&
                (temp[START_CODE_OFFSET_THIRD] == 0)) {
                fseek(fp, -START_CODE_SIZE_FRAME, SEEK_CUR);
                temp -= (START_CODE_SIZE_FRAME - 1);
                break;
            } else if ((temp[START_CODE_OFFSET_ONE] == 0) && (temp[START_CODE_OFFSET_SEC] == 0)) {
                fseek(fp, -START_CODE_SIZE_SLICE, SEEK_CUR);
                temp -= (START_CODE_SIZE_SLICE - 1);
                break;
            }
        }
        temp++;
    }
    readSize = (temp - buf);
    return readSize;
}

static ShareMemory* GetShareMemoryById(int32_t id)
{
    int32_t i;
    for (i = 0; i < INPUT_BUFFER_NUM; i++) {
        if (g_inputBuffers[i].id == id) {
            return &g_inputBuffers[i];
        }
    }
    for (i = 0; i < OUTPUT_BUFFER_NUM; i++) {
        if (g_outputBuffers[i].id == id) {
            return &g_outputBuffers[i];
        }
    }
    return NULL;
}

static void ReleaseShm(void)
{
    int32_t i;
    if (g_inputBuffers != NULL) {
        for (i = 0; i < INPUT_BUFFER_NUM; i++) {
            ReleaseFdShareMemory(&g_inputBuffers[i]);
        }
    }
    if (g_outputBuffers != NULL) {
        for (i = 0; i < OUTPUT_BUFFER_NUM; i++) {
            CodecBuffer *info = g_outputInfosData[i];
            ReleaseGrShareMemory((BufferHandle *)info->buffer[0].buf, &g_outputBuffers[i]);
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
    int32_t i;
    if (g_inputInfosData != NULL) {
        for (i = 0; i < INPUT_BUFFER_NUM; i++) {
            ReleaseCodecBuffer(g_inputInfosData[i]);
            g_inputInfosData[i] = NULL;
        }
    }
    if (g_outputInfosData != NULL) {
        for (i = 0; i < OUTPUT_BUFFER_NUM; i++) {
            ReleaseCodecBuffer(g_outputInfosData[i]);
            g_outputInfosData[i] = NULL;
        }
    }
}

static bool AllocateBuffer(int32_t inputBufferNum, int32_t inputBufferSize,
    int32_t outputBufferNum, int32_t outputBufferSize)
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

static void InitAllocInfo(AllocInfo *alloc)
{
    if (alloc == NULL) {
        HDF_LOGI("%{public}s: ignore null alloc!", __func__);
        return;
    }
    alloc->width = g_cmd.width;
    alloc->height = g_cmd.height;
    alloc->usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA;
    alloc->format = PIXEL_FMT_YCBCR_420_SP;
}

static bool InitBuffer(int32_t inputBufferNum, int32_t inputBufferSize,
    int32_t outputBufferNum, int32_t outputBufferSize)
{
    int32_t queueRet = 0;
    int32_t bufCount = 1;
    if (!AllocateBuffer(inputBufferNum, inputBufferSize, outputBufferNum, outputBufferSize)) {
        return false;
    }
    for (int32_t i = 0; i < inputBufferNum; i++) {
        g_inputBuffers[i].id = i;
        g_inputBuffers[i].size = inputBufferSize;
        CreateFdShareMemory(&g_inputBuffers[i]);
        g_inputInfosData[i] = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCount);
        g_inputInfosData[i]->bufferCnt = 1;
        g_inputInfosData[i]->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_inputInfosData[i]->bufferId = g_inputBuffers[i].id;
        g_inputInfosData[i]->buffer[0].type = BUFFER_TYPE_FD;
        g_inputInfosData[i]->buffer[0].buf = (intptr_t)g_inputBuffers[i].fd;
        g_inputInfosData[i]->buffer[0].capacity = inputBufferSize;
        queueRet = g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
            g_inputInfosData[i], (uint32_t)0, -1);
        if (queueRet != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: input buffer initial failed!", __func__);
            return false;
        }
    }

    AllocInfo alloc;
    InitAllocInfo(&alloc);
    for (int32_t j = 0; j < outputBufferNum; j++) {
        g_outputBuffers[j].id = inputBufferNum + j;
        g_outputBuffers[j].type = BUFFER_TYPE_HANDLE;
        BufferHandle *bufferHandle;
        CreateGrShareMemory(&bufferHandle, &alloc, &g_outputBuffers[j]);
        g_outputInfosData[j] = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCount);
        g_outputInfosData[j]->bufferCnt = 1;
        g_outputInfosData[j]->bufferId = g_outputBuffers[j].id;
        g_outputInfosData[j]->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_outputInfosData[j]->buffer[0].type = BUFFER_TYPE_HANDLE;
        g_outputInfosData[j]->buffer[0].buf = (intptr_t)bufferHandle;
        g_outputInfosData[j]->buffer[0].capacity = bufferHandle->size;
        queueRet = g_codecProxy->CodecQueueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
            g_outputInfosData[j], (uint32_t)0, -1);
        if (queueRet != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: output buffer initial failed!", __func__);
            return false;
        }
    }
    return true;
}

int32_t TestOnEvent(UINTPTR userData, EventType event, uint32_t length, int32_t eventData[])
{
    HDF_LOGI("%{public}s: TestOnEvent : event = %{public}d", __func__, event);
    return HDF_SUCCESS;
}

int32_t TestInputBufferAvailable(UINTPTR userData, CodecBuffer *inBuf, int32_t *acquireFd)
{
    HDF_LOGI("%{public}s: TestInputBufferAvailable enter", __func__);
    return HDF_SUCCESS;
}

int32_t TestOutputBufferAvailable(UINTPTR userData, CodecBuffer *outBuf, int32_t *acquireFd)
{
    HDF_LOGI("%{public}s: TestOutputBufferAvailable write %{public}d", __func__, outBuf->buffer[0].length);
    return HDF_SUCCESS;
}

static int32_t SetExtDecParameter(void)
{
    Param param;
    int32_t paramCnt;
    int32_t ret;

    // set split_parse enable mpp internal frame spliter when the input
    paramCnt = 1;
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    param.key = (ParamKey)KEY_EXT_SPLIT_PARSE_RK;
    param.val = &g_autoSplit;
    param.size = sizeof(uint32_t);
    ret = g_codecProxy->CodecSetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &param, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed", __func__);
        return HDF_FAILURE;
    }

    // set decode frame number
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    paramCnt = 1;
    int32_t num = g_data.frameNum;
    param.key = (ParamKey)KEY_EXT_DEC_FRAME_NUM_RK;
    param.val = &num;
    param.size = sizeof(int32_t);
    ret = g_codecProxy->CodecSetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &param, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t SetDecParameter(void)
{
    Param param;
    int32_t paramCnt = 1;
    int32_t ret;

    // set CodecType
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    CodecType ct = VIDEO_DECODER;
    param.key = KEY_CODEC_TYPE;
    param.val = &ct;
    param.size = sizeof(ct);
    ret = g_codecProxy->CodecSetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &param, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter KEY_CODEC_TYPE failed", __func__);
        return HDF_FAILURE;
    }

    // get default config
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    paramCnt = 1;
    param.key = (ParamKey)KEY_EXT_DEFAULT_CFG_RK;
    int32_t needDefault = 1;
    param.val = &needDefault;
    param.size = sizeof(int32_t);
    ret = g_codecProxy->CodecGetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &param, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed", __func__);
        return HDF_FAILURE;
    }

    // get format
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    paramCnt = 1;
    param.key = KEY_PIXEL_FORMAT;
    CodecPixelFormat fmt = PIXEL_FORMAT_NONE;
    param.val = &fmt;
    param.size = sizeof(CodecPixelFormat);
    ret = g_codecProxy->CodecGetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &param, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed", __func__);
        return HDF_FAILURE;
    }

    if (SetExtDecParameter() != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void DecodeLoopHandleInput(const MpiDecLoopData *decData)
{
    int32_t ret = 0;
    int32_t readSize = 0;
    int32_t acquireFd = 0;

    CodecBuffer *inputData = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo));
    inputData->buffer[0].type = BUFFER_TYPE_FD;
    inputData->bufferCnt = 1;
    inputData->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    ret = g_codecProxy->CodecDequeueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, QUEUE_TIME_OUT,
        &acquireFd, inputData);
    if (ret == HDF_SUCCESS) {
        if (g_autoSplit == 1) {
            readSize = ReadInputFromFile(decData->fpInput, g_readFileBuf);
            g_totalSrcSize += readSize;
            g_pktEos = (readSize <= 0);
        } else {
            readSize = ReadOneFrameFromFile(decData->fpInput, g_readFileBuf);
            g_totalSrcSize += readSize;
            g_pktEos = ((g_totalSrcSize >= g_srcFileSize) || (readSize <= 0));
        }
        if (g_pktEos) {
            HDF_LOGI("%{public}s: client inputData reach STREAM_FLAG_EOS", __func__);
            inputData->flag = STREAM_FLAG_EOS;
        }
    
        ShareMemory *sm = GetShareMemoryById(inputData->bufferId);
        memcpy_s(sm->virAddr, readSize, (uint8_t*)g_readFileBuf, readSize);
        inputData->buffer[0].length = readSize;
        g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, inputData, QUEUE_TIME_OUT, -1);
    }
    OsalMemFree(inputData);
}

static int32_t DecodeLoop(MpiDecLoopData *decData)
{
    int32_t ret = 0;

    if (!g_pktEos) {
        DecodeLoopHandleInput(decData);
    }

    CodecBuffer *outputData = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo));
    outputData->buffer[0].type = BUFFER_TYPE_HANDLE;
    outputData->bufferCnt = 1;
    outputData->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;

    int32_t acquireFd = 0;
    ret = g_codecProxy->CodecDequeueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, QUEUE_TIME_OUT,
        &acquireFd, outputData);
    if (ret == HDF_SUCCESS) {
        g_totalFrames++;
        ShareMemory *sm = GetShareMemoryById(outputData->bufferId);
        DumpOutputToFile(decData->fpOutput, sm->virAddr);

        CodecBuffer *queOutputData = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo));
        queOutputData->buffer[0].type = BUFFER_TYPE_HANDLE;
        queOutputData->buffer[0].buf = outputData->buffer[0].buf;
        queOutputData->buffer[0].capacity = outputData->buffer[0].capacity;
        queOutputData->bufferId = outputData->bufferId;
        queOutputData->bufferCnt = 1;
        queOutputData->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_codecProxy->CodecQueueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, queOutputData, QUEUE_TIME_OUT, -1);
        if (outputData->flag & STREAM_FLAG_EOS) {
            HDF_LOGI("%{public}s: reach STREAM_FLAG_EOS, loopEnd, g_totalFrames:%{public}d", __func__, g_totalFrames);
            decData->loopEnd = 1;
        }
        OsalMemFree(queOutputData);
    }
    OsalMemFree(outputData);

    return ret;
}

static void *DecodeThread(void *arg)
{
    MpiDecLoopData *decData = (MpiDecLoopData *)arg;

    while (!decData->loopEnd) {
        DecodeLoop(decData);
    }

    HDF_LOGD("%{public}s: client loopEnd", __func__);
    return NULL;
}

static void RevertDecodeStep1(void)
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

static void RevertDecodeStep2(void)
{
    int32_t ret = g_codecProxy->CodecDeinit(g_codecProxy);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecDeinit failed, ret:%{public}d", __func__, ret);
    }
    RevertDecodeStep1();
}

static void RevertDecodeStep3(void)
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
        HDF_LOGE("%{public}s: CodecDestroy failed, ret:%{public}d", __func__, ret);
    }
    RevertDecodeStep2();
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
        RevertDecodeStep1();
        return HDF_FAILURE;
    }
    g_data.fpOutput = fopen(g_cmd.fileOutput, "w+b");
    if (g_data.fpOutput == NULL) {
        HDF_LOGE("%{public}s: failed to open output file %{public}s", __func__, g_cmd.fileOutput);
        RevertDecodeStep1();
        return HDF_FAILURE;
    }

    g_readFileBuf = (uint8_t *)OsalMemAlloc(g_cmd.width * g_cmd.height * FRAME_SIZE_OPERATOR);
    if (g_readFileBuf == NULL) {
        HDF_LOGE("%{public}s: g_readFileBuf malloc failed", __func__);
        RevertDecodeStep3();
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void DecodeEnd(void)
{
    DirectionType directType = ALL_TYPE;
    int32_t ret = g_codecProxy->CodecFlush(g_codecProxy, (CODEC_HANDLETYPE)g_handle, directType);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecFlush failed, ret:%{public}d", __func__, ret);
    }

    ret = g_codecProxy->CodecStop(g_codecProxy, (CODEC_HANDLETYPE)g_handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecStop failed, ret:%{public}d", __func__, ret);
    }

    RevertDecodeStep3();
    if (g_readFileBuf != NULL) {
        OsalMemFree(g_readFileBuf);
    }
}

static int32_t Decode(void)
{
    pthread_t thd;
    pthread_attr_t attr;
    int32_t ret = 0;

    if (OpenFile() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to open file!", __func__);
        return HDF_FAILURE;
    }

    ret = g_codecProxy->CodecInit(g_codecProxy);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecInit failed, ret:%{public}d", __func__, ret);
        RevertDecodeStep1();
        return HDF_FAILURE;
    }

    ret = g_codecProxy->CodecCreate(g_codecProxy, g_data.codecName, &g_handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecCreate failed, ret:%{public}d", __func__, ret);
        RevertDecodeStep2();
        return HDF_FAILURE;
    }
    if (SetDecParameter() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SetDecParameter failed", __func__);
        RevertDecodeStep3();
        return HDF_FAILURE;
    }

    if (!InitBuffer(INPUT_BUFFER_NUM, g_cmd.width * g_cmd.height * FRAME_SIZE_OPERATOR, OUTPUT_BUFFER_NUM,
        g_cmd.width * g_cmd.height * FRAME_SIZE_OPERATOR)) {
        HDF_LOGE("%{public}s: InitBuffer failed", __func__);
        RevertDecodeStep3();
        return HDF_FAILURE;
    }

    g_codecProxy->CodecStart(g_codecProxy, (CODEC_HANDLETYPE)g_handle);

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    ret = pthread_create(&thd, &attr, DecodeThread, &g_data);
    if (ret != 0) {
        HDF_LOGE("%{public}s: failed to create thread for input ret %{public}d", __func__, ret);
        DecodeEnd();
        pthread_attr_destroy(&attr);
        return HDF_SUCCESS;
    }

    pthread_join(thd, NULL);
    DecodeEnd();
    pthread_attr_destroy(&attr);

    return HDF_SUCCESS;
}

int32_t main(int32_t argc, char **argv)
{
    if (GrAllocatorInit() != HDF_SUCCESS) {
        HDF_LOGE("GrAllocatorInit failed!");
        return HDF_FAILURE;
    }

    g_cmd.type = VIDEO_DECODER;
    int32_t ret = ParseArguments(&g_cmd, argc, argv);
    HDF_LOGI("%{public}s: ParseArguments width:%{public}d", __func__, g_cmd.width);
    HDF_LOGI("%{public}s: ParseArguments height:%{public}d", __func__, g_cmd.height);
    HDF_LOGI("%{public}s: ParseArguments codecName:%{public}s", __func__, g_cmd.codecName);
    HDF_LOGI("%{public}s: ParseArguments input:%{public}s", __func__, g_cmd.fileInput);
    HDF_LOGI("%{public}s: ParseArguments output:%{public}s", __func__, g_cmd.fileOutput);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("ParseArguments failed!");
        return ret;
    }

    memset_s(&g_data, sizeof(g_data), 0, sizeof(g_data));
    g_codecProxy = HdiCodecGet(TEST_SERVICE_NAME);
    g_data.codecName = g_cmd.codecName;

    ret = Decode();
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: test success", __func__);
    } else {
        HDF_LOGE("%{public}s: test failed ret %{public}d", __func__, ret);
    }

    // Release
    HdiCodecRelease(g_codecProxy);
    HDF_LOGI("%{public}s: test exit", __func__);
    return ret;
}

