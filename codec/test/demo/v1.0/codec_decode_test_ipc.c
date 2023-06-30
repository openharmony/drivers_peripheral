/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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

#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <securec.h>
#include <sys/stat.h>
#include "codec_utils.h"
#include "codec_gralloc_wrapper.h"
#include "hdf_log.h"
#include "icodec.h"
#include "share_mem.h"

#define HDF_LOG_TAG                         codec_hdi_demo_decode
#define TEST_SERVICE_NAME                   "codec_hdi_service"
#define STREAM_PACKET_BUFFER_SIZE           (4 * 1024)
#define QUEUE_TIME_OUT                      10
#define FRAME_SIZE_OPERATOR                 2
#define FRAME_SIZE_MULTI                    3
#define START_CODE_OFFSET_ONE               (-1)
#define START_CODE_OFFSET_SEC               (-2)
#define START_CODE_OFFSET_THIRD             (-3)
#define START_CODE_SIZE_FRAME               4
#define START_CODE_SIZE_SLICE               3
#define START_CODE                          0x1
#define VOP_START                           0xb6
#define YUV_ALIGNMENT                       16
#define READ_SIZE_FRAME                     1
#define BUF_COUNT                           1
#define TINE_OUTMS                          0
#define RELEASE_FENCEFD                     (-1)
#define FOUR_BYTE_PIX_BUF_SIZE_OPERATOR     4
#define DEC_GET_PARAM_COUNT                 3

static struct ICodec *g_codecProxy = NULL;
static CODEC_HANDLETYPE g_handle = NULL;
ShareMemory *g_inputBuffers = NULL;
ShareMemory *g_outputBuffers = NULL;
CodecBuffer **g_inputInfosData = NULL;
CodecBuffer **g_outputInfosData = NULL;

CodecCmd g_cmd = {0};
CodecEnvData g_data = {0};
uint32_t g_autoSplit = 0;
bool g_pktEos = false;
uint8_t *g_readFileBuf;
int32_t g_srcFileSize = 0;
int32_t g_totalSrcSize = 0;
int32_t g_totalFrames = 0;
int32_t g_frameStride = 0;
int32_t g_frameSize = 0;

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

static void DumpOutputToFile(FILE *fp, uint8_t *addr)
{
    size_t ret = fwrite(addr, 1, g_frameSize, fp);
    if (ret != (size_t)g_frameSize) {
        HDF_LOGE("%{public}s: Dump frame failed, ret: %{public}zu", __func__, ret);
    }
}

static int32_t ReadInputFromFile(FILE *fp, uint8_t *buf)
{
    return fread(buf, 1, STREAM_PACKET_BUFFER_SIZE, fp);
}

static int32_t ReadAvcFrame(FILE *fp, uint8_t *buf)
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

static int32_t ReadMpeg4Frame(FILE *fp, uint8_t *buf)
{
    int32_t readSize = 0;
    size_t length = fread(buf, READ_SIZE_FRAME, START_CODE_SIZE_SLICE, fp);
    if (length != START_CODE_SIZE_SLICE) {
        HDF_LOGE("%{public}s: fread failed!", __func__);
        return 0;
    }
    if (feof(fp)) {
        return readSize;
    }

    uint8_t *temp = buf;
    temp += START_CODE_SIZE_SLICE;
    bool findVop = false;
    while (!feof(fp)) {
        length = fread(temp, READ_SIZE_FRAME, READ_SIZE_FRAME, fp);
        if (length != READ_SIZE_FRAME) {
            HDF_LOGE("%{public}s: fread failed!", __func__);
            continue;
        }
        // check start code
        if ((*temp == VOP_START) && (temp[START_CODE_OFFSET_ONE] == START_CODE) && (temp[START_CODE_OFFSET_SEC] == 0) &&
            (temp[START_CODE_OFFSET_THIRD] == 0)) {
            findVop = true;
        }
        if (findVop && (*temp == START_CODE) && (temp[START_CODE_OFFSET_ONE] == 0) &&
            (temp[START_CODE_OFFSET_SEC] == 0)) {
            temp -= START_CODE_SIZE_SLICE - READ_SIZE_FRAME;
            fseek(fp, START_CODE_OFFSET_THIRD, SEEK_CUR);
            break;
        }
        temp++;
    }
    readSize = (temp - buf);
    return readSize;
}

static int32_t ReadVp9Frame(FILE *fp, uint8_t *buf)
{
    // len(4 bytes, little-end, length of vp9 data) + vp9 data
    int32_t readSize = 0;
    size_t length = fread(&readSize, READ_SIZE_FRAME, sizeof(readSize), fp);
    if (length != sizeof(readSize)) {
        HDF_LOGE("%{public}s: fread failed!", __func__);
        return 0;
    }
    if (feof(fp)) {
        return 0;
    }
    readSize = ntohl(readSize);
    length = fread(buf, READ_SIZE_FRAME, readSize, fp);
    if (length != (size_t)readSize) {
        HDF_LOGE("%{public}s: fread failed!", __func__);
        return 0;
    }
    return readSize;
}

static int32_t ReadOneFrameFromFile(FILE *fp, uint8_t *buf)
{
    if (strstr(g_cmd.codecName, CODEC_NAME_AVC_HW_DECODER)) {
        return ReadAvcFrame(fp, buf);
    } else if (strstr(g_cmd.codecName, CODEC_NAME_HEVC_HW_DECODER)) {
        return ReadAvcFrame(fp, buf);
    } else if (strstr(g_cmd.codecName, CODEC_NAME_VP9_HW_DECODER) ||
        strstr(g_cmd.codecName, CODEC_NAME_VP8_HW_DECODER)) {
        return ReadVp9Frame(fp, buf);
    } else if (strstr(g_cmd.codecName, CODEC_NAME_MPEG4_HW_DECODER)) {
        return ReadMpeg4Frame(fp, buf);
    } else {
        return 0;
    }
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
            ReleaseFdShareMemory(&g_inputBuffers[i]);
        }
    }
    if (g_outputBuffers != NULL) {
        for (i = 0; i < g_data.outputBufferCount; i++) {
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
    for (int32_t n = 0; n < num; n++) {
        OsalMemFree(g_InfosData[n]);
    }
}

static bool InitInputInfosData(int32_t inputBufferSize, int32_t num)
{
    g_inputInfosData[num] = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * BUF_COUNT);
    if (g_inputInfosData[num] == NULL) {
        FreeInfosData(g_inputInfosData, num);
        HDF_LOGE("%{public}s: g_inputInfosData[%{public}d] is NULL!", __func__, num);
        return false;
    }
    g_inputInfosData[num]->bufferCnt = BUF_COUNT;
    g_inputInfosData[num]->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    g_inputInfosData[num]->bufferId = g_inputBuffers[num].id;
    g_inputInfosData[num]->buffer[0].type = BUFFER_TYPE_FD;
    g_inputInfosData[num]->buffer[0].buf = (intptr_t)g_inputBuffers[num].fd;
    g_inputInfosData[num]->buffer[0].capacity = inputBufferSize;
    return true;
}

static bool InitOutputInfosData(int32_t inputBufferNum, BufferHandle *bufferHandle, int32_t num)
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
    g_outputInfosData[num]->buffer[0].type = BUFFER_TYPE_HANDLE;
    g_outputInfosData[num]->buffer[0].buf = (intptr_t)bufferHandle;
    g_outputInfosData[num]->buffer[0].capacity = bufferHandle->size;
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
        g_inputBuffers[i].size = inputBufferSize;
        CreateFdShareMemory(&g_inputBuffers[i]);
        if (!InitInputInfosData(inputBufferSize, i)) {
            HDF_LOGE("%{public}s: InitInput[%{public}d] failed!", __func__, i);
            return false;
        }
        queueRet = g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
            g_inputInfosData[i], TINE_OUTMS, RELEASE_FENCEFD);
        if (queueRet != HDF_SUCCESS) {
            FreeInfosData(g_inputInfosData, i);
            HDF_LOGE("%{public}s: CodecQueueInput g_inputInfosData[%{public}d] initial failed!", __func__, i);
            return false;
        }
    }

    for (int32_t j = 0; j < outputBufferNum; j++) {
        g_outputBuffers[j].id = inputBufferNum + j;
        g_outputBuffers[j].type = BUFFER_TYPE_HANDLE;
        BufferHandle *bufferHandle;
        CreateGrShareMemory(&bufferHandle, g_cmd, &g_outputBuffers[j]);
        if (!InitOutputInfosData(inputBufferNum, bufferHandle, j)) {
            FreeInfosData(g_inputInfosData, inputBufferNum);
            HDF_LOGE("%{public}s: InitInput[%{public}d] failed!", __func__, j);
            return false;
        }
        queueRet = g_codecProxy->CodecQueueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
            g_outputInfosData[j], TINE_OUTMS, RELEASE_FENCEFD);
        if (queueRet != HDF_SUCCESS) {
            FreeInfosData(g_inputInfosData, inputBufferNum);
            FreeInfosData(g_outputInfosData, j);
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

static int32_t SetBasicDecParameter(void)
{
    Param param;
    int32_t paramCnt;
    int32_t ret;

    // set width
    paramCnt = 1;
    ret = memset_s(&param, sizeof(Param), 0, sizeof(Param));
    if (ret != EOK) {
        HDF_LOGE("%{public}s, memset_s width failed!", __func__);
        return HDF_FAILURE;
    }
    param.key = (ParamKey)KEY_VIDEO_WIDTH;
    param.val = &g_cmd.width;
    param.size = sizeof(g_cmd.width);
    ret = g_codecProxy->CodecSetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &param, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed", __func__);
        return HDF_FAILURE;
    }

    // set height
    ret = memset_s(&param, sizeof(Param), 0, sizeof(Param));
    if (ret != EOK) {
        HDF_LOGE("%{public}s, memset_s height failed!", __func__);
        return HDF_FAILURE;
    }
    paramCnt = 1;
    param.key = (ParamKey)KEY_VIDEO_HEIGHT;
    param.val = &g_cmd.height;
    param.size = sizeof(g_cmd.height);
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

    if (SetBasicDecParameter() != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

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

    // set format
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    paramCnt = 1;
    param.key = KEY_PIXEL_FORMAT;
    param.val = &g_cmd.pixFmt;
    param.size = sizeof(PixelFormat);
    ret = g_codecProxy->CodecSetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &param, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed", __func__);
        return HDF_FAILURE;
    }

    // set stride
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    param.key = KEY_VIDEO_STRIDE;
    param.val = &g_frameStride;
    param.size = sizeof(g_frameStride);
    ret = g_codecProxy->CodecSetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &param, paramCnt);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t GetDecParameter(void)
{
    int32_t paramIndex = 0;
    int32_t ret;

    // get buffer size and count
    Param *param = (Param *)OsalMemCalloc(sizeof(Param) * DEC_GET_PARAM_COUNT);
    if (param == NULL) {
        HDF_LOGE("%{public}s: param malloc failed!", __func__);
        return HDF_FAILURE;
    }
    param[paramIndex++].key = KEY_BUFFERSIZE;
    param[paramIndex++].key = KEY_INPUT_BUFFER_COUNT;
    param[paramIndex++].key = KEY_OUTPUT_BUFFER_COUNT;
    ret = g_codecProxy->CodecGetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, param, DEC_GET_PARAM_COUNT);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecGetParameter failed", __func__);
        FreeParams(param, DEC_GET_PARAM_COUNT);
        return HDF_FAILURE;
    }
    paramIndex = 0;
    g_data.bufferSize = *(uint32_t *)param[paramIndex++].val;
    g_data.inputBufferCount = *(uint32_t *)param[paramIndex++].val;
    g_data.outputBufferCount = *(uint32_t *)param[paramIndex++].val;

    FreeParams(param, DEC_GET_PARAM_COUNT);
    return HDF_SUCCESS;
}

static void DecodeLoopHandleInput(const CodecEnvData *decData)
{
    int32_t readSize;
    int32_t acquireFd = 0;

    CodecBuffer *inputData = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo));
    if (inputData == NULL) {
        HDF_LOGE("%{public}s: inputData is NULL", __func__);
        return;
    }
    inputData->buffer[0].type = BUFFER_TYPE_FD;
    inputData->bufferCnt = 1;
    inputData->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    int32_t ret = g_codecProxy->CodecDequeueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, QUEUE_TIME_OUT,
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
        ret = memcpy_s(sm->virAddr, readSize, (uint8_t*)g_readFileBuf, readSize);
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memcpy_s sm->virAddr err [%{public}d].", __func__, ret);
            return;
        }
        inputData->buffer[0].length = readSize;
        g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, inputData, QUEUE_TIME_OUT, -1);
    }
    OsalMemFree(inputData);
}

static int32_t DecodeLoop(CodecEnvData *decData)
{
    int32_t ret = 0;

    if (!g_pktEos) {
        DecodeLoopHandleInput(decData);
    }

    CodecBuffer *outputData = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo));
    if (outputData == NULL) {
        HDF_LOGE("%{public}s: outputData is NULL", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
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
        if (queOutputData == NULL) {
            OsalMemFree(outputData);
            HDF_LOGE("%{public}s: queOutputData is NULL", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }
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
    CodecEnvData *decData = (CodecEnvData *)arg;

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
}

static int32_t Decode(void)
{
    pthread_t thd;
    pthread_attr_t attr;

    if (OpenFile() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to open file!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = g_codecProxy->CodecInit(g_codecProxy);
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

    if (CalcFrameParams() != HDF_SUCCESS || SetDecParameter() != HDF_SUCCESS || GetDecParameter() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: params handling failed", __func__);
        RevertDecodeStep3();
        return HDF_FAILURE;
    }

    if (!InitBuffer(g_data.inputBufferCount, g_data.bufferSize, g_data.outputBufferCount, g_frameSize)) {
        HDF_LOGE("%{public}s: InitBuffer failed", __func__);
        RevertDecodeStep3();
        return HDF_FAILURE;
    }

    g_readFileBuf = (uint8_t *)OsalMemAlloc(g_data.bufferSize);
    if (g_readFileBuf == NULL) {
        HDF_LOGE("%{public}s: g_readFileBuf malloc failed", __func__);
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
        OsalMemFree(g_readFileBuf);
        pthread_attr_destroy(&attr);
        return HDF_SUCCESS;
    }

    pthread_join(thd, NULL);
    DecodeEnd();
    OsalMemFree(g_readFileBuf);
    pthread_attr_destroy(&attr);

    return HDF_SUCCESS;
}

int32_t main(int32_t argc, char **argv)
{
    if (GrAllocatorInit() != HDF_SUCCESS) {
        HDF_LOGE("GrAllocatorInit failed!");
        return HDF_FAILURE;
    }

    g_cmd.pixFmt = PIXEL_FMT_YCBCR_420_SP;
    g_cmd.type = VIDEO_DECODER;
    int32_t ret = ParseArguments(&g_cmd, argc, argv);
    HDF_LOGI("%{public}s: ParseArguments width:%{public}d", __func__, g_cmd.width);
    HDF_LOGI("%{public}s: ParseArguments height:%{public}d", __func__, g_cmd.height);
    HDF_LOGI("%{public}s: ParseArguments codecName:%{public}s", __func__, g_cmd.codecName);
    HDF_LOGI("%{public}s: ParseArguments input:%{public}s", __func__, g_cmd.fileInput);
    HDF_LOGI("%{public}s: ParseArguments output:%{public}s", __func__, g_cmd.fileOutput);
    HDF_LOGI("%{public}s: ParseArguments pixFmt:%{public}d", __func__, g_cmd.pixFmt);
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

