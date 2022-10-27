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
#include <securec.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "codec_callback_stub.h"
#include "codec_type.h"
#include "codec_utils.h"
#include "codec_gralloc_wrapper.h"
#include "hdf_log.h"
#include "hdi_mpp.h"
#include "hdi_mpp_config.h"
#include "icodec.h"
#include "osal_mem.h"
#include "share_mem.h"

#define HDF_LOG_TAG codec_hdi_demo_encode
#define TEST_SERVICE_NAME   "codec_hdi_service"
#define QUEUE_TIME_OUT              10
#define READ_SEGMENT_SIZE           8192
#define FRAME_SIZE_MULTI         	3
#define FRAME_SIZE_OPERATOR         2
#define BPS_BASE		            16
#define BPS_MAX			            17
#define BPS_MEDIUM			        15
#define BPS_MIN            			1
#define BPS_TARGET         			2
#define FIXQP_INIT_VALUE            20
#define FIXQP_MAX_VALUE             20
#define FIXQP_MIN_VALUE             20
#define FIXQP_MAX_I_VALUE           20
#define FIXQP_MIN_I_VALUE           20
#define FIXQP_IP_VALUE              2
#define OTHER_QP_INIT_VALUE         26
#define OTHER_QP_MAX_VALUE          51
#define OTHER_QP_MIN_VALUE          10
#define OTHER_QP_MAX_I_VALUE        51
#define OTHER_QP_MIN_I_VALUE        10
#define OTHER_QP_IP_VALUE           2
#define AVC_SETUP_LEVEL_DEFAULT     40
#define AVC_SETUP_CABAC_EN_DEFAULT  1
#define AVC_SETUP_CABAC_IDC_DEFAULT 0
#define AVC_SETUP_TRANS_DEFAULT     1
#define AVC_SETUP_PROFILE_DEFAULT   100
#define FPS_OUT_NUM_OPERATOR        2
#define INPUT_BUFFER_NUM            4
#define INPUT_BUFFER_SIZE_OPERATOR  2
#define OUTPUT_BUFFER_NUM           4
#define ENC_SETUP_DROP_THD          20
#define ENC_SETUP_FPS_IN_NUM        24
#define ENC_SETUP_FPS_OUT_NUM       24
#define PARAM_ARRAY_LEN             20

typedef struct {
    char            *codecName;
    /* end of stream flag when set quit the loop */
    unsigned int    loopEnd;
    /* input and output */
    FILE            *fpInput;
    FILE            *fpOutput;
    int32_t         frameNum;
    CodecCallback   cb;
} CodecEnvData;

static struct ICodec *g_codecProxy = NULL;
static CODEC_HANDLETYPE g_handle = NULL;
ShareMemory *g_inputBuffers = NULL;
ShareMemory *g_outputBuffers = NULL;
CodecBuffer **g_inputInfosData = NULL;
CodecBuffer **g_outputInfosData = NULL;

CodecCmd g_cmd = {0};
CodecEnvData g_data = {0};
RKHdiEncodeSetup g_encodeSetup = {0};

bool g_pktEos = false;
int32_t g_srcFileSize = 0;
int32_t g_totalSrcSize = 0;
int32_t g_totalDstSize = 0;
int32_t g_frameCount = 0;

void DumpOutputToFile(FILE *fp, uint8_t *addr, uint32_t len)
{
    size_t ret = fwrite(addr, 1, len, fp);
    if (ret != len) {
        HDF_LOGE("%{public}s: DumpOutputToFile failed", __func__);
    }
}

static int32_t ReadInputFromFile(FILE *fp, uint8_t *addr)
{
    int32_t readSize = 0;
    int32_t frameSize = g_cmd.width * g_cmd.height * FRAME_SIZE_MULTI / FRAME_SIZE_OPERATOR;
    int32_t loop = frameSize / READ_SEGMENT_SIZE;
    for (int32_t i = 0; i < loop; i++) {
        readSize += fread(addr + readSize, 1, READ_SEGMENT_SIZE, fp);
    }
    if (frameSize % READ_SEGMENT_SIZE > 0) {
        readSize += fread(addr + readSize, 1, frameSize % READ_SEGMENT_SIZE, fp);
    }
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
            CodecBuffer *info = g_inputInfosData[i];
            ReleaseGrShareMemory((BufferHandle *)info->buffer[0].buf, &g_inputBuffers[i]);
        }
    }
    if (g_outputBuffers != NULL) {
        for (i = 0; i < OUTPUT_BUFFER_NUM; i++) {
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

    AllocInfo alloc;
    InitAllocInfo(&alloc);
    for (int32_t i = 0; i < inputBufferNum; i++) {
        g_inputBuffers[i].id = i;
        g_inputBuffers[i].type = BUFFER_TYPE_HANDLE;
        BufferHandle *bufferHandle;
        CreateGrShareMemory(&bufferHandle, &alloc, &g_inputBuffers[i]);
        g_inputInfosData[i] = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCount);
        g_inputInfosData[i]->bufferCnt = 1;
        g_inputInfosData[i]->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_inputInfosData[i]->bufferId = g_inputBuffers[i].id;
        g_inputInfosData[i]->buffer[0].type = BUFFER_TYPE_HANDLE;
        g_inputInfosData[i]->buffer[0].buf = (intptr_t)bufferHandle;
        g_inputInfosData[i]->buffer[0].capacity = bufferHandle->size;
        queueRet = g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
            g_inputInfosData[i], (uint32_t)0, -1);
        if (queueRet != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: input buffer initial failed!", __func__);
            return false;
        }
    }

    for (int32_t j = 0; j < outputBufferNum; j++) {
        g_outputBuffers[j].id = inputBufferNum + j;
        g_outputBuffers[j].size = outputBufferSize;
        CreateFdShareMemory(&g_outputBuffers[j]);
        g_outputInfosData[j] = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCount);
        g_outputInfosData[j]->bufferCnt = 1;
        g_outputInfosData[j]->bufferId = g_outputBuffers[j].id;
        g_outputInfosData[j]->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_outputInfosData[j]->buffer[0].type = BUFFER_TYPE_FD;
        g_outputInfosData[j]->buffer[0].buf = (intptr_t)g_outputBuffers[j].fd;
        g_outputInfosData[j]->buffer[0].capacity = outputBufferSize;
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
    HDF_LOGI("%{public}s: TestOnEvent: event = %{public}d", __func__, event);
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

static void SetQpValue(RKHdiEncodeSetup *encSetup)
{
    switch (encSetup->rc.rcMode) {
        case MPP_ENC_RC_MODE_FIXQP: {
            encSetup->rc.qpInit = FIXQP_INIT_VALUE;
            encSetup->rc.qpMax = FIXQP_MAX_VALUE;
            encSetup->rc.qpMin = FIXQP_MIN_VALUE;
            encSetup->rc.qpMaxI = FIXQP_MAX_I_VALUE;
            encSetup->rc.qpMinI = FIXQP_MIN_I_VALUE;
            encSetup->rc.qpIp = FIXQP_IP_VALUE;
            break;
        }
        case MPP_ENC_RC_MODE_CBR:
        case MPP_ENC_RC_MODE_VBR:
        case MPP_ENC_RC_MODE_AVBR: {
            encSetup->rc.qpInit = OTHER_QP_INIT_VALUE;
            encSetup->rc.qpMax = OTHER_QP_MAX_VALUE;
            encSetup->rc.qpMin = OTHER_QP_MIN_VALUE;
            encSetup->rc.qpMaxI = OTHER_QP_MAX_I_VALUE;
            encSetup->rc.qpMinI = OTHER_QP_MIN_I_VALUE;
            encSetup->rc.qpIp = OTHER_QP_IP_VALUE;
            break;
        }
        default: {
            HDF_LOGE("%{public}s: unsupported encoder rc mode %{public}d", __func__, encSetup->rc.rcMode);
            break;
        }
    }
}

static void CalcBpsRange(RKHdiEncodeSetup *encSetup)
{
    switch (encSetup->rc.rcMode) {
        case MPP_ENC_RC_MODE_FIXQP: {
            /* do not setup bitrate on FIXQP mode */
            break;
        }
        case MPP_ENC_RC_MODE_CBR: {
            /* CBR mode has narrow bound */
            encSetup->rc.bpsMax = encSetup->rc.bpsTarget * BPS_MAX / BPS_BASE;
            encSetup->rc.bpsMin = encSetup->rc.bpsTarget * BPS_MEDIUM / BPS_BASE;
            break;
        }
        case MPP_ENC_RC_MODE_VBR:
        case MPP_ENC_RC_MODE_AVBR: {
            /* VBR mode has wide bound */
            encSetup->rc.bpsMax = encSetup->rc.bpsTarget * BPS_MAX / BPS_BASE;
            encSetup->rc.bpsMin = encSetup->rc.bpsTarget * BPS_MIN / BPS_BASE;
            break;
        }
        default: {
            /* default use CBR mode */
            encSetup->rc.bpsMax = encSetup->rc.bpsTarget * BPS_MAX / BPS_BASE;
            encSetup->rc.bpsMin = encSetup->rc.bpsTarget * BPS_MEDIUM / BPS_BASE;
            break;
        }
    }
    /* setup qp for different codec and rc_mode */
    switch (encSetup->codecMime.mimeCodecType) {
        case MPP_VIDEO_CodingAVC:
        case MPP_VIDEO_CodingHEVC: {
            SetQpValue(encSetup);
            break;
        }
        default: {
            break;
        }
    }
}

static void SetCodecTypeData(RKHdiCodecMimeSetup *codecMimeSet)
{
    switch (codecMimeSet->mimeCodecType) {
        case MEDIA_MIMETYPE_VIDEO_AVC: {
            /*
            * H.264 profile_idc parameter
            * 66  - Baseline profile
            * 77  - Main profile
            * 100 - High profile
            */
            codecMimeSet->avcSetup.profile = AVC_SETUP_PROFILE_DEFAULT;
            /*
            * H.264 level_idc parameter
            * 10 / 11 / 12 / 13    - qcif@15fps / cif@7.5fps / cif@15fps / cif@30fps
            * 20 / 21 / 22         - cif@30fps / half-D1@@25fps / D1@12.5fps
            * 30 / 31 / 32         - D1@25fps / 720p@30fps / 720p@60fps
            * 40 / 41 / 42         - 1080p@30fps / 1080p@30fps / 1080p@60fps
            * 50 / 51 / 52         - 4K@30fps
            */
            codecMimeSet->avcSetup.level = AVC_SETUP_LEVEL_DEFAULT;
            codecMimeSet->avcSetup.cabacEn = AVC_SETUP_CABAC_EN_DEFAULT;
            codecMimeSet->avcSetup.cabacIdc = AVC_SETUP_CABAC_IDC_DEFAULT;
            codecMimeSet->avcSetup.trans8x8 = AVC_SETUP_TRANS_DEFAULT;
            break;
        }
        case MEDIA_MIMETYPE_VIDEO_HEVC: {
            break;
        }
        default: {
            HDF_LOGE("%{public}s: unsupport encoder coding type %{public}d", __func__, codecMimeSet->mimeCodecType);
            break;
        }
    }
}

static void FreeParams(Param *params, int32_t paramCnt)
{
    if (params == NULL || paramCnt <= 0) {
        HDF_LOGE("%{public}s: params is null or invalid count!", __func__);
        return;
    }
    for (int32_t j = 0; j < paramCnt; j++) {
        if (params[j].val != NULL && params[j].size > 0) {
            OsalMemFree(params[j].val);
            params[j].val = NULL;
        }
    }
    OsalMemFree(params);
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

static int32_t SetupExtEncParams(Param *params, RKHdiEncodeSetup *encSetup, int32_t count)
{
    Param *param = NULL;
    int32_t paramCount = count;

    param = &params[paramCount++];
    param->key = (ParamKey)KEY_EXT_SETUP_DROP_MODE_RK;
    encSetup->drop.dropMode = MPP_ENC_RC_DROP_FRM_DISABLED;
    encSetup->drop.dropThd = ENC_SETUP_DROP_THD;
    encSetup->drop.dropGap = 1;
    param->val = &(encSetup->drop);
    param->size = sizeof(encSetup->drop);

    param = &params[paramCount++];
    param->key = KEY_MIMETYPE;
    encSetup->codecMime.mimeCodecType = MEDIA_MIMETYPE_VIDEO_AVC;
    SetCodecTypeData(&encSetup->codecMime);
    param->val = &(encSetup->codecMime);
    param->size = sizeof(encSetup->codecMime);

    param = &params[paramCount++];
    param->key = KEY_CODEC_TYPE;
    encSetup->codecType = VIDEO_ENCODER;
    param->val = &encSetup->codecType;
    param->size = sizeof(encSetup->codecType);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_RC_MODE;
    encSetup->rc.rcMode = VID_CODEC_RC_VBR;
    encSetup->rc.bpsTarget = g_cmd.width * g_cmd.height * BPS_TARGET / BPS_BASE *
        (encSetup->fps.fpsOutNum / encSetup->fps.fpsOutDen);
    CalcBpsRange(encSetup);
    param->val = &(encSetup->rc);
    param->size = sizeof(encSetup->rc);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_GOP_MODE;
    encSetup->gop.gopMode = VID_CODEC_GOPMODE_NORMALP;
    encSetup->gop.gopLen = 0;
    encSetup->gop.viLen = 0;
    encSetup->gop.gop = encSetup->fps.fpsOutNum * FPS_OUT_NUM_OPERATOR;
    param->val = &(encSetup->gop);
    param->size = sizeof(encSetup->gop);

    param = &params[paramCount++];
    param->key = (ParamKey)KEY_EXT_ENC_VALIDATE_SETUP_RK;

    return paramCount;
}

static int32_t SetupEncParams(RKHdiEncodeSetup *encSetup)
{
    Param params[PARAM_ARRAY_LEN] = {0};
    Param *param = NULL;
    int32_t paramCount = 0;

    param = &params[paramCount++];
    param->key = KEY_VIDEO_WIDTH;
    encSetup->width = g_cmd.width;
    param->val = &(encSetup->width);
    param->size = sizeof(encSetup->width);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_HEIGHT;
    encSetup->height = g_cmd.height;
    param->val = &(encSetup->height);
    param->size = sizeof(encSetup->height);

    param = &params[paramCount++];
    param->key = KEY_PIXEL_FORMAT;
    encSetup->fmt = PIXEL_FORMAT_YCBCR_420_SP;
    param->val = &(encSetup->fmt);
    param->size = sizeof(encSetup->fmt);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_STRIDE;
    encSetup->stride.horStride = GetDefaultHorStride(g_cmd.width, encSetup->fmt);
    encSetup->stride.verStride = g_cmd.height;
    param->val = &(encSetup->stride);
    param->size = sizeof(encSetup->stride);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_FRAME_RATE;
    encSetup->fps.fpsInFlex = 0;
    encSetup->fps.fpsInNum = ENC_SETUP_FPS_IN_NUM;
    encSetup->fps.fpsOutNum = ENC_SETUP_FPS_OUT_NUM;
    encSetup->fps.fpsInDen = 1;
    encSetup->fps.fpsOutDen = 1;
    encSetup->fps.fpsOutFlex = 0;
    param->val = &(encSetup->fps);
    param->size = sizeof(encSetup->fps);

    paramCount = SetupExtEncParams(params, encSetup, paramCount);
    int32_t ret = g_codecProxy->CodecSetParameter(g_codecProxy, (CODEC_HANDLETYPE)g_handle, params, paramCount);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecSetParameter failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    ret = GetSetupParams(params, paramCount - 1);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetSetupParams failed", __func__);
        return ret;
    }
    
    return HDF_SUCCESS;
}

static void EncodeLoopHandleInput(const CodecEnvData *envData, uint8_t *readData)
{
    int32_t ret = 0;
    int32_t acquireFd = 0;

    CodecBuffer *inputData = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo));
    inputData->buffer[0].type = BUFFER_TYPE_HANDLE;
    inputData->bufferCnt = 1;
    inputData->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    ret = g_codecProxy->CodecDequeueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, QUEUE_TIME_OUT,
        &acquireFd, inputData);
    if (ret == HDF_SUCCESS) {
        // when packet size is valid read the input binary file
        g_frameCount++;
        int32_t readSize = ReadInputFromFile(envData->fpInput, readData);
        g_totalSrcSize += readSize;
        g_pktEos = (g_totalSrcSize >= g_srcFileSize);
        if (g_pktEos) {
            HDF_LOGI("%{public}s: client inputData reach STREAM_FLAG_EOS, g_frameCount:%{public}d",
                __func__, g_frameCount);
            inputData->flag = STREAM_FLAG_EOS;
        }
    
        ShareMemory *sm = GetShareMemoryById(inputData->bufferId);
        memcpy_s(sm->virAddr, readSize, (uint8_t*)readData, readSize);
        inputData->buffer[0].length = readSize;
        g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, inputData, QUEUE_TIME_OUT, -1);
    }
    OsalMemFree(inputData);
}

static int32_t EncodeLoop(CodecEnvData *envData, uint8_t *readData)
{
    int32_t ret = 0;

    if (!g_pktEos) {
        EncodeLoopHandleInput(envData, readData);
    }

    CodecBuffer *outputData = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo));
    outputData->buffer[0].type = BUFFER_TYPE_FD;
    outputData->bufferCnt = 1;
    outputData->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;

    int32_t acquireFd = 0;
    ret = g_codecProxy->CodecDequeueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, QUEUE_TIME_OUT,
        &acquireFd, outputData);
    if (ret == HDF_SUCCESS) {
        g_totalDstSize += outputData->buffer[0].length;
        ShareMemory *sm = GetShareMemoryById(outputData->bufferId);
        DumpOutputToFile(envData->fpOutput, sm->virAddr, outputData->buffer[0].length);

        CodecBuffer *queOutputData = (CodecBuffer *)OsalMemCalloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo));
        queOutputData->buffer[0].type = BUFFER_TYPE_FD;
        queOutputData->buffer[0].buf = outputData->buffer[0].buf;
        queOutputData->buffer[0].capacity = outputData->buffer[0].capacity;
        queOutputData->bufferId = outputData->bufferId;
        queOutputData->bufferCnt = 1;
        queOutputData->flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_codecProxy->CodecQueueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, queOutputData, QUEUE_TIME_OUT, -1);
        if (outputData->flag & STREAM_FLAG_EOS) {
            HDF_LOGI("%{public}s: client reach STREAM_FLAG_EOS, CodecEncode loopEnd", __func__);
            envData->loopEnd = 1;
        }
        OsalMemFree(queOutputData);
    }
    OsalMemFree(outputData);

    return ret;
}

static void *EncodeThread(void *arg)
{
    CodecEnvData *envData = (CodecEnvData *)arg;
    uint8_t *readData = (uint8_t*)OsalMemCalloc(g_cmd.width * g_cmd.height * 2);
    if (readData == NULL) {
        HDF_LOGE("%{public}s: input readData buffer mem alloc failed", __func__);
        return NULL;
    }

    HDF_LOGI("%{public}s: client EncodeThread start", __func__);
    while (envData->loopEnd != 1) {
        EncodeLoop(envData, readData);
    }
    OsalMemFree(readData);
    HDF_LOGI("%{public}s: client loopEnd, g_totalSrcSize:%{public}d, g_totalDstSize: %{public}d",
        __func__, g_totalSrcSize, g_totalDstSize);
    return NULL;
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
    pthread_t thd;
    pthread_attr_t attr;
    int32_t bufferSize = g_cmd.width * g_cmd.height * INPUT_BUFFER_SIZE_OPERATOR;
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

    if (SetupEncParams(&g_encodeSetup) != HDF_SUCCESS) {
        RevertEncodeStep3();
        return HDF_FAILURE;
    }
    if (!InitBuffer(INPUT_BUFFER_NUM, bufferSize, OUTPUT_BUFFER_NUM, bufferSize)) {
        HDF_LOGE("%{public}s: InitBuffer failed", __func__);
        RevertEncodeStep3();
        return HDF_FAILURE;
    }

    g_codecProxy->CodecStart(g_codecProxy, (CODEC_HANDLETYPE)g_handle);

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    ret = pthread_create(&thd, &attr, EncodeThread, &g_data);
    if (ret != 0) {
        HDF_LOGE("%{public}s: failed to create thread for input ret %{public}d", __func__, ret);
        EncodeEnd();
        pthread_attr_destroy(&attr);
        return HDF_FAILURE;
    }

    pthread_join(thd, NULL);
    EncodeEnd();
    pthread_attr_destroy(&attr);

    return HDF_SUCCESS;
}

int32_t main(int32_t argc, char **argv)
{
    if (GrAllocatorInit() != HDF_SUCCESS) {
        HDF_LOGE("GrAllocatorInit failed!");
        return HDF_FAILURE;
    }

    g_cmd.type = VIDEO_ENCODER;
    int32_t ret = ParseArguments(&g_cmd, argc, argv);
    HDF_LOGI("%{public}s: ParseArguments width:%{public}d", __func__, g_cmd.width);
    HDF_LOGI("%{public}s: ParseArguments height:%{public}d", __func__, g_cmd.height);
    HDF_LOGI("%{public}s: ParseArguments codecName:%{public}s", __func__, g_cmd.codecName);
    HDF_LOGI("%{public}s: ParseArguments input:%{public}s", __func__, g_cmd.fileInput);
    HDF_LOGI("%{public}s: ParseArguments output:%{public}s", __func__, g_cmd.fileOutput);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ParseArguments failed", __func__);
        return ret;
    }

    memset_s(&g_data, sizeof(g_data), 0, sizeof(g_data));
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

