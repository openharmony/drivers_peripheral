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
#include "codec_callback_stub.h"
#include "codec_type.h"
#include "codec_utils.h"
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
    unsigned int    loop_end;
    /* input and output */
    FILE            *fpInput;
    FILE            *fpOutput;
    int32_t         g_frameCount;
    int32_t         frameNum;
    CodecCallback   cb;
} CodecEnvData;

static struct ICodec *g_codecProxy = NULL;
static CODEC_HANDLETYPE g_handle = NULL;
ShareMemory *g_inputBuffers = NULL;
ShareMemory *g_outputBuffers = NULL;
InputInfo *g_inputInfosData = NULL;
OutputInfo *g_outputInfosData = NULL;
struct ICodecCallback *g_callback = NULL;

CodecCmd g_cmd = {0};
CodecEnvData g_data = {0};
CodecBufferInfo g_outputBuffer = {0};
RKHdiEncodeSetup g_encodeSetup = {0};

bool g_pktEos = false;
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

int32_t ReadInputFromFile(FILE *fp, uint8_t *addr)
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
            ReleaseShareMemory(&g_inputBuffers[i]);
        }
    }
    if (g_outputBuffers != NULL) {
        for (i = 0; i < OUTPUT_BUFFER_NUM; i++) {
            ReleaseShareMemory(&g_outputBuffers[i]);
        }
    }
}

static void ReleaseInfoBuffer(void)
{
    int32_t i;
    if (g_inputInfosData != NULL) {
        for (i = 0; i < INPUT_BUFFER_NUM; i++) {
            if (g_inputInfosData[i].buffers != NULL) {
                OsalMemFree(g_inputInfosData[i].buffers);
            }
        }
    }
    if (g_outputInfosData != NULL) {
        for (i = 0; i < OUTPUT_BUFFER_NUM; i++) {
            if (g_outputInfosData[i].buffers != NULL) {
                OsalMemFree(g_outputInfosData[i].buffers);
            }
        }
    }
}

static bool InitBuffer(int32_t inputBufferNum, int32_t inputBufferSize,
    int32_t outputBufferNum, int32_t outputBufferSize)
{
    int32_t queueRet = 0;
    g_inputBuffers = (ShareMemory *)OsalMemCalloc(sizeof(ShareMemory) * inputBufferNum);
    g_outputBuffers = (ShareMemory *)OsalMemCalloc(sizeof(ShareMemory) * outputBufferNum);
    g_inputInfosData = (InputInfo *)OsalMemCalloc(sizeof(InputInfo) * inputBufferNum);
    g_outputInfosData = (OutputInfo *)OsalMemCalloc(sizeof(OutputInfo) * outputBufferNum);
    if (g_inputBuffers == NULL || g_outputBuffers == NULL || g_inputInfosData == NULL || g_outputInfosData == NULL) {
        HDF_LOGE("%{public}s: buffer and info mem alloc failed!", __func__);
        return false;
    }
    for (int32_t i = 0; i < inputBufferNum; i++) {
        g_inputBuffers[i].id = i;
        g_inputBuffers[i].size = inputBufferSize;
        CreateShareMemory(&g_inputBuffers[i]);
        g_inputInfosData[i].bufferCnt = 1;
        g_inputInfosData[i].flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_inputInfosData[i].buffers = (CodecBufferInfo *)OsalMemCalloc(sizeof(CodecBufferInfo));
        if (g_inputInfosData[i].buffers != NULL) {
            g_inputInfosData[i].buffers->type = BUFFER_TYPE_FD;
            g_inputInfosData[i].buffers->fd = g_inputBuffers[i].fd;
            g_inputInfosData[i].buffers->offset = g_inputBuffers[i].id;
            g_inputInfosData[i].buffers->size = inputBufferSize;
        }

        queueRet = g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
            &g_inputInfosData[i], (uint32_t)0);
        if (queueRet != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: input buffer initial failed!", __func__);
            return false;
        }
    }
    for (int32_t j = 0; j < outputBufferNum; j++) {
        g_outputBuffers[j].id = INPUT_BUFFER_NUM + j;
        g_outputBuffers[j].size = outputBufferSize;
        CreateShareMemory(&g_outputBuffers[j]);
        g_outputInfosData[j].bufferCnt = 1;
        g_outputInfosData[j].flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_outputInfosData[j].buffers = (CodecBufferInfo *)OsalMemCalloc(sizeof(CodecBufferInfo));
        if (g_outputInfosData[j].buffers != NULL) {
            g_outputInfosData[j].buffers->type = BUFFER_TYPE_FD;
            g_outputInfosData[j].buffers->fd = g_outputBuffers[j].fd;
            g_outputInfosData[j].buffers->offset = g_outputBuffers[j].id;
            g_outputInfosData[j].buffers->size = outputBufferSize;
        }
        queueRet = g_codecProxy->CodecQueueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle,
            &g_outputInfosData[j], (uint32_t)0, 1);
        if (queueRet != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: output buffer initial failed!", __func__);
            return false;
        }
    }
    return true;
}

int32_t TestOnEvent(UINTPTR comp, UINTPTR appData, EventType event,
    uint32_t data1, uint32_t data2, UINTPTR eventData)
{
    HDF_LOGI("%{public}s: TestOnEvent: event = %{public}d", __func__, event);
    return HDF_SUCCESS;
}

int32_t TestInputBufferAvailable(UINTPTR comp, UINTPTR appData, InputInfo *inBuf)
{
    HDF_LOGI("%{public}s: TestInputBufferAvailable enter", __func__);
    return HDF_SUCCESS;
}

int32_t TestOutputBufferAvailable(UINTPTR comp, UINTPTR appData, OutputInfo *outBuf)
{
    HDF_LOGI("%{public}s: TestOutputBufferAvailable datasize: %{public}d", __func__, outBuf->buffers->size);
    return HDF_SUCCESS;
}

void SetQpValue(RKHdiEncodeSetup *encSetup)
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

void CalcBpsRange(RKHdiEncodeSetup *encSetup)
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
    switch (encSetup->codecType.mimeCodecType) {
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

void SetCodecTypeData(RKHdiCodecTypeSetup *codecTypeSet)
{
    switch (codecTypeSet->mimeCodecType) {
        case MEDIA_MIMETYPE_VIDEO_AVC: {
            /*
            * H.264 profile_idc parameter
            * 66  - Baseline profile
            * 77  - Main profile
            * 100 - High profile
            */
            codecTypeSet->avcSetup.profile = AVC_SETUP_PROFILE_DEFAULT;
            /*
            * H.264 level_idc parameter
            * 10 / 11 / 12 / 13    - qcif@15fps / cif@7.5fps / cif@15fps / cif@30fps
            * 20 / 21 / 22         - cif@30fps / half-D1@@25fps / D1@12.5fps
            * 30 / 31 / 32         - D1@25fps / 720p@30fps / 720p@60fps
            * 40 / 41 / 42         - 1080p@30fps / 1080p@30fps / 1080p@60fps
            * 50 / 51 / 52         - 4K@30fps
            */
            codecTypeSet->avcSetup.level = AVC_SETUP_LEVEL_DEFAULT;
            codecTypeSet->avcSetup.cabacEn = AVC_SETUP_CABAC_EN_DEFAULT;
            codecTypeSet->avcSetup.cabacIdc = AVC_SETUP_CABAC_IDC_DEFAULT;
            codecTypeSet->avcSetup.trans8x8 = AVC_SETUP_TRANS_DEFAULT;
            break;
        }
        case MEDIA_MIMETYPE_VIDEO_HEVC:
        case MEDIA_MIMETYPE_VIDEO_MJPEG: {
            break;
        }
        default: {
            HDF_LOGE("%{public}s: unsupported encoder coding type %{public}d", __func__, codecTypeSet->mimeCodecType);
            break;
        }
    }
}

int32_t SetupExtEncParams(Param *params, RKHdiEncodeSetup *encSetup, int32_t count)
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
    encSetup->codecType.mimeCodecType = MEDIA_MIMETYPE_VIDEO_AVC;
    SetCodecTypeData(&encSetup->codecType);
    param->val = &(encSetup->codecType);
    param->size = sizeof(encSetup->codecType);

    param = &params[paramCount++];
    param->key = KEY_CODEC_TYPE;
    CodecType codecType = VIDEO_ENCODER;
    param->val = &codecType;
    param->size = sizeof(codecType);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_RC_MODE;
    encSetup->rc.rcMode = VENCOD_RC_VBR;
    encSetup->rc.bpsTarget = g_cmd.width * g_cmd.height * BPS_TARGET / BPS_BASE *
        (encSetup->fps.fpsOutNum / encSetup->fps.fpsOutDen);
    CalcBpsRange(encSetup);
    param->val = &(encSetup->rc);
    param->size = sizeof(encSetup->rc);

    param = &params[paramCount++];
    param->key = KEY_VIDEO_GOP_MODE;
    encSetup->gop.gopMode = VENCOD_GOPMODE_NORMALP;
    encSetup->gop.gopLen = 0;
    encSetup->gop.viLen = 0;
    encSetup->gop.gop = encSetup->gop.gopLen ? encSetup->gop.gopLen: encSetup->fps.fpsOutNum *
        FPS_OUT_NUM_OPERATOR;
    param->val = &(encSetup->gop);
    param->size = sizeof(encSetup->gop);

    param = &params[paramCount++];
    param->key = (ParamKey)KEY_EXT_ENC_VALIDATE_SETUP_RK;

    return paramCount;
}

int32_t SetupEncParams(RKHdiEncodeSetup *encSetup)
{
    Param params[PARAM_ARRAY_LEN] = {0};
    Param *param = NULL;
    int32_t paramCount = 0;

    param = &params[paramCount++];
    param->key = KEY_WIDTH;
    encSetup->width = g_cmd.width;
    param->val = &(encSetup->width);
    param->size = sizeof(encSetup->width);

    param = &params[paramCount++];
    param->key = KEY_HEIGHT;
    encSetup->height = g_cmd.height;
    param->val = &(encSetup->height);
    param->size = sizeof(encSetup->height);

    param = &params[paramCount++];
    param->key = KEY_PIXEL_FORMAT;
    encSetup->fmt = YVU_SEMIPLANAR_420;
    param->val = &(encSetup->fmt);
    param->size = sizeof(encSetup->fmt);

    param = &params[paramCount++];
    param->key = KEY_STRIDE;
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
        HDF_LOGE("%{public}s: CodecSetParameter KEY_ENC_SETUP_RK failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void EncodeLoopHandleInput(CodecEnvData *p_data, uint8_t *readData)
{
    int32_t ret = 0;
    int32_t readSize = 0;

    CodecBufferInfo inputBuffer;
    memset_s(&inputBuffer, sizeof(CodecBufferInfo), 0, sizeof(CodecBufferInfo));
    inputBuffer.type = BUFFER_TYPE_FD;
    InputInfo inputData;
    memset_s(&inputData, sizeof(InputInfo), 0, sizeof(InputInfo));
    inputData.bufferCnt = 1;
    inputData.buffers = &inputBuffer;
    inputData.flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    
    ret = g_codecProxy->CodecDequeInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, QUEUE_TIME_OUT, &inputData);
    if (ret == HDF_SUCCESS) {
        // when packet size is valid read the input binary file
        g_frameCount++;
        readSize = ReadInputFromFile(p_data->fpInput, readData);
    
        g_pktEos = (readSize <= 0);
        if (g_pktEos) {
            HDF_LOGD("%{public}s: client inputData reach STREAM_FLAG_EOS, g_frameCount:%{public}d",
                __func__, g_frameCount);
            inputData.flag = STREAM_FLAG_EOS;
        }
    
        g_totalSrcSize += readSize;
        ShareMemory *sm = GetShareMemoryById(inputBuffer.offset);
        memcpy_s(sm->virAddr, readSize, (uint8_t*)readData, readSize);
        inputBuffer.size = readSize;
        g_codecProxy->CodecQueueInput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &inputData, QUEUE_TIME_OUT);
    }
}

static int32_t EncodeLoop(CodecEnvData *p_data, uint8_t *readData)
{
    int32_t ret = 0;

    if (!g_pktEos) {
        EncodeLoopHandleInput(p_data, readData);
    }

    CodecBufferInfo g_outputBuffer;
    memset_s(&g_outputBuffer, sizeof(CodecBufferInfo), 0, sizeof(CodecBufferInfo));
    g_outputBuffer.type = BUFFER_TYPE_FD;
    OutputInfo outputData;
    memset_s(&outputData, sizeof(OutputInfo), 0, sizeof(OutputInfo));
    outputData.bufferCnt = 1;
    outputData.buffers = &g_outputBuffer;
    outputData.flag = STREAM_FLAG_CODEC_SPECIFIC_INF;

    int32_t acquireFd = 0;
    ret = g_codecProxy->CodecDequeueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, QUEUE_TIME_OUT,
        &acquireFd, &outputData);
    if (ret == HDF_SUCCESS) {
        g_totalDstSize += outputData.buffers->length;
        ShareMemory *sm = GetShareMemoryById(g_outputBuffer.offset);
        DumpOutputToFile(p_data->fpOutput, sm->virAddr, outputData.buffers->length);
        CodecBufferInfo queOutputBuffer;
        memset_s(&queOutputBuffer, sizeof(CodecBufferInfo), 0, sizeof(CodecBufferInfo));
        queOutputBuffer.type = BUFFER_TYPE_FD;
        queOutputBuffer.fd = outputData.buffers->fd;
        queOutputBuffer.offset = outputData.buffers->offset;
        OutputInfo queOutputData;
        memset_s(&queOutputData, sizeof(OutputInfo), 0, sizeof(OutputInfo));
        queOutputData.bufferCnt = 1;
        queOutputData.buffers = &queOutputBuffer;
        queOutputData.flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
        g_codecProxy->CodecQueueOutput(g_codecProxy, (CODEC_HANDLETYPE)g_handle, &queOutputData, QUEUE_TIME_OUT, 1);
        if (outputData.flag & STREAM_FLAG_EOS) {
            HDF_LOGD("%{public}s: client reach STREAM_FLAG_EOS, CodecEncode loop_end", __func__);
            p_data->loop_end = 1;
        }
    }

    return ret;
}

void *EncodeThread(void *arg)
{
    CodecEnvData *p_data = (CodecEnvData *)arg;
    uint8_t *readData = (uint8_t*)OsalMemCalloc(g_cmd.width * g_cmd.height * 2);
    if (readData == NULL) {
        HDF_LOGE("%{public}s: input readData buffer mem alloc failed", __func__);
        return NULL;
    }

    HDF_LOGI("%{public}s: client EncodeThread start", __func__);
    while (p_data->loop_end != 1) {
        EncodeLoop(p_data, readData);
    }
    OsalMemFree(readData);
    HDF_LOGI("%{public}s: client loop_end, g_totalSrcSize:%{public}d, g_totalDstSize: %{public}d",
        __func__, g_totalSrcSize, g_totalDstSize);
    return NULL;
}

void RevertEncodeStep1(void)
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

void RevertEncodeStep2(void)
{
    int32_t ret = g_codecProxy->CodecDeinit(g_codecProxy);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to CodecDeinit %{public}d", __func__, ret);
    }
    RevertEncodeStep1();
}

void RevertEncodeStep3(void)
{
    ReleaseShm();
    ReleaseInfoBuffer();

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

int32_t OpenFile(void)
{
    g_data.fpInput = fopen(g_cmd.file_input, "rb");
    if (g_data.fpInput == NULL) {
        HDF_LOGE("%{public}s: failed to open input file %{public}s", __func__, g_cmd.file_input);
        RevertEncodeStep1();
        return HDF_FAILURE;
    }

    g_data.fpOutput = fopen(g_cmd.file_output, "w+b");
    if (g_data.fpOutput == NULL) {
        HDF_LOGE("%{public}s: failed to open output file %{public}s", __func__, g_cmd.file_output);
        RevertEncodeStep1();
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void EncodeEnd(void)
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

    if (g_callback != NULL) {
        CodecCallbackStubRelease(g_callback);
    }
}

int32_t Encode(void)
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

    Param param;
    memset_s(&param, sizeof(Param), 0, sizeof(Param));
    int32_t val = VIDEO_ENCODER;
    param.key = KEY_CODEC_TYPE;
    param.val = &val;
    param.size = sizeof(val);
    ret = g_codecProxy->CodecCreate(g_codecProxy, g_data.codecName, &param, 1, &g_handle);
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
    g_cmd.type = VIDEO_ENCODER;
    int32_t ret = ParseArguments(&g_cmd, argc, argv);
    HDF_LOGI("%{public}s: ParseArguments width:%{public}d", __func__, g_cmd.width);
    HDF_LOGI("%{public}s: ParseArguments height:%{public}d", __func__, g_cmd.height);
    HDF_LOGI("%{public}s: ParseArguments codecName:%{public}s", __func__, g_cmd.codecName);
    HDF_LOGI("%{public}s: ParseArguments input:%{public}s", __func__, g_cmd.file_input);
    HDF_LOGI("%{public}s: ParseArguments output:%{public}s", __func__, g_cmd.file_output);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ParseArguments failed");
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

