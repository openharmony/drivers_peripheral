/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */


#include "hi3516_aiao_impl_test.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "hdf_types.h"
#include "hi3516_aiao_impl.h"

#define HDF_LOG_TAG hi3516_aiao_impl_test

const unsigned int CHANNELNUM = 2;
const unsigned int BITWIDTH = 16;
const unsigned int SAMPLERATE = 48000;

int32_t TestAiaoHalSysInit(void)
{
    int ret;
    HDF_LOGI("TestAiaoHalSysInit: enter");
    ret = AiaoHalSysInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAiaoHalSysInit: AiaoHalSysInit fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAiaoHalSysInit: success");
    return HDF_SUCCESS;
}

int32_t TestAiaoClockReset(void)
{
    int ret;
    HDF_LOGI("TestAiaoClockReset: enter");
    ret = AiaoClockReset();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAiaoClockReset: AiaoClockReset fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAiaoClockReset: success");
    return HDF_SUCCESS;
}

int32_t TestAiaoHalReadReg(void)
{
    uint32_t ret;
    unsigned int offset;
    const unsigned int offValue = 0x100;
    HDF_LOGI("TestAiaoHalReadReg: enter");
    offset = offValue;
    ret = AiaoHalReadReg(offset);
    if (ret == 0x0) {
        HDF_LOGE("TestAiaoHalReadReg: AiaoHalReadReg fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAiaoHalReadReg: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBuffRptr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("TestAopHalSetBuffRptr: enter");
    ret = AopHalSetBuffRptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetBuffRptr: AopHalSetBuffRptr fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopHalSetBuffRptr: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBuffRptrInvalidChdId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    chnId = R_CHANNEL_ID_MAX;
    value = 0;
    HDF_LOGI("TestAopHalSetBuffRptrInvalidChdId: enter");
    ret = AopHalSetBuffRptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetBuffRptrInvalidChdId: AopHalSetBuffRptr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopHalSetBuffRptrInvalidChdId: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBuffWptr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("TestAopHalSetBuffWptr: enter");
    ret = AopHalSetBuffWptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetBuffWptr: AopHalSetBuffWptr fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopHalSetBuffWptr: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBuffWptrInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    chnId = W_CHANNEL_ID_MAX;
    value = 0;
    HDF_LOGI("TestAopHalSetBuffWptrInvalidChnId: enter");
    ret = AopHalSetBuffWptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetBuffWptrInvalidChnID: AopHalSetBuffWptr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopHalSetBuffWptrInvalidChnID: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBufferAddr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    HDF_LOGI("TestAopHalSetBufferAddr: enter");

    chnId = 0;
    value = 0;
    ret = AopHalSetBufferAddr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetBufferAddr: AopHalSetBufferAddr fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopHalSetBufferAddr: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBufferAddrInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    HDF_LOGI("TestAopHalSetBufferAddrInvalidChnId: enter");
    chnId = W_CHANNEL_ID_MAX;
    value = 0;
    ret = AopHalSetBufferAddr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetBufferAddrInvalidChnId: AopHalSetBufferAddr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopHalSetBufferAddrInvalidChnId success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBufferAddr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("TestAipHalSetBufferAddr: enter");
    ret = AipHalSetBufferAddr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetBufferAddr: AipHalSetBufferAddr fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipHalSetBufferAddr: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBufferAddrInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    chnId = W_CHANNEL_ID_MAX;
    value = 0;
    HDF_LOGI("TestAipHalSetBufferAddrInvalidChnId: enter");
    ret = AipHalSetBufferAddr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetBufferAddrInvalidChnId: AipHalSetBufferAddr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipHalSetBufferAddrInvalidChnId: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBufferSize(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("TestAipHalSetBufferSize: enter");
    ret = AipHalSetBufferSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetBufferSize: AipHalSetBufferSize fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipHalSetBufferSize: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBufferSizeInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    chnId = HI_AO_DEV_MAX_NUM;
    value = 0;
    HDF_LOGI("TestAipHalSetBufferSizeInvalidChnId: enter");
    ret = AipHalSetBufferSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetBufferSizeInvalidChnId: AipHalSetBufferSize fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipHalSetBufferSizeInvalidChnId: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetTransSize(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    const unsigned int transferSize = 320;

    chnId = 0;
    value = transferSize;

    HDF_LOGI("TestAipHalSetTransSize: enter");
    ret = AipHalSetTransSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetTransSize: AipHalSetTransSize fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipHalSetTransSize: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetTransSizeInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    const unsigned int transferSize = 320;
    chnId = HI_AO_DEV_MAX_NUM;
    value = transferSize;
    HDF_LOGI("TestAipHalSetTransSizeInvalidChnId: enter");
    ret = AipHalSetTransSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetTransSizeInvalidChnId: AipHalSetTransSize fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipHalSetTransSizeInvalidChnId: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetRxStart(void)
{
    int ret;
    unsigned int chnId;
    bool en = HI_TRUE;

    chnId = 0;
    HDF_LOGI("TestAipHalSetRxStart: enter");
    ret = AipHalSetRxStart(chnId, en);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetRxStart: AipHalSetRxStart fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipHalSetRxStart: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetRxStartInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    bool en = HI_TRUE;
    chnId = HI_AI_DEV_MAX_NUM;
    HDF_LOGI("TestAipHalSetRxStartInvalid: enter");
    ret = AipHalSetRxStart(chnId, en);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetRxStartInvalid: AipHalSetRxStart fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipHalSetRxStartInvalid: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBuffWptr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("TestAipHalSetBuffWptr: enter");
    ret = AipHalSetBuffWptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetBuffWptr: AipHalSetBuffWptr fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipHalSetBuffWptr: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBuffWptrInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    chnId = W_CHANNEL_ID_MAX;
    value = 0;
    HDF_LOGI("TestAipHalSetBuffWptrInvalidChnId: enter");
    ret = AipHalSetBuffWptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetBuffWptrInvalidChnId: AipHalSetBuffWptr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipHalSetBuffWptrInvalidChnId: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBuffRptr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("TestAipHalSetBuffRptr: enter");
    ret = AipHalSetBuffRptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetBuffRptr: AipHalSetBuffRptr fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipHalSetBuffRptrs: success");
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBuffRptrInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    chnId = HI_AI_DEV_MAX_NUM;
    value = 0;
    HDF_LOGI("TestAipHalSetBuffRptrInvalidChnId: enter");
    ret = AipHalSetBuffRptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipHalSetBuffRptrInvalidChnId: AipHalSetBuffRptr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipHalSetBuffRptrInvalidChnId: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBufferSize(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("TestAopHalSetBufferSize: enter");
    ret = AopHalSetBufferSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetBufferSize: AopHalSetBufferSize fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopHalSetBufferSize: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBufferSizeInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    chnId = HI_AO_DEV_MAX_NUM;
    value = 0;
    HDF_LOGI("TestAopHalSetBufferSizeInvalidChnId: enter");
    ret = AopHalSetBufferSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetBufferSizeInvalidChnId: AopHalSetBufferSize fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopHalSetBufferSizeInvalidChnId: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetTransSize(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("TestAopHalSetTransSize: enter");
    ret = AopHalSetTransSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetTransSize: AopHalSetTransSize fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopHalSetTransSize: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetTransSizeInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    chnId = HI_AO_DEV_MAX_NUM;
    value = 0;
    HDF_LOGI("TestAopHalSetTransSizeInvalidChnId: enter");
    ret = AopHalSetTransSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetTransSizeInvalidChnId: AopHalSetTransSize fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopHalSetTransSizeInvalidChnId: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetTxStart(void)
{
    int ret;
    unsigned int chnId;
    bool en = HI_TRUE;
    HDF_LOGI("TestAopHalSetTxStart: enter");

    chnId = 0;
    ret = AopHalSetTxStart(chnId, en);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetTxStart: AopHalSetTxStart fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopHalSetTxStart: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalSetTxStartInvalidChnId(void)
{
    int ret;
    unsigned int chnId;
    bool en = HI_TRUE;
    HDF_LOGI("TestAopHalSetTxStartInvalidChnId: enter");
    chnId = HI_AO_DEV_MAX_NUM;
    ret = AopHalSetTxStart(chnId, en);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalSetTxStartInvalidChnId: AopHalSetTxStart fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopHalSetTxStartInvalidChnId: success");
    return HDF_SUCCESS;
}

int32_t TestAopHalDevEnable(void)
{
    int ret;
    unsigned int chnId;

    chnId = 0;
    HDF_LOGI("TestAopHalDevEnable: enter");
    ret = AopHalDevEnable(chnId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopHalDevEnable: AopHalDevEnable fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopHalDevEnable: success");
    return HDF_SUCCESS;
}

int32_t TestAipBuffRptrReg(void)
{
    uint32_t ret;
    uint32_t m;
    const uint32_t aipRptrReg = 0x108C;

    HDF_LOGI("TestAipBuffRptrReg: enter");
    m = 0;
    ret = AipBuffRptrReg(m);
    if (ret != aipRptrReg) {
        HDF_LOGE("TestAipBuffRptrReg: AipBuffRptrReg fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipBuffRptrReg: success");
    return HDF_SUCCESS;
}

int32_t TestAipBuffWptrReg(void)
{
    uint32_t ret;
    uint32_t m;
    const uint32_t aipWptrReg = 0x1088;

    HDF_LOGI("TestAipBuffWptrReg: enter");
    m = 0;
    ret = AipBuffWptrReg(m);
    if (ret != aipWptrReg) {
        HDF_LOGE("TestAipBuffWptrReg: AipBuffWptrReg fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipBuffWptrReg: success");
    return HDF_SUCCESS;
}

int32_t TestAopBuffRptrReg(void)
{
    uint32_t ret;
    uint32_t m;
    const uint32_t aopRptrReg = 0x208C;

    HDF_LOGI("TestAopBuffRptrReg: enter");
    m = 0;
    ret = AopBuffRptrReg(m);
    if (ret != aopRptrReg) {
        HDF_LOGE("TestAopBuffRptrReg: AopBuffRptrReg fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopBuffRptrReg: success");
    return HDF_SUCCESS;
}

int32_t TestAopBuffWptrReg(void)
{
    uint32_t ret;
    uint32_t m;
    const uint32_t aopWptrReg = 0x2088;

    HDF_LOGI("TestAopBuffWptrReg: enter");
    m = 0;
    ret = AopBuffWptrReg(m);
    if (ret != aopWptrReg) {
        HDF_LOGE("TestAopBuffWptrReg: AopBuffWptrReg fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopBuffWptrReg: success");
    return HDF_SUCCESS;
}

int32_t TestAopSetSysCtlReg(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;
    unsigned int rate = SAMPLERATE;

    HDF_LOGI("TestAopSetSysCtlReg: enter");
    ret = AopSetSysCtlReg(chnId, channelCnt, bitWidth, rate);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopSetSysCtlReg: AopBuffWptrReg fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopSetSysCtlReg: success");
    return HDF_SUCCESS;
}

int32_t TestAopSetSysCtlRegInvalidRate(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;
    unsigned int rate = AUDIO_SAMPLE_RATE_BUTT;

    HDF_LOGI("TestAopSetSysCtlRegInvalidRate: enter");
    ret = AopSetSysCtlReg(chnId, channelCnt, bitWidth, rate);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopSetSysCtlRegInvalidRate: AopBuffWptrReg fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopSetSysCtlRegInvalidRate: success");
    return HDF_SUCCESS;
}

int32_t TestAopSetAttr(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;

    HDF_LOGI("TestAopSetAttr: enter");
    ret = AopSetAttr(chnId, channelCnt, bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopSetAttr: AopSetAttr fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAopSetAttr: success");
    return HDF_SUCCESS;
}

int32_t TestAopSetAttrInvalidChannelCnt(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM * CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;
    HDF_LOGI("TestAopSetAttrInvalidChannelCnt: enter");
    ret = AipSetAttr(chnId, channelCnt, bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopSetAttrInvalidChannelCnt: AipSetAttr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopSetAttrInvalidChannelCnt: success");
    return HDF_SUCCESS;
}

int32_t TestAopSetAttrInvalidBitWidth(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH * CHANNELNUM;
    HDF_LOGI("TestAopSetAttrInvalidBitWidth: enter");
    ret = AipSetAttr(chnId, channelCnt, bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAopSetAttrInvalidBitWidth: AipSetAttr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAopSetAttrInvalidBitWidth: success");
    return HDF_SUCCESS;
}

int32_t TestAipSetSysCtlReg(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;
    unsigned int rate = SAMPLERATE;

    HDF_LOGI("TestAipSetSysCtlReg: enter");
    ret = AipSetSysCtlReg(chnId, channelCnt, bitWidth, rate);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipSetSysCtlReg: AipSetSysCtlReg fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipSetSysCtlReg: success");
    return HDF_SUCCESS;
}

int32_t TestAipSetSysCtlRegInvalidRate(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;
    unsigned int rate = AUDIO_SAMPLE_RATE_BUTT;

    HDF_LOGI("TestAipSetSysCtlRegInvalidRate: enter");
    ret = AipSetSysCtlReg(chnId, channelCnt, bitWidth, rate);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipSetSysCtlRegInvalidRate: AipSetSysCtlReg fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipSetSysCtlRegInvalidRate: success");
    return HDF_SUCCESS;
}

int32_t TestAipSetAttr(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;

    HDF_LOGI("TestAipSetAttr: enter");
    ret = AipSetAttr(chnId, channelCnt, bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipSetAttr: AipSetAttr fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAipSetAttr: success");
    return HDF_SUCCESS;
}

int32_t TestAipSetAttrInvalidChannelCnt(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM * CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;
    HDF_LOGI("TestAipSetAttrInvalidChannelCnt: enter");
    ret = AipSetAttr(chnId, channelCnt, bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipSetAttrInvalidChannelCnt: AipSetAttr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipSetAttrInvalidChannelCnt: success");
    return HDF_SUCCESS;
}

int32_t TestAipSetAttrInvalidBitWidth(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH * CHANNELNUM;
    HDF_LOGI("TestAipSetAttrInvalidBitWidth: enter");
    ret = AipSetAttr(chnId, channelCnt, bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAipSetAttrInvalidBitWidth: AipSetAttr fail ret = %d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("TestAipSetAttrInvalidBitWidth: success");
    return HDF_SUCCESS;
}

int32_t TestAiaoDeviceInit(void)
{
    int ret;
    int32_t chnId;

    HDF_LOGI("TestAiaoDeviceInit: enter");
    chnId = 0;
    ret = AiaoDeviceInit(chnId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAiaoDeviceInit: AiaoDeviceInit fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAiaoDeviceInit: success");
    return HDF_SUCCESS;
}

int32_t TestI2sCrgCfgInit(void)
{
    int ret;
    int32_t chnId;

    HDF_LOGI("TestI2sCrgCfgInit: enter");
    chnId = 0;
    ret = I2sCrgCfgInit(chnId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestI2sCrgCfgInit: I2sCrgCfgInit fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestI2sCrgCfgInit: success");
    return HDF_SUCCESS;
}
