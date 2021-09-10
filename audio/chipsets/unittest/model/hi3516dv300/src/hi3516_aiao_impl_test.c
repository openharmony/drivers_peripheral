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
    HDF_LOGI("%s: enter", __func__);
    ret = AiaoHalSysInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AiaoHalSysInit fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAiaoClockReset(void)
{
    int ret;
    HDF_LOGI("%s: enter", __func__);
    ret = AiaoClockReset();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AiaoClockReset fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAiaoHalReadReg(void)
{
    int ret;
    unsigned int offset;
    const unsigned int offValue = 0x100;
    HDF_LOGI("%s: enter", __func__);
    offset = offValue;
    ret = AiaoHalReadReg(offset);
    if (ret == 0x0) {
        HDF_LOGE("%s: AiaoHalReadReg fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBuffRptr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AopHalSetBuffRptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopHalSetBuffRptr fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBuffWptr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AopHalSetBuffWptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopHalSetBuffWptr fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBufferAddr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;
    HDF_LOGI("%s: enter", __func__);

    chnId = 0;
    value = 0;
    ret = AopHalSetBufferAddr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopHalSetBufferAddr fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBufferAddr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AipHalSetBufferAddr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AipHalSetBufferAddr fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBufferSize(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AipHalSetBufferSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AipHalSetBufferSize fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
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

    HDF_LOGI("%s: enter", __func__);
    ret = AipHalSetTransSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AipHalSetTransSize fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAipHalSetRxStart(void)
{
    int ret;
    unsigned int chnId;
    bool en = HI_TRUE;

    chnId = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AipHalSetRxStart(chnId, en);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AipHalSetRxStart fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBuffWptr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AipHalSetBuffWptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AipHalSetBuffWptr fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAipHalSetBuffRptr(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AipHalSetBuffRptr(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AipHalSetBuffRptr fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopHalSetBufferSize(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AopHalSetBufferSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopHalSetBufferSize fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopHalSetTransSize(void)
{
    int ret;
    unsigned int chnId;
    unsigned int value;

    chnId = 0;
    value = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AopHalSetTransSize(chnId, value);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopHalSetTransSize fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopHalSetTxStart(void)
{
    int ret;
    unsigned int chnId;
    bool en = HI_TRUE;
    HDF_LOGI("%s: enter", __func__);

    chnId = 0;
    ret = AopHalSetTxStart(chnId, en);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopHalSetTxStart fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopHalDevEnable(void)
{
    int ret;
    unsigned int chnId;

    chnId = 0;
    HDF_LOGI("%s: enter", __func__);
    ret = AopHalDevEnable(chnId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopHalDevEnable fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAipBuffRptrReg(void)
{
    uint32_t ret;
    uint32_t m;
    const uint32_t aipRptrReg = 0x108C;

    HDF_LOGI("%s: enter", __func__);
    m = 0;
    ret = AipBuffRptrReg(m);
    if (ret != aipRptrReg) {
        HDF_LOGE("%s: AipBuffRptrReg fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAipBuffWptrReg(void)
{
    int ret;
    uint32_t m;
    const uint32_t aipWptrReg = 0x1088;

    HDF_LOGI("%s: enter", __func__);
    m = 0;
    ret = AipBuffWptrReg(m);
    if (ret != aipWptrReg) {
        HDF_LOGE("%s: AipBuffWptrReg fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopBuffRptrReg(void)
{
    uint32_t ret;
    uint32_t m;
    const uint32_t aopRptrReg = 0x208C;

    HDF_LOGI("%s: enter", __func__);
    m = 0;
    ret = AopBuffRptrReg(m);
    if (ret != aopRptrReg) {
        HDF_LOGE("%s: AopBuffRptrReg fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopBuffWptrReg(void)
{
    uint32_t ret;
    uint32_t m;
    const uint32_t aopWptrReg = 0x2088;

    HDF_LOGI("%s: enter", __func__);
    m = 0;
    ret = AopBuffWptrReg(m);
    if (ret != aopWptrReg) {
        HDF_LOGE("%s: AopBuffWptrReg fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopSetSysCtlReg(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;
    unsigned int rate = SAMPLERATE;

    HDF_LOGI("%s: enter", __func__);
    ret = AopSetSysCtlReg(chnId, channelCnt, bitWidth, rate);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopBuffWptrReg fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAopSetAttr(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;

    HDF_LOGI("%s: enter", __func__);
    ret = AopSetAttr(chnId, channelCnt, bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AopSetAttr fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}
int32_t TestAipSetSysCtlReg(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;
    unsigned int rate = SAMPLERATE;

    HDF_LOGI("%s: enter", __func__);
    ret = AipSetSysCtlReg(chnId, channelCnt, bitWidth, rate);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AipSetSysCtlReg fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAipSetAttr(void)
{
    int ret;
    int32_t chnId = 0;
    unsigned int channelCnt = CHANNELNUM;
    unsigned int bitWidth = BITWIDTH;

    HDF_LOGI("%s: enter", __func__);
    ret = AipSetAttr(chnId, channelCnt, bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AipSetAttr fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}


int32_t TestAiaoDeviceInit(void)
{
    int ret;
    int32_t chnId;

    HDF_LOGI("%s: enter", __func__);
    chnId = 0;
    ret = AiaoDeviceInit(chnId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AiaoDeviceInit fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestI2sCrgCfgInit(void)
{
    int ret;
    int32_t chnId;

    HDF_LOGI("%s: enter", __func__);
    chnId = 0;
    ret = I2sCrgCfgInit(chnId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: I2sCrgCfgInit fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}
