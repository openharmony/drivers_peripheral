/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hi3516_codec_impl_test.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "hdf_types.h"
#include "hi3516_codec_impl.h"

#define HDF_LOG_TAG hi3516_codec_impl_test

int32_t TestCodecHalSysInit(void)
{
    int ret;

    HDF_LOGI("%s: enter", __func__);
    ret = CodecHalSysInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: CodecHalSysInit fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAcodecDeviceInit(void)
{
    int ret;

    HDF_LOGI("%s: enter", __func__);
    ret = AcodecDeviceInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AcodecDeviceInit fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAcodecHalReadReg(void)
{
    int ret;
    unsigned int offset;
    const int offsetValue = 0x14;
    HDF_LOGI("%s: enter", __func__);

    offset = offsetValue;
    ret = AcodecHalReadReg(offset);

    // ret is  value that is storaged in address.
    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAcodecHalWriteReg(void)
{
    uint32_t offset;
    uint32_t value;
    const uint32_t offsetValue = 0x14;
    const uint32_t regValue = 0x04000002;
    HDF_LOGI("%s: enter", __func__);
    // wiretreg no return value
    offset = offsetValue;
    value = regValue;
    AcodecHalWriteReg(offset, value);

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAcodecSetI2s1Fs(void)
{
    int ret;
    unsigned int rate;
    const unsigned int sampleRate = 48000;
    HDF_LOGI("%s: enter", __func__);
    // rate value is  8000, 12000, 11025, 16000, 22050,
    // 24000, 32000, 44100, 48000, 64000, 96000
    rate = sampleRate;
    ret = AcodecSetI2s1Fs(rate);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AcodecSetI2s1Fs fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestAcodecSetI2s1DataWidth(void)
{
    int ret;
    unsigned int bitWidth;
    const unsigned int bitValue = 16;
    HDF_LOGI("%s: enter", __func__);
    // input 8 16 18 20 24 32
    bitWidth = bitValue;
    ret = AcodecSetI2s1DataWidth(bitWidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AcodecSetI2s1DataWidth fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}
