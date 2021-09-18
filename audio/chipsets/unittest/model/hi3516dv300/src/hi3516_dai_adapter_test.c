/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hi3516_dai_adapter_test.h"
#include "audio_dai_if.h"
#include "audio_host.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "hi3516_common_func.h"

#define HDF_LOG_TAG hi3516_dai_adapter_test

int32_t SetHwParam(struct AudioPcmHwParams *param)
{
    if (param == NULL) {
        HDF_LOGE("input param is NULL.");
        return HDF_FAILURE;
    }
    const uint32_t channelNum = 2;
    const uint32_t sampleRate = 48000;
    const uint32_t periodSize =  4096;
    const uint32_t periodCount = 8;
    const uint32_t format = 2;
    const uint32_t startThreshold = 1024;
    const uint32_t stopThreshold = 0x7fffffff;
    const uint32_t silenceThreshold = 16 * 1024;

    param->channels  = channelNum;
    param->rate = sampleRate;
    param->periodSize = periodSize;
    param->periodCount = periodCount;
    param->format = format;
    param->cardServiceName = "hdf_audio_codec_dev0";
    param->isBigEndian = false;
    param->isSignedData = true;
    param->startThreshold = startThreshold;
    param->stopThreshold = stopThreshold;
    param->silenceThreshold = silenceThreshold;
    param->streamType = 0; // AUDIO_RENDER_STREAM
    return HDF_SUCCESS;
}

int32_t TestDaiHwParams(void)
{
    // CodecDaiHwParams: channels = 2, rate = 48000,
    // PERIODSIZE = 960,         PERIODCOUNT = 8, FORMAT = 2,
    // cardServiceName = audio_service_0
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    struct DaiDevice *cpuDai = NULL;
    AudioType type;

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDaiHwParams::get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("%s: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = SetHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("set hwparm fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    if (card->rtd == NULL) {
        HDF_LOGE("card rtd is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    cpuDai = card->rtd->cpuDai;
    if (cpuDai->devData == NULL || cpuDai->devData->ops == NULL) {
        HDF_LOGE("cpuDai param is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    if (cpuDai->devData->ops->HwParams != NULL) {
        ret = cpuDai->devData->ops->HwParams(card, param, cpuDai);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: DaiHwParams fail ret = %d", __func__, ret);
            OsalMemFree(param);
            return HDF_FAILURE;
        }
    }

    OsalMemFree(param);
    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}
