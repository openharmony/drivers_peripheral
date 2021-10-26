/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hi3516_dai_adapter_test.h"
#include "audio_host.h"
#include "audio_dai_if.h"
#include "audio_platform_if.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "hi3516_common_func.h"

#define HDF_LOG_TAG hi3516_dai_adapter_test

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
        HDF_LOGE("TestDaiHwParams: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestDaiHwParams: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDaiHwParams: set hwparm fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    if (card->rtd == NULL) {
        HDF_LOGE("TestDaiHwParams: card rtd is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    cpuDai = card->rtd->cpuDai;
    if (cpuDai->devData == NULL || cpuDai->devData->ops == NULL) {
        HDF_LOGE("TestDaiHwParams: cpuDai param is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    if (cpuDai->devData->ops->HwParams != NULL) {
        ret = cpuDai->devData->ops->HwParams(card, param, cpuDai);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("TestDaiHwParams: DaiHwParams fail ret = %d", ret);
            OsalMemFree(param);
            return HDF_FAILURE;
        }
    }

    OsalMemFree(param);
    HDF_LOGI("TestDaiHwParams: success");
    return HDF_SUCCESS;
}

int32_t TestDaiInvalidRateParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    struct DaiDevice *cpuDevDai = NULL;
    AudioType type;

    if (GetAudioCard(&card, &type) != HDF_SUCCESS) {
        HDF_LOGE("TestDaiInvalidRateParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestDaiInvalidRateParam:  alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDaiInvalidRateParam: set hwparm fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    param->rate = 0;

    if (card->rtd == NULL || card->rtd->cpuDai == NULL) {
        HDF_LOGE("TestDaiInvalidRateParam: card rtd is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    cpuDevDai = card->rtd->cpuDai;
    if (cpuDevDai->devData == NULL || cpuDevDai->devData->ops == NULL) {
        HDF_LOGE("TestDaiInvalidRateParam: cpuDevDai param is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    if (cpuDevDai->devData->ops->HwParams != NULL) {
        ret = cpuDevDai->devData->ops->HwParams(card, param, cpuDevDai);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("TestDaiInvalidRateParam: DaiHwParams fail ret = %d", ret);
            OsalMemFree(param);
            return HDF_FAILURE;
        }
    }

    OsalMemFree(param);
    HDF_LOGI("TestDaiInvalidRateParam: success");
    return HDF_SUCCESS;
}

int32_t TestDaiInvalidRenderBitWidthParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    struct DaiDevice *cpuDai = NULL;
    AudioType type;

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDaiInvalidRenerBitWidthParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestDaiInvalidRenerBitWidthParam: :alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDaiInvalidRenerBitWidthParam: set hwparm fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    param->streamType = 0;
    param->format = 1;

    if (card->rtd == NULL || card->rtd->cpuDai == NULL) {
        HDF_LOGE("TestDaiInvalidRenerBitWidthParam: card rtd is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    cpuDai = card->rtd->cpuDai;
    if (cpuDai->devData == NULL || cpuDai->devData->ops == NULL) {
        HDF_LOGE("TestDaiInvalidRenerBitWidthParam: cpuDai param is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    if (cpuDai->devData->ops->HwParams != NULL) {
        ret = cpuDai->devData->ops->HwParams(card, param, cpuDai);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("TestDaiInvalidRenerBitWidthParam: DaiHwParams fail ret = %d", ret);
            OsalMemFree(param);
            return HDF_FAILURE;
        }
    }

    OsalMemFree(param);
    HDF_LOGI("TestDaiInvalidRenerBitWidthParam: success");
    return HDF_SUCCESS;
}

int32_t TestDaiInvalidCaptureBitWidthParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    struct DaiDevice *cpuDai = NULL;
    AudioType type;

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDailInvalidCaptureBitWidthParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestDailInvalidCaptureBitWidthParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDailInvalidCaptureBitWidthParam: set hwparm failed");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    param->streamType = 1;
    param->format = 1;

    if (card->rtd == NULL || card->rtd->cpuDai == NULL) {
        HDF_LOGE("TestDailInvalidCaptureBitWidthParam: card rtd is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    cpuDai = card->rtd->cpuDai;
    if (cpuDai->devData == NULL || cpuDai->devData->ops == NULL) {
        HDF_LOGE("TestDailInvalidCaptureBitWidthParam: cpuDai param is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    if (cpuDai->devData->ops->HwParams != NULL) {
        ret = cpuDai->devData->ops->HwParams(card, param, cpuDai);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("TestDailInvalidCaptureBitWidthParam: DaiHwParams fail ret = %d", ret);
            OsalMemFree(param);
            return HDF_FAILURE;
        }
    }

    OsalMemFree(param);
    HDF_LOGI("TestDailInvalidCaptureBitWidthParam: success");
    return HDF_SUCCESS;
}


int32_t TestDaiInvalidStreamTypeParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    struct DaiDevice *cpuDai = NULL;
    const int streamTypeDefault = 2;
    AudioType type;

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDailInvalidStreamTypeParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestDailInvalidStreamTypeParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDailInvalidStreamTypeParam: set hwparm failed");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    param->streamType = streamTypeDefault;

    if (card->rtd == NULL || card->rtd->cpuDai == NULL) {
        HDF_LOGE("TestDailInvalidStreamTypeParam: card rtd is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    cpuDai = card->rtd->cpuDai;
    if (cpuDai->devData == NULL || cpuDai->devData->ops == NULL) {
        HDF_LOGE("TestDailInvalidStreamTypeParam: cpuDai param is NULL.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    if (cpuDai->devData->ops->HwParams != NULL) {
        ret = cpuDai->devData->ops->HwParams(card, param, cpuDai);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("TestDailInvalidStreamTypeParam: DaiHwParams fail ret = %d", ret);
            OsalMemFree(param);
            return HDF_FAILURE;
        }
    }

    OsalMemFree(param);
    HDF_LOGI("TestDailInvalidStreamTypeParam:  success");
    return HDF_SUCCESS;
}

int32_t TestDaiTrigger(void)
{
    int ret;
    struct AudioCard *card = NULL;
    int cmd;
    struct DaiDevice *cpuDai = NULL;
    AudioType type;

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestDaiTrigger: get card instance failed.");
        return HDF_FAILURE;
    }

    if (card->rtd == NULL || card->rtd->cpuDai == NULL) {
        HDF_LOGE("TestDaiTrigger: card rtd is NULL.");
        return HDF_FAILURE;
    }
    cpuDai = card->rtd->cpuDai;
    if (cpuDai->devData == NULL || cpuDai->devData->ops == NULL) {
        HDF_LOGE("TestDaiTrigger: cpuDai param is NULL.");
        return HDF_FAILURE;
    }
    cmd = 1;
    if (cpuDai->devData->ops->Trigger != NULL) {
        ret = cpuDai->devData->ops->Trigger(card, cmd, cpuDai);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("TestDaiTrigger: Trigger fail ret = %d", ret);
            return HDF_FAILURE;
        }
    }

    HDF_LOGI("TestDaiTrigger: success");
    return HDF_SUCCESS;
}
