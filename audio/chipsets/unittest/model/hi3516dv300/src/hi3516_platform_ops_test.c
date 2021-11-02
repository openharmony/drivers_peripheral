/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hi3516_platform_ops_test.h"
#include "audio_platform_base.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "hi3516_common_func.h"
#include "hi3516_platform_ops.h"

#define HDF_LOG_TAG hi3516_platform_ops_test

int32_t TestAudioPlatformDeviceInit(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct PlatformDevice *platform = NULL;
    AudioType type;
    HDF_LOGI("TestAudioPlatformDeviceInit: enter");

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAudioPlatformDeviceInit: get card instance failed.");
        return HDF_FAILURE;
    }

    if (card == NULL || card->rtd == NULL || card->rtd->platform == NULL) {
        HDF_LOGE("TestAudioPlatformDeviceInit: get card instance failed.");
        return HDF_FAILURE;
    }

    platform = card->rtd->platform;
    ret = AudioPlatformDeviceInit(card, platform);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAudioPlatformDeviceInit: AudioPlatformDeviceInit fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestAudioPlatformDeviceInit: success");
    return HDF_SUCCESS;
}

int32_t TestPlatformHwParams(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformHwParams: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformHwParams: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestPlatformHwParams: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("AudioHwParams set hw param is fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    ret = AudioHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformHwParams: AudioHwParams fail ret = %d", ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformHwParams: success");
    OsalMemFree(param);
    return HDF_SUCCESS;
}

int32_t TestPlatformInvalidChannelsParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformInvalidChannelsParam: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidChannelsParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestPlatformInvalidChannelsParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidChannelsParam: AudioHwParams set hw param is fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    param->channels = 0;
    ret = AudioHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidChannelsParam: AudioHwParams fail ret = %d", ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformInvalidChannelsParam: success");
    OsalMemFree(param);
    return HDF_SUCCESS;
}

int32_t TestPlatformInvalidStreamTypeParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    AudioType type;
    const int invalidStreamType = 2;

    HDF_LOGI("TestPlatformInvalidStreamTypeParam: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidStreamTypeParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestPlatformInvalidStreamTypeParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidStreamTypeParam: AudioHwParams set hw param is fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    param->streamType = invalidStreamType;
    ret = AudioHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidStreamTypeParam: AudioHwParams fail ret = %d", ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformInvalidStreamTypeParam: success");
    OsalMemFree(param);
    return HDF_SUCCESS;
}

int32_t TestPlatformInvalidRenderPeriodCountParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    const int periodCountValue = 4;
    AudioType type;

    HDF_LOGI("TestPlatformInvalidRenderPeriodCountParam: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidRenderPeriodCountParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestPlatformInvalidRenderPeriodCountParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidRenderPeriodCountParam: AudioHwParams set hw param is fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    param->streamType = 1;
    param->periodCount = periodCountValue;
    ret = AudioHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidRenderPeriodCountParam: AudioHwParams fail ret = %d", ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformInvalidRenderPeriodCountParam: success");
    OsalMemFree(param);
    return HDF_SUCCESS;
}
int32_t TestPlatformInvalidRenderPeriodSizeParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    const int periodSizeValue = 1024;
    AudioType type;

    HDF_LOGI("TestPlatformInvalidRenderPeriodSizeParam: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidRenderPeriodSizeParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestPlatformInvalidRenderPeriodSizeParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidRenderPeriodSizeParam: AudioHwParams set hw param is fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    param->streamType = 1;
    param->periodSize = periodSizeValue;
    ret = AudioHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidRenderPeriodSizeParam: AudioHwParams fail ret = %d", ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformInvalidRenderPeriodSizeParam: success");
    OsalMemFree(param);
    return HDF_SUCCESS;
}

int32_t TestPlatformInvalidCaptuerPeriodCountParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    const int periodCountValue = 4;
    AudioType type;

    HDF_LOGI("TestPlatformInvalidCaptuerPeriodCountParam: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerPeriodCountParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestPlatformInvalidCaptuerPeriodCountParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerPeriodCountParam: AudioHwParams set hw param is fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    param->streamType = 0;
    param->periodCount = periodCountValue;
    ret = AudioHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerPeriodCountParam: AudioHwParams fail ret = %d", ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformInvalidCaptuerPeriodCountParam: success");
    OsalMemFree(param);
    return HDF_SUCCESS;
}

int32_t TestPlatformInvalidCaptuerPeriodSizeParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    const int periodSizeValue = 1024;
    AudioType type;

    HDF_LOGI("TestPlatformInvalidCaptuerPeriodSizeParam: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerPeriodSizeParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestPlatformInvalidCaptuerPeriodSizeParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerPeriodSizeParam: AudioHwParams set hw param is fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    param->streamType = 0;
    param->periodSize = periodSizeValue;
    ret = AudioHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerPeriodSizeParam: AudioHwParams fail ret = %d", ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformInvalidCaptuerPreiodSizeParam: success");
    OsalMemFree(param);
    return HDF_SUCCESS;
}

int32_t TestPlatformInvalidCaptuerSilenceThresholdParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    const int silenceThresholdValue = 1024;
    AudioType type;

    HDF_LOGI("TestPlatformInvalidCaptuerSilenceThresholdParam: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerSilenceThresholdParam: get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestPlatformInvalidCaptuerSilenceThresholdParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerSilenceThresholdParam: AudioHwParams set hw param is fail");
        OsalMemFree(param);
        return HDF_FAILURE;
    }
    param->streamType = 0;
    param->silenceThreshold = silenceThresholdValue;
    ret = AudioHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformInvalidCaptuerSilenceThresholdParam: AudioHwParams fail ret = %d", ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformInvalidCaptuerSilenceThresholdParam: success");
    OsalMemFree(param);
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderPrepare(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderPrepare: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = AudioRenderPrepare(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderPrepare: AudioRenderPrepare fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformRenderPrepare: success");
    return HDF_SUCCESS;
}

int32_t TestPlatformCapturePrepare(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformCapturePrepare: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCapturePrepare: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = AudioCapturePrepare(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCapturePrepare: AudioCapturePrepare fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformCapturePrepare: success");
    return HDF_SUCCESS;
}

int32_t TestPlatformWrite(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioTxData *txData = NULL;
    struct PlatformHost *platformHost = NULL;
    AudioType type;
    const unsigned long frameNum = 1000;
    HDF_LOGI("TestPlatformWrite: enter");

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformWrite: get card instance failed.");
        return HDF_FAILURE;
    }

    if (card->rtd == NULL || card->rtd->platform == NULL || card->rtd->platform->device == NULL) {
        HDF_LOGE("get card params fail.");
        return HDF_FAILURE;
    }
    platformHost = PlatformHostFromDevice(card->rtd->platform->device);
    if (platformHost == NULL) {
        HDF_LOGE("TestPlatformWrite: PlatformHostFromDevice fail.");
        return HDF_FAILURE;
    }
    OsalMutexInit(&platformHost->renderBufInfo.buffMutex);

    txData =  (struct AudioTxData *)OsalMemCalloc(sizeof(*txData));
    if (txData == NULL) {
        HDF_LOGE("TestPlatformWrite: aclloc txData memory fail");
        OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
        return HDF_ERR_MALLOC_FAIL;
    }

    txData->status = ENUM_CIR_BUFF_NORMAL;
    txData->buf = "this is a test";
    txData->frames = frameNum;

    ret = PlatformWrite(card, txData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformWrite: PlatformWrite fail ret = %d", ret);
        OsalMemFree(txData);
        OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformWrite: success");
    OsalMemFree(txData);
    OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
    return HDF_SUCCESS;
}

int32_t TestPlatformRead(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioRxData *rxData = NULL;
    struct PlatformHost *platformHost = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformRead: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRead: get card instance failed.");
        return HDF_FAILURE;
    }

    if (card->rtd == NULL || card->rtd->platform == NULL || card->rtd->platform->device == NULL) {
        HDF_LOGE("TestPlatformRead: get card params fail.");
        return HDF_FAILURE;
    }
    platformHost = PlatformHostFromDevice(card->rtd->platform->device);
    if (platformHost == NULL) {
        HDF_LOGE("TestPlatformRead: PlatformHostFromDevice fail.");
        return HDF_FAILURE;
    }
    OsalMutexInit(&platformHost->captureBufInfo.buffMutex);

    rxData =  (struct AudioRxData *)OsalMemCalloc(sizeof(*rxData));
    if (rxData == NULL) {
        HDF_LOGE("TestPlatformRead: aclloc rxData memory fail");
        OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = PlatformRead(card, rxData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRead: PlatformRead fail ret = %d", ret);
        OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
        OsalMemFree(rxData);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformRead: success");
    OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
    OsalMemFree(rxData);
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderStart(void)
{
    int ret;
    struct AudioCard *card = NULL;

    HDF_LOGI("TestPlatformRenderStart: enter");
    AudioType type;
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderStart: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformRenderStart(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderStart: PlatformRenderStart fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformRenderStart: success");
    return HDF_SUCCESS;
}

int32_t TestPlatformCaptureStart(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformCaptureStart: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureStart: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCaptureStart(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureStart: PlatformCaptureStart fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformCaptureStart: success");
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderStop(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct PlatformHost *platformHost = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformRenderStop: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderStop: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCreatePlatformHost(card, &platformHost);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("PlatformCreatePlatformHost failed.");
        return HDF_FAILURE;
    }
    OsalMutexInit(&platformHost->renderBufInfo.buffMutex);

    ret = PlatformRenderStop(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderStop: PlatformRenderStop fail ret = %d", ret);
        OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformRenderStop: success");
    OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
    return HDF_SUCCESS;
}

int32_t TestPlatformCaptureStop(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct PlatformHost *platformHost = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformCaptureStop: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureStop: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCreatePlatformHost(card, &platformHost);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("PlatformCreatePlatformHost failed.");
        return HDF_FAILURE;
    }
    OsalMutexInit(&platformHost->captureBufInfo.buffMutex);

    ret = PlatformCaptureStop(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureStop: PlatformRenderStop fail ret = %d", ret);
        OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformCaptureStop: success");
    OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
    return HDF_SUCCESS;
}

int32_t TestPlatformCapturePause(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformCapturePause: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCapturePause: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCapturePause(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCapturePause: PlatformCapturePause fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformCapturePause: success");
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderPause(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformRenderPause: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderPause: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformRenderPause(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderPause: PlatformRenderPause fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformRenderPause: success");
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderResume(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformRenderResume: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderResume: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformRenderResume(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderResume: PlatformRenderResume fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformRenderResume: success");
    return HDF_SUCCESS;
}

int32_t TestPlatformCaptureResume(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("TestPlatformCaptureResume: enter");
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureResume: get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCaptureResume(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureResume PlatformCaptureResume fail ret = %d", ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestPlatformCaptureResume: success");
    return HDF_SUCCESS;
}
