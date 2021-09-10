/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hi3516_platform_ops_test.h"
#include "audio_platform_base.h"
#include "devsvc_manager_clnt.h"
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
    HDF_LOGI("%s: enter", __func__);

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestAudioPlatformDeviceInit::get card instance failed.");
        return HDF_FAILURE;
    }

    if (card == NULL || card->rtd == NULL || card->rtd->platform == NULL) {
        HDF_LOGE("get card instance failed.");
        return HDF_FAILURE;
    }

    platform = card->rtd->platform;
    ret = AudioPlatformDeviceInit(card, platform);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AudioPlatformDeviceInit fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestPlatformHwParams(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    AudioType type;
    const uint32_t channelNum = 2;
    const uint32_t sampleRate = 48000;
    const uint32_t periodSize = 4096;
    const uint32_t periodCount = 8;
    const int format = 2;
    const uint32_t startThreshold = 1024;
    const uint32_t stopThreshold = 0x7fffffff;
    const uint32_t silenceThreshold = 1024 * 16;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformHwParams::get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("%s: alloc param memory failed");
        return HDF_FAILURE;
    }

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

    ret = PlatformHwParams(card, param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformHwParams fail ret = %d", __func__, ret);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
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
        HDF_LOGE("TestPlatformRenderPrepare::get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformRenderPrepare(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformRenderPrepare fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestPlatformCapturePrepare(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCapturePrepare::get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCapturePrepare(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformCapturePrepare fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
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
    HDF_LOGI("%s: enter", __func__);

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformWrite::get card instance failed.");
        return HDF_FAILURE;
    }

    if (card->rtd == NULL || card->rtd->platform == NULL || card->rtd->platform->device == NULL) {
        HDF_LOGE("get card params fail.");
        return HDF_FAILURE;
    }
    platformHost = PlatformHostFromDevice(card->rtd->platform->device);
    if (platformHost == NULL) {
        HDF_LOGE("PlatformHostFromDevice fail.");
        return HDF_FAILURE;
    }
    OsalMutexInit(&platformHost->renderBufInfo.buffMutex);

    txData =  (struct AudioTxData *)OsalMemCalloc(sizeof(*txData));
    if (txData == NULL) {
        HDF_LOGE("aclloc txData memory fail");
        OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
        return HDF_ERR_MALLOC_FAIL;
    }

    txData->status = ENUM_CIR_BUFF_NORMAL;
    txData->buf = "this is a test";
    txData->frames = frameNum;

    ret = PlatformWrite(card, txData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformWrite fail ret = %d", __func__, ret);
        OsalMemFree(txData);
        OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
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

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRead::get card instance failed.");
        return HDF_FAILURE;
    }

    if (card->rtd == NULL || card->rtd->platform == NULL || card->rtd->platform->device == NULL) {
        HDF_LOGE("get card params fail.");
        return HDF_FAILURE;
    }
    platformHost = PlatformHostFromDevice(card->rtd->platform->device);
    if (platformHost == NULL) {
        HDF_LOGE("PlatformHostFromDevice fail.");
        return HDF_FAILURE;
    }
    OsalMutexInit(&platformHost->captureBufInfo.buffMutex);

    rxData =  (struct AudioRxData *)OsalMemCalloc(sizeof(*rxData));
    if (rxData == NULL) {
        HDF_LOGE("aclloc rxData memory fail");
        OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = PlatformRead(card, rxData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformRead fail ret = %d", __func__, ret);
        OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
        OsalMemFree(rxData);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
    OsalMemFree(rxData);
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderStart(void)
{
    int ret;
    struct AudioCard *card = NULL;

    HDF_LOGI("%s: enter", __func__);
    AudioType type;
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderStart::get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformRenderStart(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformRenderStart fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestPlatformCaptureStart(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureStart::get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCaptureStart(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformCaptureStart fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderStop(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct PlatformHost *platformHost = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderStop::get card instance failed.");
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
        HDF_LOGE("%s: PlatformRenderStop fail ret = %d", __func__, ret);
        OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    OsalMutexDestroy(&platformHost->renderBufInfo.buffMutex);
    return HDF_SUCCESS;
}

int32_t TestPlatformCaptureStop(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct PlatformHost *platformHost = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureStop::get card instance failed.");
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
        HDF_LOGE("%s: PlatformRenderStop fail ret = %d", __func__, ret);
        OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    OsalMutexDestroy(&platformHost->captureBufInfo.buffMutex);
    return HDF_SUCCESS;
}

int32_t TestPlatformCapturePause(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCapturePause::get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCapturePause(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformCapturePause fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderPause(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderPause::get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformRenderPause(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformRenderPause fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestPlatformRenderResume(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformRenderResume::get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformRenderResume(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformRenderResume fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}

int32_t TestPlatformCaptureResume(void)
{
    int ret;
    struct AudioCard *card = NULL;
    AudioType type;

    HDF_LOGI("%s: enter", __func__);
    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestPlatformCaptureResume::get card instance failed.");
        return HDF_FAILURE;
    }

    ret = PlatformCaptureResume(card);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: PlatformCaptureResume fail ret = %d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}
