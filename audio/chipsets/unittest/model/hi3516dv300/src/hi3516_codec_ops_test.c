/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "hi3516_codec_ops_test.h"
#include "audio_codec_base.h"
#include "devsvc_manager_clnt.h"
#include "hdf_base.h"
#include "hi3516_codec_ops.h"
#include "hi3516_common_func.h"

#define HDF_LOG_TAG hi3516_codec_ops_test

void InitCodecDataFunc(struct CodecData *codecData)
{
    codecData->Init = CodecDeviceInit;
    codecData->Read = CodecDeviceReadReg;
    codecData->Write = CodecDeviceWriteReg;
    codecData->AiaoRead = CodecAiaoDeviceReadReg;
    codecData->AiaoWrite = CodecAiaoDeviceWriteReg;
}

int32_t TestCodecDeviceInit(void)
{
    int ret;
    struct AudioCard *audioCard = NULL;
    struct CodecDevice *codec = NULL;
    AudioType type;
    HDF_LOGI("%s: enter", __func__);

    ret = GetAudioCard(&audioCard, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDeviceInit::get audioCard instance failed.");
        return HDF_FAILURE;
    }

    codec = (struct CodecDevice *)OsalMemCalloc(sizeof(*codec));
    if (codec == NULL) {
        HDF_LOGE("Malloc codec device fail!");
        return HDF_ERR_MALLOC_FAIL;
    }
    OsalMutexInit(&codec->mutex);
    codec->devCodecName = "codec_service_0";
    codec->device = DevSvcManagerClntGetDeviceObject(codec->devCodecName);
    codec->devData = (struct CodecData *)OsalMemCalloc(sizeof(*codec->devData));
    if (codec->devData == NULL) {
        HDF_LOGE("Malloc codec devData fail!");
        OsalMutexDestroy(&codec->mutex);
        OsalMemFree(codec);
        return HDF_ERR_MALLOC_FAIL;
    }
    codec->devData->drvCodecName = "codec_service_0";
    InitCodecDataFunc(codec->devData);

    ret = CodecDeviceInit(audioCard, codec);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: CodecDeviceInit fail ret = %d", __func__, ret);
        OsalMemFree(codec->devData);
        OsalMutexDestroy(&codec->mutex);
        OsalMemFree(codec);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    OsalMemFree(codec->devData);
    OsalMutexDestroy(&codec->mutex);
    OsalMemFree(codec);
    return HDF_SUCCESS;
}

int32_t TestCodecDaiDeviceInit(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct DaiDevice *device = NULL;
    AudioType type;
    HDF_LOGI("%s: enter", __func__);

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiDeviceInit::get audioCard instance failed.");
        return HDF_FAILURE;
    }

    device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("Malloc device device fail!");
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = "dai_service";
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiDeviceInit(card, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: CodecDaiDeviceInit fail ret = %d", __func__, ret);
        OsalMemFree((void*)device);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    OsalMemFree(device);
    return HDF_SUCCESS;
}

int32_t TestCodecDaiStartup(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct DaiDevice *device = NULL;
    AudioType type;
    HDF_LOGI("%s: enter", __func__);

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiStartup::get audioCard instance failed.");
        return HDF_FAILURE;
    }

    device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("Malloc device device fail!");
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = "dai_service";
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiStartup(card, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AiaoHalSysInit fail ret = %d", __func__, ret);
        OsalMemFree((void*)device);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: success", __func__);
    OsalMemFree(device);
    return HDF_SUCCESS;
}

int32_t TestCodecDaiHwParams(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    struct DaiDevice *device = NULL;
    const uint32_t channelNum = 2;
    const uint32_t sampleRate = 48000;
    const uint32_t periodSize = 960;
    const uint32_t periodCount = 8;
    const int foramt = 2;
    AudioType type;
    HDF_LOGI("%s: enter", __func__);

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiHwParams::get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("%s: alloc param memory failed");
        return HDF_FAILURE;
    }

    param->channels = channelNum;
    param->rate = sampleRate;
    param->periodSize = periodSize;
    param->periodCount  = periodCount;
    param->format = foramt;
    param->cardServiceName = "hdf_audio_codec_dev0";

    device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("Malloc device device fail!");
        OsalMemFree(param);
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = "dai_service";
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiHwParams(card, param, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AiaoHalSysInit fail ret = %d", __func__, ret);
        OsalMemFree(device);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    OsalMemFree(device);
    OsalMemFree(param);
    HDF_LOGI("%s: success", __func__);
    return HDF_SUCCESS;
}
