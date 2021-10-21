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

int32_t InitCodecDataFunc(struct CodecData *codecData)
{
    if (codecData == NULL) {
        HDF_LOGE("InitCodecDataFunc:input param is NULL.");
        return HDF_FAILURE;
    }
    codecData->Init = CodecDeviceInit;
    codecData->Read = CodecDeviceReadReg;
    codecData->Write = CodecDeviceWriteReg;
    codecData->AiaoRead = CodecAiaoDeviceReadReg;
    codecData->AiaoWrite = CodecAiaoDeviceWriteReg;
    return HDF_SUCCESS;
}

int32_t TestCodecDeviceInit(void)
{
    int32_t ret;
    struct AudioCard *audioCard = NULL;
    struct CodecDevice *codec = NULL;
    AudioType type;
    HDF_LOGI("%s: enter", __func__);

    ret = GetAudioCard(&audioCard, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDeviceInit:get audioCard instance failed.");
        return HDF_FAILURE;
    }

    codec = (struct CodecDevice *)OsalMemCalloc(sizeof(*codec));
    if (codec == NULL) {
        HDF_LOGE("TestCodecDeviceInit:Malloc codec device fail!");
        return HDF_ERR_MALLOC_FAIL;
    }
    OsalMutexInit(&codec->mutex);
    codec->devCodecName = "codec_service_0";
    codec->device = DevSvcManagerClntGetDeviceObject(codec->devCodecName);
    codec->devData = (struct CodecData *)OsalMemCalloc(sizeof(*codec->devData));
    if (codec->devData == NULL) {
        HDF_LOGE("TestCodecDeviceInit:Malloc codec devData fail!");
        OsalMutexDestroy(&codec->mutex);
        OsalMemFree(codec);
        return HDF_ERR_MALLOC_FAIL;
    }
    codec->devData->drvCodecName = "codec_service_0";
    ret = InitCodecDataFunc(codec->devData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDeviceInit: InitCodecDataFunc fail ret = %d", ret);
        OsalMemFree(codec->devData);
        OsalMutexDestroy(&codec->mutex);
        OsalMemFree(codec);
        return HDF_FAILURE;
    }

    ret = CodecDeviceInit(audioCard, codec);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDeviceInit: CodecDeviceInit fail ret = %d", ret);
        OsalMemFree(codec->devData);
        OsalMutexDestroy(&codec->mutex);
        OsalMemFree(codec);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestCodecDeviceInit:%s: success", __func__);
    OsalMemFree(codec->devData);
    OsalMutexDestroy(&codec->mutex);
    OsalMemFree(codec);
    return HDF_SUCCESS;
}

int32_t TestCodecDeviceInitFail(void)
{
    int ret;
    struct AudioCard *audioCard = NULL;
    struct CodecDevice *codec = NULL;
    AudioType type;
    HDF_LOGI("%s: enter", __func__);

    ret = GetAudioCard(&audioCard, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDeviceInitFail:get audioCard instance failed.");
        return HDF_FAILURE;
    }

    codec = (struct CodecDevice *)OsalMemCalloc(sizeof(*codec));
    if (codec == NULL) {
        HDF_LOGE("TestCodecDeviceInitFail:Malloc codec device fail!");
        return HDF_ERR_MALLOC_FAIL;
    }
    OsalMutexInit(&codec->mutex);
    codec->devCodecName = "codec_service_0";
    codec->device = DevSvcManagerClntGetDeviceObject(codec->devCodecName);
    codec->devData = (struct CodecData *)OsalMemCalloc(sizeof(*codec->devData));
    if (codec->devData == NULL) {
        HDF_LOGE("TestCodecDeviceInitFail:Malloc codec devData fail!");
        OsalMutexDestroy(&codec->mutex);
        OsalMemFree(codec);
        return HDF_ERR_MALLOC_FAIL;
    }
    codec->devData->drvCodecName = "codec_service_0";

    ret = CodecDeviceInit(audioCard, codec);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDeviceInitFail: CodecDeviceInit fail ret = %d", ret);
        OsalMemFree(codec->devData);
        OsalMutexDestroy(&codec->mutex);
        OsalMemFree(codec);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestCodecDeviceInitFail: success");
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
        HDF_LOGE("TestCodecDaiDeviceInit:get audioCard instance failed.");
        return HDF_FAILURE;
    }

    device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("TestCodecDaiDeviceInit:Malloc device device fail!");
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = "dai_service";
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiDeviceInit(card, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiDeviceInit:CodecDaiDeviceInit fail ret = %d", ret);
        OsalMemFree((void*)device);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestCodecDaiDeviceInit: success");
    OsalMemFree(device);
    return HDF_SUCCESS;
}

int32_t TestCodecDaiDeviceInitFail(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct DaiDevice *device = NULL;
    AudioType type;
    HDF_LOGI("TestCodecDaiDeviceInitFail: enter");

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiDeviceInitFail:get audioCard instance failed.");
        return HDF_FAILURE;
    }

    device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("TestCodecDaiDeviceInitFail:Malloc device device fail!");
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = NULL;
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiDeviceInit(card, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiDeviceInitFail: CodecDaiDeviceInit fail ret = %d", ret);
        OsalMemFree((void*)device);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestCodecDaiDeviceInitFail: success");
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
        HDF_LOGE("TestCodecDaiStartup:get audioCard instance failed.");
        return HDF_FAILURE;
    }

    device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("TestCodecDaiStartup:Malloc device device fail!");
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = "dai_service";
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiStartup(card, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiStartup: CodecDaiStartup fail ret = %d", ret);
        OsalMemFree((void*)device);
        return HDF_FAILURE;
    }

    HDF_LOGI("TestCodecDaiStartup: success");
    OsalMemFree(device);
    return HDF_SUCCESS;
}

int32_t TestCodecDaiHwParams(void)
{
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    struct DaiDevice *device = NULL;
    int ret;
    AudioType type;
    HDF_LOGI("TestCodecDaiHwParams: enter");

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiHwParams:get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestCodecDaiHwParams:alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiHwParams:set hw params failed.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("TestCodecDaiHwParams:Malloc device device fail!");
        OsalMemFree(param);
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = "dai_service";
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiHwParams(card, param, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiHwParams: CodecDaiHwParams fail ret = %d", ret);
        OsalMemFree(device);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    OsalMemFree(device);
    OsalMemFree(param);
    HDF_LOGI("TestCodecDaiHwParams: success");
    return HDF_SUCCESS;
}

int32_t TestCodecDaiInvalidBitWidthParam(void)
{
    struct AudioCard *card = NULL;
    AudioType type;
    HDF_LOGI("TestCodecDaiInvalidBitWidthParam: enter");

    int ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiInvalidBitWidthParam:get card instance failed.");
        return HDF_FAILURE;
    }

    struct AudioPcmHwParams *param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestCodecDaiInvalidBitWidthParam:alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiInvalidBitWidthParam:set hw params failed.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    param->format = 1;
    struct DaiDevice *device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("TestCodecDaiInvalidBitWidthParam:Malloc device device fail!");
        OsalMemFree(param);
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = "dai_service";
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiHwParams(card, param, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiInvalidBitWidthParam: CodecDaiHwParams fail ret = %d", ret);
        OsalMemFree(device);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    OsalMemFree(device);
    OsalMemFree(param);
    HDF_LOGI("TestCodecDaiInvalidBitWidthParam: success");
    return HDF_SUCCESS;
}

int32_t TestCodecDaiInvalidRateParam(void)
{
    int ret;
    struct AudioCard *card = NULL;
    struct AudioPcmHwParams *param = NULL;
    struct DaiDevice *device = NULL;
    const int setInvalidSampleRate = 96000 * 2;

    AudioType type;
    HDF_LOGI("TestCodecDaiInvalidRateParam: enter");

    ret = GetAudioCard(&card, &type);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiInvalidRateParam:get card instance failed.");
        return HDF_FAILURE;
    }

    param = (struct AudioPcmHwParams *)OsalMemCalloc(sizeof(*param));
    if (param == NULL) {
        HDF_LOGE("TestCodecDaiInvalidRateParam: alloc param memory failed");
        return HDF_FAILURE;
    }

    ret = InitHwParam(param);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiInvalidRateParam:set hw params failed.");
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    param->rate = setInvalidSampleRate;
    device = (struct DaiDevice *)OsalMemCalloc(sizeof(*device));
    if (device == NULL) {
        HDF_LOGE("TestCodecDaiInvalidRateParam:Malloc device device fail!");
        OsalMemFree(param);
        return HDF_ERR_MALLOC_FAIL;
    }

    device->devDaiName = "dai_service";
    device->devData = NULL;
    device->device = DevSvcManagerClntGetDeviceObject(device->devDaiName);

    ret = CodecDaiHwParams(card, param, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("TestCodecDaiInvalidRateParam: AiaoHalSysInit fail ret = %d", ret);
        OsalMemFree(device);
        OsalMemFree(param);
        return HDF_FAILURE;
    }

    OsalMemFree(device);
    OsalMemFree(param);
    HDF_LOGI("TestCodecDaiInvalidRateParam: success");
    return HDF_SUCCESS;
}
