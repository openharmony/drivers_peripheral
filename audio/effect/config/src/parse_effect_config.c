/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "osal_mem.h"
#include "securec.h"

#include "parse_effect_config.h"
#include "audio_uhdf_log.h"

#define HDF_EFFECT_NUM_MAX 32
#define HDF_EFFECT_CONFIG_SIZE_MAX ((HDF_EFFECT_NUM_MAX) * 1024)
#define HDF_EFFECT_NAME_LEN 64
#define HDF_LOG_TAG HDF_AUDIO_EFFECT

static char *GetAudioEffectConfig(const char *fpath)
{
    char *pJsonStr = NULL;
    if (fpath == NULL) {
        HDF_LOGE("%{public}s: fpath is null!", __func__);
        return NULL;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(fpath, pathBuf) == NULL) {
        HDF_LOGE("%{public}s: realpath is null! [%{public}d]", __func__, errno);
        return NULL;
    }

    FILE *fp = fopen(pathBuf, "r");
    if (fp == NULL) {
        HDF_LOGE("%{public}s: can not open config file! [%{public}d]", __func__, errno);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: fseek fail! [%{public}d]", __func__, errno);
        (void)fclose(fp);
        return NULL;
    }
    int32_t jsonStrSize = ftell(fp);
    if (jsonStrSize <= 0) {
        HDF_LOGE("%{public}s: ftell fail! [%{public}d]", __func__, errno);
        (void)fclose(fp);
        return NULL;
    }
    rewind(fp);
    if (jsonStrSize > HDF_EFFECT_CONFIG_SIZE_MAX) {
        HDF_LOGE("%{public}s: The configuration file is too large to load!", __func__);
        (void)fclose(fp);
        return NULL;
    }
    pJsonStr = (char *)OsalMemCalloc((uint32_t)jsonStrSize + 1);
    if (pJsonStr == NULL) {
        HDF_LOGE("%{public}s: alloc pJsonStr failed!", __func__);
        (void)fclose(fp);
        return NULL;
    }
    if (fread(pJsonStr, jsonStrSize, 1, fp) != 1) {
        HDF_LOGE("%{public}s: read to file fail! [%{public}d]", __func__, errno);
        OsalMemFree((void *)pJsonStr);
        (void)fclose(fp);
        return NULL;
    }
    (void)fclose(fp);
    return pJsonStr;
}

cJSON *GetAudioEffectConfigToJsonObj(const char *fpath)
{
    char *pJsonStr = GetAudioEffectConfig(fpath);
    if (pJsonStr == NULL) {
        HDF_LOGE("%{public}s: get audio effect config failed!", __func__);
        return NULL;
    }
    cJSON *cJsonObj = cJSON_Parse(pJsonStr);
    if (cJsonObj == NULL) {
        HDF_LOGE("%{public}s: cJSON_Parse failed!", __func__);
        OsalMemFree((void *)pJsonStr);
        return NULL;
    }
    OsalMemFree((void *)pJsonStr);
    return cJsonObj;
}

static char *AudioEffectGetAndCheckName(const cJSON *cJSONObj, const char *name)
{
    if (cJSONObj == NULL || name == NULL) {
        HDF_LOGE("%{public}s: invalid parameter!", __func__);
        return NULL;
    }

    cJSON *cJSONName = cJSON_GetObjectItem(cJSONObj, name);
    if (cJSONName == NULL || cJSONName->valuestring == NULL) {
        HDF_LOGE("%{public}s: cJSONName or cJSONName->valuestring is null!", __func__);
        return NULL;
    }

    char *effectValue = cJSONName->valuestring;
    if (strlen(effectValue) == 0) {
        HDF_LOGE("%{public}s: effectValue is null!", __func__);
        return NULL;
    }

    if (strcmp(name, "effectId")) {
        if (!isalpha(*effectValue)) { // Names must begin with a letter
            HDF_LOGE("%{public}s: effectValue is illegal!", __func__);
            return NULL;
        }
        effectValue++;
    }

    while (*effectValue != '\0') {
        if (*effectValue == '_' || (strcmp(name, "effectId") == 0 && *effectValue == '-')) {
            effectValue++;
            continue;
        }

        if (!isalnum(*effectValue++)) {
            HDF_LOGE("%{public}s: effectValue is illegal!, %{public}c", __func__, *effectValue);
            return NULL;
        }
    }
    return cJSONName->valuestring;
}

static int32_t AudioEffectParseItem(const cJSON *cJSONObj, const char *item, const char **dest)
{
    if (cJSONObj == NULL || item == NULL || dest == NULL) {
        HDF_LOGE("%{public}s: invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    const char *itemName = AudioEffectGetAndCheckName(cJSONObj, item);
    if (itemName == NULL) {
        HDF_LOGE("%{public}s: get %{public}s fail!", __func__, item);
        return HDF_FAILURE;
    }

    *dest = (char *)OsalMemCalloc(HDF_EFFECT_NAME_LEN * sizeof(char));
    if (*dest == NULL) {
        HDF_LOGE("%{public}s: out of memory! Item is %{public}s", __func__, item);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (memcpy_s((void *)(*dest), HDF_EFFECT_NAME_LEN, itemName, strlen(itemName)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s effect name fail! Item is %{public}s", __func__, item);
        OsalMemFree((void *)(*dest));
        *dest = NULL;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioEffectParseEffect(const cJSON *effectObj, struct EffectConfigDescriptor *effectDesc)
{
    if (effectObj == NULL || effectDesc == NULL) {
        HDF_LOGE("%{public}s: invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (AudioEffectParseItem(effectObj, "name", &(effectDesc->name)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: parse item %{public}s fail!", __func__, "name");
        return HDF_FAILURE;
    }

    if (AudioEffectParseItem(effectObj, "library", &(effectDesc->library)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: parse item %{public}s fail!", __func__, "library");
        OsalMemFree((void *)effectDesc->name);
        return HDF_FAILURE;
    }

    if (AudioEffectParseItem(effectObj, "effectId", &(effectDesc->effectId)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: parse item %{public}s fail!", __func__, "library");
        OsalMemFree((void *)effectDesc->name);
        OsalMemFree((void *)effectDesc->library);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void AudioEffectReleaseDescs(struct EffectConfigDescriptor *effectDescs, int32_t effectNum)
{
    int32_t i = 0;

    if (effectDescs == NULL || effectNum <= 0 || effectNum > HDF_EFFECT_NUM_MAX) {
        HDF_LOGE("%{public}s: effectDescs is null or effectNum is invalid!", __func__);
        return;
    }

    for (i = 0; i < effectNum; i++) {
        OsalMemFree((void *)effectDescs[i].name);
        OsalMemFree((void *)effectDescs[i].library);
        OsalMemFree((void *)effectDescs[i].effectId);
    }
}

static int32_t AudioEffectGetEffectCfgDescs(cJSON *cJsonObj, const char *item, struct ConfigDescriptor *cfgDesc)
{
    HDF_LOGD("enter to %{public}s", __func__);
    uint32_t effectNum;
    uint32_t i;
    cJSON *effectObj = NULL;
    struct EffectConfigDescriptor *effectDescs = NULL;
    int32_t ret;

    if (cJsonObj == NULL || item == NULL || cfgDesc == NULL) {
        HDF_LOGE("%{public}s: invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    cJSON *effectsObj = cJSON_GetObjectItem(cJsonObj, item);
    if (effectsObj == NULL) {
        HDF_LOGE("%{public}s: get effects failed!", __func__);
        return HDF_FAILURE;
    }

    effectNum = (uint32_t)cJSON_GetArraySize(effectsObj);
    if (effectNum == 0 || effectNum > HDF_EFFECT_NUM_MAX) {
        HDF_LOGE("%{public}s: effectNum invalid, effectNum = %{public}d!", __func__, effectNum);
        return HDF_FAILURE;
    }
    effectDescs = (struct EffectConfigDescriptor *)OsalMemCalloc(effectNum * sizeof(struct EffectConfigDescriptor));
    if (effectDescs == NULL) {
        HDF_LOGE("%{public}s: alloc effectDescs failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    for (i = 0; i < effectNum; i++) {
        effectObj = cJSON_GetArrayItem(effectsObj, i);
        if (effectObj == NULL) {
            HDF_LOGE("%{public}s get effect item fail!", __func__);
            AudioEffectReleaseDescs(effectDescs, i);
            OsalMemFree((void *)effectDescs);
            return HDF_FAILURE;
        }
        ret = AudioEffectParseEffect(effectObj, &effectDescs[i]);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: parse effect[%{public}d] failed, ret = %{public}d", __func__, i, ret);
            AudioEffectReleaseDescs(effectDescs, i);
            OsalMemFree((void *)effectDescs);
            return HDF_FAILURE;
        }
    }
    cfgDesc->effectNum = effectNum;
    cfgDesc->effectCfgDescs = effectDescs;
    HDF_LOGD("%{public}s success", __func__);
    return HDF_SUCCESS;
}

static int32_t AudioEffectParseLibrary(const cJSON *libObj, struct LibraryConfigDescriptor *libDesc)
{
    if (libObj == NULL || libDesc == NULL) {
        HDF_LOGE("%{public}s: invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (AudioEffectParseItem(libObj, "name", &(libDesc->libName)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: parse item %{public}s fail!", __func__, "name");
        return HDF_FAILURE;
    }

    if (AudioEffectParseItem(libObj, "path", &(libDesc->libPath)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: parse item %{public}s fail!", __func__, "path");
        OsalMemFree((void *)libDesc->libName);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void AudioEffectLibraryReleaseDescs(struct LibraryConfigDescriptor *libDescs, int32_t libNum)
{
    int32_t i = 0;

    if (libDescs == NULL || libNum <= 0 || libNum > HDF_EFFECT_LIB_NUM_MAX) {
        HDF_LOGE("%{public}s: libDescs is null or libNum is invalid!", __func__);
        return;
    }

    for (i = 0; i < libNum; i++) {
        OsalMemFree((void *)libDescs[i].libName);
        OsalMemFree((void *)libDescs[i].libPath);
    }
}

static int32_t AudioEffectGetLibraryCfgDescs(cJSON *cJsonObj, const char *item, struct ConfigDescriptor *cfgDesc)
{
    HDF_LOGD("enter to %{public}s", __func__);
    int32_t ret;
    uint32_t i;
    uint32_t libNum;
    cJSON *libObj = NULL;
    struct LibraryConfigDescriptor *libDescs = NULL;
    if (cJsonObj == NULL || item == NULL || cfgDesc == NULL) {
        HDF_LOGE("%{public}s: invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    cJSON *libsObj = cJSON_GetObjectItem(cJsonObj, item);
    if (libsObj == NULL) {
        HDF_LOGE("%{public}s: get libs failed!", __func__);
        return HDF_FAILURE;
    }

    libNum = (uint32_t)cJSON_GetArraySize(libsObj);
    if (libNum == 0 || libNum > HDF_EFFECT_NUM_MAX) {
        HDF_LOGE("%{public}s: libNum invalid, libNum = %{public}d!", __func__, libNum);
        return HDF_FAILURE;
    }
    libDescs = (struct LibraryConfigDescriptor *)OsalMemCalloc(libNum * sizeof(struct LibraryConfigDescriptor));
    if (libDescs == NULL) {
        HDF_LOGE("%{public}s: malloc libDescs failed", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    for (i = 0; i < libNum; i++) {
        libObj = cJSON_GetArrayItem(libsObj, i);
        if (libObj == NULL) {
            HDF_LOGE("%{public}s get library item fail!", __func__);
            AudioEffectLibraryReleaseDescs(libDescs, i);
            OsalMemFree((void *)libDescs);
            return HDF_FAILURE;
        }
        ret = AudioEffectParseLibrary(libObj, &libDescs[i]);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: parse library[%{public}d] failed, ret = %{public}d", __func__, i, ret);
            AudioEffectLibraryReleaseDescs(libDescs, i);
            OsalMemFree((void *)libDescs);
            return HDF_FAILURE;
        }
    }
    cfgDesc->libNum = libNum;
    cfgDesc->libCfgDescs = libDescs;
    HDF_LOGD("%{public}s success", __func__);
    return HDF_SUCCESS;
}

void AudioEffectReleaseCfgDesc(struct ConfigDescriptor *cfgDesc)
{
    if (cfgDesc == NULL) {
        return;
    }

    if (cfgDesc->libCfgDescs != NULL) {
        AudioEffectLibraryReleaseDescs(cfgDesc->libCfgDescs, cfgDesc->libNum);
        OsalMemFree((void *)cfgDesc->libCfgDescs);
    }

    if (cfgDesc->effectCfgDescs != NULL) {
        AudioEffectReleaseDescs(cfgDesc->effectCfgDescs, cfgDesc->effectNum);
        OsalMemFree((void *)cfgDesc->effectCfgDescs);
    }

    OsalMemFree((void *)cfgDesc);
    cfgDesc = NULL;
}

int32_t AudioEffectGetConfigDescriptor(const char *path, struct ConfigDescriptor **cfgDesc)
{
    if (path == NULL || cfgDesc == NULL) {
        HDF_LOGE("%{public}s: invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    cJSON *cJsonObj = GetAudioEffectConfigToJsonObj(path);
    if (cJsonObj == NULL) {
        HDF_LOGE("%{public}s: get cJsonObj failed!", __func__);
        return HDF_FAILURE;
    }

    *cfgDesc = (struct ConfigDescriptor *)OsalMemCalloc(sizeof(struct ConfigDescriptor));
    if (*cfgDesc == NULL) {
        HDF_LOGE("%{public}s: alloc libDescs failed", __func__);
        cJSON_Delete(cJsonObj);
        cJsonObj = NULL;
        return HDF_ERR_MALLOC_FAIL;
    }

    if (AudioEffectGetLibraryCfgDescs(cJsonObj, "libraries", *cfgDesc) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get library config failed", __func__);
        AudioEffectReleaseCfgDesc(*cfgDesc);
        cJSON_Delete(cJsonObj);
        cJsonObj = NULL;
        return HDF_FAILURE;
    }

    if (AudioEffectGetEffectCfgDescs(cJsonObj, "effects", *cfgDesc) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get effect config failed", __func__);
        AudioEffectReleaseCfgDesc(*cfgDesc);
        cJSON_Delete(cJsonObj);
        cJsonObj = NULL;
        return HDF_FAILURE;
    }

    cJSON_Delete(cJsonObj);
    cJsonObj = NULL;
    HDF_LOGD("%{public}s success", __func__);
    return HDF_SUCCESS;
}
