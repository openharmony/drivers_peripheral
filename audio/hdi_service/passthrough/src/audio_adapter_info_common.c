/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "audio_adapter_info_common.h"
#include <ctype.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "audio_common.h"
#include "audio_internal.h"
#include "audio_uhdf_log.h"
#include "cJSON.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG AUDIO_HDI_IMPL

#define AUDIO_ADAPTER_CONFIG HDF_CONFIG_DIR "/audio_adapter.json"
#define ADAPTER_NAME_LEN     32
#define PORT_NAME_LEN        ADAPTER_NAME_LEN
#define SUPPORT_PORT_NUM_MAX 4
#define SUPPORT_PORT_ID_MAX  41
#define CONFIG_FILE_SIZE_MAX ((SUPPORT_ADAPTER_NUM_MAX) * 1024 * 2) // 16KB
#define CONFIG_CHANNEL_COUNT 2                                    // two channels
#define TIME_BASE_YEAR_1900  1900
#define DECIMAL_SYSTEM       10
#define MAX_ADDR_RECORD_NUM  ((SUPPORT_ADAPTER_NUM_MAX) * 3)

uint32_t g_adapterNum = 0;
struct AudioAdapterDescriptor *g_audioAdapterDescs = NULL;

struct AudioAdapterDescriptor *AudioAdapterGetConfigDescs(void)
{
    return g_audioAdapterDescs;
}

int32_t AudioAdapterGetAdapterNum(void)
{
    return g_adapterNum;
}

static int32_t AudioAdapterCheckPortFlow(const char *name)
{
    uint32_t len;

    len = strlen(name);
    if (len == 0) {
        AUDIO_FUNC_LOGE("port name is null!");
        return HDF_FAILURE;
    } else if (len >= PORT_NAME_LEN) {
        AUDIO_FUNC_LOGE("port name is too long!");
        return HDF_FAILURE;
    }

    if (strcmp(name, "AIP") != 0 && strcmp(name, "AOP") != 0 && strcmp(name, "AIOP") != 0) {
        AUDIO_FUNC_LOGE("Incorrect port name: [ %{public}s ]!", name);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioAdapterCheckName(const char *name)
{
    uint32_t len;

    len = strlen(name);
    if (len == 0) {
        AUDIO_FUNC_LOGE("adapter name is null!");
        return HDF_FAILURE;
    } else if (len >= ADAPTER_NAME_LEN) {
        AUDIO_FUNC_LOGE("adapter name is too long!");
        return HDF_FAILURE;
    }

    const char *strName = name;
    if (!isalpha(*strName++)) { // Names must begin with a letter
        AUDIO_FUNC_LOGE("The adapter name of the illegal!");
        return HDF_FAILURE;
    }

    while (*strName != '\0') {
        if (*strName == '_') {
            strName++;
            continue;
        }

        if (!isalnum(*strName++)) {
            AUDIO_FUNC_LOGE("The adapter name of the illegal!");
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioAdapterExist(const char *adapterName)
{
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (g_audioAdapterDescs == NULL || g_adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("no adapter info");
        return HDF_FAILURE;
    }

    for (uint32_t i = 0; i < g_adapterNum; i++) {
        if (strcmp(adapterName, g_audioAdapterDescs[i].adapterName) == 0) {
            return i;
        }
    }
    AUDIO_FUNC_LOGE("adapterName=%{public}s does not exist!", adapterName);

    return HDF_FAILURE;
}

static void AudioAdapterJudegReleaseDescs(const struct AudioAdapterDescriptor *desc)
{
    uint32_t portIdx;

    if (desc->adapterName != NULL) {
        AudioMemFree((void **)&desc->adapterName);
    }

    if (desc->ports != NULL) {
        portIdx = 0;
        if (desc->portsLen <= 0 || desc->portsLen > SUPPORT_PORT_NUM_MAX) {
            AUDIO_FUNC_LOGE("desc->portsLen error!");
            AudioMemFree((void **)&desc->ports);
            return;
        }

        while (portIdx < desc->portsLen) {
            if (desc->ports[portIdx].portName != NULL) {
                AudioMemFree((void **)&desc->ports[portIdx].portName);
            }
            portIdx++;
        }
        AudioMemFree((void **)&desc->ports);
    }
}

static void AudioAdapterReleaseDescs(const struct AudioAdapterDescriptor *descs, uint32_t adapterNum)
{
    uint32_t adapterIdx = 0;

    if (descs == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return;
    }

    if (adapterNum > g_adapterNum) {
        adapterNum = g_adapterNum;
    }

    while (adapterIdx < adapterNum) {
        AudioAdapterJudegReleaseDescs(&descs[adapterIdx]);
        adapterIdx++;
    }
}

static int32_t AudioAdapterGetDir(const char *dir)
{
    if (strcmp(dir, "PORT_OUT") == 0) {
        return PORT_OUT;
    } else if (strcmp(dir, "PORT_IN") == 0) {
        return PORT_IN;
    } else if (strcmp(dir, "PORT_OUT_IN") == 0) {
        return PORT_OUT_IN;
    } else {
        return HDF_FAILURE;
    }
}

static int32_t AudioAdaptersGetArraySize(const cJSON *cJsonObj, uint32_t *size)
{
    int adapterArraySize;

    /* Follow the new adapterNum by the number of actual parses */
    adapterArraySize = cJSON_GetArraySize(cJsonObj);
    if (adapterArraySize <= 0) {
        AUDIO_FUNC_LOGE("Failed to get JSON array size!");
        return HDF_FAILURE;
    }
    *size = (uint32_t)adapterArraySize;

    return HDF_SUCCESS;
}

static int32_t AudioAdapterParsePort(struct AudioPort *info, const cJSON *port)
{
    int32_t ret;

    cJSON *portDir = cJSON_GetObjectItem(port, "dir");
    if (portDir == NULL || portDir->valuestring == NULL) {
        AUDIO_FUNC_LOGE("Get dir is error!");
        return HDF_FAILURE;
    }
    ret = AudioAdapterGetDir(portDir->valuestring);
    if (ret == HDF_FAILURE) {
        return ret;
    }
    info->dir = ret;

    cJSON *portID = cJSON_GetObjectItem(port, "id");
    if (portID == NULL) {
        AUDIO_FUNC_LOGE("Get portID error!");
        return HDF_FAILURE;
    }
    int32_t tmpId = portID->valueint;
    if (tmpId < 0 || tmpId > SUPPORT_PORT_ID_MAX) {
        AUDIO_FUNC_LOGE("portID error!");
        return HDF_FAILURE;
    }
    info->portId = (uint32_t)tmpId;

    cJSON *portName = cJSON_GetObjectItem(port, "name");
    if (portName == NULL || portName->valuestring == NULL) {
        AUDIO_FUNC_LOGE("Get portName error");
        return HDF_FAILURE;
    }
    ret = AudioAdapterCheckPortFlow(portName->valuestring);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    info->portName = (char *)OsalMemCalloc(PORT_NAME_LEN);
    if (info->portName == NULL) {
        AUDIO_FUNC_LOGE("Out of memory");
        return HDF_ERR_MALLOC_FAIL;
    }
    ret = memcpy_s((void *)info->portName, PORT_NAME_LEN, portName->valuestring, strlen(portName->valuestring));
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("memcpy_s port name fail");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

enum AudioAdapterType MatchAdapterType(const char *adapterName, uint32_t portId)
{
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return AUDIO_ADAPTER_MAX;
    }

    if (strncmp(adapterName, "primary", strlen("primary")) == 0) {
        if (portId >= AUDIO_PRIMARY_ID_MIN && portId <= AUDIO_PRIMARY_ID_MAX) {
            return AUDIO_ADAPTER_PRIMARY;
        }
        return AUDIO_ADAPTER_PRIMARY_EXT;
    } else if (strcmp(adapterName, "usb") == 0) {
        return AUDIO_ADAPTER_USB;
    } else if (strcmp(adapterName, "a2dp") == 0) {
        return AUDIO_ADAPTER_A2DP;
    } else {
        return AUDIO_ADAPTER_MAX;
    }
}

static int32_t AudioAdapterCheckPortId(const char *adapterName, uint32_t portId)
{
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_ERR_INVALID_PARAM;
    }

    enum AudioAdapterType adapterType = MatchAdapterType(adapterName, portId);
    switch (adapterType) {
        case AUDIO_ADAPTER_PRIMARY:
            if (portId < AUDIO_PRIMARY_ID_MIN || portId > AUDIO_PRIMARY_ID_MAX) {
                return HDF_FAILURE;
            }
            break;
        case AUDIO_ADAPTER_PRIMARY_EXT:
            if (portId < AUDIO_PRIMARY_EXT_ID_MIN || portId > AUDIO_PRIMARY_EXT_ID_MAX) {
                return HDF_FAILURE;
            }
            break;
        case AUDIO_ADAPTER_USB:
            if (portId < AUDIO_USB_ID_MIN || portId > AUDIO_USB_ID_MAX) {
                return HDF_FAILURE;
            }
            break;
        case AUDIO_ADAPTER_A2DP:
            if (portId < AUDIO_A2DP_ID_MIN || portId > AUDIO_A2DP_ID_MAX) {
                return HDF_FAILURE;
            }
            break;
        default:
            AUDIO_FUNC_LOGE("An unsupported adapter type.");
            return HDF_ERR_NOT_SUPPORT;
    }

    return HDF_SUCCESS;
}

static int32_t AudioAdapterParsePorts(struct AudioAdapterDescriptor *desc, const cJSON *adapter)
{
    uint32_t realSize = 0;

    if (desc == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_ERR_INVALID_PARAM;
    }
    cJSON *adapterportsLen = cJSON_GetObjectItem(adapter, "portnum");
    if (adapterportsLen == NULL) {
        AUDIO_FUNC_LOGE("adapterportsLen is NULL");
        return HDF_FAILURE;
    }
    int32_t tmpNum = cJSON_GetNumberValue(adapterportsLen);
    if (tmpNum <= 0 || tmpNum > SUPPORT_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("portsLen error!");
        return HDF_FAILURE;
    }
    desc->portsLen = (uint32_t)tmpNum;
    cJSON *adapterPorts = cJSON_GetObjectItem(adapter, "port");
    if (adapterPorts == NULL) {
        AUDIO_FUNC_LOGE("adapterPorts is NULL!");
        return HDF_FAILURE;
    }
    int32_t ret = AudioAdaptersGetArraySize(adapterPorts, &realSize);
    if (ret != HDF_SUCCESS || realSize != desc->portsLen) {
        AUDIO_FUNC_LOGE("realSize = %{public}d, portsLen = %{public}d.", realSize, desc->portsLen);
        return HDF_FAILURE;
    }
    desc->ports = (struct AudioPort *)OsalMemCalloc(desc->portsLen * sizeof(struct AudioPort));
    if (desc->ports == NULL) {
        AUDIO_FUNC_LOGE("Out of memory!");
        return HDF_ERR_MALLOC_FAIL;
    }
    for (uint32_t i = 0; i < desc->portsLen; i++) {
        cJSON *adapterPort = cJSON_GetArrayItem(adapterPorts, i);
        if (adapterPort != NULL) {
            ret = AudioAdapterParsePort(&desc->ports[i], adapterPort);
            if (ret != HDF_SUCCESS) {
                AUDIO_FUNC_LOGE("AudioAdapterParsePort ret = %{public}d", ret);
                return ret;
            }
            ret = AudioAdapterCheckPortId(desc->adapterName, desc->ports[i].portId);
            if (ret != HDF_SUCCESS) {
                AUDIO_FUNC_LOGE("AudioAdapterCheckPortId ret = %{public}d", ret);
                return ret;
            }
        }
    }
    return HDF_SUCCESS;
}

static int32_t AudioAdapterParseAdapter(struct AudioAdapterDescriptor *desc, const cJSON *adapter)
{
    int32_t ret;

    cJSON *adapterName = cJSON_GetObjectItem(adapter, "name");
    if (adapterName == NULL || adapterName->valuestring == NULL) {
        AUDIO_FUNC_LOGE("adapterName or adapterName's valuestring is null.");
        return HDF_FAILURE;
    }
    ret = AudioAdapterCheckName(adapterName->valuestring);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    desc->adapterName = (char *)OsalMemCalloc(ADAPTER_NAME_LEN);
    if (desc->adapterName == NULL) {
        AUDIO_FUNC_LOGE("Out of memory!");
        return HDF_ERR_MALLOC_FAIL;
    }
    ret = memcpy_s(
        (void *)desc->adapterName, ADAPTER_NAME_LEN, adapterName->valuestring, strlen(adapterName->valuestring));
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("memcpy_s adapter name fail!");
        return HDF_FAILURE;
    }

    ret = AudioAdapterParsePorts(desc, adapter);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioAdapterParsePorts error ret = %{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

static char *AudioAdaptersGetConfig(const char *fpath)
{
    char *pJsonStr = NULL;

    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(fpath, pathBuf) == NULL) {
        AUDIO_FUNC_LOGE("The file path is not realpath!");
        return NULL;
    }
    FILE *fp = fopen(pathBuf, "r");
    if (fp == NULL) {
        AUDIO_FUNC_LOGE("Can not open config file [ %{public}s ].", fpath);
        return NULL;
    }
    (void)fseek(fp, 0, SEEK_END);
    int32_t jsonStrSize = ftell(fp);
    if (jsonStrSize <= 0) {
        AUDIO_FUNC_LOGE("config file size is error!");
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    if (jsonStrSize > CONFIG_FILE_SIZE_MAX) {
        AUDIO_FUNC_LOGE("The configuration file is too large to load!");
        fclose(fp);
        return NULL;
    }
    pJsonStr = (char *)OsalMemCalloc((uint32_t)jsonStrSize + 1);
    if (pJsonStr == NULL) {
        AUDIO_FUNC_LOGE("Out of memory!");
        fclose(fp);
        return NULL;
    }
    if (fread(pJsonStr, jsonStrSize, 1, fp) != 1) {
        AUDIO_FUNC_LOGE("read to file fail!");
        fclose(fp);
        AudioMemFree((void **)&pJsonStr);
        return NULL;
    }
    (void)fclose(fp);
    return pJsonStr;
}

cJSON *AudioAdaptersGetConfigToJsonObj(const char *fpath)
{
    if (fpath == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return NULL;
    }

    char *pJsonStr = AudioAdaptersGetConfig(fpath);
    if (pJsonStr == NULL) {
        return NULL;
    }
    cJSON *cJsonObj = cJSON_Parse(pJsonStr);
    if (cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("cJSON_Parse failed!");
        AudioMemFree((void **)&pJsonStr);
        return NULL;
    }
    AudioMemFree((void **)&pJsonStr);

    cJSON *adapterNum = cJSON_GetObjectItem(cJsonObj, "adapterNum");
    if (adapterNum == NULL) {
        AUDIO_FUNC_LOGE("Get adapter number error!");
        cJSON_Delete(cJsonObj);
        return NULL;
    }
    if (adapterNum->valueint <= 0 || adapterNum->valueint > SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("Adapter number error!");
        cJSON_Delete(cJsonObj);
        return NULL;
    }
    g_adapterNum = (uint32_t)adapterNum->valueint;

    return cJsonObj;
}

static int32_t AudioAdaptersSetAdapter(
    struct AudioAdapterDescriptor *descs, int32_t adapterNum, const cJSON *adaptersObj)
{
    int32_t i;
    int32_t ret;
    cJSON *adapterObj = NULL;

    if (descs == NULL || adaptersObj == NULL || adapterNum <= 0 || adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_ERR_INVALID_PARAM;
    }

    for (i = 0; i < adapterNum; i++) {
        adapterObj = cJSON_GetArrayItem(adaptersObj, i);
        if (adapterObj != NULL) {
            ret = AudioAdapterParseAdapter(&(descs[i]), adapterObj);
            if (ret != HDF_SUCCESS) {
                AudioAdapterReleaseDescs(descs, adapterNum);
                return HDF_FAILURE;
            }
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioAdaptersForUser(struct AudioAdapterDescriptor *descs, const uint32_t *size)
{
    uint32_t realSize = 0;
    if (descs == NULL || size == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_ERR_INVALID_PARAM;
    }
    cJSON *cJsonObj = AudioAdaptersGetConfigToJsonObj(AUDIO_ADAPTER_CONFIG);
    if (cJsonObj == NULL) {
        return HDF_FAILURE;
    }
    cJSON *adaptersObj = cJSON_GetObjectItem(cJsonObj, "adapters");
    if (adaptersObj == NULL) {
        cJSON_Delete(cJsonObj);
        AUDIO_FUNC_LOGE("adaptersObj is NULL!");
        return HDF_FAILURE;
    }
    if (AudioAdaptersGetArraySize(adaptersObj, &realSize) != HDF_SUCCESS || realSize != g_adapterNum) {
        AUDIO_FUNC_LOGE("realSize = %{public}d, adaptersNum = %{public}d.", realSize, g_adapterNum);
        g_adapterNum = 0;
        cJSON_Delete(cJsonObj);
        return HDF_FAILURE;
    }
    if (*size < g_adapterNum) {
        AUDIO_FUNC_LOGE("size < g_adapterNum");
        return HDF_FAILURE;
    }
    if (AudioAdaptersSetAdapter(descs, g_adapterNum, adaptersObj) != HDF_SUCCESS) {
        g_adapterNum = 0;
        cJSON_Delete(cJsonObj);
        return HDF_FAILURE;
    }
    if (g_audioAdapterDescs == NULL) {
        g_audioAdapterDescs =
            (struct AudioAdapterDescriptor *)OsalMemCalloc(g_adapterNum * sizeof(struct AudioAdapterDescriptor));
        if (g_audioAdapterDescs == NULL) {
            AUDIO_FUNC_LOGE("calloc AudioAdapterDescriptor failed");
            g_adapterNum = 0;
            cJSON_Delete(cJsonObj);
            return HDF_ERR_MALLOC_FAIL;
        }
        if (AudioAdaptersSetAdapter(g_audioAdapterDescs, g_adapterNum, adaptersObj) != HDF_SUCCESS) {
            g_adapterNum = 0;
            AudioMemFree((void **)&g_audioAdapterDescs);
            cJSON_Delete(cJsonObj);
            return HDF_FAILURE;
        }
    }
    cJSON_Delete(cJsonObj);
    return HDF_SUCCESS;
}

bool ReleaseAudioManagerObjectComm(struct IAudioManager *object)
{
    if (object == NULL) {
        return false;
    }

    object->GetAllAdapters = NULL;
    object->LoadAdapter = NULL;
    object->UnloadAdapter = NULL;
    object->ReleaseAudioManagerObject = NULL;

    AudioAdapterReleaseDescs(g_audioAdapterDescs, g_adapterNum);
    AudioMemFree((void **)&g_audioAdapterDescs);
    g_adapterNum = 0;

    return true;
}

static enum AudioFormat g_formatIdZero = AUDIO_FORMAT_PCM_16_BIT;

int32_t InitPortForCapabilitySub(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex)
{
    if (capabilityIndex == NULL) {
        AUDIO_FUNC_LOGE("capabilityIndex Is NULL");
        return HDF_FAILURE;
    }
    if (portIndex.portId == 0 || (portIndex.portId > 1 && portIndex.portId <= AUDIO_PRIMARY_ID_MAX)) {
        capabilityIndex->deviceId = PIN_OUT_SPEAKER;
        capabilityIndex->sampleRateMasks = AUDIO_SAMPLE_RATE_MASK_16000;
    } else if (portIndex.portId == 1 ||
        (portIndex.portId >= AUDIO_USB_ID_MIN && portIndex.portId <= AUDIO_USB_ID_MAX)) {
        capabilityIndex->deviceId = PIN_OUT_HEADSET;
        capabilityIndex->sampleRateMasks = AUDIO_SAMPLE_RATE_MASK_16000 | AUDIO_SAMPLE_RATE_MASK_8000;
    } else if (portIndex.portId >= AUDIO_PRIMARY_EXT_ID_MIN && portIndex.portId <= AUDIO_PRIMARY_EXT_ID_MAX) {
        capabilityIndex->deviceId = PIN_OUT_SPEAKER;
        capabilityIndex->sampleRateMasks = AUDIO_SAMPLE_RATE_MASK_16000 | AUDIO_SAMPLE_RATE_MASK_24000;
    } else {
        AUDIO_FUNC_LOGE("The port ID not support!");
        return HDF_ERR_NOT_SUPPORT;
    }
    capabilityIndex->hardwareMode = true;
    capabilityIndex->channelMasks = AUDIO_CHANNEL_STEREO;
    capabilityIndex->channelCount = CONFIG_CHANNEL_COUNT;
    capabilityIndex->deviceType = portIndex.dir;
    capabilityIndex->formatNum = 1;
    capabilityIndex->formatsLen = 1;
    capabilityIndex->formats = &g_formatIdZero;
    capabilityIndex->subPortsLen = 1;
    capabilityIndex->subPorts = (struct AudioSubPortCapability *)OsalMemCalloc(
        capabilityIndex->subPortsLen * sizeof(struct AudioSubPortCapability));
    if (capabilityIndex->subPorts == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null!");
        return HDF_FAILURE;
    }
    capabilityIndex->subPorts->portId = portIndex.portId;
    capabilityIndex->subPorts->desc = portIndex.portName;
    capabilityIndex->subPorts->mask = PORT_PASSTHROUGH_LPCM;
    return HDF_SUCCESS;
}

int32_t FormatToBits(enum AudioFormat format, uint32_t *formatBits)
{
    if (formatBits == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }
    switch (format) {
        case AUDIO_FORMAT_PCM_32_BIT:
            *formatBits = BIT_NUM_32;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_24_BIT:
            *formatBits = BIT_NUM_24;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_16_BIT:
            *formatBits = BIT_NUM_16;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_8_BIT:
            *formatBits = BIT_NUM_8;
            return HDF_SUCCESS;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
}

static int32_t BitsToFormat(enum AudioFormat *format, long formatBits)
{
    switch (formatBits) {
        case BIT_NUM_32:
            *format = AUDIO_FORMAT_PCM_32_BIT;
            return HDF_SUCCESS;
        case BIT_NUM_24:
            *format = AUDIO_FORMAT_PCM_24_BIT;
            return HDF_SUCCESS;
        case BIT_NUM_16:
            *format = AUDIO_FORMAT_PCM_16_BIT;
            return HDF_SUCCESS;
        case BIT_NUM_8:
            *format = AUDIO_FORMAT_PCM_8_BIT;
            return HDF_SUCCESS;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
}

static int32_t CheckAttrRoute(int32_t param)
{
    if (param < DEEP_BUFF || param > LOW_LATRNCY) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t CheckAttrChannel(uint32_t param)
{
    if (param != 1 && param != 2) { // channel 1 and 2
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t TransferRoute(const char *value, int32_t *route)
{
    errno = 0;
    char *endptr = NULL;

    if (value == NULL || route == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    long tempRoute = strtol(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempRoute == LONG_MAX || tempRoute == LONG_MIN)) || (errno != 0 && tempRoute == 0)) {
        return HDF_FAILURE;
    }

    int32_t ret = CheckAttrRoute((int32_t)tempRoute);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    *route = (int32_t)tempRoute;

    return HDF_SUCCESS;
}

static int32_t TransferFormat(const char *value, int32_t *format)
{
    errno = 0;
    char *endptr = NULL;

    if (value == NULL || format == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    long tempFormat = strtol(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempFormat == LONG_MAX || tempFormat == LONG_MIN)) || (errno != 0 && tempFormat == 0)) {
        return HDF_FAILURE;
    }
    enum AudioFormat audioFormat;
    int32_t ret = BitsToFormat(&audioFormat, tempFormat);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("BitsToFormat fail! ret = %{public}d", ret);
        return HDF_FAILURE;
    }
    ret = CheckAttrFormat(audioFormat);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CheckAttrForma fail! ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    *format = audioFormat;
    return HDF_SUCCESS;
}

static int32_t TransferChannels(const char *value, uint32_t *channels)
{
    errno = 0;
    char *endptr = NULL;

    if (value == NULL || channels == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    unsigned long tempChannels = strtoul(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempChannels == ULONG_MAX)) || (errno != 0 && tempChannels == 0)) {
        return HDF_FAILURE;
    }

    if (CheckAttrChannel((uint32_t)tempChannels) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    *channels = (uint32_t)tempChannels;

    return HDF_SUCCESS;
}

static int32_t TransferFrames(const char *value, uint64_t *frames)
{
    errno = 0;
    char *endptr = NULL;

    if (value == NULL || frames == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    uint64_t tempFrames = strtoull(value, &endptr, 10);
    if ((errno == ERANGE && (tempFrames == ULLONG_MAX)) || (errno != 0 && tempFrames == 0)) {
        return HDF_FAILURE;
    }
    *frames = tempFrames;

    return HDF_SUCCESS;
}

static int32_t TransferSampleRate(const char *value, uint32_t *sampleRate)
{
    errno = 0;
    char *endptr = NULL;

    if (value == NULL || sampleRate == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    unsigned long tempSampleRate = strtoul(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempSampleRate == ULONG_MAX)) || (errno != 0 && tempSampleRate == 0)) {
        return HDF_FAILURE;
    }

    if (CheckAttrSamplingRate(tempSampleRate) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    *sampleRate = tempSampleRate;

    return HDF_SUCCESS;
}

static int32_t KeyValueListToMap(const char *keyValueList, struct ParamValMap mParamValMap[], int32_t *count)
{
    int32_t i = 0;
    int32_t ret = 0;
    char *mParaMap[MAP_MAX];
    char *outPtr = NULL;
    char *inPtr = NULL;
    char buffer[KEY_VALUE_LIST_LEN] = {0};

    ret = sprintf_s(buffer, KEY_VALUE_LIST_LEN - 1, "%s", keyValueList);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("sprintf_s failed!");
        return HDF_FAILURE;
    }

    char *tempBuf = buffer;
    while (i < MAP_MAX && ((mParaMap[i] = strtok_r(tempBuf, ";", &outPtr)) != NULL)) {
        tempBuf = mParaMap[i];
        if ((mParaMap[i] = strtok_r(tempBuf, "=", &inPtr)) != NULL) {
            ret = strncpy_s(mParamValMap[i].key, EXTPARAM_LEN - 1, mParaMap[i], strlen(mParaMap[i]) + 1);
            if (ret != EOK) {
                AUDIO_FUNC_LOGE("sprintf_s failed!");
                return HDF_FAILURE;
            }
            tempBuf = NULL;
        }
        if ((mParaMap[i] = strtok_r(tempBuf, "=", &inPtr)) != NULL) {
            ret = strncpy_s(mParamValMap[i].value, EXTPARAM_LEN - 1, mParaMap[i], strlen(mParaMap[i]) + 1);
            if (ret != EOK) {
                AUDIO_FUNC_LOGE("sprintf_s failed!");
                return HDF_FAILURE;
            }
            tempBuf = NULL;
        } else {
            AUDIO_FUNC_LOGE("Has no value!");
            return HDF_FAILURE;
        }
        tempBuf = NULL;
        i++;
    }
    *count = i;
    return HDF_SUCCESS;
}

int32_t AddElementToList(char *keyValueList, int32_t listLenth, const char *key, void *value)
{
    uint32_t formatBits = 0;
    int32_t ret = HDF_FAILURE;
    char strValue[MAP_MAX] = {0};

    if (keyValueList == NULL || key == NULL || value == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    if (strcmp(key, AUDIO_ATTR_PARAM_ROUTE) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%d;", key, *((int32_t *)value));
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FORMAT) == 0) {
        ret = FormatToBits((enum AudioFormat)(*((int32_t *)value)), &formatBits);
        if (ret == 0) {
            ret = sprintf_s(strValue, sizeof(strValue), "%s=%u;", key, formatBits);
        }
    } else if (strcmp(key, AUDIO_ATTR_PARAM_CHANNELS) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%u;", key, *((uint32_t *)value));
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FRAME_COUNT) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%llu;", key, *((uint64_t *)value));
    } else if (strcmp(key, AUDIO_ATTR_PARAM_SAMPLING_RATE) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%u", key, *((uint32_t *)value));
    } else {
        AUDIO_FUNC_LOGE("NO this key correspond value!");
        return HDF_FAILURE;
    }
    if (ret < 0) {
        AUDIO_FUNC_LOGE("sprintf_s failed!");
        return HDF_FAILURE;
    }
    ret = strncat_s(keyValueList, listLenth, strValue, strlen(strValue));
    if (ret < 0) {
        AUDIO_FUNC_LOGE("strcat_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SetExtParam(const char *key, const char *value, struct ExtraParams *mExtraParams)
{
    int ret = HDF_FAILURE;

    if (key == NULL || value == NULL || mExtraParams == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }
    if (strcmp(key, AUDIO_ATTR_PARAM_ROUTE) == 0) {
        int32_t route;
        ret = TransferRoute(value, &route);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->route = route;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FORMAT) == 0) {
        int32_t format;
        ret = TransferFormat(value, &format);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->format = format;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_CHANNELS) == 0) {
        uint32_t channels;
        ret = TransferChannels(value, &channels);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->channels = channels;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FRAME_COUNT) == 0) {
        uint64_t frames;
        ret = TransferFrames(value, &frames);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->frames = frames;
        mExtraParams->flag = true;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_SAMPLING_RATE) == 0) {
        uint32_t sampleRate = 0;
        ret = TransferSampleRate(value, &sampleRate);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->sampleRate = sampleRate;
    } else {
        AUDIO_FUNC_LOGE("NO this key correspond value or value is invalid!");
        return HDF_FAILURE;
    }
    return ret;
}

int32_t GetErrorReason(int reason, char *reasonDesc)
{
    int32_t ret;

    if (reasonDesc == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    switch (reason) {
        case HDF_FAILURE:
            ret = snprintf_s(reasonDesc, ERROR_REASON_DESC_LEN - 1, strlen("NOT SUPPORT") + 1, "%s", "NOT SUPPORT");
            break;
        case HDF_ERR_NOT_SUPPORT:
            ret = snprintf_s(reasonDesc, ERROR_REASON_DESC_LEN - 1, strlen("BUFFER FULL") + 1, "%s", "BUFFER FULL");
            break;
        default:
            ret = snprintf_s(reasonDesc, ERROR_REASON_DESC_LEN - 1, strlen("UNKNOW") + 1, "%s", "UNKNOW");
            break;
    }
    if (ret < 0) {
        AUDIO_FUNC_LOGE("sprintf_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
int32_t GetCurrentTime(char *currentTime)
{
    time_t timeSec;
    int32_t ret = 0;
    char *week[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

    if (currentTime == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return HDF_FAILURE;
    }

    // Get the current time
    (void)time(&timeSec);
    struct tm *specificTime = localtime(&timeSec);
    if (specificTime == NULL) {
        AUDIO_FUNC_LOGE("localtime failed!");
        return HDF_FAILURE;
    }
    ret = sprintf_s(currentTime, ERROR_REASON_DESC_LEN - 1, "%d/%d/%d %s %d:%d:%d",
        (TIME_BASE_YEAR_1900 + specificTime->tm_year), (1 + specificTime->tm_mon), specificTime->tm_mday,
        week[specificTime->tm_wday], specificTime->tm_hour, specificTime->tm_min, specificTime->tm_sec);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("sprintf_s failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioSetExtraParams(const char *keyValueList, int32_t *count, struct ExtraParams *mExtraParams, int32_t *sumOk)
{
    int index = 0;
    struct ParamValMap mParamValMap[MAP_MAX];

    if (keyValueList == NULL || count == NULL || mExtraParams == NULL || sumOk == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    int32_t ret = KeyValueListToMap(keyValueList, mParamValMap, count);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Convert to map FAIL!");
        return AUDIO_ERR_INTERNAL;
    }
    mExtraParams->route = -1;
    mExtraParams->format = -1;
    mExtraParams->channels = 0;
    mExtraParams->frames = 0;
    mExtraParams->sampleRate = 0;
    mExtraParams->flag = false;
    while (index < *count) {
        ret = SetExtParam(mParamValMap[index].key, mParamValMap[index].value, mExtraParams);
        if (ret < 0) {
            return AUDIO_ERR_INTERNAL;
        } else {
            (*sumOk)++;
        }
        index++;
    }
    return AUDIO_SUCCESS;
}

int32_t SetDescParam(
    struct AudioMmapBufferDescripter *desc, FILE *fp, int32_t reqSize, int64_t *fileSize, int32_t *flags)
{
    if (fp == NULL || desc == NULL || fileSize == NULL || flags == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    *flags = desc->isShareable ? MAP_SHARED : MAP_PRIVATE;
    desc->memoryFd = fileno(fp);
    if (desc->memoryFd == -1) {
        AUDIO_FUNC_LOGE("fileno failed, fd is %{public}d", desc->memoryFd);
        return AUDIO_ERR_INTERNAL;
    }

    *fileSize = lseek(desc->memoryFd, 0, SEEK_END);
    if ((int64_t)reqSize > *fileSize) {
        AUDIO_FUNC_LOGE("reqSize is out of file Size!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    desc->memoryAddress = mmap(NULL, reqSize, PROT_READ | PROT_WRITE, *flags, desc->memoryFd, 0);
    if (desc->memoryAddress == NULL || desc->memoryAddress == (void *)(-1)) {
        AUDIO_FUNC_LOGE("AudioRenderReqMmapBuffer mmap FAIL and errno is:%{public}d !", errno);
        return AUDIO_ERR_INTERNAL;
    }

    return AUDIO_SUCCESS;
}
