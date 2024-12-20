/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <cctype>
#include <climits>
#include <hdf_log.h>
#include "audio_internal.h"
#include "cJSON.h"
#include "audio_adapter_info_common.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD000105

namespace OHOS::HDI::Audio_Bluetooth {
constexpr const char *AUDIO_ADAPTER_CONFIG = "/vendor/etc/hdfconfig/a2dp_adapter_config.json";
constexpr int ADAPTER_NAME_LEN = 32;
#define PORT_NAME_LEN           ADAPTER_NAME_LEN
constexpr int SUPPORT_ADAPTER_NUM_MAX = 8;
constexpr int SUPPORT_PORT_NUM_MAX = 3;
constexpr int SUPPORT_PORT_ID_MAX = 18;
constexpr int CONFIG_FILE_SIZE_MAX = (SUPPORT_ADAPTER_NUM_MAX * 1024);  // 8KB
constexpr int CONFIG_CHANNEL_COUNT = 2; // two channels
constexpr int DECIMAL_SYSTEM = 10;

int32_t g_adapterNum = 0;
struct AudioAdapterDescriptor *g_audioAdapterOut = NULL;
struct AudioAdapterDescriptor *g_audioAdapterDescs = NULL;
static const char *g_adaptersName[SUPPORT_ADAPTER_NUM_MAX] = {NULL};
static const char *g_portsName[SUPPORT_ADAPTER_NUM_MAX][SUPPORT_PORT_NUM_MAX] = {{NULL}};

static void ClearAdaptersAllName(void)
{
    int i, j;

    for (i = 0; i < SUPPORT_ADAPTER_NUM_MAX; i++) {
        g_adaptersName[i] = NULL;
        for (j = 0; j < SUPPORT_PORT_NUM_MAX; j++) {
            g_portsName[i][j] = NULL;
        }
    }
}

struct AudioAdapterDescriptor *AudioAdapterGetConfigOut(void)
{
    return g_audioAdapterOut;
}

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

    if (name == NULL) {
        HDF_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    len = strlen(name);
    if (len == 0) {
        HDF_LOGE("port name is null!\n");

        return HDF_FAILURE;
    } else if (len >= PORT_NAME_LEN) {
        HDF_LOGE("port name is too long!\n");

        return HDF_FAILURE;
    } else {
        /* Nothing to do */
    }

    if (strcmp(name, "AIP") && strcmp(name, "AOP") && strcmp(name, "AIOP")) {
        HDF_LOGE("Incorrect port name: [ %s ]!\n", name);

        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioAdapterCheckName(const char *name)
{
    uint32_t len;

    if (name == NULL) {
        HDF_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    len = strlen(name);
    if (len == 0) {
        HDF_LOGE("adapter name is null!\n");

        return HDF_FAILURE;
    } else if (len >= ADAPTER_NAME_LEN) {
        HDF_LOGE("adapter name is too long!\n");

        return HDF_FAILURE;
    } else {
        /* Nothing to do */
    }

    if (!isalpha(*name++)) { // Names must begin with a letter
        HDF_LOGE("The adapter name of the illegal!\n");

        return HDF_FAILURE;
    }

    while (*name != '\0') {
        if (*name == '_') {
            name++;
            continue;
        }

        if (!isalnum(*name++)) {
            HDF_LOGE("The adapter name of the illegal!\n");

            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioAdapterExist(const char *adapterName)
{
    if (adapterName == NULL) {
        HDF_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }
    if (g_audioAdapterDescs == NULL || g_adapterNum <= 0 || g_adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        HDF_LOGE("no adapter info");

        return HDF_FAILURE;
    }
    for (int i = 0; i < g_adapterNum; i++) {
        if (strcmp(adapterName, g_audioAdapterDescs[i].adapterName) == 0) {
            return HDF_SUCCESS;
        }
    }

    return HDF_FAILURE;
}

static void AudioAdapterJudegReleaseDescs(const struct AudioAdapterDescriptor *desc)
{
    uint32_t portIdx;

    if (desc == NULL) {
        return;
    }

    if (desc->adapterName != NULL) {
        AudioMemFree(reinterpret_cast<void **>(const_cast<char **>(&desc->adapterName)));
    }

    if (desc->ports != NULL) {
        portIdx = 0;
        if (desc->portNum <= 0 || desc->portNum > SUPPORT_PORT_NUM_MAX) {
            HDF_LOGE("desc->portNum error!\n");
            AudioMemFree(reinterpret_cast<void **>(const_cast<AudioPort **>(&desc->ports)));

            return;
        }

        while (portIdx < desc->portNum) {
            if (desc->ports[portIdx].portName != NULL) {
                AudioMemFree((void **)&desc->ports[portIdx].portName);
            }
            portIdx++;
        }
        AudioMemFree(reinterpret_cast<void **>(const_cast<AudioPort **>(&desc->ports)));
    }
}

static void AudioAdapterReleaseDescs(const struct AudioAdapterDescriptor *descs, int32_t adapterNum)
{
    int32_t adapterIdx = 0;

    if (descs == NULL || adapterNum <= 0 || adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        return;
    }

    if (adapterNum > g_adapterNum) {
        adapterNum = g_adapterNum;
    }

    while (adapterIdx < adapterNum) {
        AudioAdapterJudegReleaseDescs(&descs[adapterIdx]);
        adapterIdx++;
    }

    AudioMemFree(reinterpret_cast<void **>(const_cast<AudioAdapterDescriptor **>(&descs)));
}

static int32_t AudioAdapterGetDir(const char *dir)
{
    if (dir == NULL) {
        return HDF_FAILURE;
    }
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

static int32_t AudioAdaptersGetArraySize(const cJSON *cJsonObj, int *size)
{
    int adapterArraySize;

    if (cJsonObj == NULL || size == NULL) {
        HDF_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    /* Follow the new adapterNum by the number of actual parses */
    adapterArraySize = cJSON_GetArraySize(cJsonObj);
    if (adapterArraySize <= 0) {
        HDF_LOGE("Failed to get JSON array size!\n");

        return HDF_FAILURE;
    }
    *size = adapterArraySize;

    return HDF_SUCCESS;
}

static int32_t AudioAdapterParsePort(struct AudioPort *info, const cJSON *port)
{
    int32_t ret;
    uint32_t tmpId;
    cJSON *portDir = NULL;
    cJSON *portID = NULL;
    cJSON *portName = NULL;

    if (info == NULL || port == NULL) {
        HDF_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    portDir = cJSON_GetObjectItem(port, "dir");
    if (portDir == NULL || portDir->valuestring == NULL) {
        return HDF_FAILURE;
    }
    ret = AudioAdapterGetDir(portDir->valuestring);
    if (ret == HDF_FAILURE) {
        HDF_LOGE("port dir error!\n");

        return ret;
    }
    info->dir = (AudioPortDirection)ret;

    portID = cJSON_GetObjectItem(port, "id");
    if (portID == NULL) {
        return HDF_FAILURE;
    }
    tmpId = portID->valueint;
    if (tmpId < 0 || tmpId > SUPPORT_PORT_ID_MAX) {
        HDF_LOGE("portID error!\n");

        return HDF_FAILURE;
    }
    info->portId = (uint32_t)tmpId;

    portName = cJSON_GetObjectItem(port, "name");
    if (portName == NULL || portName->valuestring == NULL) {
        return HDF_FAILURE;
    }
    ret = AudioAdapterCheckPortFlow(portName->valuestring);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("Port name error!\n");

        return ret;
    }
    info->portName = static_cast<char *>(calloc(1, PORT_NAME_LEN));
    if (info->portName == NULL) {
        HDF_LOGE("Out of memory\n");

        return HDF_ERR_MALLOC_FAIL;
    }
    ret = memcpy_s(static_cast<void *>(const_cast<char *>(info->portName)), PORT_NAME_LEN,
        portName->valuestring, strlen(portName->valuestring));
    if (ret != EOK) {
        HDF_LOGE("memcpy_s port name fail");

        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioAdapterParsePorts(struct AudioAdapterDescriptor *desc, const cJSON *adapter)
{
    uint32_t i;
    int32_t ret, tmpNum;
    cJSON *adapterPort = NULL;
    int32_t realSize = 0;
    if (desc == NULL || adapter == NULL) {
        HDF_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }
    cJSON *adapterPortNum = cJSON_GetObjectItem(adapter, "portnum");
    if (adapterPortNum == NULL) {
        return HDF_FAILURE;
    }
    tmpNum = cJSON_GetNumberValue(adapterPortNum);
    if (tmpNum <= 0 || tmpNum > SUPPORT_PORT_NUM_MAX) {
        HDF_LOGE("portnum error!\n");

        return HDF_FAILURE;
    }
    desc->portNum = (uint32_t)tmpNum;

    cJSON *adapterPorts = cJSON_GetObjectItem(adapter, "port");
    if (adapterPorts == NULL) {
        return HDF_FAILURE;
    }
    ret = AudioAdaptersGetArraySize(adapterPorts, &realSize);
    if (ret != HDF_SUCCESS || realSize != (int)(desc->portNum)) {
        HDF_LOGE("realSize = %d, portNum = %d.\n", realSize, desc->portNum);
        HDF_LOGE("The defined portnum does not match the actual portnum!\n");

        return HDF_FAILURE;
    }

    desc->ports = reinterpret_cast<struct AudioPort *>(calloc(1, desc->portNum * sizeof(struct AudioPort)));
    if (desc->ports == NULL) {
        HDF_LOGE("Out of memory!\n");

        return HDF_ERR_MALLOC_FAIL;
    }
    for (i = 0; i < desc->portNum; i++) {
        adapterPort = cJSON_GetArrayItem(adapterPorts, i);
        if (adapterPort) {
            ret = AudioAdapterParsePort(&desc->ports[i], adapterPort);
            if (ret != HDF_SUCCESS) {
                return ret;
            }
        }
    }
    return HDF_SUCCESS;
}

static int32_t AudioAdapterParseAdapter(struct AudioAdapterDescriptor *desc,
                                        const cJSON *adapter)
{
    int32_t ret;

    if (desc == NULL || adapter == NULL) {
        HDF_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    cJSON *adapterName = cJSON_GetObjectItem(adapter, "name");
    if (adapterName == NULL || adapterName->valuestring == NULL) {
        return HDF_FAILURE;
    }
    ret = AudioAdapterCheckName(adapterName->valuestring);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("The Adapter name is incorrect!\n");

        return ret;
    }

    desc->adapterName = static_cast<char *>(calloc(1, ADAPTER_NAME_LEN));
    if (desc->adapterName == NULL) {
        HDF_LOGE("Out of memory!\n");

        return HDF_ERR_MALLOC_FAIL;
    }
    ret = memcpy_s(static_cast<void *>(const_cast<char *>(desc->adapterName)), ADAPTER_NAME_LEN,
        adapterName->valuestring, strlen(adapterName->valuestring));
    if (ret != EOK) {
        HDF_LOGE("memcpy_s adapter name fail!\n");

        return HDF_FAILURE;
    }

    ret = AudioAdapterParsePorts(desc, adapter);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    return HDF_SUCCESS;
}

static char *AudioAdaptersGetConfig(const char *fpath)
{
    char *pJsonStr = NULL;

    if (fpath == NULL) {
        /* The file path is bad or unreadable */
        return NULL;
    }
    if (access(fpath, F_OK | R_OK)) {
        return NULL;
    }
    FILE *fp = fopen(fpath, "r");
    if (fp == NULL) {
        HDF_LOGE("Can not open config file [ %s ].\n", fpath);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    int32_t jsonStrSize = ftell(fp);
    if (jsonStrSize <= 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    if (jsonStrSize > CONFIG_FILE_SIZE_MAX) {
        HDF_LOGE("The configuration file is too large to load!\n");
        fclose(fp);
        return NULL;
    }
    pJsonStr = static_cast<char *>(calloc(1, (uint32_t)jsonStrSize));
    if (pJsonStr == NULL) {
        fclose(fp);
        return NULL;
    }
    if (fread(pJsonStr, jsonStrSize, 1, fp) != 1) {
        HDF_LOGE("read to file fail!");
        fclose(fp);
        AudioMemFree(reinterpret_cast<void **>(&pJsonStr));
        return NULL;
    }
    if (fclose(fp) != 0) {
        HDF_LOGE("close fp fail!");
    }
    return pJsonStr;
}

cJSON *AudioAdaptersGetConfigToJsonObj(const char *fpath)
{
    char *pJsonStr = AudioAdaptersGetConfig(fpath);
    if (pJsonStr == NULL) {
        return NULL;
    }
    cJSON *cJsonObj = cJSON_Parse(pJsonStr);
    if (cJsonObj == NULL) {
        AudioMemFree(reinterpret_cast<void **>(&pJsonStr));
        return NULL;
    }
    AudioMemFree(reinterpret_cast<void **>(&pJsonStr));
    cJSON *adapterNum = cJSON_GetObjectItem(cJsonObj, "adapterNum");
    if (adapterNum == NULL) {
        cJSON_Delete(cJsonObj);
        return NULL;
    }
    g_adapterNum = adapterNum->valueint;
    if (g_adapterNum <= 0 || g_adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        HDF_LOGE("Adapter number error!\n");
        cJSON_Delete(cJsonObj);
        return NULL;
    }
    return cJsonObj;
}

static int32_t AudioAdaptersSetAdapter(struct AudioAdapterDescriptor **descs,
    int32_t adapterNum, const cJSON *adaptersObj)
{
    int32_t i, ret;
    cJSON *adapterObj = NULL;

    if (descs == NULL || adaptersObj == NULL ||
        adapterNum <= 0 || adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        HDF_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }
    if (*descs != NULL) {
        /* Existing content is no longer assigned twice */
        return HDF_SUCCESS;
    }

    *descs = reinterpret_cast<struct AudioAdapterDescriptor *>(calloc(1,
        adapterNum * sizeof(struct AudioAdapterDescriptor)));
    if (*descs == NULL) {
        HDF_LOGE("calloc g_audioAdapterDescs failed");

        return HDF_ERR_MALLOC_FAIL;
    }

    for (i = 0; i < adapterNum; i++) {
        adapterObj = cJSON_GetArrayItem(adaptersObj, i);
        if (adapterObj) {
            ret = AudioAdapterParseAdapter(&(*descs)[i], adapterObj);
            if (ret != HDF_SUCCESS) {
                AudioAdapterReleaseDescs(*descs, adapterNum);
                *descs = NULL;

                return HDF_FAILURE;
            }
        }
    }

    return HDF_SUCCESS;
}

static void AudioAdaptersNamesRepair(void)
{
    int i, realNum;

    if (g_audioAdapterOut == NULL ||
        g_audioAdapterDescs == NULL || g_adapterNum <= 0) {
        return;
    }

    realNum = (g_adapterNum < SUPPORT_ADAPTER_NUM_MAX) ? g_adapterNum : SUPPORT_ADAPTER_NUM_MAX;
    for (i = 0; i < realNum; i++) {
        if (g_adaptersName[i] == NULL) {
            return;
        }

        if (strcmp(g_audioAdapterOut[i].adapterName, g_audioAdapterDescs[i].adapterName)) {
            /* Retrieve the location of the port name */
            g_audioAdapterOut[i].adapterName = g_adaptersName[i];
        }
    }
}

static void AudioPortsNamesRepair(void)
{
    int i, j, adapterNum, portNum;

    if (g_audioAdapterOut == NULL ||
        g_audioAdapterDescs == NULL || g_adapterNum <= 0) {
        return;
    }

    adapterNum = (g_adapterNum < SUPPORT_ADAPTER_NUM_MAX) ? g_adapterNum : SUPPORT_ADAPTER_NUM_MAX;
    for (i = 0; i < adapterNum; i++) {
        portNum = (g_audioAdapterOut[i].portNum < SUPPORT_PORT_NUM_MAX) ?
            g_audioAdapterOut[i].portNum : SUPPORT_PORT_NUM_MAX;
        for (j = 0; j < portNum; j++) {
            if (g_portsName[i][j] == NULL) {
                return;
            }
            if (strcmp(g_audioAdapterOut[i].ports[j].portName, g_audioAdapterDescs[i].ports[j].portName)) {
                /* Retrieve the location of the sound card name */
                g_audioAdapterOut[i].ports[j].portName = g_portsName[i][j];
            }
        }
    }
}

static void AudioAdaptersNamesRecord(void)
{
    int i, currentNum;

    if (g_audioAdapterOut == NULL ||
        g_audioAdapterDescs == NULL || g_adapterNum <= 0) {
        return;
    }

    currentNum = (g_adapterNum < SUPPORT_ADAPTER_NUM_MAX) ? g_adapterNum : SUPPORT_ADAPTER_NUM_MAX;
    for (i = 0; i < currentNum; i++) {
        /* Record the location of the sound card name */
        g_adaptersName[i] = g_audioAdapterOut[i].adapterName;
    }
}

static void AudioPortsNamesRecord(void)
{
    int i, j, adapterCurNum, portCurNum;

    if (g_audioAdapterOut == NULL || g_audioAdapterDescs == NULL || g_adapterNum <= 0) {
        return;
    }

    adapterCurNum = (g_adapterNum < SUPPORT_ADAPTER_NUM_MAX) ? g_adapterNum : SUPPORT_ADAPTER_NUM_MAX;
    for (i = 0; i < adapterCurNum; i++) {
        portCurNum = (g_audioAdapterOut[i].portNum < SUPPORT_PORT_NUM_MAX) ?
            g_audioAdapterOut[i].portNum : SUPPORT_PORT_NUM_MAX;
        for (j = 0; j < portCurNum; j++) {
            /* Record the location of the port name */
            g_portsName[i][j] = g_audioAdapterOut[i].ports[j].portName;
        }
    }
}

int32_t AudioAdaptersForUser(struct AudioAdapterDescriptor **descs, int *size)
{
    int32_t realSize = -1;

    if (descs == NULL || size == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_audioAdapterDescs != NULL && g_audioAdapterOut != NULL &&
        g_adapterNum > 0 && g_adapterNum <= SUPPORT_ADAPTER_NUM_MAX) {
        AudioAdaptersNamesRepair();
        AudioPortsNamesRepair();
        /* Existing content is no longer assigned twice */
        *descs = g_audioAdapterOut;
        *size = g_adapterNum;

        return HDF_SUCCESS;
    }
    cJSON *cJsonObj = AudioAdaptersGetConfigToJsonObj(AUDIO_ADAPTER_CONFIG);
    if (cJsonObj == NULL) {
        return HDF_FAILURE;
    }
    cJSON *adaptersObj = cJSON_GetObjectItem(cJsonObj, "adapters");
    if (adaptersObj == NULL) {
        cJSON_Delete(cJsonObj);

        return HDF_FAILURE;
    }
    if (AudioAdaptersGetArraySize(adaptersObj, &realSize) != HDF_SUCCESS || realSize != g_adapterNum) {
        HDF_LOGE("realSize = %d, adaptersNum = %d.\n", realSize, g_adapterNum);
        HDF_LOGE("The defined adaptersnum does not match the actual adapters!\n");
        g_adapterNum = 0;
        cJSON_Delete(cJsonObj);

        return HDF_FAILURE;
    }
    if (AudioAdaptersSetAdapter(&g_audioAdapterDescs, g_adapterNum, adaptersObj) != HDF_SUCCESS) {
        g_adapterNum = 0;
        cJSON_Delete(cJsonObj);

        return HDF_FAILURE;
    }
    if (AudioAdaptersSetAdapter(&g_audioAdapterOut, g_adapterNum, adaptersObj) != HDF_SUCCESS) {
        /* g_audioAdapterOut failure also releases g_audioAdapterDescs */
        AudioAdapterReleaseDescs(g_audioAdapterDescs, g_adapterNum);
        ClearAdaptersAllName();
        g_audioAdapterDescs = NULL;
        g_adapterNum = 0;
        cJSON_Delete(cJsonObj);

        return HDF_FAILURE;
    }
    AudioAdaptersNamesRecord();
    AudioPortsNamesRecord();
    *descs = g_audioAdapterOut;
    *size = g_adapterNum;
    cJSON_Delete(cJsonObj);

    return HDF_SUCCESS;
}

static AudioFormat g_formatIdZero = AUDIO_FORMAT_TYPE_PCM_16_BIT;
int32_t HdmiPortInit(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex)
{
    if (capabilityIndex == NULL) {
        HDF_LOGE("capabilityIndex Is NULL");
        return HDF_FAILURE;
    }
    capabilityIndex->hardwareMode = true;
    capabilityIndex->channelMasks = AUDIO_CHANNEL_STEREO;
    capabilityIndex->channelCount = CONFIG_CHANNEL_COUNT;
    capabilityIndex->deviceType = portIndex.dir;
    capabilityIndex->deviceId = PIN_OUT_SPEAKER;
    capabilityIndex->formatNum = 1;
    capabilityIndex->formats = &g_formatIdZero;
    capabilityIndex->sampleRateMasks = AUDIO_SAMPLE_RATE_MASK_16000 | AUDIO_SAMPLE_RATE_MASK_24000;
    capabilityIndex->subPortsNum = 1;
    capabilityIndex->subPorts = reinterpret_cast<struct AudioSubPortCapability *>(calloc(capabilityIndex->subPortsNum,
        sizeof(struct AudioSubPortCapability)));
    if (capabilityIndex->subPorts == NULL) {
        HDF_LOGE("The pointer is null!");
        return HDF_FAILURE;
    }
    capabilityIndex->subPorts->portId = portIndex.portId;
    capabilityIndex->subPorts->desc = portIndex.portName;
    capabilityIndex->subPorts->mask = PORT_PASSTHROUGH_LPCM;
    return HDF_SUCCESS;
}

int32_t FormatToBits(AudioFormat format, uint32_t *formatBits)
{
    if (formatBits == NULL) {
        return HDF_FAILURE;
    }
    switch (format) {
        case AUDIO_FORMAT_TYPE_PCM_32_BIT:
            *formatBits = BIT_NUM_32;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_TYPE_PCM_24_BIT:
            *formatBits = BIT_NUM_24;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_TYPE_PCM_16_BIT:
            *formatBits = BIT_NUM_16;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_TYPE_PCM_8_BIT:
            *formatBits = BIT_NUM_8;
            return HDF_SUCCESS;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
}

int32_t BitsToFormat(AudioFormat *format, long formatBits)
{
    if (format == NULL) {
        return HDF_FAILURE;
    }
    switch (formatBits) {
        case BIT_NUM_32:
            *format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
            return HDF_SUCCESS;
        case BIT_NUM_24:
            *format = AUDIO_FORMAT_TYPE_PCM_24_BIT;
            return HDF_SUCCESS;
        case BIT_NUM_16:
            *format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
            return HDF_SUCCESS;
        case BIT_NUM_8:
            *format = AUDIO_FORMAT_TYPE_PCM_8_BIT;
            return HDF_SUCCESS;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
}

int32_t CheckAttrRoute(long param)
{
    if (param < DEEP_BUFF || param > LOW_LATRNCY) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CheckAttrChannel(unsigned long param)
{
    if (param != 1 && param != 2) { // channel 1 and 2
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t TransferRoute(const char *value, int32_t *route)
{
    if (value == NULL || route == NULL) {
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    long tempRoute = strtol(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempRoute == LONG_MAX || tempRoute == LONG_MIN)) || (errno != 0 && tempRoute == 0)) {
        return HDF_FAILURE;
    }
    int32_t ret = CheckAttrRoute(tempRoute);
    if (ret == 0) {
        *route = tempRoute;
    }
    return ret;
}

int32_t TransferFormat(const char *value, int32_t *format)
{
    if (value == NULL || format == NULL) {
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    long tempFormat = strtol(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempFormat == LONG_MAX || tempFormat == LONG_MIN)) || (errno != 0 && tempFormat == 0)) {
        return HDF_FAILURE;
    }
    AudioFormat audioFormat;
    int32_t ret = BitsToFormat(&audioFormat, tempFormat);
    if (ret == HDF_SUCCESS) {
        ret = CheckAttrFormat(audioFormat);
        if (ret == 0) {
            *format = audioFormat;
        }
    }
    return ret;
}

int32_t TransferChannels(const char *value, uint32_t *channels)
{
    if (value == NULL || channels == NULL) {
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    unsigned long tempChannels = strtoul(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempChannels == ULONG_MAX)) || (errno != 0 && tempChannels == 0)) {
        return HDF_FAILURE;
    }
    int32_t ret = CheckAttrChannel(tempChannels);
    if (ret == 0) {
        *channels = tempChannels;
    }
    return ret;
}

int32_t TransferFrames(const char *value, uint64_t *frames)
{
    if (value == NULL || frames == NULL) {
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    uint64_t tempFrames = strtoull(value, &endptr, 10);
    if ((errno == ERANGE && (tempFrames == ULLONG_MAX)) || (errno != 0 && tempFrames == 0)) {
        return HDF_FAILURE;
    } else {
        *frames = tempFrames;
        return HDF_SUCCESS;
    }
}

int32_t TransferSampleRate(const char *value, uint32_t *sampleRate)
{
    if (value == NULL || sampleRate == NULL) {
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    unsigned long tempSampleRate = strtoul(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempSampleRate == ULONG_MAX)) || (errno != 0 && tempSampleRate == 0)) {
        return HDF_FAILURE;
    }
    int32_t ret = CheckAttrSamplingRate(tempSampleRate);
    if (ret == 0) {
        *sampleRate = tempSampleRate;
    }
    return ret;
}

#ifdef A2DP_HDI_SERVICE
int32_t TransferA2dpSuspended(const char *value, uint32_t *result)
{
    if (value == NULL || result == NULL) {
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    unsigned long toSuspend = strtoul(value, &endptr, DECIMAL_SYSTEM);
    if (errno == ERANGE) {
        return HDF_FAILURE;
    }
    if (toSuspend != 0 && toSuspend != 1) {
        HDF_LOGE("TransferA2dpSuspended, wrong value");
        return HDF_FAILURE;
    }
    *result = toSuspend;
    return HDF_SUCCESS;
}
#endif

int32_t KeyValueListToMap(const char *keyValueList, struct ParamValMap mParamValMap[], int32_t *count)
{
    if (keyValueList == NULL || mParamValMap == NULL || count == NULL) {
        return HDF_FAILURE;
    }
    int i = 0;
    char *mParaMap[MAP_MAX];
    char buffer[ERROR_REASON_DESC_LEN] = {0};
    errno_t ret = strcpy_s(buffer, ERROR_REASON_DESC_LEN, keyValueList);
    if (ret != EOK) {
        HDF_LOGE("strcpy_s failed!");
        return HDF_FAILURE;
    }
    char *tempBuf = buffer;
    char *outPtr = NULL;
    char *inPtr = NULL;
    while (i < MAP_MAX && ((mParaMap[i] = strtok_r(tempBuf, ";", &outPtr)) != NULL)) {
        tempBuf = mParaMap[i];
        if ((mParaMap[i] = strtok_r(tempBuf, "=", &inPtr)) != NULL) {
            ret = strncpy_s(mParamValMap[i].key, EXTPARAM_LEN - 1, mParaMap[i], strlen(mParaMap[i]) + 1);
            if (ret != 0) {
                return HDF_FAILURE;
            }
            tempBuf = NULL;
        }
        if ((mParaMap[i] = strtok_r(tempBuf, "=", &inPtr)) != NULL) {
            ret = strncpy_s(mParamValMap[i].value, EXTPARAM_LEN - 1, mParaMap[i], strlen(mParaMap[i]) + 1);
            if (ret != 0) {
                return HDF_FAILURE;
            }
            tempBuf = NULL;
        }
        tempBuf = NULL;
        i++;
    }
    *count = i;
    return HDF_SUCCESS;
}

int32_t AddElementToList(char *keyValueList, int32_t listLenth, const char *key, void *value)
{
    if (keyValueList == NULL || key == NULL || value == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret = HDF_FAILURE;
    char strValue[MAP_MAX] = { 0 };
    if (strcmp(key, AUDIO_ATTR_PARAM_ROUTE) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%d;", key, *(reinterpret_cast<int32_t *>(value)));
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FORMAT) == 0) {
        uint32_t formatBits = 0;
        ret = FormatToBits((AudioFormat)(*(reinterpret_cast<int32_t *>(value))), &formatBits);
        if (ret == 0) {
            ret = sprintf_s(strValue, sizeof(strValue), "%s=%u;", key, formatBits);
        }
    } else if (strcmp(key, AUDIO_ATTR_PARAM_CHANNELS) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%u;", key, *(reinterpret_cast<uint32_t *>(value)));
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FRAME_COUNT) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%llu;", key, *(reinterpret_cast<uint64_t *>(value)));
    } else if (strcmp(key, AUDIO_ATTR_PARAM_SAMPLING_RATE) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%u", key, *(reinterpret_cast<uint32_t *>(value)));
    } else {
        HDF_LOGE("NO this key correspond value!");
        return HDF_FAILURE;
    }
    if (ret < 0) {
        HDF_LOGE("sprintf_s failed!");
        return HDF_FAILURE;
    }
    ret = strncat_s(keyValueList, listLenth, strValue, strlen(strValue));
    if (ret < 0) {
        HDF_LOGE("strcat_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SetExtParam(const char *key, const char *value, struct ExtraParams *mExtraParams)
{
    if (key == NULL || value == NULL || mExtraParams == NULL) {
        return HDF_FAILURE;
    }
    HDF_LOGI("SetExtParam, key is:%{public}s", key);
    int ret = HDF_FAILURE;
#ifdef A2DP_HDI_SERVICE
    if (strcmp(key, A2DP_SUSPEND) == 0) {
        uint32_t result = 0;
        ret = TransferA2dpSuspended(value, &result);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->audioStreamCtl = result;
    }
#endif
    if (strcmp(key, AUDIO_ATTR_PARAM_ROUTE) == 0) {
        int32_t route = 0;
        ret = TransferRoute(value, &route);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->route = route;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FORMAT) == 0) {
        int32_t format = 0;
        ret = TransferFormat(value, &format);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->format = format;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_CHANNELS) == 0) {
        uint32_t channels = 0;
        ret = TransferChannels(value, &channels);
        if (ret < 0) {
            return HDF_FAILURE;
        }
        mExtraParams->channels = channels;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FRAME_COUNT) == 0) {
        uint64_t frames = 0;
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
        HDF_LOGE("NO this key correspond value or value is invalid!");
        return HDF_FAILURE;
    }
    return ret;
}

int32_t GetErrorReason(int reason, char *reasonDesc)
{
    int32_t ret;
    if (reasonDesc == NULL) {
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
        HDF_LOGE("sprintf_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioSetExtraParams(const char *keyValueList, int32_t *count,
    struct ExtraParams *mExtraParams, int32_t *sumOk)
{
    if (keyValueList == NULL || count == NULL || mExtraParams == NULL || sumOk == NULL) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct ParamValMap mParamValMap[MAP_MAX];
    int32_t ret = KeyValueListToMap(keyValueList, mParamValMap, count);
    if (ret < 0) {
        HDF_LOGE("Convert to map FAIL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int index = 0;
    mExtraParams->route = -1;
    mExtraParams->format = -1;
    mExtraParams->channels = 0;
    mExtraParams->frames = 0;
    mExtraParams->sampleRate = 0;
    mExtraParams->flag = false;
    while (index < *count) {
        ret = SetExtParam(mParamValMap[index].key, mParamValMap[index].value, mExtraParams);
        if (ret < 0) {
            return AUDIO_HAL_ERR_INTERNAL;
        } else {
            (*sumOk)++;
        }
        index++;
    }
    return AUDIO_HAL_SUCCESS;
}
}
