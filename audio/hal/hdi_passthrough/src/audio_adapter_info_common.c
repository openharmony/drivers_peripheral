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

#include "audio_internal.h"
#include "audio_adapter_info_common.h"
#include "cJSON.h"

#define AUDIO_ADAPTER_CONFIG    "/system/etc/hdfconfig/adapter_config.json"
#define ADAPTER_NAME_LEN        32
#define PORT_NAME_LEN           32
#define CONFIG_SIEZ_MAX         4096
#define CONFIG_CHANNEL_COUNT  2 // two channels


struct AudioAdapterDescriptor *g_audioAdapterOut = NULL;
struct AudioAdapterDescriptor *g_audioAdapterDescs = NULL;
int32_t g_adapterNum = 0;

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

int32_t AudioAdapterExist(const char *adapterName)
{
    if (adapterName == NULL) {
        return HDF_FAILURE;
    }
    if (g_audioAdapterDescs == NULL || g_adapterNum <= 0) {
        LOG_FUN_ERR("no adapter info");
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
    if (desc == NULL) {
        return;
    }
    uint32_t portIdx;
    if (desc->adapterName != NULL) {
        AudioMemFree((void **)&desc->adapterName);
    }
    if (desc->ports != NULL) {
        portIdx = 0;
        while (portIdx < desc->portNum) {
            if (desc->ports[portIdx].portName != NULL) {
                AudioMemFree((void **)&desc->ports[portIdx].portName);
            }
            portIdx++;
        }
        AudioMemFree((void **)&desc->ports);
    }
}

static void AudioAdapterReleaseDescs(struct AudioAdapterDescriptor *descs, int32_t adapterNum)
{
    int32_t adapterIdx = 0;
    if (descs == NULL) {
        return;
    }
    if (adapterNum > g_adapterNum) {
        adapterNum = g_adapterNum;
    }
    if (adapterNum < 0) {
        return;
    }
    while (adapterIdx < adapterNum) {
        AudioAdapterJudegReleaseDescs(&descs[adapterIdx]);
        adapterIdx++;
    }
    AudioMemFree((void **)&descs);
}

static int32_t AudioAdapterGetDir(char *dir)
{
    if (strcmp(dir, "PORT_OUT") == 0) {
        return PORT_OUT;
    } else if (strcmp(dir, "PORT_IN") == 0) {
        return PORT_IN;
    } else if (strcmp(dir, "PORT_OUT_IN") == 0) {
        return PORT_OUT_IN;
    } else {
        return -1;
    }
}

static int32_t AudioAdapterParsePort(struct AudioPort *info, cJSON *port)
{
    int32_t ret;
    cJSON *portDir = NULL;
    cJSON *portID = NULL;
    cJSON *portName = NULL;
    portDir = cJSON_GetObjectItem(port, "dir");
    if (portDir == NULL) {
        return HDF_FAILURE;
    }
    info->dir = AudioAdapterGetDir(portDir->valuestring);
    portID = cJSON_GetObjectItem(port, "id");
    if (portID == NULL) {
        return HDF_FAILURE;
    }
    info->portId = cJSON_GetNumberValue(portID);
    portName = cJSON_GetObjectItem(port, "name");
    if (portName == NULL) {
        return HDF_FAILURE;
    }
    info->portName = (char *)calloc(1, PORT_NAME_LEN);
    if (info->portName == NULL) {
        return -ENOMEM;
    }
    ret = memcpy_s((void *)info->portName, PORT_NAME_LEN,
        portName->valuestring, strlen(portName->valuestring));
    if (ret != EOK) {
        LOG_FUN_ERR("memcpy_s port name fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioAdapterParseAdapter(struct AudioAdapterDescriptor *desc, cJSON *adapter)
{
    uint32_t i;
    int32_t ret;
    cJSON *adapterPort = NULL;
    cJSON *adapterName = cJSON_GetObjectItem(adapter, "name");
    if (adapterName == NULL) {
        return HDF_FAILURE;
    }
    desc->adapterName = (char *)calloc(1, ADAPTER_NAME_LEN);
    if (desc->adapterName == NULL) {
        return -ENOMEM;
    }
    ret = memcpy_s((void *)desc->adapterName, ADAPTER_NAME_LEN,
        adapterName->valuestring, strlen(adapterName->valuestring));
    if (ret != EOK) {
        LOG_FUN_ERR("memcpy_s adapter name fail");
        return HDF_FAILURE;
    }
    cJSON *adapterPortNum = cJSON_GetObjectItem(adapter, "portnum");
    if (adapterPortNum == NULL) {
        return HDF_FAILURE;
    }
    desc->portNum = cJSON_GetNumberValue(adapterPortNum);
    if (desc->portNum == 0) {
        LOG_FUN_ERR("no port info");
        return HDF_FAILURE;
    }
    cJSON *adapterPorts = cJSON_GetObjectItem(adapter, "port");
    if (adapterPorts == NULL) {
        return HDF_FAILURE;
    }
    desc->ports = (struct AudioPort *)calloc(1, desc->portNum * sizeof(struct AudioPort));
    if (desc->ports == NULL) {
        LOG_FUN_ERR("calloc adapterPorts failed");
        return -ENOMEM;
    }
    for (i = 0; i < desc->portNum; i++) {
        adapterPort = cJSON_GetArrayItem(adapterPorts, i);
        if (adapterPort) {
            ret = AudioAdapterParsePort(&desc->ports[i], adapterPort);
            if (ret != HDF_SUCCESS) {
                return HDF_FAILURE;
            }
        }
    }
    return HDF_SUCCESS;
}

cJSON *AudioAdaptersGetConfigToJsonObj(const char *fpath)
{
    char *pJsonStr = NULL;
    if (fpath == NULL) {
        return NULL;
    }
    FILE *fp = fopen(fpath, "r");
    if (fp == NULL) {
        LOG_FUN_ERR("Can not open config file [ %s ].\n", fpath);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    uint32_t jsonStrSize = ftell(fp);
    rewind(fp);
    if (jsonStrSize > CONFIG_SIEZ_MAX) {
        LOG_FUN_ERR("The configuration file is too large to load!\n");
        fclose(fp);
        return NULL;
    }
    pJsonStr = (char *)calloc(1, jsonStrSize);
    if (NULL == pJsonStr) {
        fclose(fp);
        return NULL;
    }
    if (fread(pJsonStr, jsonStrSize, 1, fp) != 1) {
        LOG_FUN_ERR("read to file fail!");
        fclose(fp);
        fp = NULL;
        AudioMemFree((void **)&pJsonStr);
        return NULL;
    }
    fclose(fp);
    cJSON *cJsonObj = cJSON_Parse(pJsonStr);
    if (cJsonObj == NULL) {
        AudioMemFree((void **)&pJsonStr);
        return NULL;
    }
    AudioMemFree((void **)&pJsonStr);
    cJSON *adapterNum = cJSON_GetObjectItem(cJsonObj, "adapterNum");
    if (adapterNum == NULL) {
        cJSON_Delete(cJsonObj);
        return NULL;
    }
    g_adapterNum = cJSON_GetNumberValue(adapterNum);
    if (g_adapterNum == 0) {
        LOG_FUN_ERR("no adapter info");
        cJSON_Delete(cJsonObj);
        return NULL;
    }
    return cJsonObj;
}

static int32_t AudioAdaptersSetAdapter(struct AudioAdapterDescriptor **descs,
    int32_t adapterNum, cJSON *adaptersObj)
{
    int32_t i, ret;
    cJSON *adapterObj = NULL;
    if (adaptersObj == NULL || adapterNum <= 0) {
        return HDF_FAILURE;
    }
    if (*descs != NULL) {
        /* Existing content is no longer assigned twice */
        return HDF_SUCCESS;
    }
    *descs = (struct AudioAdapterDescriptor *)calloc(1,
        adapterNum * sizeof(struct AudioAdapterDescriptor));
    if (*descs == NULL) {
        LOG_FUN_ERR("calloc g_audioAdapterDescs failed");
        return -ENOMEM;
    }
    for (i = 0; i < adapterNum; i++) {
        adapterObj = cJSON_GetArrayItem(adaptersObj, i);
        if (adapterObj) {
            ret = AudioAdapterParseAdapter(&(*descs)[i], adapterObj);
            if (ret != HDF_SUCCESS) {
                AudioAdapterReleaseDescs(*descs, adapterNum);
                return HDF_FAILURE;
            }
        }
    }
    return HDF_SUCCESS;
}

int32_t AudioAdaptersForUser(struct AudioAdapterDescriptor **descs, int *size)
{
    int ret;

    if (descs == NULL || size == NULL) {
        return HDF_FAILURE;
    }
    if (g_audioAdapterDescs != NULL && g_audioAdapterOut != NULL &&
        g_adapterNum > 0) {
        /* Existing content is no longer assigned twice */
        *descs = g_audioAdapterOut;
        *size = g_adapterNum;
        return HDF_SUCCESS;
    }
    cJSON *cJsonObj = AudioAdaptersGetConfigToJsonObj(AUDIO_ADAPTER_CONFIG);
    if (cJsonObj == NULL) {
        LOG_FUN_ERR("cJsonObj is NULL!");
        return HDF_FAILURE;
    }
    cJSON *adaptersObj = cJSON_GetObjectItem(cJsonObj, "adapters");
    if (adaptersObj == NULL) {
        cJSON_Delete(cJsonObj);
        return HDF_FAILURE;
    }
    ret = AudioAdaptersSetAdapter(&g_audioAdapterDescs, g_adapterNum, adaptersObj);
    if (ret != HDF_SUCCESS) {
        g_adapterNum = 0;
        cJSON_Delete(cJsonObj);
        return HDF_FAILURE;
    }
    ret = AudioAdaptersSetAdapter(&g_audioAdapterOut, g_adapterNum, adaptersObj);
    if (ret != HDF_SUCCESS) {
        /* g_audioAdapterOut failure also releases g_audioAdapterDescs */
        AudioAdapterReleaseDescs(g_audioAdapterDescs, g_adapterNum);
        g_adapterNum = 0;
        cJSON_Delete(cJsonObj);
        return HDF_FAILURE;
    }
    *descs = g_audioAdapterOut;
    *size = g_adapterNum;
    cJSON_Delete(cJsonObj);
    return HDF_SUCCESS;
}

static enum AudioFormat g_formatIdZero = AUDIO_FORMAT_PCM_16_BIT;
int32_t HdmiPortInit(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex)
{
    if (capabilityIndex == NULL) {
        LOG_FUN_ERR("capabilityIndex Is NULL");
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
    capabilityIndex->subPorts = (struct AudioSubPortCapability *)calloc(capabilityIndex->subPortsNum,
        sizeof(struct AudioSubPortCapability));
    if (capabilityIndex->subPorts == NULL) {
        LOG_FUN_ERR("capabilityIndex->subPorts is NULL!");
        return HDF_FAILURE;
    }
    capabilityIndex->subPorts->portId = portIndex.portId;
    capabilityIndex->subPorts->desc = portIndex.portName;
    capabilityIndex->subPorts->mask = PORT_PASSTHROUGH_LPCM;
    return HDF_SUCCESS;
}

