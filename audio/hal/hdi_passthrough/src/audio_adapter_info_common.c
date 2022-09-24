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

#include "audio_adapter_info_common.h"
#include <ctype.h>
#include <limits.h>
#include "cJSON.h"
#include "osal_mem.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_IMPL

#define AUDIO_ADAPTER_CONFIG    HDF_CONFIG_DIR"/audio_adapter.json"
#define ADAPTER_NAME_LEN        32
#define PORT_NAME_LEN           ADAPTER_NAME_LEN
#define SUPPORT_PORT_NUM_MAX    4
#define SUPPORT_PORT_ID_MAX     41
#define CONFIG_FILE_SIZE_MAX    (SUPPORT_ADAPTER_NUM_MAX * 1024 * 2)  // 16KB
#define CONFIG_CHANNEL_COUNT    2 // two channels
#define TIME_BASE_YEAR_1900     1900
#define DECIMAL_SYSTEM          10
#define MAX_ADDR_RECORD_NUM     (SUPPORT_ADAPTER_NUM_MAX * 3)

int32_t g_adapterNum = 0;
struct AudioAdapterDescriptor *g_audioAdapterOut = NULL;
struct AudioAdapterDescriptor *g_audioAdapterDescs = NULL;
static const char *g_adaptersName[SUPPORT_ADAPTER_NUM_MAX] = {NULL};
static const char *g_portsName[SUPPORT_ADAPTER_NUM_MAX][SUPPORT_PORT_NUM_MAX] = {{NULL}};


struct AudioAddrDB g_localAudioAddrList[MAX_ADDR_RECORD_NUM];
bool g_fuzzCheckFlag = true;

void AudioSetFuzzCheckFlag(bool check)
{
    g_fuzzCheckFlag = check;
    return;
}

void AudioAdapterAddrMgrInit()
{
    (void)memset_s(&g_localAudioAddrList, sizeof(g_localAudioAddrList), 0, sizeof(g_localAudioAddrList));
    for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
        g_localAudioAddrList[index].addrType = AUDIO_INVALID_ADDR;
    }
    return;
}

int32_t AudioAddAdapterAddrToList(AudioHandle adapter, const struct AudioAdapterDescriptor *desc)
{
    int pos = MAX_ADDR_RECORD_NUM;
    if (adapter == NULL || desc == NULL || desc->adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapter or desc or desc->adapterName is null!");
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
        if (g_localAudioAddrList[index].adapterName) {
            if (!strcmp(g_localAudioAddrList[index].adapterName, desc->adapterName)) {
                AUDIO_FUNC_LOGE("The adapter has been loaded. Please reselect the adapter!");
                return AUDIO_HAL_ERR_NOTREADY;
            } else {
                continue;
            }
        } else {
            if (pos == MAX_ADDR_RECORD_NUM && (g_localAudioAddrList[index].addrType == AUDIO_INVALID_ADDR)) {
                pos = index;
            }
        }
    }
    if (pos < MAX_ADDR_RECORD_NUM) {
        g_localAudioAddrList[pos].adapterName = desc->adapterName;
        g_localAudioAddrList[pos].addrValue = adapter;
        g_localAudioAddrList[pos].addrType = AUDIO_ADAPTER_ADDR;
        return AUDIO_HAL_SUCCESS;
    }
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

int32_t AudioCheckAdapterAddr(AudioHandle adapter)
{
    if (g_fuzzCheckFlag == false) {
        return AUDIO_HAL_SUCCESS;
    }
    if (adapter != NULL) {
        for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
            if (g_localAudioAddrList[index].addrValue == adapter &&
                g_localAudioAddrList[index].addrType == AUDIO_ADAPTER_ADDR) {
                return AUDIO_HAL_SUCCESS;
            }
        }
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

int32_t AudioDelAdapterAddrFromList(AudioHandle adapter)
{
    if (adapter != NULL) {
        for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
            if (g_localAudioAddrList[index].addrValue == adapter &&
                g_localAudioAddrList[index].addrType == AUDIO_ADAPTER_ADDR) {
                g_localAudioAddrList[index].addrValue = NULL;
                g_localAudioAddrList[index].adapterName = NULL;
                g_localAudioAddrList[index].addrType = AUDIO_INVALID_ADDR;
                return AUDIO_HAL_SUCCESS;
            }
        }
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

int32_t AudioAddRenderAddrToList(AudioHandle render)
{
    if (render != NULL) {
        for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
            if (g_localAudioAddrList[index].addrValue == NULL) {
                g_localAudioAddrList[index].addrValue = render;
                g_localAudioAddrList[index].addrType = AUDIO_RENDER_ADDR;
                return AUDIO_HAL_SUCCESS;
            }
        }
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

int32_t AudioCheckRenderAddr(AudioHandle render)
{
    if (g_fuzzCheckFlag == false) {
        return AUDIO_HAL_SUCCESS;
    }
    if (render != NULL) {
        for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
            if (g_localAudioAddrList[index].addrValue == render &&
                g_localAudioAddrList[index].addrType == AUDIO_RENDER_ADDR) {
                return AUDIO_HAL_SUCCESS;
            }
        }
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

int32_t AudioDelRenderAddrFromList(AudioHandle render)
{
    if (render != NULL) {
        for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
            if (g_localAudioAddrList[index].addrValue == render &&
                g_localAudioAddrList[index].addrType == AUDIO_RENDER_ADDR) {
                g_localAudioAddrList[index].addrValue = NULL;
                g_localAudioAddrList[index].addrType = AUDIO_INVALID_ADDR;
                return AUDIO_HAL_SUCCESS;
            }
        }
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

int32_t AudioAddCaptureAddrToList(AudioHandle capture)
{
    if (capture != NULL) {
        for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
            if (g_localAudioAddrList[index].addrValue == NULL) {
                g_localAudioAddrList[index].addrValue = capture;
                g_localAudioAddrList[index].addrType = AUDIO_CAPTURE_ADDR;
                return AUDIO_HAL_SUCCESS;
            }
        }
    }
    return AUDIO_HAL_ERR_INVALID_OBJECT;
}

int32_t AudioCheckCaptureAddr(AudioHandle capture)
{
    if (g_fuzzCheckFlag == false) {
        return AUDIO_HAL_SUCCESS;
    }
    if (capture != NULL) {
        for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
            if (g_localAudioAddrList[index].addrValue == capture &&
                g_localAudioAddrList[index].addrType == AUDIO_CAPTURE_ADDR) {
                return AUDIO_HAL_SUCCESS;
            }
        }
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    return AUDIO_HAL_ERR_INVALID_PARAM;
}


int32_t AudioDelCaptureAddrFromList(AudioHandle capture)
{
    if (capture != NULL) {
        for (int index = 0; index < MAX_ADDR_RECORD_NUM; index++) {
            if (g_localAudioAddrList[index].addrValue == capture &&
                g_localAudioAddrList[index].addrType == AUDIO_CAPTURE_ADDR) {
                g_localAudioAddrList[index].addrValue = NULL;
                g_localAudioAddrList[index].addrType = AUDIO_INVALID_ADDR;
                return AUDIO_HAL_SUCCESS;
            }
        }
        return AUDIO_HAL_ERR_INVALID_OBJECT;
    }
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

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
        AUDIO_FUNC_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    len = strlen(name);
    if (len == 0) {
        AUDIO_FUNC_LOGE("port name is null!\n");

        return HDF_FAILURE;
    } else if (len >= PORT_NAME_LEN) {
        AUDIO_FUNC_LOGE("port name is too long!\n");

        return HDF_FAILURE;
    } else {
        /* Nothing to do */
    }

    if (strcmp(name, "AIP") && strcmp(name, "AOP") && strcmp(name, "AIOP")) {
        AUDIO_FUNC_LOGE("Incorrect port name: [ %{public}s ]!\n", name);

        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioAdapterCheckName(const char *name)
{
    uint32_t len;

    if (name == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    len = strlen(name);
    if (len == 0) {
        AUDIO_FUNC_LOGE("adapter name is null!\n");

        return HDF_FAILURE;
    } else if (len >= ADAPTER_NAME_LEN) {
        AUDIO_FUNC_LOGE("adapter name is too long!\n");

        return HDF_FAILURE;
    } else {
        /* Nothing to do */
    }

    if (!isalpha(*name++)) { // Names must begin with a letter
        AUDIO_FUNC_LOGE("The adapter name of the illegal!\n");

        return HDF_FAILURE;
    }

    while (*name != '\0') {
        if (*name == '_') {
            name++;
            continue;
        }

        if (!isalnum(*name++)) {
            AUDIO_FUNC_LOGE("The adapter name of the illegal!\n");

            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioAdapterExist(const char *adapterName)
{
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }
    if (g_audioAdapterDescs == NULL || g_adapterNum <= 0 || g_adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("no adapter info");

        return HDF_FAILURE;
    }
    for (int i = 0; i < g_adapterNum; i++) {
        if (strcmp(adapterName, g_audioAdapterDescs[i].adapterName) == 0) {
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("adapterName=%{public}s does not exist!", adapterName);
    return HDF_FAILURE;
}

static void AudioAdapterJudegReleaseDescs(const struct AudioAdapterDescriptor *desc)
{
    uint32_t portIdx;

    if (desc == NULL) {
        AUDIO_FUNC_LOGE("param desc is null!");
        return;
    }

    if (desc->adapterName != NULL) {
        AudioMemFree((void **)&desc->adapterName);
    }

    if (desc->ports != NULL) {
        portIdx = 0;
        if (desc->portNum <= 0 || desc->portNum > SUPPORT_PORT_NUM_MAX) {
            AUDIO_FUNC_LOGE("desc->portNum error!\n");
            AudioMemFree((void **)&desc->ports);

            return;
        }

        while (portIdx < desc->portNum) {
            if (desc->ports[portIdx].portName != NULL) {
                AudioMemFree((void **)&desc->ports[portIdx].portName);
            }
            portIdx++;
        }
        AudioMemFree((void **)&desc->ports);
    }
}

static void AudioAdapterReleaseDescs(const struct AudioAdapterDescriptor *descs, int32_t adapterNum)
{
    int32_t adapterIdx = 0;

    if (descs == NULL || adapterNum <= 0 || adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("descs is null or adapterNum is invalid!");
        return;
    }

    if (adapterNum > g_adapterNum) {
        adapterNum = g_adapterNum;
    }

    while (adapterIdx < adapterNum) {
        AudioAdapterJudegReleaseDescs(&descs[adapterIdx]);
        adapterIdx++;
    }

    AudioMemFree((void **)&descs);
}

static int32_t AudioAdapterGetDir(const char *dir)
{
    if (dir == NULL) {
        AUDIO_FUNC_LOGE("param dir is null!");
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

static int32_t AudioAdaptersGetArraySize(const cJSON *cJsonObj, uint32_t *size)
{
    int adapterArraySize;

    if (cJsonObj == NULL || size == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    /* Follow the new adapterNum by the number of actual parses */
    adapterArraySize = cJSON_GetArraySize(cJsonObj);
    if (adapterArraySize <= 0) {
        AUDIO_FUNC_LOGE("Failed to get JSON array size!\n");

        return HDF_FAILURE;
    }
    *size = (uint32_t)adapterArraySize;

    return HDF_SUCCESS;
}

static int32_t AudioAdapterParsePortGetDir(struct AudioPort *info, const cJSON *port)
{
    if (info == NULL || port == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    cJSON *portDir = NULL;

    portDir = cJSON_GetObjectItem(port, "dir");
    if (portDir == NULL || portDir->valuestring == NULL) {
        AUDIO_FUNC_LOGE("cJSON_GetObjectItem portDir failed!");
        return HDF_FAILURE;
    }
    ret = AudioAdapterGetDir(portDir->valuestring);
    if (ret == HDF_FAILURE) {
        AUDIO_FUNC_LOGE("port dir error! ret = %{public}d", ret);
        return ret;
    }
    info->dir = ret;
    return HDF_SUCCESS;
}

static int32_t AudioAdapterParsePortGetID(struct AudioPort *info, const cJSON *port)
{
    if (info == NULL || port == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t tmpId;
    cJSON *portID = NULL;

    portID = cJSON_GetObjectItem(port, "id");
    if (portID == NULL) {
        AUDIO_FUNC_LOGE("cJSON_GetObjectItem portID failed!");
        return HDF_FAILURE;
    }
    tmpId = portID->valueint;
    if (tmpId < 0 || tmpId > SUPPORT_PORT_ID_MAX) {
        AUDIO_FUNC_LOGE("portID error!\n");
        return HDF_FAILURE;
    }
    info->portId = (uint32_t)tmpId;
    return HDF_SUCCESS;
}

static int32_t AudioAdapterParsePortGetPortName(struct AudioPort *info, const cJSON *port)
{
    if (info == NULL || port == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    cJSON *portName = NULL;

    portName = cJSON_GetObjectItem(port, "name");
    if (portName == NULL || portName->valuestring == NULL) {
        AUDIO_FUNC_LOGE("cJSON_GetObjectItem portName failed!");
        return HDF_FAILURE;
    }
    ret = AudioAdapterCheckPortFlow(portName->valuestring);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Port name error!\n");
        return ret;
    }
    info->portName = (char *)OsalMemCalloc(PORT_NAME_LEN);
    if (info->portName == NULL) {
        AUDIO_FUNC_LOGE("Out of memory\n");

        return HDF_ERR_MALLOC_FAIL;
    }
    ret = memcpy_s((void *)info->portName, PORT_NAME_LEN,
                   portName->valuestring, strlen(portName->valuestring));
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("memcpy_s port name fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioAdapterParsePort(struct AudioPort *info, const cJSON *port)
{
    int32_t ret;
    if (info == NULL || port == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");
        return HDF_ERR_INVALID_PARAM;
    }
    ret = AudioAdapterParsePortGetDir(info, port);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioAdapterParsePortGetDir failed!\n");
        return ret;
    }
    ret = AudioAdapterParsePortGetID(info, port);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioAdapterParsePortGetID failed!\n");
        return ret;
    }
    ret = AudioAdapterParsePortGetPortName(info, port);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioAdapterParsePortGetPortName failed!\n");
        return ret;
    }
    return HDF_SUCCESS;
}

enum AudioAdapterType MatchAdapterType(const char *adapterName, uint32_t portId)
{
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");

        return AUDIO_ADAPTER_MAX;
    }

    if (strncmp(adapterName, PRIMARY, strlen(PRIMARY)) == 0) {
        if (portId >= AUDIO_PRIMARY_ID_MIN && portId <= AUDIO_PRIMARY_ID_MAX) {
            return AUDIO_ADAPTER_PRIMARY;
        }
        return AUDIO_ADAPTER_PRIMARY_EXT;
    } else if (strcmp(adapterName, USB) == 0) {
        return AUDIO_ADAPTER_USB;
    } else if (strcmp(adapterName, A2DP) == 0) {
        return AUDIO_ADAPTER_A2DP;
    } else {
        return AUDIO_ADAPTER_MAX;
    }
}

int32_t AudioAdapterCheckPortId(const char *adapterName, uint32_t portId)
{
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");
        return HDF_ERR_INVALID_PARAM;
    }

    enum AudioAdapterType adapterType = MatchAdapterType(adapterName, portId);
    switch (adapterType) {
        case AUDIO_ADAPTER_PRIMARY:
            if (portId < AUDIO_PRIMARY_ID_MIN || portId > AUDIO_PRIMARY_ID_MAX) {
                AUDIO_FUNC_LOGE("portId is invalid!");
                return HDF_FAILURE;
            }
            break;
        case AUDIO_ADAPTER_PRIMARY_EXT:
            if (portId < AUDIO_PRIMARY_EXT_ID_MIN || portId > AUDIO_PRIMARY_EXT_ID_MAX) {
                AUDIO_FUNC_LOGE("portId is invalid!");
                return HDF_FAILURE;
            }
            break;
        case AUDIO_ADAPTER_USB:
            if (portId < AUDIO_USB_ID_MIN || portId > AUDIO_USB_ID_MAX) {
                AUDIO_FUNC_LOGE("portId is invalid!");
                return HDF_FAILURE;
            }
            break;
        case AUDIO_ADAPTER_A2DP:
            if (portId < AUDIO_A2DP_ID_MIN || portId > AUDIO_A2DP_ID_MAX) {
                AUDIO_FUNC_LOGE("portId is invalid!");
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
    uint32_t i;
    int32_t ret, tmpNum;
    cJSON *adapterPort = NULL;
    uint32_t realSize = 0;
    if (desc == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }
    cJSON *adapterPortNum = cJSON_GetObjectItem(adapter, "portnum");
    if (adapterPortNum == NULL) {
        AUDIO_FUNC_LOGE("cJSON_GetObjectItem portnum failed!");
        return HDF_FAILURE;
    }
    tmpNum = cJSON_GetNumberValue(adapterPortNum);
    if (tmpNum <= 0 || tmpNum > SUPPORT_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("portnum error! tmpNum = %{public}d\n", tmpNum);

        return HDF_FAILURE;
    }
    desc->portNum = (uint32_t)tmpNum;

    cJSON *adapterPorts = cJSON_GetObjectItem(adapter, "port");
    if (adapterPorts == NULL) {
        return HDF_FAILURE;
    }
    ret = AudioAdaptersGetArraySize(adapterPorts, &realSize);
    if (ret != HDF_SUCCESS || realSize != desc->portNum) {
        AUDIO_FUNC_LOGE("realSize = %{public}u, portNum = %{public}u.\n", realSize, desc->portNum);
        return HDF_FAILURE;
    }

    desc->ports = (struct AudioPort *)OsalMemCalloc(desc->portNum * sizeof(struct AudioPort));
    if (desc->ports == NULL) {
        AUDIO_FUNC_LOGE("Out of memory!\n");

        return HDF_ERR_MALLOC_FAIL;
    }
    for (i = 0; i < desc->portNum; i++) {
        adapterPort = cJSON_GetArrayItem(adapterPorts, i);
        if (adapterPort != NULL) {
            ret = AudioAdapterParsePort(&desc->ports[i], adapterPort);
            if (ret != HDF_SUCCESS) {
                return ret;
            }

            ret = AudioAdapterCheckPortId(desc->adapterName, desc->ports[i].portId);
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
        AUDIO_FUNC_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }

    cJSON *adapterName = cJSON_GetObjectItem(adapter, "name");
    if (adapterName == NULL || adapterName->valuestring == NULL) {
        AUDIO_FUNC_LOGE("adapterName or adapterName->valuestring is null!");
        return HDF_FAILURE;
    }
    ret = AudioAdapterCheckName(adapterName->valuestring);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("The Adapter name is incorrect!\n");

        return ret;
    }

    desc->adapterName = (char *)OsalMemCalloc(ADAPTER_NAME_LEN);
    if (desc->adapterName == NULL) {
        AUDIO_FUNC_LOGE("Out of memory!\n");

        return HDF_ERR_MALLOC_FAIL;
    }
    ret = memcpy_s((void *)desc->adapterName, ADAPTER_NAME_LEN,
        adapterName->valuestring, strlen(adapterName->valuestring));
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("memcpy_s adapter name fail!\n");

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
        AUDIO_FUNC_LOGE("fpath is null!");
        return NULL;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(fpath, pathBuf) == NULL) {
        return NULL;
    }
    FILE *fp = fopen(pathBuf, "r");
    if (fp == NULL) {
        AUDIO_FUNC_LOGE("Can not open config file [ %{public}s ].\n", fpath);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("fseek fail!");
        (void)fclose(fp);
        return NULL;
    }
    int32_t jsonStrSize = ftell(fp);
    if (jsonStrSize <= 0) {
        (void)fclose(fp);
        return NULL;
    }
    rewind(fp);
    if (jsonStrSize > CONFIG_FILE_SIZE_MAX) {
        AUDIO_FUNC_LOGE("The configuration file is too large to load!\n");
        (void)fclose(fp);
        return NULL;
    }
    pJsonStr = (char *)OsalMemCalloc((uint32_t)jsonStrSize + 1);
    if (pJsonStr == NULL) {
        AUDIO_FUNC_LOGE("alloc pJsonStr failed!");
        (void)fclose(fp);
        return NULL;
    }
    if (fread(pJsonStr, jsonStrSize, 1, fp) != 1) {
        AUDIO_FUNC_LOGE("read to file fail!");
        (void)fclose(fp);
        AudioMemFree((void **)&pJsonStr);
        return NULL;
    }
    (void)fclose(fp);
    return pJsonStr;
}

cJSON *AudioAdaptersGetConfigToJsonObj(const char *fpath)
{
    char *pJsonStr = AudioAdaptersGetConfig(fpath);
    if (pJsonStr == NULL) {
        AUDIO_FUNC_LOGE("AudioAdaptersGetConfig failed!");
        return NULL;
    }
    cJSON *cJsonObj = cJSON_Parse(pJsonStr);
    if (cJsonObj == NULL) {
        AudioMemFree((void **)&pJsonStr);
        return NULL;
    }
    AudioMemFree((void **)&pJsonStr);
    cJSON *adapterNum = cJSON_GetObjectItem(cJsonObj, "adapterNum");
    if (adapterNum == NULL) {
        AUDIO_FUNC_LOGE("cJSON_GetObjectItem adapterNum failed!");
        cJSON_Delete(cJsonObj);
        return NULL;
    }
    g_adapterNum = adapterNum->valueint;
    if (g_adapterNum <= 0 || g_adapterNum > SUPPORT_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("Adapter number error!\n");
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
        AUDIO_FUNC_LOGE("Invalid parameter!\n");

        return HDF_ERR_INVALID_PARAM;
    }
    if (*descs != NULL) {
        /* Existing content is no longer assigned twice */
        return HDF_SUCCESS;
    }

    *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        adapterNum * sizeof(struct AudioAdapterDescriptor));
    if (*descs == NULL) {
        AUDIO_FUNC_LOGE("alloc g_audioAdapterDescs failed");

        return HDF_ERR_MALLOC_FAIL;
    }

    for (i = 0; i < adapterNum; i++) {
        adapterObj = cJSON_GetArrayItem(adaptersObj, i);
        if (adapterObj != NULL) {
            ret = AudioAdapterParseAdapter(&(*descs)[i], adapterObj);
            if (ret != HDF_SUCCESS) {
                AUDIO_FUNC_LOGE("AudioAdapterParseAdapter failed ret = %{public}d", ret);
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
    int32_t i;
    uint32_t j;
    int32_t adapterNum;
    uint32_t portNum;

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
    int32_t i;
    uint32_t j;
    int32_t adapterCurNum;
    uint32_t portCurNum;

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
int32_t AudioAdaptersSetAdapterVar(cJSON *adaptersObj)
{
    if (adaptersObj == NULL) {
        AUDIO_FUNC_LOGE("adaptersObj is NULL!");
        return HDF_FAILURE;
    }
    if (AudioAdaptersSetAdapter(&g_audioAdapterDescs, g_adapterNum, adaptersObj) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioAdaptersSetAdapter g_audioAdapterDescs is failed!");
        return HDF_FAILURE;
    }
    if (AudioAdaptersSetAdapter(&g_audioAdapterOut, g_adapterNum, adaptersObj) != HDF_SUCCESS) {
        /* g_audioAdapterOut failure also releases g_audioAdapterDescs */
        AUDIO_FUNC_LOGE("AudioAdaptersSetAdapter g_audioAdapterOut is failed!");
        AudioAdapterReleaseDescs(g_audioAdapterDescs, g_adapterNum);
        ClearAdaptersAllName();
        g_audioAdapterDescs = NULL;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioAdaptersForUser(struct AudioAdapterDescriptor **descs, int *size)
{
    uint32_t realSize = 0;
    if (descs == NULL || size == NULL) {
        AUDIO_FUNC_LOGE("param descs or size is null!");
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
        AUDIO_FUNC_LOGE("AudioAdaptersGetConfigToJsonObj failed!");
        return HDF_FAILURE;
    }
    cJSON *adaptersObj = cJSON_GetObjectItem(cJsonObj, "adapters");
    if (adaptersObj == NULL) {
        AUDIO_FUNC_LOGE("cJSON_GetObjectItem adapters failed!");
        cJSON_Delete(cJsonObj);
        return HDF_FAILURE;
    }
    if (g_adapterNum > 0) {
        if (AudioAdaptersGetArraySize(adaptersObj, &realSize) != HDF_SUCCESS || realSize != (uint32_t)g_adapterNum) {
            AUDIO_FUNC_LOGE("realSize = %{public}d, adaptersNum = %{public}d.\n", realSize, g_adapterNum);
            g_adapterNum = 0;
            cJSON_Delete(cJsonObj);
            return HDF_FAILURE;
        }
    }
    if (AudioAdaptersSetAdapterVar(adaptersObj) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioAdaptersSetAdapterVar is failed!");
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

bool ReleaseAudioManagerObjectComm(struct AudioManager *object)
{
    if (object == NULL) {
        AUDIO_FUNC_LOGE("param object is null!");
        return false;
    }

    object->GetAllAdapters = NULL;
    object->LoadAdapter = NULL;
    object->UnloadAdapter = NULL;
    object->ReleaseAudioManagerObject = NULL;

    if (g_audioAdapterDescs != NULL && g_audioAdapterOut != NULL &&
        g_adapterNum > 0 && g_adapterNum <= SUPPORT_ADAPTER_NUM_MAX) {
        AudioAdaptersNamesRepair();
        AudioPortsNamesRepair();
    }

    AudioAdapterReleaseDescs(g_audioAdapterDescs, g_adapterNum);
    AudioAdapterReleaseDescs(g_audioAdapterOut, g_adapterNum);
    g_audioAdapterDescs = NULL;
    g_audioAdapterOut = NULL;
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
    capabilityIndex->formats = &g_formatIdZero;
    capabilityIndex->subPortsNum = 1;
    capabilityIndex->subPorts = (struct AudioSubPortCapability *)OsalMemCalloc(
        capabilityIndex->subPortsNum * sizeof(struct AudioSubPortCapability));
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
        AUDIO_FUNC_LOGE("param formatBits is null!");
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

int32_t BitsToFormat(enum AudioFormat *format, int32_t formatBits)
{
    if (format == NULL) {
        AUDIO_FUNC_LOGE("param format is null!");
        return HDF_FAILURE;
    }
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

int32_t CheckAttrRoute(int32_t param)
{
    if (param < DEEP_BUFF || param > LOW_LATRNCY) {
        AUDIO_FUNC_LOGE("param is invalid!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CheckAttrChannel(uint32_t param)
{
    if (param != 1 && param != 2) { // channel 1 and 2
        AUDIO_FUNC_LOGE("param is invalid!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t TransferRoute(const char *value, int32_t *route)
{
    if (value == NULL || route == NULL) {
        AUDIO_FUNC_LOGE("param value or route is null!");
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    int64_t tempRoute = strtol(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempRoute == LONG_MAX || tempRoute == LONG_MIN)) || (errno != 0 && tempRoute == 0)) {
        AUDIO_FUNC_LOGE("TransferRoute failed!");
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
        AUDIO_FUNC_LOGE("param value or format is null!");
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    int64_t tempFormat = strtol(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempFormat == LONG_MAX || tempFormat == LONG_MIN)) || (errno != 0 && tempFormat == 0)) {
        return HDF_FAILURE;
    }
    enum AudioFormat audioFormat;
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
        AUDIO_FUNC_LOGE("param value or channels is null!");
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    uint64_t tempChannels = strtoul(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempChannels == ULONG_MAX)) || (errno != 0 && tempChannels == 0)) {
        AUDIO_FUNC_LOGE("strtoul failed!");
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
        AUDIO_FUNC_LOGE("param value or frames is null!");
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    uint64_t tempFrames = strtoull(value, &endptr, 10);
    if ((errno == ERANGE && (tempFrames == ULLONG_MAX)) || (errno != 0 && tempFrames == 0)) {
        AUDIO_FUNC_LOGE("strtoull is failed!");
        return HDF_FAILURE;
    } else {
        *frames = tempFrames;
        return HDF_SUCCESS;
    }
}

int32_t TransferSampleRate(const char *value, uint32_t *sampleRate)
{
    if (value == NULL || sampleRate == NULL) {
        AUDIO_FUNC_LOGE("param value or sampleRate is null!");
        return HDF_FAILURE;
    }
    char *endptr = NULL;
    errno = 0;
    uint64_t tempSampleRate = strtoul(value, &endptr, DECIMAL_SYSTEM);
    if ((errno == ERANGE && (tempSampleRate == ULONG_MAX)) || (errno != 0 && tempSampleRate == 0)) {
        AUDIO_FUNC_LOGE("strtoul is failed!");
        return HDF_FAILURE;
    }
    int32_t ret = CheckAttrSamplingRate(tempSampleRate);
    if (ret == 0) {
        *sampleRate = tempSampleRate;
    }
    return ret;
}

int32_t KeyValueListToMap(const char *keyValueList, struct ParamValMap mParamValMap[], int32_t *count)
{
    if (keyValueList == NULL || mParamValMap == NULL || count == NULL) {
        AUDIO_FUNC_LOGE("param keyValueList or mParamValMap or count is null!");
        return HDF_FAILURE;
    }
    int i = 0;
    char *mParaMap[MAP_MAX];
    char buffer[KEY_VALUE_LIST_LEN] = {0};
    int32_t ret = sprintf_s(buffer, KEY_VALUE_LIST_LEN - 1, "%s", keyValueList);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("sprintf_s failed!");
        return HDF_FAILURE;
    }
    char *tempBuf = buffer;
    char *outPtr = NULL;
    char *inPtr = NULL;
    while (i < MAP_MAX) {
        if ((mParaMap[i] = strtok_r(tempBuf, ";", &outPtr)) == NULL) {
            break;
        }
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
    if (keyValueList == NULL || key == NULL || value == NULL) {
        AUDIO_FUNC_LOGE("param is null!");
        return HDF_FAILURE;
    }
    int32_t ret = HDF_FAILURE;
    char strValue[MAP_MAX] = { 0 };
    if (strcmp(key, AUDIO_ATTR_PARAM_ROUTE) == 0) {
        ret = sprintf_s(strValue, sizeof(strValue), "%s=%d;", key, *((int32_t *)value));
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FORMAT) == 0) {
        uint32_t formatBits = 0;
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
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("strcat_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SetExtParam(const char *key, const char *value, struct ExtraParams *mExtraParams)
{
    if (key == NULL || value == NULL || mExtraParams == NULL) {
        AUDIO_FUNC_LOGE("param key or value or mExtraParams is null!");
        return HDF_FAILURE;
    }
    int ret = HDF_FAILURE;
    if (strcmp(key, AUDIO_ATTR_PARAM_ROUTE) == 0) {
        int32_t route;
        if ((ret = TransferRoute(value, &route)) < 0) {
            AUDIO_FUNC_LOGE("TransferRoute failed ! ret = %{public}d\n", ret);
            return HDF_FAILURE;
        }
        mExtraParams->route = route;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FORMAT) == 0) {
        int32_t format = 0;
        if ((ret = TransferFormat(value, &format)) < 0) {
            AUDIO_FUNC_LOGE("TransferFormat failed ! ret = %{public}d\n", ret);
            return HDF_FAILURE;
        }
        mExtraParams->format = format;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_CHANNELS) == 0) {
        uint32_t channels;
        if ((ret = TransferChannels(value, &channels)) < 0) {
            AUDIO_FUNC_LOGE("TransferChannels failed ! ret = %{public}d\n", ret);
            return HDF_FAILURE;
        }
        mExtraParams->channels = channels;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_FRAME_COUNT) == 0) {
        uint64_t frames;
        if ((ret = TransferFrames(value, &frames)) < 0) {
            AUDIO_FUNC_LOGE("TransferFrames failed ! ret = %{public}d\n", ret);
            return HDF_FAILURE;
        }
        mExtraParams->frames = frames;
        mExtraParams->flag = true;
    } else if (strcmp(key, AUDIO_ATTR_PARAM_SAMPLING_RATE) == 0) {
        uint32_t sampleRate = 0;
        if ((ret = TransferSampleRate(value, &sampleRate)) < 0) {
            AUDIO_FUNC_LOGE("TransferSampleRate failed ! ret = %{public}d\n", ret);
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
        AUDIO_FUNC_LOGE("param reasonDesc is null!");
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
    if (currentTime == NULL) {
        AUDIO_FUNC_LOGE("param currentTime is null!");
        return HDF_FAILURE;
    }
    // Get the current time
    char *week[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    time_t timeSec;
    (void)time(&timeSec);
    struct tm *specificTime = localtime(&timeSec);
    if (specificTime == NULL) {
        AUDIO_FUNC_LOGE("localtime failed!");
        return HDF_FAILURE;
    }
    int32_t ret = sprintf_s(currentTime, ERROR_REASON_DESC_LEN - 1, "%d/%d/%d %s %d:%d:%d",
        (TIME_BASE_YEAR_1900 + specificTime->tm_year), (1 + specificTime->tm_mon), specificTime->tm_mday,
        week[specificTime->tm_wday], specificTime->tm_hour, specificTime->tm_min, specificTime->tm_sec);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("sprintf_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioSetExtraParams(const char *keyValueList, int32_t *count,
    struct ExtraParams *mExtraParams, int32_t *sumOk)
{
    if (keyValueList == NULL || count == NULL || mExtraParams == NULL || sumOk == NULL) {
        AUDIO_FUNC_LOGE("param keyValueList or count or mExtraParams or sumOk is null!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct ParamValMap mParamValMap[MAP_MAX];
    int32_t ret = KeyValueListToMap(keyValueList, mParamValMap, count);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Convert to map FAIL!");
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

