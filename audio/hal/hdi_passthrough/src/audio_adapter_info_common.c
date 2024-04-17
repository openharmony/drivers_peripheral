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
#include "audio_uhdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_IMPL

#define ADAPTER_NAME_LEN        32
#define PORT_NAME_LEN           ADAPTER_NAME_LEN
#define SUPPORT_PORT_NUM_MAX    10
#define SUPPORT_PORT_ID_MAX     41
#define CONFIG_FILE_SIZE_MAX    (SUPPORT_ADAPTER_NUM_MAX * 1024 * 2)  // 16KB
#define CONFIG_CHANNEL_COUNT    2 // two channels
#define TIME_BASE_YEAR_1900     1900
#define DECIMAL_SYSTEM          10
#define MAX_ADDR_RECORD_NUM     (SUPPORT_ADAPTER_NUM_MAX * 3)

int32_t g_adapterNum = 0;
struct AudioAdapterDescriptor *g_audioAdapterDescs = NULL;

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

void AudioAdapterReleaseDescs(const struct AudioAdapterDescriptor *descs, int32_t adapterNum)
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
    } else if (strcmp(adapterName, HDMI) == 0) {
        return AUDIO_ADAPTER_HDMI;
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
        case AUDIO_ADAPTER_HDMI:
            if (portId < AUDIO_HDMI_ID_MIN || portId > AUDIO_HDMI_ID_MAX) {
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

bool ReleaseAudioManagerObjectComm(const struct AudioManager *object)
{
    if (object == NULL) {
        AUDIO_FUNC_LOGE("param object is null!");
        return false;
    }

    AudioAdapterReleaseDescs(g_audioAdapterDescs, g_adapterNum);
    g_audioAdapterDescs = NULL;
    g_adapterNum = 0;

    return true;
}

static enum AudioFormat g_formatIdZero = AUDIO_FORMAT_TYPE_PCM_16_BIT;
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
    } else if (portIndex.portId >= AUDIO_HDMI_ID_MIN && portIndex.portId <= AUDIO_HDMI_ID_MAX) {
        capabilityIndex->deviceId = PIN_OUT_HDMI;
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

int32_t BitsToFormat(enum AudioFormat *format, int32_t formatBits)
{
    if (format == NULL) {
        AUDIO_FUNC_LOGE("param format is null!");
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
    if (keyValueList == NULL || listLenth < 0 || key == NULL || value == NULL) {
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
    if (listLenth < (int32_t)strlen(strValue)) {
        AUDIO_FUNC_LOGE("keyValueList length too little!");
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
