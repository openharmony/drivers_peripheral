/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "audio_pathselect.h"
#include "audio_uhdf_log.h"
#include "audio_common.h"
#include "cJSON.h"
#include "osal_mem.h"
#include "securec.h"

#ifdef IDL_MODE
#define HDF_LOG_TAG AUDIO_HDI_IMPL
#else
#define HDF_LOG_TAG HDF_AUDIO_HAL_IMPL
#endif

#define SPEAKER                   "Speaker"
#define HEADPHONES                "Headphones"
#define MIC                       "Mic"
#define HS_MIC                    "MicHs"
#define EARPIECE                  "Earpiece"
#define BLUETOOTH_SCO             "Bluetooth"
#define BLUETOOTH_SCO_HEADSET     "Bluetooth_SCO_Headset"
#define HEADSET                   "Headset"
#define DAUDIO_DEFAULT            "Default"

#define JSON_UNPRINT 1

#define OUTPUT_MASK   0xFFF
#define OUTPUT_OFFSET 12
#define INPUT_MASK    0x80000FF
#define INPUT_OFFSET  27

#define AUDIO_DEV_ON  1
#define AUDIO_DEV_OFF 0

#define HDF_PATH_NUM_MAX (32 * 4)
#define ADM_VALUE_SIZE 4

static cJSON *g_cJsonObj = NULL;

int32_t AudioPathSelGetConfToJsonObj(void)
{
    FILE *fpJson = NULL;
    char *pJsonStr = NULL;
    if (g_cJsonObj != NULL) {
        return HDF_SUCCESS;
    }
    fpJson = fopen(CJSONFILE_CONFIG_PATH, "r");
    if (fpJson == NULL) {
        AUDIO_FUNC_LOGE("open %{pulbic}s fail!", CJSONFILE_CONFIG_PATH);
        return HDF_FAILURE;
    }
    if (fseek(fpJson, 0, SEEK_END) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("fseek fail!");
        (void)fclose(fpJson);
        return HDF_FAILURE;
    }
    int32_t jsonStrSize = ftell(fpJson);
    rewind(fpJson);
    if (jsonStrSize <= 0) {
        (void)fclose(fpJson);
        return HDF_FAILURE;
    }
    pJsonStr = (char *)OsalMemCalloc(jsonStrSize + 1);
    if (pJsonStr == NULL) {
        (void)fclose(fpJson);
        return HDF_FAILURE;
    }
    if (fread(pJsonStr, jsonStrSize, 1, fpJson) != 1) {
        AUDIO_FUNC_LOGE("read to file fail!");
        (void)fclose(fpJson);
        fpJson = NULL;
        OsalMemFree(pJsonStr);
        return HDF_FAILURE;
    }
    (void)fclose(fpJson);
    fpJson = NULL;
#ifndef JSON_UNPRINT
    AUDIO_FUNC_LOGI("pJsonStr = %{public}s", pJsonStr);
#endif
    g_cJsonObj = cJSON_Parse(pJsonStr);
    if (g_cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("cJSON_GetErrorPtr() = %{public}s", cJSON_GetErrorPtr());
        OsalMemFree(pJsonStr);
        return HDF_FAILURE;
    }
    OsalMemFree(pJsonStr);
    return HDF_SUCCESS;
}

static const char *AudioPathSelGetDeviceType(enum AudioPortPin pin)
{
    if (pin < PIN_OUT_SPEAKER || pin > PIN_IN_BLUETOOTH_SCO_HEADSET) {
        return NULL;
    }
    switch (pin) {
        case PIN_OUT_SPEAKER:
        case PIN_OUT_BLUETOOTH_A2DP:
            return SPEAKER;
        case PIN_OUT_HEADSET:
            return HEADSET;
        case PIN_IN_MIC:
            return MIC;
        case PIN_IN_HS_MIC:
            return HS_MIC;
        case PIN_OUT_EARPIECE:
            return EARPIECE;
        case PIN_OUT_BLUETOOTH_SCO:
            return BLUETOOTH_SCO;
        case PIN_IN_BLUETOOTH_SCO_HEADSET:
            return BLUETOOTH_SCO_HEADSET;
        case PIN_OUT_DAUDIO_DEFAULT:
            return DAUDIO_DEFAULT;
        case PIN_OUT_HEADPHONE:
            return HEADPHONES;
        default:
            AUDIO_FUNC_LOGE("UseCase not support!");
            break;
    }
    return NULL;
}

static const char *AudioPathSelGetUseCase(enum AudioCategory type)
{
    static const char *usecaseType[AUDIO_MMAP_NOIRQ + 1] = {
        [AUDIO_IN_MEDIA] = "deep-buffer-playback",
        [AUDIO_IN_COMMUNICATION] = "low-latency-communication",
        [AUDIO_IN_RINGTONE] = "ringtone-playback",
        [AUDIO_IN_CALL] = "voice-call",
        [AUDIO_MMAP_NOIRQ] = "low-latency-noirq-playback",
    };

    if (type < 0 || type > AUDIO_MMAP_NOIRQ) {
        return NULL;
    }
    return usecaseType[type];
}

static int32_t InitDeviceSwitchValue(char **switchValue, cJSON *swVal, int32_t value)
{
    AUDIO_FUNC_LOGI("InitDeviceSwitchValue enter");
    int32_t ret = -1;
#ifdef ALSA_LIB_MODE
    /* alsa Adaptation */
    int32_t len = strlen(swVal->valuestring) + 1;
    *switchValue = (char *)OsalMemCalloc(sizeof(char) * len);
    if (*switchValue == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc failed");
        return HDF_FAILURE;
    }
    ret = strncpy_s(*switchValue, len, swVal->valuestring, len - 1);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
#else
    *switchValue = (char *)OsalMemCalloc(ADM_VALUE_SIZE);
    if (*switchValue == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc failed!");
        return HDF_FAILURE;
    }
    ret = sprintf_s(*switchValue, ADM_VALUE_SIZE, "%d", value);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("sprintf_s failed ret:%{public}d!", ret);
        return HDF_FAILURE;
    }
#endif
    AUDIO_FUNC_LOGI("InitDeviceSwitchValue end switchValue:%{public}s", *switchValue);
    return HDF_SUCCESS;
}

static int32_t SetRenderPathDefaultValue(cJSON *renderSwObj, struct AudioHwRenderParam *renderParam)
{
    if (renderSwObj == NULL || renderParam == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    char *devKey = NULL;
    int32_t renderDevNum;

    renderDevNum = renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    int32_t renderPathNum = cJSON_GetArraySize(renderSwObj);
    if (renderPathNum < 0 || renderPathNum > HDF_PATH_NUM_MAX) {
        AUDIO_FUNC_LOGE("renderPathNum is invalid!");
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < renderPathNum; i++) {
        cJSON *tmpValue = cJSON_GetArrayItem(renderSwObj, i);
        cJSON *renderSwName = tmpValue->child;
        cJSON *renderSwVal = renderSwName->next;
        if (renderSwName->valuestring == NULL) {
            AUDIO_FUNC_LOGE("renderSwName->valuestring is null!");
            return HDF_FAILURE;
        }
        devKey = renderSwName->valuestring;
        (void)memset_s(renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[renderDevNum].deviceSwitch,
            PATHPLAN_LEN, 0, PATHPLAN_LEN);
        int32_t ret =
            strncpy_s(renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[renderDevNum].deviceSwitch,
                PATHPLAN_COUNT, devKey, strlen(devKey) + 1);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("strcpy_s failed!");
            return HDF_FAILURE;
        }
        int32_t len = strlen(renderSwVal->valuestring) + 1;
        renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[renderDevNum].value =
                            (char *)OsalMemCalloc(sizeof(char) * len);
        if (renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[renderDevNum].value == NULL) {
            AUDIO_FUNC_LOGE("OsalMemCalloc failed!");
            return HDF_FAILURE;
        }
        ret = strncpy_s(renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[renderDevNum].value,
            len, renderSwVal->valuestring, len - 1);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("strncpy_s failed!");
            return HDF_FAILURE;
        }
        renderDevNum++;
    }
    renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum = renderDevNum;
    return HDF_SUCCESS;
}

static int32_t SetCapturePathDefaultValue(cJSON *captureSwObj, struct AudioHwCaptureParam *captureParam)
{
    if (captureSwObj == NULL || captureParam == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    char *devKey = NULL;

    int32_t devNum = captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    int32_t pathNum = cJSON_GetArraySize(captureSwObj);
    if (pathNum < 0 || pathNum > HDF_PATH_NUM_MAX) {
        AUDIO_FUNC_LOGE("pathNum is invalid!");
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < pathNum; i++) {
        cJSON *tmpValue = cJSON_GetArrayItem(captureSwObj, i);
        cJSON *captureSwName = tmpValue->child;
        cJSON *captureSwVal = captureSwName->next;
        if (captureSwName->valuestring == NULL) {
            AUDIO_FUNC_LOGE("captureSwName->valuestring is null!");
            return HDF_FAILURE;
        }

        devKey = captureSwName->valuestring;
        (void)memset_s(captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].deviceSwitch,
            PATHPLAN_LEN, 0, PATHPLAN_LEN);
        int32_t ret =
            strncpy_s(captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].deviceSwitch,
                PATHPLAN_COUNT, devKey, strlen(devKey) + 1);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("strcpy_s failed!");
            return HDF_FAILURE;
        }

        int32_t len = strlen(captureSwVal->valuestring) + 1;
        captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].value =
                            (char *)OsalMemCalloc(sizeof(char) * len);
        if (captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].value == NULL) {
            AUDIO_FUNC_LOGE("OsalMemCalloc failed!");
            return HDF_FAILURE;
        }
        ret = strncpy_s(captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].value,
            len, captureSwVal->valuestring, len - 1);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("strncpy_s failed!");
            return HDF_FAILURE;
        }

        devNum++;
    }
    captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum = devNum;
    return HDF_SUCCESS;
}

static int32_t SetRenderPathValue(
    int32_t tpins, cJSON *renderObj, struct AudioHwRenderParam *renderParam, int32_t value)
{
    if (renderObj == NULL || renderParam == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    const char *renderDeviceType = AudioPathSelGetDeviceType(tpins);
    if (renderDeviceType == NULL) {
        AUDIO_FUNC_LOGE("DeviceType not found.");
        return HDF_FAILURE;
    }
    int32_t devNum = renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    AUDIO_FUNC_LOGI("SetRenderPathValue devNum: %{public}d, renderDeviceType: %{public}s.", devNum, renderDeviceType);
    /* pins = 0, parse default value */
    if (strcasecmp(renderDeviceType, renderObj->string) == 0) {
        int32_t pathNum = cJSON_GetArraySize(renderObj);
        if (pathNum < 0 || pathNum > HDF_PATH_NUM_MAX) {
            AUDIO_FUNC_LOGE("pathNum is invalid!");
            return HDF_FAILURE;
        }
        AUDIO_FUNC_LOGI("SetRenderPathValue pathNum: %{public}d.", pathNum);
        for (int32_t i = 0; i < pathNum; i++) {
            cJSON *tmpValue = cJSON_GetArrayItem(renderObj, i);
            cJSON *swName = tmpValue->child;
            if (swName->valuestring == NULL) {
                AUDIO_FUNC_LOGE("ValueString is null!");
                return HDF_FAILURE;
            }
            char *devKey = swName->valuestring;
            (void)memset_s(renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].deviceSwitch,
                PATHPLAN_LEN, 0, PATHPLAN_LEN);
            int32_t ret =
                strncpy_s(renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].deviceSwitch,
                    PATHPLAN_COUNT, devKey, strlen(devKey) + 1);
            if (ret < 0) {
                AUDIO_FUNC_LOGE("strcpy_s failed!");
                return HDF_FAILURE;
            }
            char **switchsValue = &renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].value;
            cJSON *swVal = swName->next;
            ret = InitDeviceSwitchValue(switchsValue, swVal, value);
            if (ret < 0) {
                AUDIO_FUNC_LOGE("InitDeviceSwitchValue failed!");
                return HDF_FAILURE;
            }
            devNum++;
        }
        renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum = devNum;
    }
    return HDF_SUCCESS;
}

static int32_t SetMatchRenderDevicePath(
    int32_t tpins, struct AudioHwRenderParam *renderParam, cJSON *cJsonObj, const char *deviceType, int32_t value)
{
    if (cJsonObj == NULL || renderParam == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    if (strcasecmp(cJsonObj->string, deviceType) == 0) {
        int32_t ret = SetRenderPathValue(tpins, cJsonObj, renderParam, value);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("set value failed!");
            return ret;
        }
    }
    return HDF_SUCCESS;
}

static int32_t SetMatchRenderDefaultDevicePath(struct AudioHwRenderParam *renderParam, cJSON *cJsonObj)
{
    int32_t ret;
    if (cJsonObj == NULL || renderParam == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t i = PIN_OUT_SPEAKER; i <= PIN_OUT_EARPIECE; i = i << 1) {
        const char *deviceType = AudioPathSelGetDeviceType((int32_t)i);
        if (deviceType == NULL) {
            AUDIO_FUNC_LOGE("DeviceType not found.");
            return HDF_FAILURE;
        }
        if (strcasecmp(deviceType, cJsonObj->string) == 0) {
            ret = SetRenderPathDefaultValue(cJsonObj, renderParam);
            if (ret != HDF_SUCCESS) {
                AUDIO_FUNC_LOGE("set default value failed!");
                return ret;
            }
            break;
        }
    }
    return HDF_SUCCESS;
}

static int32_t SetMatchRenderOtherDevicePath(
    int32_t tpins, struct AudioHwRenderParam *renderParam, cJSON *cJsonObj, int32_t value)
{
    int32_t ret;
    if (cJsonObj == NULL || renderParam == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t j = PIN_OUT_SPEAKER; j <= PIN_OUT_EARPIECE; j = j << 1) {
        if ((j & tpins) == j) {
            ret = SetRenderPathValue((int32_t)j, cJsonObj, renderParam, AUDIO_DEV_ON);
            if (ret != HDF_SUCCESS) {
                AUDIO_FUNC_LOGW("set value failed!");
                continue;
            }
        }
    }
    return HDF_SUCCESS;
}

static int32_t AudioRenderParseDevice(struct AudioHwRenderParam *renderParam, cJSON *cJsonObj)
{
    int32_t ret;
    if (cJsonObj == NULL || renderParam == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t pins = renderParam->renderMode.hwInfo.deviceDescript.pins;

    int32_t tpins = pins & OUTPUT_MASK;
    AUDIO_FUNC_LOGI("AudioRenderParseDevice pins: %{public}ud, tpins: %{public}ud", pins, tpins);
    if ((pins >> OUTPUT_OFFSET) != 0) {
        AUDIO_FUNC_LOGE("pins: %d, error!\n", pins);
        return HDF_FAILURE;
    }

    if (strcasecmp(cJsonObj->string, MIC) == 0 || strcasecmp(cJsonObj->string, HS_MIC) == 0 || 
        strcasecmp(cJsonObj->string, BLUETOOTH_SCO_HEADSET) == 0) {
        return HDF_SUCCESS;
    }

    switch (tpins) {
        case PIN_NONE:
            /* pins = 0, parse default value */
            ret = SetMatchRenderDefaultDevicePath(renderParam, cJsonObj);
            break;
        case PIN_OUT_SPEAKER:
        case PIN_OUT_BLUETOOTH_A2DP:
            /* 1.open speaker */
            ret = SetMatchRenderDevicePath(tpins, renderParam, cJsonObj, SPEAKER, AUDIO_DEV_ON);
#ifndef ALSA_LIB_MODE
            /* 2.close headphones */
            ret |= SetMatchRenderDevicePath(PIN_OUT_HEADSET, renderParam, cJsonObj, HEADPHONES, AUDIO_DEV_OFF);
#endif
            break;
        case PIN_OUT_HEADSET:
            /* 1、open headphone */
            ret = SetMatchRenderDevicePath(tpins, renderParam, cJsonObj, HEADPHONES, AUDIO_DEV_ON);
#ifndef ALSA_LIB_MODE
            /* 2、close speaker */
            ret |= SetMatchRenderDevicePath(PIN_OUT_SPEAKER, renderParam, cJsonObj, SPEAKER, AUDIO_DEV_OFF);
#endif
            break;
        case PIN_OUT_EARPIECE:
            /* 1、open earpiece */
            ret = SetMatchRenderDevicePath(tpins, renderParam, cJsonObj, EARPIECE, AUDIO_DEV_ON);
            break;
        case PIN_OUT_BLUETOOTH_SCO:
            /* 1、open bluetooth */
            ret = SetMatchRenderDevicePath(tpins, renderParam, cJsonObj, BLUETOOTH_SCO, AUDIO_DEV_ON);
            break;
        default:
            ret = SetMatchRenderOtherDevicePath(tpins, renderParam, cJsonObj, AUDIO_DEV_ON);
            break;
    }

    return ret;
}

static int32_t AudioRenderParseUsecase(struct AudioHwRenderParam *renderParam, const char *useCase)
{
    /* reset path numbers */
    renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum = 0;

    cJSON *cardNode = cJSON_GetObjectItem(g_cJsonObj, renderParam->renderMode.hwInfo.cardServiceName);
    if (cardNode == NULL) {
        AUDIO_FUNC_LOGE(
            "failed to check item when [%{public}s] gets object!", renderParam->renderMode.hwInfo.cardServiceName);
        return HDF_FAILURE;
    }
    cJSON *cardList = cardNode->child;
    if (cardList == NULL) {
        AUDIO_FUNC_LOGE("no child when [%{public}s] gets object!", renderParam->renderMode.hwInfo.cardServiceName);
        return HDF_FAILURE;
    }

    cJSON *useCaseNode = cJSON_GetObjectItem(cardList, useCase);
    if (useCaseNode == NULL) {
        AUDIO_FUNC_LOGE("failed to check item when [%{public}s] gets object!", useCase);
        return HDF_FAILURE;
    }

    cJSON *useCaseList = useCaseNode->child;
    if (useCaseList == NULL) {
        AUDIO_FUNC_LOGE("no child when [%{public}s] gets object!", useCase);
        return HDF_FAILURE;
    }

    int32_t len = cJSON_GetArraySize(useCaseList);
    if (len < 0 || len > HDF_PATH_NUM_MAX) {
        AUDIO_FUNC_LOGE("len is invalid!");
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < len; i++) {
        cJSON *tmpValue = cJSON_GetArrayItem(useCaseList, i);
        /* Each device in the incoming scene */
        int32_t ret = AudioRenderParseDevice(renderParam, tmpValue);
        if (ret != HDF_SUCCESS) {
            return ret;
        }
    }
    return HDF_SUCCESS;
}

static int32_t AudioPathSelGetPlanRender(struct AudioHwRenderParam *renderParam)
{
    if (renderParam == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    const char *useCase = AudioPathSelGetUseCase(renderParam->frameRenderMode.attrs.type);
    if (useCase == NULL) {
        AUDIO_FUNC_LOGE("useCase not support!");
        return HDF_FAILURE;
    }
    return AudioRenderParseUsecase(renderParam, useCase);
}

static int32_t SetCapturePathValue(
    int32_t tpins, cJSON *captureSwitchObj, struct AudioHwCaptureParam *captureParam, int32_t value)
{
    if (captureParam == NULL || captureSwitchObj == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    const char *captureDeviceType = AudioPathSelGetDeviceType(tpins);
    if (captureDeviceType == NULL) {
        AUDIO_FUNC_LOGE("DeviceType not found.");
        return HDF_FAILURE;
    }

    int32_t devNum = captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (strcasecmp(captureDeviceType, captureSwitchObj->string) == 0) {
        int32_t pathNum = cJSON_GetArraySize(captureSwitchObj);
        if (pathNum < 0 || pathNum > HDF_PATH_NUM_MAX) {
            AUDIO_FUNC_LOGE("pathNum is invalid!");
            return HDF_FAILURE;
        }
        for (int32_t i = 0; i < pathNum; i++) {
            cJSON *captureTmpValue = cJSON_GetArrayItem(captureSwitchObj, i);
            cJSON *swName = captureTmpValue->child;
            if (swName->valuestring == NULL) {
                AUDIO_FUNC_LOGE("ValueString is null!");
                return HDF_FAILURE;
            }

            (void)memset_s(captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].deviceSwitch,
                PATHPLAN_LEN, 0, PATHPLAN_LEN);
            int32_t ret =
                strncpy_s(captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].deviceSwitch,
                    PATHPLAN_COUNT, swName->valuestring, strlen(swName->valuestring) + 1);
            if (ret < 0) {
                AUDIO_FUNC_LOGE("strcpy_s failed!");
                return HDF_FAILURE;
            }
            char **switchsValue = &captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[devNum].value;
            cJSON *swVal = swName->next;
            ret = InitDeviceSwitchValue(switchsValue, swVal, value);
            if (ret < 0) {
                AUDIO_FUNC_LOGE("InitDeviceSwitchValue failed!");
                return HDF_FAILURE;
            }
            devNum++;
        }
        captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum = devNum;
    }
    return HDF_SUCCESS;
}

static int32_t SetMatchCaptureDevicePath(
    struct AudioHwCaptureParam *captureParam, cJSON *cJsonObj, int32_t tpins, char *deviceType, int32_t value)
{
    if (captureParam == NULL || cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    if (strcasecmp(cJsonObj->string, deviceType) == 0) {
        int32_t ret = SetCapturePathValue(tpins, cJsonObj, captureParam, value);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("set value failed!");
            return ret;
        }
    }
    return HDF_SUCCESS;
}

static int32_t SetMatchCaptureDefaultDevicePath(struct AudioHwCaptureParam *captureParam, cJSON *cJsonObj)
{
    int32_t ret;
    if (captureParam == NULL || cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t i = PIN_IN_MIC; i <= PIN_IN_BLUETOOTH_SCO_HEADSET;
         i = (1 << INPUT_OFFSET) | ((i & OUTPUT_MASK) << 1)) {
        const char *deviceType = AudioPathSelGetDeviceType((int32_t)i);
        if (deviceType == NULL) {
            AUDIO_FUNC_LOGE("DeviceType not found.");
            return HDF_FAILURE;
        }

        if (strcasecmp(deviceType, cJsonObj->string) == 0) {
            ret = SetCapturePathDefaultValue(cJsonObj, captureParam);
            if (ret != HDF_SUCCESS) {
                AUDIO_FUNC_LOGE("set default value failed!");
                return ret;
            }
            break;
        }
    }
    return HDF_SUCCESS;
}

static int32_t SetMatchCaptureOtherDevicePath(
    struct AudioHwCaptureParam *captureParam, cJSON *cJsonObj, int32_t tpins, int32_t value)
{
    int32_t ret;
    uint32_t i;
    if (captureParam == NULL || cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    for (i = PIN_IN_MIC; i <= PIN_IN_BLUETOOTH_SCO_HEADSET; i = (1 << INPUT_OFFSET) | ((i & OUTPUT_MASK) << 1)) {
        if ((i & tpins) == i) { /* Select which device to open and get the pin of which device */
            ret = SetCapturePathValue((int32_t)i, cJsonObj, captureParam, value);
            if (ret != HDF_SUCCESS) {
                AUDIO_FUNC_LOGE("set value failed!");
                continue;
            }
        }
    }
    return HDF_SUCCESS;
}

static int32_t AudioCaptureParseDevice(struct AudioHwCaptureParam *captureParam, cJSON *cJsonObj)
{
    int32_t ret;
    if (captureParam == NULL || cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t pins = captureParam->captureMode.hwInfo.deviceDescript.pins;

    if (!((pins >> INPUT_OFFSET) & 0x01)) {
        AUDIO_FUNC_LOGE("pins: %{public}d, error!", pins);
        return HDF_FAILURE;
    }

    if (strcasecmp(cJsonObj->string, SPEAKER) == 0 || strcasecmp(cJsonObj->string, HEADPHONES) == 0 || 
        strcasecmp(cJsonObj->string, EARPIECE) == 0  || strcasecmp(cJsonObj->string, BLUETOOTH_SCO) == 0) {
        return HDF_SUCCESS;
    }

    int32_t tpins = pins & INPUT_MASK;
    switch (tpins) {
        case (1 << INPUT_OFFSET):
            /* pins = 0, parse default value */
            ret = SetMatchCaptureDefaultDevicePath(captureParam, cJsonObj);
            break;
        case PIN_IN_MIC:
            /* 1.open main mic */
            ret = SetMatchCaptureDevicePath(captureParam, cJsonObj, tpins, MIC, AUDIO_DEV_ON);
#ifndef ALSA_LIB_MODE
            /* 2.close headset mic */
            ret |= SetMatchCaptureDevicePath(captureParam, cJsonObj, PIN_IN_HS_MIC, HS_MIC, AUDIO_DEV_OFF);
#endif
            break;
        case PIN_IN_HS_MIC:
            /* 1、open headset mic */
            ret = SetMatchCaptureDevicePath(captureParam, cJsonObj, tpins, HS_MIC, AUDIO_DEV_ON);
#ifndef ALSA_LIB_MODE
            /* 2、close main mic */
            ret |= SetMatchCaptureDevicePath(captureParam, cJsonObj, PIN_IN_MIC, MIC, AUDIO_DEV_OFF);
#endif
            break;
        case PIN_IN_BLUETOOTH_SCO_HEADSET:
            /* 1、open bluetooth sco headset mic */
            ret = SetMatchCaptureDevicePath(captureParam, cJsonObj, tpins, BLUETOOTH_SCO_HEADSET, AUDIO_DEV_ON);
#ifndef ALSA_LIB_MODE
            /* 2、close main mic */
            ret |= SetMatchCaptureDevicePath(captureParam, cJsonObj, PIN_IN_MIC, MIC, AUDIO_DEV_OFF);
            /* 3.close headset mic */
            ret |= SetMatchCaptureDevicePath(captureParam, cJsonObj, PIN_IN_HS_MIC, HS_MIC, AUDIO_DEV_OFF);
#endif
            break;
        default:
            ret = SetMatchCaptureOtherDevicePath(captureParam, cJsonObj, tpins, AUDIO_DEV_ON);
            break;
    }
    return ret;
}

static int32_t AudioCaptureParseUsecase(struct AudioHwCaptureParam *captureParam, const char *useCase)
{
    if (captureParam == NULL || useCase == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_ERR_INVALID_PARAM;
    }
    /* reset path numbers */
    captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum = 0;

    cJSON *cardNode = cJSON_GetObjectItem(g_cJsonObj, captureParam->captureMode.hwInfo.cardServiceName);
    if (cardNode == NULL) {
        AUDIO_FUNC_LOGE(
            "failed to check item when [%{public}s] gets object!", captureParam->captureMode.hwInfo.cardServiceName);
        return HDF_FAILURE;
    }
    cJSON *cardList = cardNode->child;
    if (cardList == NULL) {
        AUDIO_FUNC_LOGE("no child when [%{public}s] gets object!", captureParam->captureMode.hwInfo.cardServiceName);
        return HDF_FAILURE;
    }

    cJSON *useCaseNode = cJSON_GetObjectItem(cardList, useCase);
    if (useCaseNode == NULL) {
        AUDIO_FUNC_LOGE("failed to check item when [%{public}s] gets object!", useCase);
        return HDF_FAILURE;
    }
    cJSON *useCaseList = useCaseNode->child;
    if (useCaseList == NULL) {
        AUDIO_FUNC_LOGE("no child when [%{public}s] gets object!", useCase);
        return HDF_FAILURE;
    }

    int32_t len = cJSON_GetArraySize(useCaseList);
    if (len < 0 || len > HDF_PATH_NUM_MAX) {
        AUDIO_FUNC_LOGE("len is invalid!");
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < len; i++) {
        cJSON *tmpValue = cJSON_GetArrayItem(useCaseList, i);
        int32_t ret = AudioCaptureParseDevice(captureParam, tmpValue);
        if (ret != HDF_SUCCESS) {
            return ret;
        }
    }
    return HDF_SUCCESS;
}

static int32_t AudioPathSelGetPlanCapture(struct AudioHwCaptureParam *captureParam)
{
    enum AudioCategory type = captureParam->frameCaptureMode.attrs.type;

    if (type == AUDIO_IN_RINGTONE) {
        AUDIO_FUNC_LOGE("useCase not support!");
        return HDF_ERR_NOT_SUPPORT;
    }

    if (type == AUDIO_MMAP_NOIRQ) {
        AUDIO_FUNC_LOGE("useCase set as AUDIO_IN_MEDIA");
        type = AUDIO_IN_MEDIA;
    }

    const char *useCase = AudioPathSelGetUseCase(type);
    if (useCase == NULL) {
        AUDIO_FUNC_LOGE("useCase not support!");
        return HDF_FAILURE;
    }

    return AudioCaptureParseUsecase(captureParam, useCase);
}

static int32_t AudioPathSelRenderChkScene(struct AudioHwRenderParam *renderSceneParam)
{
    return AudioPathSelGetPlanRender(renderSceneParam);
}

static int32_t AudioPathSelCaptureChkScene(struct AudioHwCaptureParam *captureSceneParam)
{
    return AudioPathSelGetPlanCapture(captureSceneParam);
}

static void FreeAllDeviceSwitchsValue(struct PathDeviceInfo *deviceInfo)
{
    for (int i = 0; i < HDF_PATH_NUM_MAX; i++) {
        if (deviceInfo != NULL) {
            AudioMemFree((void **)&(deviceInfo->deviceSwitchs[i].value));
        }
    }
}

int32_t AudioPathSelAnalysisJson(const AudioHandle adapterParam, enum AudioAdaptType adaptType)
{
    AUDIO_FUNC_LOGI("AudioPathSelAnalysisJson enter");
    if (adaptType < 0 || adapterParam == NULL) {
        AUDIO_FUNC_LOGE("Param Invaild!");
        return HDF_ERR_INVALID_PARAM;
    }
    struct AudioHwRenderParam *renderParam = NULL;
    struct AudioHwCaptureParam *captureParam = NULL;
    struct AudioHwRenderParam *renderSceneCheck = NULL;
    struct AudioHwCaptureParam *captureScenceCheck = NULL;
    switch (adaptType) {
        case RENDER_PATH_SELECT:
            renderParam = (struct AudioHwRenderParam *)adapterParam;
            if (strcasecmp(renderParam->renderMode.hwInfo.adapterName, USB) == 0 ||
                strcasecmp(renderParam->renderMode.hwInfo.adapterName, HDMI) == 0) {
                return HDF_SUCCESS;
            }
            FreeAllDeviceSwitchsValue(&renderParam->renderMode.hwInfo.pathSelect.deviceInfo);
            return (AudioPathSelGetPlanRender(renderParam));
        case CAPTURE_PATH_SELECT:
            captureParam = (struct AudioHwCaptureParam *)adapterParam;
            if (strcasecmp(captureParam->captureMode.hwInfo.adapterName, USB) == 0 ||
                strcasecmp(captureParam->captureMode.hwInfo.adapterName, HDMI) == 0) {
                return HDF_SUCCESS;
            }
            FreeAllDeviceSwitchsValue(&captureParam->captureMode.hwInfo.pathSelect.deviceInfo);
            return (AudioPathSelGetPlanCapture(captureParam));
        /* Scene is supported */
        case CHECKSCENE_PATH_SELECT:
            renderSceneCheck = (struct AudioHwRenderParam *)adapterParam;
            if (strcasecmp(renderSceneCheck->renderMode.hwInfo.adapterName, USB) == 0 ||
                strcasecmp(renderSceneCheck->renderMode.hwInfo.adapterName, HDMI) == 0) {
                return HDF_SUCCESS;
            }
            FreeAllDeviceSwitchsValue(&renderSceneCheck->renderMode.hwInfo.pathSelect.deviceInfo);
            return (AudioPathSelRenderChkScene(renderSceneCheck));
        case CHECKSCENE_PATH_SELECT_CAPTURE:
            captureScenceCheck = (struct AudioHwCaptureParam *)adapterParam;
            if (strcasecmp(captureScenceCheck->captureMode.hwInfo.adapterName, USB) == 0 ||
                strcasecmp(captureScenceCheck->captureMode.hwInfo.adapterName, HDMI) == 0) {
                return HDF_SUCCESS;
            }
            FreeAllDeviceSwitchsValue(&captureScenceCheck->captureMode.hwInfo.pathSelect.deviceInfo);
            return (AudioPathSelCaptureChkScene(captureScenceCheck));
        default:
            AUDIO_FUNC_LOGE("Path select mode invalid");
            break;
    }
    return HDF_FAILURE;
}
