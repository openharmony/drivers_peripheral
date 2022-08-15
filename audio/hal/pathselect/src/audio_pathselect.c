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

#include "audio_pathselect.h"
#include "osal_mem.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_IMPL

#define SPEAKER     "Speaker"
#define HEADPHONES  "headphones"
#define MIC         "mic"
#define HS_MIC      "micHs"
#define JSON_UNPRINT 1

static cJSON *g_cJsonObj = NULL;

/* Depend on Audio_types.h : enum AudioCategory */
enum AudioCategoryPathSel {
    PATH_USE_IN_MEDIA = 0,
    PATH_USE_IN_COMMUNICATION,
    PATH_USE_TYPE_MAX,
};

enum AudioPortPinPathSel {
    PATH_DEV_NONE        = 0x0u,       /* Invalid pin */
    PATH_DEV_OUT_SPEAKER = 0x1u,       /* Speaker output pin */
    PATH_DEV_OUT_HEADSET = 0x2u,       /* Wired headset pin for output */
    PATH_DEV_OUT_LINEOUT = 0x4u,       /* Line-out pin */
    PATH_DEV_OUT_HDMI    = 0x8u,       /* HDMI output pin */
    PATH_DEV_MID         = 0x8000000u, /* Microphone input pin */
    PATH_DEV_IN_MIC      = 0x8000001u, /* Microphone input pin */
    PATH_DEV_IN_HS_MIC   = 0x8000002u, /* Wired headset microphone pin for input */
    PATH_DEV_IN_LINEIN   = 0x8000004u, /* Line-in pin */
    PATH_DEV_MAX,
};

int32_t AudioPathSelGetConfToJsonObj()
{
    FILE *fpJson = NULL;
    char *pJsonStr = NULL;
    if (g_cJsonObj != NULL) {
        return HDF_SUCCESS;
    }
    fpJson = fopen(CJSONFILE_CONFIG_PATH, "r");
    if (fpJson == NULL) {
        AUDIO_FUNC_LOGE("audio_paths.json file fail!");
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
        AudioMemFree((void **)&pJsonStr);
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
        AudioMemFree((void **)&pJsonStr);
        return HDF_FAILURE;
    }
    AudioMemFree((void **)&pJsonStr);
    return HDF_SUCCESS;
}

static const char *AudioPathSelGetDeviceType(enum AudioPortPin pins)
{
    if (pins < PATH_DEV_NONE || pins > PATH_DEV_MAX) {
        return NULL;
    }
    switch (pins) {
        case PATH_DEV_OUT_SPEAKER:
            return SPEAKER;
        case PATH_DEV_OUT_HEADSET:
            return HEADPHONES;
        case PATH_DEV_IN_MIC:
            return MIC;
        case PATH_DEV_IN_HS_MIC:
            return HS_MIC;
        default:
            AUDIO_FUNC_LOGE("UseCase not support!");
            break;
    }
    return NULL;
}

static const char *AudioPathSelGetUseCase(enum AudioCategory type)
{
    static const char *usecaseType[PATH_USE_TYPE_MAX + 1] = {
        [PATH_USE_IN_MEDIA] = "deep-buffer-playback",
        [PATH_USE_IN_COMMUNICATION] = "low-latency-playback",
        [PATH_USE_TYPE_MAX] = "none",
    };

    if (type < 0 || type > PATH_USE_TYPE_MAX) {
        return NULL;
    }
    return usecaseType[type];
}

static int32_t AudioCJsonCardServiceItemCheck(cJSON *cJsonObj, const char *firstItem, const char *secondItem,
                                              const char *thirdItem)
{
    if (cJsonObj == NULL || firstItem == NULL || secondItem == NULL || thirdItem == NULL) {
        AUDIO_FUNC_LOGE("cJsonObj or firstItem or secondItem or thirdItem is NULL!");
        return HDF_FAILURE;
    }
    cJSON *cardNode = cJSON_GetObjectItem(cJsonObj, firstItem);
    if (cardNode == NULL) {
        AUDIO_FUNC_LOGE("failed to check item when firstItem[%{public}s] gets object!", firstItem);
        return HDF_FAILURE;
    }
    cJSON *cardList = cardNode->child;
    if (cardList == NULL) {
        AUDIO_FUNC_LOGE("no child when firstItem[%{public}s] gets object!", firstItem);
        return HDF_FAILURE;
    }

    cJSON *pathNode = cJSON_GetObjectItem(cardList, secondItem);
    if (pathNode == NULL) {
        AUDIO_FUNC_LOGE("failed to check item when secondItem[%{public}s] gets object!", secondItem);
        return HDF_ERR_NOT_SUPPORT;
    }
    cJSON *deviceNode = cJSON_GetObjectItem(cardList, thirdItem);
    if (deviceNode == NULL) {
        AUDIO_FUNC_LOGE("failed to check item when thirdItem[%{public}s] gets object!", thirdItem);
        return HDF_ERR_NOT_SUPPORT;
    }
    return HDF_SUCCESS;
}

static int32_t AudioPathSelGetPlanRenderScene(struct AudioHwRenderParam *renderSceneParam)
{
    AUDIO_FUNC_LOGI();
    int32_t ret;
    if (renderSceneParam == NULL) {
        AUDIO_FUNC_LOGE("AudioPathSelGetPlanRenderScene param Is NULL");
        return HDF_FAILURE;
    }
    char pathName[PATH_NAME_LEN] = {0};
    enum AudioPortPin pins = renderSceneParam->renderMode.hwInfo.deviceDescript.pins;
    if (pins >= PATH_DEV_MAX || pins < PATH_DEV_NONE) {
        AUDIO_FUNC_LOGE("deviceDescript pins error!");
        return HDF_FAILURE;
    }
    enum AudioCategory type = renderSceneParam->frameRenderMode.attrs.type;
    const char *useCase = AudioPathSelGetUseCase(type);
    const char *deviceType = AudioPathSelGetDeviceType(pins);
    if (useCase == NULL || deviceType == NULL) {
        AUDIO_FUNC_LOGE("pins or type not support!");
        return HDF_FAILURE;
    }
    if (snprintf_s(pathName, sizeof(pathName), sizeof(pathName) - 1, "%s %s", useCase, deviceType) < 0) {
        AUDIO_FUNC_LOGE("snprintf_s Invalid!");
        return HDF_FAILURE;
    }
    ret = AudioCJsonCardServiceItemCheck(g_cJsonObj, renderSceneParam->renderMode.hwInfo.cardServiceName, pathName,
                                         deviceType);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    ret = strncpy_s(renderSceneParam->renderMode.hwInfo.pathSelect.useCase,
                    NAME_LEN, useCase, strlen(useCase) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
    ret = strncpy_s(renderSceneParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceType,
                    NAME_LEN, deviceType, strlen(deviceType) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioPathSelGetPlanCaptureScene(struct AudioHwCaptureParam *captureSceneParam)
{
    AUDIO_FUNC_LOGI();
    int32_t ret;
    if (captureSceneParam == NULL) {
        AUDIO_FUNC_LOGE("AudioPathSelGetPlanCaptureScene param Is NULL");
        return HDF_FAILURE;
    }
    char pathName[PATH_NAME_LEN] = {0};
    enum AudioPortPin pins = captureSceneParam->captureMode.hwInfo.deviceDescript.pins;
    if (pins >= PATH_DEV_MAX || pins < PATH_DEV_MID) {
        AUDIO_FUNC_LOGE("deviceDescript pins error!");
        return HDF_FAILURE;
    }
    enum AudioCategory type = captureSceneParam->frameCaptureMode.attrs.type;
    const char *useCase = AudioPathSelGetUseCase(type);
    const char *deviceType = AudioPathSelGetDeviceType(pins);
    if (useCase == NULL || deviceType == NULL) {
        AUDIO_FUNC_LOGE("pins or type not support!");
        return HDF_FAILURE;
    }
    if (snprintf_s(pathName, sizeof(pathName), sizeof(pathName) - 1, "%s %s", useCase, deviceType) < 0) {
        AUDIO_FUNC_LOGE("snprintf_s failed!");
        return HDF_FAILURE;
    }
    ret = AudioCJsonCardServiceItemCheck(g_cJsonObj, captureSceneParam->captureMode.hwInfo.cardServiceName, pathName,
                                         deviceType);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    ret = strncpy_s(captureSceneParam->captureMode.hwInfo.pathSelect.useCase,
                    NAME_LEN, useCase, strlen(useCase) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
    ret = strncpy_s(captureSceneParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceType,
                    NAME_LEN, deviceType, strlen(deviceType) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioCJsonParseGetSubItem(cJSON *cJsonObj, const char *firstItem, const char *secondItem,
                                         cJSON **deviceList)
{
    if (cJsonObj == NULL || firstItem == NULL || secondItem == NULL || deviceList == NULL) {
        AUDIO_FUNC_LOGE("cJsonObj or firstItem or secondItem or deviceList is null");
        return HDF_FAILURE;
    }
    cJSON *cardNode = cJSON_GetObjectItem(cJsonObj, firstItem);
    if (cardNode == NULL) {
        AUDIO_FUNC_LOGE("firstItem[%{public}s] Get Object Fail!", firstItem);
        return HDF_FAILURE;
    }

    cJSON *cardList = cardNode->child;
    if (cardList == NULL) {
        AUDIO_FUNC_LOGE("firstItem[%{public}s] no child!", firstItem);
        return HDF_FAILURE;
    }

    cJSON *deviceNode = cJSON_GetObjectItem(cardList, secondItem);
    if (deviceNode == NULL) {
        AUDIO_FUNC_LOGE("secondItem[%{public}s] Get Object Fail!", secondItem);
        return HDF_FAILURE;
    }
    *deviceList = deviceNode->child;
    if (*deviceList == NULL) {
        AUDIO_FUNC_LOGE("deviceList is NULL!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioCapturePathSelGetUsecaseDevice(struct AudioHwCaptureParam *captureParam, const char *pathName)
{
    if (captureParam == NULL || pathName == NULL || g_cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("AudioCapturePathSelGetUsecaseDevice param Is NULL");
        return HDF_FAILURE;
    }
    int32_t pathIndex = 0;
    char *pathKey = NULL;
    int32_t ret;

    cJSON *pathList = NULL;
    ret = AudioCJsonParseGetSubItem(g_cJsonObj, captureParam->captureMode.hwInfo.cardServiceName, pathName, &pathList);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    while (pathList != NULL) {
        cJSON *device = cJSON_GetObjectItem(pathList, "name");
        if (device == NULL) {
            AUDIO_FUNC_LOGE("Get Object Invalid!");
            return HDF_FAILURE;
        }
        pathKey = device->valuestring;
        if (pathKey == NULL) {
            pathList = pathList->next;
            continue;
        }
        device = cJSON_GetObjectItem(pathList, "value");
        if (device == NULL) {
            return HDF_FAILURE;
        }
        captureParam->captureMode.hwInfo.pathSelect.pathPlan[pathIndex].value = device->valueint;
        ret = strncpy_s(captureParam->captureMode.hwInfo.pathSelect.pathPlan[pathIndex].pathPlanName,
                        PATHPLAN_LEN, pathKey, strlen(pathKey) + 1);
        if (ret != 0) {
            AUDIO_FUNC_LOGE("strncpy_s failed!");
            return HDF_FAILURE;
        }
        pathList = pathList->next;
        pathIndex++;
    }
    if (pathIndex >= PATHPLAN_COUNT || pathIndex < 0) {
        AUDIO_FUNC_LOGE("AudioCapturePathSel Get Object Fail!");
        return HDF_FAILURE;
    }
    captureParam->captureMode.hwInfo.pathSelect.useCaseDeviceNum = pathIndex;
    return HDF_SUCCESS;
}

static int32_t AudioCapturePathSelGetDeviceSplit(struct AudioHwCaptureParam *captureParam, cJSON *deviceList)
{
    AUDIO_FUNC_LOGI();
    int32_t decIndex = 0;
    char *decKey = NULL;
    int32_t decValue;
    int32_t ret;
    cJSON *devObj = NULL;
    if (captureParam == NULL || deviceList == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_FAILURE;
    }
    while (deviceList != NULL) {
        devObj = cJSON_GetObjectItem(deviceList, "name");
        if (devObj == NULL) {
            AUDIO_FUNC_LOGE("Get Object Fail!");
            return HDF_FAILURE;
        }
        decKey = devObj->valuestring;
        if (decKey == NULL) {
            deviceList = deviceList->next;
            continue;
        }
        devObj = cJSON_GetObjectItem(deviceList, "value");
        if (devObj == NULL) {
            return HDF_FAILURE;
        }
        decValue = devObj->valueint;
        captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[decIndex].value = decValue;
        ret = strncpy_s(captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[decIndex].deviceSwitch,
                        PATHPLAN_LEN, decKey, strlen(decKey) + 1);
        if (ret != 0) {
            AUDIO_FUNC_LOGE("strncpy_s failed!");
            return HDF_FAILURE;
        }
        deviceList = deviceList->next;
        decIndex++;
    }
    if (decIndex >= PATHPLAN_COUNT || decIndex < 0) {
        AUDIO_FUNC_LOGE("Get Object Fail!");
        return HDF_FAILURE;
    }
    captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum = decIndex;
    return HDF_SUCCESS;
}

static int32_t AudioCapturePathSelGetDevice(struct AudioHwCaptureParam *captureParam, const char *deviceType)
{
    AUDIO_FUNC_LOGI();
    if (captureParam == NULL || deviceType == NULL || g_cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("AudioCapturePathSelGetUsecaseDevice param Is NULL");
        return HDF_FAILURE;
    }

    cJSON *cardNode = cJSON_GetObjectItem(g_cJsonObj, captureParam->captureMode.hwInfo.cardServiceName);
    if (cardNode == NULL) {
        AUDIO_FUNC_LOGE("cardNode Get Object Fail cardServiceName = %{public}s !",
            captureParam->captureMode.hwInfo.cardServiceName);
        return HDF_FAILURE;
    }
    cJSON *cardList = cardNode->child;
    if (cardList == NULL) {
        AUDIO_FUNC_LOGE("AudioRenderPathSel Get cardList Fail!");
        return HDF_FAILURE;
    }

    cJSON *deviceNode = cJSON_GetObjectItem(cardList, deviceType);
    if (deviceNode == NULL) {
        AUDIO_FUNC_LOGE("Get deviceType Fail!");
        return HDF_FAILURE;
    }
    cJSON *deviceList = deviceNode->child;
    if (deviceList == NULL) {
        AUDIO_FUNC_LOGE("Get deviceList Fail!");
        return HDF_FAILURE;
    }
    if (AudioCapturePathSelGetDeviceSplit(captureParam, deviceList) < 0) {
        AUDIO_FUNC_LOGE("AudioCapturePathSelGetDeviceSplit Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioPathSelGetPlanCapture(struct AudioHwCaptureParam *captureParam)
{
    AUDIO_FUNC_LOGI();
    int32_t ret;
    if (captureParam == NULL) {
        AUDIO_FUNC_LOGE("AudioPathSelGetPlanCapture param Is NULL");
        return HDF_FAILURE;
    }
    char pathName[PATH_NAME_LEN] = {0};
    enum AudioPortPin pins = captureParam->captureMode.hwInfo.deviceDescript.pins;
    if (pins <= PATH_DEV_MID) {
        AUDIO_FUNC_LOGE("deviceDescript pins error!");
        return HDF_FAILURE;
    }
    enum AudioCategory type = captureParam->frameCaptureMode.attrs.type;
    const char *useCase = AudioPathSelGetUseCase(type);
    const char *deviceType = AudioPathSelGetDeviceType(pins);
    if (useCase == NULL || deviceType == NULL) {
        AUDIO_FUNC_LOGE("pins or type not support!");
        return HDF_FAILURE;
    }
    ret = strncpy_s(captureParam->captureMode.hwInfo.pathSelect.useCase,
                    NAME_LEN, useCase, strlen(useCase) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
    ret = strncpy_s(captureParam->captureMode.hwInfo.pathSelect.deviceInfo.deviceType,
                    NAME_LEN, deviceType, strlen(deviceType) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
    if (snprintf_s(pathName, sizeof(pathName), sizeof(pathName) - 1, "%s %s", useCase, deviceType) < 0) {
        AUDIO_FUNC_LOGE("snprintf_s failed!");
        return HDF_FAILURE;
    }
    if (AudioCapturePathSelGetUsecaseDevice(captureParam, pathName) < 0) {
        AUDIO_FUNC_LOGE("AudioCapturePathSelGetUsecaseDevice failed!");
        return HDF_FAILURE;
    }
    if (AudioCapturePathSelGetDevice(captureParam, deviceType) < 0) {
        AUDIO_FUNC_LOGE("AudioCapturePathSelGetDevice failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioRenderPathSelGetUsecaseDevice(struct AudioHwRenderParam *renderParam, const char *pathName)
{
    if (renderParam == NULL || pathName == NULL || g_cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("AudioPathSelGetUsecaseDevice param Is NULL");
        return HDF_FAILURE;
    }
    int32_t pathIndex = 0;
    char *pathKey = NULL;
    int32_t ret;

    cJSON *pathList = NULL;
    ret = AudioCJsonParseGetSubItem(g_cJsonObj, renderParam->renderMode.hwInfo.cardServiceName, pathName, &pathList);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    while (pathList != NULL) {
        cJSON *device = cJSON_GetObjectItem(pathList, "name");
        if (device == NULL) {
            AUDIO_FUNC_LOGE("Get Object Fail!");
            return HDF_FAILURE;
        }
        pathKey = device->valuestring;
        if (pathKey == NULL) {
            pathList = pathList->next;
            continue;
        }
        device = cJSON_GetObjectItem(pathList, "value");
        if (device == NULL) {
            return HDF_FAILURE;
        }
        renderParam->renderMode.hwInfo.pathSelect.pathPlan[pathIndex].value = device->valueint;
        ret = strncpy_s(renderParam->renderMode.hwInfo.pathSelect.pathPlan[pathIndex].pathPlanName,
                        PATHPLAN_LEN, pathKey, strlen(pathKey));
        if (ret != 0) {
            AUDIO_FUNC_LOGE("strncpy_s is Fail!");
            return HDF_FAILURE;
        }
        pathList = pathList->next;
        pathIndex++;
    }
    if (pathIndex >= PATHPLAN_COUNT || pathIndex < 0) {
        AUDIO_FUNC_LOGE("AudioRenderPathSel Get Object Fail!");
        return HDF_FAILURE;
    }
    renderParam->renderMode.hwInfo.pathSelect.useCaseDeviceNum = pathIndex;
    return HDF_SUCCESS;
}

static int32_t AudioRenderPathSelGetDevice(struct AudioHwRenderParam *renderParam, const char *deviceType)
{
    if (renderParam == NULL || deviceType == NULL || g_cJsonObj == NULL) {
        AUDIO_FUNC_LOGE("AudioPathSelGetDevice param Is NULL");
        return HDF_FAILURE;
    }
    char *decKey = NULL;
    int32_t decIndex = 0;
    int32_t ret;

    cJSON *deviceList = NULL;
    ret = AudioCJsonParseGetSubItem(g_cJsonObj, renderParam->renderMode.hwInfo.cardServiceName, deviceType,
                                    &deviceList);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    while (deviceList != NULL) {
        cJSON *device = cJSON_GetObjectItem(deviceList, "name");
        if (device == NULL) {
            AUDIO_FUNC_LOGE("Get Object Invalid!");
            return HDF_FAILURE;
        }
        decKey = device->valuestring;
        if (decKey == NULL) {
            deviceList = deviceList->next;
            continue;
        }
        device = cJSON_GetObjectItem(deviceList, "value");
        if (device == NULL) {
            return HDF_FAILURE;
        }
        renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[decIndex].value = device->valueint;
        ret = strncpy_s(renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[decIndex].deviceSwitch,
                        PATHPLAN_LEN, decKey, strlen(decKey) + 1);
        if (ret != 0) {
            AUDIO_FUNC_LOGE("strncpy_s is Fail!");
            return HDF_FAILURE;
        }
        deviceList = deviceList->next;
        decIndex++;
    }
    if (decIndex >= PATHPLAN_COUNT || decIndex < 0) {
        AUDIO_FUNC_LOGE("Get Object Fail!");
        return HDF_FAILURE;
    }
    renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum = decIndex;
    return HDF_SUCCESS;
}

static int32_t AudioPathSelGetPlanRender(struct AudioHwRenderParam *renderParam)
{
    AUDIO_FUNC_LOGI();
    int32_t ret;
    if (renderParam == NULL) {
        AUDIO_FUNC_LOGE("AudioPathSelGetPlanRender param Is NULL");
        return HDF_FAILURE;
    }
    char pathName[PATH_NAME_LEN] = {0};
    enum AudioPortPin pins = renderParam->renderMode.hwInfo.deviceDescript.pins;
    if (pins >= PATH_DEV_MID) {
        AUDIO_FUNC_LOGE("deviceDescript pins error!");
        return HDF_FAILURE;
    }
    enum AudioCategory type = renderParam->frameRenderMode.attrs.type;
    const char *useCase = AudioPathSelGetUseCase(type);
    const char *deviceType = AudioPathSelGetDeviceType(pins);
    if (useCase == NULL || deviceType == NULL) {
        AUDIO_FUNC_LOGE("pins or type not support!");
        return HDF_FAILURE;
    }
    ret = strncpy_s(renderParam->renderMode.hwInfo.pathSelect.useCase,
                    NAME_LEN, useCase, strlen(useCase) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s is Fail!");
        return HDF_FAILURE;
    }
    ret = strncpy_s(renderParam->renderMode.hwInfo.pathSelect.deviceInfo.deviceType,
                    NAME_LEN, deviceType, strlen(deviceType) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s is Fail!");
        return HDF_FAILURE;
    }
    if (snprintf_s(pathName, sizeof(pathName), sizeof(pathName) - 1, "%s %s", useCase, deviceType) < 0) {
        AUDIO_FUNC_LOGE("snprintf_s failed!");
        return HDF_FAILURE;
    }
    if (AudioRenderPathSelGetUsecaseDevice(renderParam, pathName) < 0) {
        AUDIO_FUNC_LOGE("AudioRenderPathSelGetUsecaseDevice failed!");
        return HDF_FAILURE;
    }
    if (AudioRenderPathSelGetDevice(renderParam, deviceType) < 0) {
        AUDIO_FUNC_LOGE("AudioRenderPathSelGetDevice failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioPathSelAnalysisJson(const AudioHandle adapterParam, enum AudioAdaptType adaptType)
{
    AUDIO_FUNC_LOGI();
    if (adaptType < 0 || adapterParam == NULL) {
        AUDIO_FUNC_LOGE("Param Invaild!");
        return HDF_FAILURE;
    }
    struct AudioHwRenderParam *renderParam = NULL;
    struct AudioHwCaptureParam *captureParam = NULL;
    struct AudioHwRenderParam *renderSceneCheck = NULL;
    struct AudioHwCaptureParam *captureScenceCheck = NULL;
    switch (adaptType) {
        case RENDER_PATH_SELECT:
            renderParam = (struct AudioHwRenderParam *)adapterParam;
            return (AudioPathSelGetPlanRender(renderParam));
        case CAPTURE_PATH_SELECT:
            captureParam = (struct AudioHwCaptureParam *)adapterParam;
            return (AudioPathSelGetPlanCapture(captureParam));
        /* Scene is supported */
        case CHECKSCENE_PATH_SELECT:
            renderSceneCheck = (struct AudioHwRenderParam *)adapterParam;
            return (AudioPathSelGetPlanRenderScene(renderSceneCheck));
        case CHECKSCENE_PATH_SELECT_CAPTURE:
            captureScenceCheck = (struct AudioHwCaptureParam *)adapterParam;
            return (AudioPathSelGetPlanCaptureScene(captureScenceCheck));
        default:
            AUDIO_FUNC_LOGE("Path select mode invalid");
            break;
    }
    return HDF_FAILURE;
}

