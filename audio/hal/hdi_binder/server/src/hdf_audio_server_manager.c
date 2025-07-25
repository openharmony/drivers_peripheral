/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "hdf_audio_server_manager.h"
#include "audio_adapter_info_common.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"

#define MAX_AUDIO_ADAPTER_NUM_SERVER 8 // Limit the number of sound cards supported to a maximum of 8
#define MANAGER_ADAPTER_NAME_LEN     32

static struct AudioInfoInAdapter g_renderAndCaptureManage[MAX_AUDIO_ADAPTER_NUM_SERVER];
static int32_t g_serverAdapterNum = 0;

int32_t AudioServerGetAdapterNum(void)
{
    return g_serverAdapterNum;
}

static int32_t AudioInfoInAdapterFindDesc(int32_t index, const char *adapterName)
{
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is NULL");
        return HDF_ERR_INVALID_PARAM;
    }

    for (int i = 0; i < g_serverAdapterNum; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGW("g_renderAndCaptureManage[%{public}d].adapterName is NULL", i);
            continue;
        }
        if (strncmp(g_renderAndCaptureManage[i].adapterName, adapterName, strlen(adapterName)) == 0) {
            if (i != index) {
                (void)memcpy_s(&g_renderAndCaptureManage[index], sizeof(struct AudioInfoInAdapter),
                    &g_renderAndCaptureManage[i], sizeof(struct AudioInfoInAdapter));
                (void)memset_s(&g_renderAndCaptureManage[i], sizeof(struct AudioInfoInAdapter),
                    0, sizeof(struct AudioInfoInAdapter));
            }
            return HDF_SUCCESS;
        }
    }

    return HDF_FAILURE;
}

static int32_t AudioAdapterInfoInit(struct AudioInfoInAdapter *adapterManage, const char *adapterName)
{
    if (adapterManage == NULL || adapterName == NULL) {
        AUDIO_FUNC_LOGE("Parameter error! ");
        return HDF_ERR_INVALID_PARAM;
    }

    if (adapterManage->adapterName != NULL) {
        AUDIO_FUNC_LOGI("adapterManage->adapterName = %{public}s", adapterManage->adapterName);
    } else {
        adapterManage->adapterName = (char *)OsalMemCalloc(MANAGER_ADAPTER_NAME_LEN);
    }

    if (adapterManage->adapterName == NULL) {
        AUDIO_FUNC_LOGE("alloc adapter name failed!");
        return HDF_FAILURE;
    }

    int32_t ret = memcpy_s((void *)adapterManage->adapterName, MANAGER_ADAPTER_NAME_LEN,
        adapterName, strlen(adapterName));
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("memcpy adapter name fail!");
        OsalMemFree((void *)&adapterManage->adapterName);
        return HDF_FAILURE;
    }

    adapterManage->adapter = NULL;
    adapterManage->adapterUserNum = 0;
    adapterManage->renderStatus = 0;
    adapterManage->renderPriority = -1;
    adapterManage->render = NULL;
    adapterManage->renderBusy = false;
    adapterManage->renderDestory = false;
    adapterManage->renderPid = 0;
    adapterManage->captureStatus = 0;
    adapterManage->capturePriority = -1;
    adapterManage->capture = NULL;
    adapterManage->captureBusy = false;
    adapterManage->captureDestory = false;
    adapterManage->capturePid = 0;

    return HDF_SUCCESS;
}

int32_t AdapterManageInit(const struct AudioAdapterDescriptor *descs, int32_t num)
{
    int32_t index = 0;
    if (descs == NULL || num <= 0) {
        HDF_LOGE("Invaild parameters: descs=%p, num=%d", descs, num);
        return HDF_FAILURE;
    }
    struct AudioInfoInAdapter *adapterManage = g_renderAndCaptureManage;

    for (index = 0; index < num; index++) {
        if (AudioInfoInAdapterFindDesc(index, descs[index].adapterName) != HDF_SUCCESS) {
            if (AudioAdapterInfoInit(&adapterManage[index], descs[index].adapterName)) {
                return HDF_FAILURE;
            }
        }
    }

    g_serverAdapterNum = num;
    return HDF_SUCCESS;
}

int32_t ServerManageGetAdapterNum(int32_t serverAdapterNum)
{
    return ((serverAdapterNum > MAX_AUDIO_ADAPTER_NUM_SERVER) ? MAX_AUDIO_ADAPTER_NUM_SERVER : serverAdapterNum);
}

static void AdaptersServerManageRelease(struct AudioInfoInAdapter *adaptersManage, int32_t num)
{
    int32_t i;

    if (adaptersManage == NULL || num <= 0) {
        AUDIO_FUNC_LOGE("Parameter error! ");

        return;
    }
    num = ServerManageGetAdapterNum(num);
    for (i = 0; i < num; i++) {
        if (adaptersManage[i].adapterName != NULL) {
            OsalMemFree((void *)&adaptersManage[i].adapterName);
        }
    }

    (void)memset_s(adaptersManage, MAX_AUDIO_ADAPTER_NUM_SERVER * sizeof(struct AudioInfoInAdapter),
        0, MAX_AUDIO_ADAPTER_NUM_SERVER * sizeof(struct AudioInfoInAdapter));
}

void AdaptersServerManageInfomationRecycle(void)
{
    AdaptersServerManageRelease(g_renderAndCaptureManage, g_serverAdapterNum);
    g_serverAdapterNum = 0;
}

int32_t AudioAdapterListGetAdapterCapture(const char *adapterName,
    struct AudioAdapter **adapter, struct AudioCapture **capture)
{
    int32_t i;

    if (adapterName == NULL || adapter == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null ");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("The pointer is null ");
            return HDF_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            *adapter = g_renderAndCaptureManage[i].adapter;
            *capture = g_renderAndCaptureManage[i].capture;
            return HDF_SUCCESS;
        }
    }
    return HDF_ERR_INVALID_PARAM;
}

int32_t AudioDestroyCaptureInfoInAdapter(const char *adapterName)
{
    int32_t i;

    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("Param Is NULL ");
        return HDF_FAILURE;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            return HDF_FAILURE;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            g_renderAndCaptureManage[i].captureStatus = 0;
            g_renderAndCaptureManage[i].capturePriority = -1;
            g_renderAndCaptureManage[i].capture = NULL;
            g_renderAndCaptureManage[i].capturePid = 0;
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("Can not find Adapter! ");
    return HDF_FAILURE;
}

static int32_t AudioDestroyFormerCapture(struct AudioInfoInAdapter *captureManage)
{
    if (captureManage == NULL || captureManage->adapter == NULL || captureManage->capture == NULL) {
        AUDIO_FUNC_LOGE("input para is NULL ");
        return HDF_FAILURE;
    }
    int count = 0;
    captureManage->captureDestory = true;
    while (captureManage->captureBusy) {
        if (count > 1000) { // Less than 1000
            AUDIO_FUNC_LOGE(", count = %{public}d", count);
            captureManage->captureDestory = false;
            return AUDIO_HAL_ERR_AI_BUSY; // capture is busy now
        }
        usleep(500); // sleep 500us
        count++;
    }
    captureManage->capturePid = 0;
    if (captureManage->adapter->DestroyCapture(captureManage->adapter, captureManage->capture)) {
        captureManage->captureDestory = false;
        return HDF_FAILURE;
    }
    captureManage->capture = NULL;
    captureManage->captureStatus = 0;
    captureManage->captureBusy = false;
    captureManage->captureDestory = false;
    captureManage->renderPriority = -1;
    return HDF_SUCCESS;
}

static int32_t AudioJudgeCapturePriority(const int32_t priority, int which)
{
    int num = ServerManageGetAdapterNum(g_serverAdapterNum);
    if (which < 0 || which >= num) {
        AUDIO_FUNC_LOGE("invalid value! ");
        return HDF_FAILURE;
    }
    if (!(g_renderAndCaptureManage[which].captureStatus)) {
        return HDF_SUCCESS;
    } else {
        if (g_renderAndCaptureManage[which].capturePriority <= priority) {
            return AudioDestroyFormerCapture(&g_renderAndCaptureManage[which]);
        } else {
            return AUDIO_HAL_ERR_AI_BUSY; // capture is busy now
        }
    }
    return HDF_FAILURE;
}

int32_t AudioCreatCaptureCheck(const char *adapterName, const int32_t priority)
{
    int32_t i;

    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is NULL! ");
        return HDF_FAILURE;
    }
    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_FAILURE;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            return AudioJudgeCapturePriority(priority, i);
        }
    }
    AUDIO_FUNC_LOGE("Can not find Adapter! ");
    return HDF_FAILURE;
}

int32_t AudioAddCaptureInfoInAdapter(const char *adapterName, struct AudioCapture *capture,
    const struct AudioAdapter *adapter, const int32_t priority, uint32_t capturePid)
{
    int32_t i;

    if (adapterName == NULL || adapter == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("input para is NULL. ");
        return HDF_FAILURE;
    }
    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_FAILURE;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            g_renderAndCaptureManage[i].captureStatus = 1;
            g_renderAndCaptureManage[i].capturePriority = priority;
            g_renderAndCaptureManage[i].capture = capture;
            g_renderAndCaptureManage[i].capturePid = capturePid;
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("Can not find Adapter! ");
    return HDF_FAILURE;
}

int32_t AudioAdapterListGetAdapter(const char *adapterName, struct AudioAdapter **adapter)
{
    int32_t i;

    AUDIO_FUNC_LOGI();
    if (adapterName == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null ");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            *adapter = g_renderAndCaptureManage[i].adapter;
            return HDF_SUCCESS;
        }
    }
    return HDF_ERR_INVALID_PARAM;
}

static int32_t AudioDestroyFormerRender(struct AudioInfoInAdapter *renderManage)
{
    AUDIO_FUNC_LOGI();
    if (renderManage == NULL || renderManage->adapter == NULL || renderManage->render == NULL) {
        AUDIO_FUNC_LOGE("input para is NULL. ");
        return HDF_FAILURE;
    }
    int count = 0;
    renderManage->renderDestory = true;
    while (renderManage->renderBusy) {
        if (count > 1000) { // Less than 1000
            AUDIO_FUNC_LOGE(", count = %{public}d", count);
            renderManage->renderDestory = false;
            return AUDIO_HAL_ERR_AO_BUSY; // render is busy now
        }
        usleep(500); // sleep 500us
        count++;
    }
    renderManage->renderPid = 0;
    if (renderManage->adapter->DestroyRender(renderManage->adapter, renderManage->render)) {
        renderManage->renderDestory = false;
        return HDF_FAILURE;
    }
    renderManage->render = NULL;
    renderManage->renderStatus = 0;
    renderManage->renderBusy = false;
    renderManage->renderDestory = false;
    renderManage->renderPriority = -1;
    return HDF_SUCCESS;
}

static int32_t AudioJudgeRenderPriority(const int32_t priority, int which)
{
    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    if (which < 0 || which >= num) {
        AUDIO_FUNC_LOGE("invalid value! ");
        return HDF_FAILURE;
    }
    if (g_renderAndCaptureManage[which].renderPriority <= priority) {
        if (AudioDestroyFormerRender(&g_renderAndCaptureManage[which])) {
            AUDIO_FUNC_LOGE("AudioDestroyFormerRender: Fail. ");
            return HDF_FAILURE;
        }
        return HDF_SUCCESS;
    } else {
        return AUDIO_HAL_ERR_AO_BUSY; // render is busy now
    }
    return HDF_FAILURE;
}

int32_t AudioCreatRenderCheck(const char *adapterName, const int32_t priority)
{
    int32_t i;

    if (adapterName == NULL) {
        return HDF_FAILURE;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_FAILURE;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            if (!(g_renderAndCaptureManage[i].renderStatus)) {
                return HDF_SUCCESS;
            } else {
                return AudioJudgeRenderPriority(priority, i);
            }
        }
    }
    AUDIO_FUNC_LOGE("Can not find Adapter! ");
    return HDF_FAILURE;
}

int32_t AudioAddRenderInfoInAdapter(const char *adapterName, struct AudioRender *render,
    const struct AudioAdapter *adapter, const int32_t priority, uint32_t renderPid)
{
    int32_t i;

    if (adapterName == NULL || adapter == NULL || render == NULL) {
        AUDIO_FUNC_LOGE("input para is NULL. ");
        return HDF_FAILURE;
    }
    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_FAILURE;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            g_renderAndCaptureManage[i].renderStatus = 1;
            g_renderAndCaptureManage[i].renderPriority = priority;
            g_renderAndCaptureManage[i].render = render;
            g_renderAndCaptureManage[i].renderPid = renderPid;
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("Can not find Adapter! ");
    return HDF_FAILURE;
}

void AudioSetRenderStatus(const char *adapterName, bool renderStatus)
{
    int32_t i;
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is null ");
        return;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            g_renderAndCaptureManage[i].renderBusy = renderStatus;
            return;
        }
    }
    AUDIO_FUNC_LOGE("AudioDestroyRenderInfoInAdapter: Can not find Adapter! ");
    return;
}

int32_t AudioGetRenderStatus(const char *adapterName)
{
    int32_t i;

    if (adapterName == NULL) {
        return HDF_FAILURE;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL!", i);
            return HDF_FAILURE;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            if (!g_renderAndCaptureManage[i].renderDestory) {
                return HDF_SUCCESS;
            } else {
                g_renderAndCaptureManage[i].renderBusy = false;
                AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].renderBusy is NULL!", i);
                return HDF_FAILURE;
            }
        }
    }
    AUDIO_FUNC_LOGE("AudioDestroyRenderInfoInAdapter: Can not find Adapter!");
    return HDF_FAILURE;
}

int32_t AudioDestroyRenderInfoInAdapter(const char *adapterName)
{
    int32_t i;

    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is null ");
        return HDF_FAILURE;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_FAILURE;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            g_renderAndCaptureManage[i].renderStatus = 0;
            g_renderAndCaptureManage[i].renderPriority = -1;
            g_renderAndCaptureManage[i].render = NULL;
            g_renderAndCaptureManage[i].renderPid = 0;
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("Can not find Adapter! ");
    return HDF_FAILURE;
}

int32_t AudioAdapterListGetAdapterRender(const char *adapterName,
    struct AudioAdapter **adapter, struct AudioRender **render)
{
    int32_t i;

    if (adapterName == NULL || adapter == NULL || render == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null ");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            *adapter = g_renderAndCaptureManage[i].adapter;
            *render = g_renderAndCaptureManage[i].render;
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("AudioAdapterListGetAdapterRender failed!");
    return HDF_ERR_INVALID_PARAM;
}

int32_t AudioAdapterListGetRender(const char *adapterName, struct AudioRender **render, uint32_t pid)
{
    if (adapterName == NULL || render == NULL) {
        AUDIO_FUNC_LOGE("pointer is null ");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (int32_t i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            if (g_renderAndCaptureManage[i].renderPid != pid) {
                AUDIO_FUNC_LOGE("[%{public}d].renderPid:%{public}d != pid:%{public}d ", i,
                    g_renderAndCaptureManage[i].renderPid, pid);
                return AUDIO_HAL_ERR_INVALID_OBJECT;
            }
            *render = g_renderAndCaptureManage[i].render;
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("AudioAdapterListGetRender failed!");
    return HDF_ERR_INVALID_PARAM;
}

int32_t AudioAdapterListGetCapture(const char *adapterName, struct AudioCapture **capture, uint32_t pid)
{
    int32_t i;
    if (adapterName == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            if (g_renderAndCaptureManage[i].capturePid != pid) {
                AUDIO_FUNC_LOGE("managerList[%{public}d].capturePid:%{public}d != pid:%{public}d ", i,
                    g_renderAndCaptureManage[i].capturePid, pid);
                return AUDIO_HAL_ERR_INVALID_OBJECT;
            }
            *capture = g_renderAndCaptureManage[i].capture;
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("AudioAdapterListGetCapture failed!");
    return HDF_ERR_INVALID_PARAM;
}

int32_t AudioAdapterFrameGetCapture(const char *adapterName,
    struct AudioCapture **capture, uint32_t pid, uint32_t *index)
{
    int32_t i;
    if (adapterName == NULL || capture == NULL || index == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    *index = MAX_AUDIO_ADAPTER_NUM_SERVER;
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            if (g_renderAndCaptureManage[i].capturePid != pid) {
                AUDIO_FUNC_LOGE("[%{public}d].capturePid: %{public}d != pid: %{public}d ", i,
                    g_renderAndCaptureManage[i].capturePid, pid);
                return AUDIO_HAL_ERR_INVALID_OBJECT;
            }
            if (!g_renderAndCaptureManage[i].captureDestory) {
                *capture = g_renderAndCaptureManage[i].capture;
                *index = i;
                return HDF_SUCCESS;
            } else {
                g_renderAndCaptureManage[i].captureBusy = false;
                AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].captureBusy is false! ", i);
                return HDF_FAILURE;
            }
        }
    }
    AUDIO_FUNC_LOGE("AudioAdapterFrameGetCapture failed!");
    return HDF_FAILURE;
}

int32_t AudioAdapterCheckListExist(const char *adapterName)
{
    int32_t i;

    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null.");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return AUDIO_HAL_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            if (g_renderAndCaptureManage[i].adapterUserNum == 0) {
                AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterUserNum is zero! ", i);
                return AUDIO_HAL_ERR_INTERNAL;
            } else if (g_renderAndCaptureManage[i].adapterUserNum > 0) {
                g_renderAndCaptureManage[i].adapterUserNum++;
                return AUDIO_HAL_SUCCESS;
            }
        }
    }
    AUDIO_FUNC_LOGE("AudioAdapterCheckListExist failed!");
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

int32_t AudioAdapterListDestory(const char *adapterName, struct AudioAdapter **adapter)
{
    int32_t i;
    if (adapter == NULL || adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapter or adapterName is NULL.");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return AUDIO_HAL_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            if (g_renderAndCaptureManage[i].adapterUserNum == 1) {
                g_renderAndCaptureManage[i].adapterUserNum--;
                *adapter = g_renderAndCaptureManage[i].adapter;
                g_renderAndCaptureManage[i].adapter = NULL;
                return AUDIO_HAL_SUCCESS;
            } else if (g_renderAndCaptureManage[i].adapterUserNum > 1) {
                g_renderAndCaptureManage[i].adapterUserNum--;
                AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterUserNum > 1! ", i);
                return AUDIO_HAL_ERR_INTERNAL;
            }
        }
    }
    AUDIO_FUNC_LOGE("AudioAdapterListDestory failed!");
    return AUDIO_HAL_ERR_INVALID_PARAM;
}

int32_t AudioAdapterListAdd(const char *adapterName, struct AudioAdapter *adapter)
{
    int32_t i;

    if (adapterName == NULL || adapter == NULL) {
        AUDIO_FUNC_LOGE("adapterName is NULL. ");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_ERR_INVALID_PARAM;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            g_renderAndCaptureManage[i].adapter = adapter;
            g_renderAndCaptureManage[i].adapterUserNum = 1;
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("AudioAdapterListAdd failed!");
    return HDF_ERR_INVALID_PARAM;
}

void AudioSetCaptureStatus(const char *adapterName, bool captureStatus)
{
    int32_t i;
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is NULL. ");
        return;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            g_renderAndCaptureManage[i].captureBusy = captureStatus;
            return;
        }
    }
    AUDIO_FUNC_LOGE("AudioSetCaptureStatus failed! ");
    return;
}

void AudioSetCaptureBusy(uint32_t index, bool captureStatus)
{
    if (index < MAX_AUDIO_ADAPTER_NUM_SERVER) {
        g_renderAndCaptureManage[index].captureBusy = captureStatus;
    }
    return;
}

int32_t AudioGetCaptureStatus(const char *adapterName)
{
    int32_t i;
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is NULL. ");
        return HDF_FAILURE;
    }

    int32_t num = ServerManageGetAdapterNum(g_serverAdapterNum);
    for (i = 0; i < num; i++) {
        if (g_renderAndCaptureManage[i].adapterName == NULL) {
            AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d].adapterName is NULL! ", i);
            return HDF_FAILURE;
        }
        if (strcmp(g_renderAndCaptureManage[i].adapterName, adapterName) == 0) {
            if (!g_renderAndCaptureManage[i].captureDestory) {
                return HDF_SUCCESS;
            } else {
                g_renderAndCaptureManage[i].captureBusy = false;
                AUDIO_FUNC_LOGE("g_renderAndCaptureManage[%{public}d]! ", i);
                return HDF_FAILURE;
            }
        }
    }
    AUDIO_FUNC_LOGE("AudioGetCaptureStatus failed! ");
    return HDF_FAILURE;
}