/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "light_controller.h"
#include <fcntl.h>
#include <securec.h>
#include <stdio.h>
#include "osal_mem.h"
#include "hdf_base.h"
#include "hdf_dlist.h"
#include "hdf_io_service_if.h"
#include "light_uhdf_log.h"
#include "light_dump.h"
#include "light_if.h"
#include "light_type.h"

#define HDF_LOG_TAG           uhdf_light_service
#define LIGHT_SERVICE_NAME    "hdf_light"

#define MULTI_LIGHT_MAX_NUMBER    48
#define LIGHT_ON    1
#define LIGHT_OFF   0

struct LightEffect g_lightEffect;
uint8_t g_lightState[LIGHT_ID_BUTT] = {0};

struct LightDevice *GetLightDevicePriv(void)
{
    static struct LightDevice lightDeviceData = {
        .initState = false,
        .lightNum = 0,
        .ioService = NULL,
        .lightInfoEntry = NULL,
    };

    return &lightDeviceData;
}

struct LightEffect *GetLightEffect(void)
{
    return &g_lightEffect;
}

uint8_t *GetLightState(void)
{
    return g_lightState;
}

static int32_t SendLightMsg(uint32_t cmd, struct HdfSBuf *msg, struct HdfSBuf *reply)
{
    struct LightDevice *priv = GetLightDevicePriv();

    if (priv->ioService == NULL || priv->ioService->dispatcher == NULL ||
        priv->ioService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%s: para invalid", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = priv->ioService->dispatcher->Dispatch(&priv->ioService->object, cmd, msg, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Light dispatch failed", __func__);
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t ReadLightInfo(struct HdfSBuf *reply, struct LightDevice *priv)
{
    struct LightInfo *pos = NULL;
    const char *name = NULL;

    if (!HdfSbufReadUint32(reply, &priv->lightNum)) {
        HDF_LOGE("%s: sbuf read lightNum failed", __func__);
        return HDF_FAILURE;
    }

    if (priv->lightInfoEntry != NULL) {
        OsalMemFree(priv->lightInfoEntry);
        priv->lightInfoEntry = NULL;
    }

    priv->lightInfoEntry = (struct LightInfo *)OsalMemCalloc(sizeof(*priv->lightInfoEntry) * priv->lightNum);
    if (priv->lightInfoEntry == NULL) {
        HDF_LOGE("%s: malloc fail", __func__);
        return HDF_FAILURE;
    }

    pos = priv->lightInfoEntry;

    for (uint32_t i = 0; i < priv->lightNum; ++i) {
        if (!HdfSbufReadUint32(reply, &pos->lightId)) {
            HDF_LOGE("%{public}s:read lightId failed!", __func__);
            return HDF_FAILURE;
        }

        name = HdfSbufReadString(reply);
        if (strcpy_s(pos->lightName, NAME_MAX_LEN, name) != EOK) {
            HDF_LOGE("%{public}s:copy lightName failed!", __func__);
            return HDF_FAILURE;
        }

        if (!HdfSbufReadUint32(reply, &pos->lightNumber)) {
            HDF_LOGE("%{public}s:read lightNumber failed!", __func__);
            return HDF_FAILURE;
        }

        if (!HdfSbufReadInt32(reply, &pos->lightType)) {
            HDF_LOGE("%{public}s:read lightType failed!", __func__);
            return HDF_FAILURE;
        }
        pos++;
    }

    return HDF_SUCCESS;
}

static int32_t GetLightInfo(struct LightInfo **lightInfo, uint32_t *count)
{
    if ((lightInfo == NULL) || (count == NULL)) {
        HDF_LOGE("%s:line:%{public}d pointer is null and return ret", __func__, __LINE__);
        return HDF_FAILURE;
    }

    struct LightDevice *priv = GetLightDevicePriv();

    if (priv->lightNum > 0) {
        *count = priv->lightNum;
        *lightInfo = priv->lightInfoEntry;
        return HDF_SUCCESS;
    }

    (void)OsalMutexLock(&priv->mutex);
    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        HDF_LOGE("%s: get sbuf failed", __func__);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    int32_t ret = SendLightMsg(LIGHT_IO_CMD_GET_INFO_LIST, NULL, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Light send cmd failed, ret[%{public}d]", __func__, ret);
        HdfSbufRecycle(reply);
        (void)OsalMutexUnlock(&priv->mutex);
        return ret;
    }

    if (ReadLightInfo(reply, priv) != HDF_SUCCESS) {
        HdfSbufRecycle(reply);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    HdfSbufRecycle(reply);
    (void)OsalMutexUnlock(&priv->mutex);

    *count = priv->lightNum;
    *lightInfo = priv->lightInfoEntry;

    return HDF_SUCCESS;
}

static int32_t OnLightValidityJudgment(uint32_t lightId, struct LightEffect *effect)
{
    if (lightId >= LIGHT_ID_BUTT) {
        HDF_LOGE("%{public}s: id not supported", __func__);
        return LIGHT_NOT_SUPPORT;
    }

    if (effect->flashEffect.flashMode < LIGHT_FLASH_NONE || effect->flashEffect.flashMode > LIGHT_FLASH_BLINK) {
        HDF_LOGE("%{public}s: flashMode not supported", __func__);
        return LIGHT_NOT_FLASH;
    }

    if ((effect->flashEffect.flashMode == LIGHT_FLASH_BLINK) && (effect->flashEffect.onTime == 0 ||
        effect->flashEffect.offTime == 0)) {
        HDF_LOGE("%{public}s: flashMode not supported", __func__);
        return LIGHT_NOT_FLASH;
    }

    return LIGHT_SUCCESS;
}

static int32_t OnLight(uint32_t lightId, struct LightEffect *effect)
{
    int32_t ret;

    if (effect == NULL) {
        HDF_LOGE("%{public}s: effect is NULL", __func__);
        return HDF_FAILURE;
    }

    ret = OnLightValidityJudgment(lightId, effect);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: effect is false", __func__);
        return ret;
    }

    struct LightDevice *priv = GetLightDevicePriv();
    (void)OsalMutexLock(&priv->mutex);

    struct HdfSBuf *msg = HdfSbufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("%{public}s: Failed to obtain sBuf size", __func__);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, lightId)) {
        HDF_LOGE("%{public}s: Light write id failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, LIGHT_OPS_IO_CMD_ENABLE)) {
        HDF_LOGE("%{public}s: Light write enable failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteBuffer(msg, effect, sizeof(*effect))) {
        HDF_LOGE("%{public}s: Light write enable failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    ret = SendLightMsg(LIGHT_IO_CMD_OPS, msg, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Light enable failed, ret[%{public}d]", __func__, ret);
    }
    HdfSbufRecycle(msg);
    (void)OsalMutexUnlock(&priv->mutex);

    if (memcpy_s(&g_lightEffect, sizeof(g_lightEffect), effect, sizeof(*effect)) != EOK) {
        HDF_LOGE("%{public}s: Light effect cpy faild", __func__);
        return HDF_FAILURE;
    }

    g_lightState[lightId] = LIGHT_ON;

    return ret;
}

static int32_t OnMultiLightsValidityJudgment(uint32_t lightId, const struct LightColor *colors, const uint32_t count)
{
    if (lightId >= LIGHT_ID_BUTT) {
        HDF_LOGE("%{public}s: id not supported", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    if (colors == NULL) {
        HDF_LOGE("%{public}s: colors is nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (count == 0 || count > MULTI_LIGHT_MAX_NUMBER) {
        HDF_LOGE("%{public}s: count out of range", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t OnMultiLights(uint32_t lightId, const struct LightColor *colors, const uint32_t count)
{
    int32_t ret;
    struct HdfSBuf *sbuf = NULL;

    ret = OnMultiLightsValidityJudgment(lightId, colors, count);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: effect is false", __func__);
        return ret;
    }

    struct LightDevice *priv = GetLightDevicePriv();
    (void)OsalMutexLock(&priv->mutex);

    sbuf = HdfSbufObtain(sizeof(struct LightColor) * count);
    if (sbuf == NULL) {
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    if (!HdfSbufWriteInt32(sbuf, lightId)) {
        HDF_LOGE("%{public}s: light write id failed", __func__);
        ret = HDF_FAILURE;
        goto EXIT;
    }

    if (!HdfSbufWriteInt32(sbuf, LIGHT_OPS_IO_CMD_ENABLE_MULTI_LIGHTS)) {
        HDF_LOGE("%{public}s: light write cmd failed", __func__);
        ret = HDF_FAILURE;
        goto EXIT;
    }

    if (!HdfSbufWriteBuffer(sbuf, colors, sizeof(*colors))) {
        HDF_LOGE("%{public}s: light write buf failed", __func__);
        ret = HDF_FAILURE;
        goto EXIT;
    }

    if (!HdfSbufWriteInt32(sbuf, count)) {
        HDF_LOGE("%{public}s: light write count failed", __func__);
        ret = HDF_FAILURE;
        goto EXIT;
    }

    ret = SendLightMsg(LIGHT_IO_CMD_OPS, sbuf, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: light enable failed, ret[%{public}d]", __func__, ret);
    }

EXIT:
    HdfSbufRecycle(sbuf);
    (void)OsalMutexUnlock(&priv->mutex);

    if (memcpy_s(&(g_lightEffect.lightColor), sizeof(g_lightEffect.lightColor),
        colors, sizeof(*colors)) != EOK) {
        HDF_LOGE("%{public}s: Light colors cpy faild", __func__);
        return HDF_FAILURE;
    }

    g_lightState[lightId] = LIGHT_ON;

    return ret;
}

static int32_t OffLight(uint32_t lightId)
{
    if (lightId >= LIGHT_ID_BUTT) {
        HDF_LOGE("%{public}s: id not supported", __func__);
        return HDF_FAILURE;
    }

    struct LightDevice *priv = GetLightDevicePriv();
    (void)OsalMutexLock(&priv->mutex);

    struct HdfSBuf *msg = HdfSbufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("%{public}s: Failed to obtain sBuf", __func__);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, lightId)) {
        HDF_LOGE("%{public}s: Light write id failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, LIGHT_OPS_IO_CMD_DISABLE)) {
        HDF_LOGE("%{public}s: Light write disable failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    int32_t ret = SendLightMsg(LIGHT_IO_CMD_OPS, msg, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Light disable failed, ret[%{public}d]", __func__, ret);
    }
    HdfSbufRecycle(msg);
    (void)OsalMutexUnlock(&priv->mutex);

    g_lightState[lightId] = LIGHT_OFF;

    return ret;
}

const struct LightInterface *NewLightInterfaceInstance(void)
{
    static struct LightInterface lightDevInstance;
    struct LightDevice *priv = GetLightDevicePriv();

    if (priv->initState) {
        return &lightDevInstance;
    }

    OsalMutexInit(&priv->mutex);
    lightDevInstance.GetLightInfo = GetLightInfo;
    lightDevInstance.TurnOnLight = OnLight;
    lightDevInstance.TurnOffLight = OffLight;
    lightDevInstance.TurnOnMultiLights = OnMultiLights;

    priv->ioService = HdfIoServiceBind(LIGHT_SERVICE_NAME);
    if (priv->ioService == NULL) {
        HDF_LOGE("%s: get light ioService failed", __func__);
        OsalMutexDestroy(&priv->mutex);
        return NULL;
    }

    priv->initState = true;
    HDF_LOGI("get light devInstance success");

    return &lightDevInstance;
}

int32_t FreeLightInterfaceInstance(void)
{
    struct LightDevice *priv = GetLightDevicePriv();

    if (!priv->initState) {
        HDF_LOGI("%s: light instance had released", __func__);
        return HDF_SUCCESS;
    }

    priv->lightNum = 0;

    if (priv->ioService != NULL) {
        HdfIoServiceRecycle(priv->ioService);
    }

    if (priv->lightInfoEntry != NULL) {
        OsalMemFree(priv->lightInfoEntry);
        priv->lightInfoEntry = NULL;
    }

    OsalMutexDestroy(&priv->mutex);

    return HDF_SUCCESS;
}