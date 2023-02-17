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

#include "vibrator_controller.h"
#include <securec.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG              uhdf_vibrator
#define EFFECT_SUN 64
#define VIBRATOR_SERVICE_NAME    "hdf_misc_vibrator"

static struct VibratorDevice *GetVibratorDevicePriv(void)
{
    static struct VibratorDevice vibratorDeviceData = {
        .initState = false,
        .ioService = NULL,
    };

    return &vibratorDeviceData;
}

static int32_t SendVibratorMsg(uint32_t cmd, struct HdfSBuf *msg, struct HdfSBuf *reply)
{
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    if (priv->ioService == NULL || priv->ioService->dispatcher == NULL ||
        priv->ioService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%s: para invalid", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = priv->ioService->dispatcher->Dispatch(&priv->ioService->object, cmd, msg, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Vibrator dispatch failed", __func__);
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t ReadVibratorInfo(struct HdfSBuf *reply, struct VibratorDevice *priv)
{
    uint32_t len;
    struct VibratorInfo *buf = NULL;

    if (!HdfSbufReadBuffer(reply, (const void **)&buf, &len)) {
        return HDF_FAILURE;
    }

    if (buf == NULL || len != sizeof(struct VibratorInfo)) {
        HDF_LOGE("%{public}s: read size is error, len = %{public}d, size = %{public}zu\n",\
            __func__, len, sizeof(struct VibratorInfo));
        HdfSbufRecycle(reply);
        return HDF_FAILURE;
    }

    if (memcpy_s(&priv->vibratorInfoEntry, sizeof(priv->vibratorInfoEntry), buf, sizeof(*buf)) != EOK) {
        HDF_LOGE("%s: Memcpy buf failed", __func__);
        HdfSbufRecycle(reply);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t GetVibratorInfo(struct VibratorInfo **vibratorInfo)
{
    int32_t ret;
    if (vibratorInfo == NULL) {
        HDF_LOGE("%s:line:%{public}d pointer is null and return ret", __func__, __LINE__);
        return HDF_FAILURE;
    }
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    (void)OsalMutexLock(&priv->mutex);
    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        HDF_LOGE("%s: get sbuf failed", __func__);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    ret = SendVibratorMsg(VIBRATOR_IO_GET_INFO, NULL, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Vibrator send cmd failed, ret[%{public}d]", __func__, ret);
        HdfSbufRecycle(reply);
        (void)OsalMutexUnlock(&priv->mutex);
        return ret;
    }

    if (ReadVibratorInfo(reply, priv) != HDF_SUCCESS) {
        HdfSbufRecycle(reply);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    HdfSbufRecycle(reply);
    (void)OsalMutexUnlock(&priv->mutex);

    *vibratorInfo = &priv->vibratorInfoEntry;

    return HDF_SUCCESS;
}

static int32_t ValidityJudgment(uint32_t duration, uint16_t intensity, int16_t frequency)
{
    struct VibratorDevice *priv = GetVibratorDevicePriv();
    if (duration == 0) {
        HDF_LOGE("%s:invalid vibration period", __func__);
        return VIBRATOR_NOT_PERIOD;
    }

    if ((priv->vibratorInfoEntry.isSupportIntensity == 0) || (intensity < priv->vibratorInfoEntry.intensityMinValue) ||
        (intensity > priv->vibratorInfoEntry.intensityMaxValue)) {
        HDF_LOGE("%s:intensity not supported", __func__);
        return VIBRATOR_NOT_INTENSITY;
    }

    if ((priv->vibratorInfoEntry.isSupportFrequency == 0) || (frequency < priv->vibratorInfoEntry.frequencyMinValue) ||
        (frequency > priv->vibratorInfoEntry.frequencyMaxValue)) {
        HDF_LOGE("%s:frequency not supported", __func__);
        return VIBRATOR_NOT_FREQUENCY;
    }

    return VIBRATOR_SUCCESS;
}

static int32_t EnableVibratorModulation(uint32_t duration, uint16_t intensity, int16_t frequency)
{
    int32_t ret;
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    ret = ValidityJudgment(duration, intensity, frequency);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: effect is false", __func__);
        return ret;
    }

    (void)OsalMutexLock(&priv->mutex);
    struct HdfSBuf *msg = HdfSbufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("%{public}s: get sbuf failed", __func__);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(msg, duration)) {
        HDF_LOGE("%{public}s: write duration failed.", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint16(msg, intensity)) {
        HDF_LOGE("%{public}s: write intensity failed.", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt16(msg, frequency)) {
        HDF_LOGE("%{public}s: write frequency failed.", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }
    ret = SendVibratorMsg(VIBRATOR_IO_ENABLE_MODULATION_PARAMETER, msg, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Vibrator send cmd failed, ret[%{public}d]", __func__, ret);
    }
    HdfSbufRecycle(msg);
    (void)OsalMutexUnlock(&priv->mutex);

    return ret;
}

static int32_t StartOnce(uint32_t duration)
{
    int32_t ret;
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    if (duration == 0) {
        HDF_LOGE("%s:invalid duration para", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    (void)OsalMutexLock(&priv->mutex);
    struct HdfSBuf *msg = HdfSbufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("%s: get sbuf failed", __func__);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(msg, duration)) {
        HDF_LOGE("%s: write duration failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    ret = SendVibratorMsg(VIBRATOR_IO_START_ONCE, msg, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Vibrator send cmd failed, ret[%{public}d]", __func__, ret);
    }
    HdfSbufRecycle(msg);
    (void)OsalMutexUnlock(&priv->mutex);

    return ret;
}

static int32_t Start(const char *effect)
{
    int32_t ret;
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    if (effect == NULL) {
        HDF_LOGE("%s: start vibrator effect type invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    (void)OsalMutexLock(&priv->mutex);
    struct HdfSBuf *msg = HdfSbufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("%s: get sbuf failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(msg, effect)) {
        HDF_LOGE("%s: write effectName failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    ret = SendVibratorMsg(VIBRATOR_IO_START_EFFECT, msg, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Vibrator send cmd failed, ret[%{public}d]", __func__, ret);
    }
    HdfSbufRecycle(msg);
    (void)OsalMutexUnlock(&priv->mutex);

    return ret;
}

static int32_t Stop(enum VibratorMode mode)
{
    int32_t ret;
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    (void)OsalMutexLock(&priv->mutex);
    struct HdfSBuf *msg = HdfSbufObtainDefaultSize();
    if (msg == NULL) {
        HDF_LOGE("%s: get sbuf failed", __func__);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(msg, mode)) {
        HDF_LOGE("%s: write mode failed", __func__);
        HdfSbufRecycle(msg);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    ret = SendVibratorMsg(VIBRATOR_IO_STOP, msg, NULL);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Vibrator send cmd failed, ret[%{public}d]", __func__, ret);
    }
    HdfSbufRecycle(msg);
    (void)OsalMutexUnlock(&priv->mutex);

    return ret;
}

const struct VibratorInterface *NewVibratorInterfaceInstance(void)
{
    static struct VibratorInterface vibratorDevInstance;
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    if (priv->initState) {
        return &vibratorDevInstance;
    }

    OsalMutexInit(&priv->mutex);
    vibratorDevInstance.Start = Start;
    vibratorDevInstance.StartOnce = StartOnce;
    vibratorDevInstance.Stop = Stop;
    vibratorDevInstance.GetVibratorInfo = GetVibratorInfo;
    vibratorDevInstance.EnableVibratorModulation = EnableVibratorModulation;

    priv->ioService = HdfIoServiceBind(VIBRATOR_SERVICE_NAME);
    if (priv->ioService == NULL) {
        HDF_LOGE("%s: get vibrator ioService failed", __func__);
        OsalMutexDestroy(&priv->mutex);
        return NULL;
    }

    priv->initState = true;
    HDF_LOGD("get vibrator devInstance success");
    return &vibratorDevInstance;
}

int32_t FreeVibratorInterfaceInstance(void)
{
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    if (!priv->initState) {
        HDF_LOGD("%s: vibrator instance had released", __func__);
        return HDF_SUCCESS;
    }

    if (priv->ioService != NULL) {
        HdfIoServiceRecycle(priv->ioService);
    }

    OsalMutexDestroy(&priv->mutex);

    return HDF_SUCCESS;
}