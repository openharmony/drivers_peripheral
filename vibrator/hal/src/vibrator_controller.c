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
#include "vibrator_uhdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG uhdf_vibrator_service
#define EFFECT_SUN 64
#define EFFECT_DURATION 2000
#define VIBRATOR_SERVICE_NAME "hdf_misc_vibrator"
#define DEFAULT_START_UP_TIME 20

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

    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);
    CHECK_NULL_PTR_RETURN_VALUE(priv->ioService, HDF_FAILURE);
    CHECK_NULL_PTR_RETURN_VALUE(priv->ioService->dispatcher, HDF_FAILURE);
    CHECK_NULL_PTR_RETURN_VALUE(priv->ioService->dispatcher->Dispatch, HDF_FAILURE);

    int32_t ret = priv->ioService->dispatcher->Dispatch(&priv->ioService->object, cmd, msg, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Vibrator dispatch failed", __func__);
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t ReadVibratorInfo(struct HdfSBuf *reply, struct VibratorDevice *priv)
{
    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);
    uint32_t len;
    struct VibratorInfo *buf = NULL;

    if (!HdfSbufReadBuffer(reply, (const void **)&buf, &len)) {
        return HDF_FAILURE;
    }

    if (buf == NULL || len != sizeof(struct VibratorInfo)) {
        HDF_LOGE("%{public}s: read size is error, len = %{public}d, size = %{public}zu\n",\
            __func__, len, sizeof(struct VibratorInfo));
        return HDF_FAILURE;
    }

    if (memcpy_s(&priv->vibratorInfoEntry, sizeof(priv->vibratorInfoEntry), buf, sizeof(*buf)) != EOK) {
        HDF_LOGE("%s: Memcpy buf failed", __func__);
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

    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);

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
    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);
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
    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);

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
    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);

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

static int32_t GetEffectInfo(const char *effect, struct EffectInfo *effectInfo)
{
    CHECK_NULL_PTR_RETURN_VALUE(effectInfo, HDF_FAILURE);
    for (int i = 0; i < EFFECT_TYPE_MAX; i++) {
        if (!strcmp(effect, g_effectmap[i].effectName)) {
            effectInfo->isSupportEffect = g_effectmap[i].issupport;
            effectInfo->duration = g_effectmap[i].duration;
        }
    }
    return HDF_SUCCESS;
}

static int32_t Stop(enum VibratorMode mode)
{
    if (mode < VIBRATOR_MODE_ONCE || mode >= VIBRATOR_MODE_BUTT) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (mode == VIBRATOR_MODE_HDHAPTIC) {
        return HDF_ERR_NOT_SUPPORT;
    }
    int32_t ret;
    struct VibratorDevice *priv = GetVibratorDevicePriv();
    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);

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

static int32_t PlayHapticPattern(struct HapticPaket *pkg)
{
    (void)pkg;
    return HDF_SUCCESS;
}

static int32_t GetHapticCapacity(struct HapticCapacity *hapticCapacity)
{
    (void)hapticCapacity;
    return HDF_SUCCESS;
}

static int32_t GetHapticStartUpTime(int32_t mode, int32_t *startUpTime)
{
    *startUpTime = DEFAULT_START_UP_TIME;
    HDF_LOGE("%{public}s: mode = %{public}d", __func__, mode);
    HDF_LOGE("%{public}s: startUpTime = %{public}d", __func__, *startUpTime);
    return HDF_SUCCESS;
}

static int32_t IsVibratorRunning(bool *state)
{
    HDF_LOGI("%{public}s: in", __func__);
    int32_t ret;
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);

    (void)OsalMutexLock(&priv->mutex);
    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        HDF_LOGE("%s: get sbuf failed", __func__);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    ret = SendVibratorMsg(VIBRATOR_IO_IS_VIBRATOR_RUNNING, NULL, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Vibrator send cmd failed, ret[%{public}d]", __func__, ret);
        HdfSbufRecycle(reply);
        (void)OsalMutexUnlock(&priv->mutex);
        return ret;
    }

    int32_t stateNum;
    if (HdfSbufReadInt32(reply, &stateNum) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSbufReadInt32 failed", __func__);
        HdfSbufRecycle(reply);
        (void)OsalMutexUnlock(&priv->mutex);
        return HDF_FAILURE;
    }

    *state = stateNum;
    HdfSbufRecycle(reply);
    (void)OsalMutexUnlock(&priv->mutex);

    HDF_LOGI("%{public}s: *state %{public}d", __func__, *state);

    return HDF_SUCCESS;
}

const struct VibratorInterface *NewVibratorInterfaceInstance(void)
{
    static struct VibratorInterface vibratorDevInstance;
    struct VibratorDevice *priv = GetVibratorDevicePriv();

    if (priv == NULL) {
        return &vibratorDevInstance;
    }
    if (priv->initState) {
        return &vibratorDevInstance;
    }

    OsalMutexInit(&priv->mutex);
    vibratorDevInstance.Start = Start;
    vibratorDevInstance.StartOnce = StartOnce;
    vibratorDevInstance.Stop = Stop;
    vibratorDevInstance.GetVibratorInfo = GetVibratorInfo;
    vibratorDevInstance.GetEffectInfo = GetEffectInfo;
    vibratorDevInstance.EnableVibratorModulation = EnableVibratorModulation;
    vibratorDevInstance.PlayHapticPattern = PlayHapticPattern;
    vibratorDevInstance.GetHapticCapacity = GetHapticCapacity;
    vibratorDevInstance.GetHapticStartUpTime = GetHapticStartUpTime;
    vibratorDevInstance.IsVibratorRunning = IsVibratorRunning;

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

    CHECK_NULL_PTR_RETURN_VALUE(priv, HDF_FAILURE);

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