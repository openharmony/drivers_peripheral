/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "light_dump.h"
#include <securec.h>
#include <stdio.h>
#include "devhost_dump_reg.h"
#include "hdf_base.h"
#include "light_uhdf_log.h"
#include "light_controller.h"
#include "light_type.h"

#define HDF_LOG_TAG    uhdf_light_service

#define STRING_LEN    1024

static const char *g_dumpHelp =
    " usage:\n"
    " -h, --help: dump help\n"
    " -c, --channel: dump the light channel info\n";

static int32_t ShowLightInfo(struct HdfSBuf *reply)
{
    uint32_t i;
    int32_t ret;
    uint8_t *lightState = NULL;
    struct LightDevice *lightDevice = NULL;
    char lightInfo[STRING_LEN] = {0};

    lightState = GetLightState();
    if (lightState == NULL) {
        HDF_LOGE("%{public}s: get light state failed", __func__);
        return HDF_FAILURE;
    }

    lightDevice = GetLightDevicePriv();
    if (lightDevice == NULL || lightDevice->lightInfoEntry == NULL ||
        lightDevice->lightNum == 0) {
        HDF_LOGE("%{public}s: get light device info failed", __func__);
        return HDF_FAILURE;
    }
    for (i = 0; i < lightDevice->lightNum; i++) {
        ret = memset_s(lightInfo, STRING_LEN, 0, STRING_LEN);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: memset sensorInfoList is failed\n", __func__);
            return HDF_FAILURE;
        }

        ret = sprintf_s(lightInfo, STRING_LEN,
            " lightId: %u\n state: %hhu\n lightNumber: %u\n lightName: %s\n lightType: %d\n",
            lightDevice->lightInfoEntry->lightId,
            lightState[lightDevice->lightInfoEntry->lightId],
            lightDevice->lightInfoEntry->lightNumber,
            lightDevice->lightInfoEntry->lightName,
            lightDevice->lightInfoEntry->lightType);
        if (ret < 0) {
            HDF_LOGE("%{public}s: sprintf light info failed", __func__);
            return HDF_FAILURE;
        }

        if (!HdfSbufWriteString(reply, lightInfo)) {
            HDF_LOGE("%{public}s: write lightInfo failed", __func__);
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

static int32_t ShowLightEffectInfo(struct HdfSBuf *reply)
{
    int32_t ret;
    struct LightEffect *lightEffect = NULL;
    char lightEffectInfo[STRING_LEN] = {0};

    lightEffect = GetLightEffect();
    if (lightEffect == NULL) {
        HDF_LOGE("%{public}s: get light effect info failed", __func__);
        return HDF_FAILURE;
    }

    ret = memset_s(lightEffectInfo, STRING_LEN, 0, STRING_LEN);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: memset sensorInfoList is failed\n", __func__);
        return HDF_FAILURE;
    }

    ret = sprintf_s(lightEffectInfo, STRING_LEN,
        " r: %hhu\n g: %hhu\n b: %hhu\n flashMode: %d\n onTime: %d\n offTime: %d\n",
        lightEffect->lightColor.colorValue.rgbColor.r,
        lightEffect->lightColor.colorValue.rgbColor.g,
        lightEffect->lightColor.colorValue.rgbColor.b,
        lightEffect->flashEffect.flashMode,
        lightEffect->flashEffect.onTime,
        lightEffect->flashEffect.offTime);
    if (ret < 0) {
        HDF_LOGE("%{public}s: sprintf light effect info failed", __func__);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(reply, lightEffectInfo)) {
        HDF_LOGE("%{public}s: write lightEffectInfo failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t DumpLightChannel(struct HdfSBuf *reply)
{
    int32_t ret;

    ret = ShowLightInfo(reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: show light info failed", __func__);
        return HDF_FAILURE;
    }

    ret = ShowLightEffectInfo(reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: show light effect info failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t LightDriverDump(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t i;
    uint32_t argv = 0;

    if (data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(data, &argv)) {
        HDF_LOGE("%{public}s: read argv failed", __func__);
        return HDF_FAILURE;
    }

    if (argv == 0) {
        if (!HdfSbufWriteString(reply, g_dumpHelp)) {
            HDF_LOGE("%{public}s: write -h failed", __func__);
            return HDF_FAILURE;
        }
    }

    for (i = 0; i < argv; i++) {
        const char *value = HdfSbufReadString(data);
        if (value == NULL) {
            HDF_LOGE("%{public}s value is invalid", __func__);
            return HDF_FAILURE;
        }

        if (strcmp(value, "-h") == HDF_SUCCESS) {
            if (!HdfSbufWriteString(reply, g_dumpHelp)) {
                HDF_LOGE("%{public}s: write -h failed", __func__);
                return HDF_FAILURE;
            }
            continue;
        } else if (strcmp(value, "-c") == HDF_SUCCESS) {
            DumpLightChannel(reply);
            continue;
        }
    }

    return HDF_SUCCESS;
}

int32_t GetLightDump(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret = LightDriverDump(data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get light dump failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
