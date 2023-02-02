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

#include "alsa_lib_common.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_LIB

static int32_t AlsaControls(char *cardCtlName, const char *pathName, uint32_t *numId)
{
    int ret;
    snd_hctl_t *handle = NULL;
    snd_hctl_elem_t *elem = NULL;
    snd_ctl_elem_id_t *id = NULL;
    snd_ctl_elem_info_t *info = NULL;

    if (cardCtlName == NULL || pathName == NULL || numId == NULL) {
        AUDIO_FUNC_LOGE("The parameter is NULL!");
        return HDF_FAILURE;
    }

    snd_ctl_elem_id_alloca(&id);
    snd_ctl_elem_info_alloca(&info);
    if (id == NULL || info == NULL) {
        AUDIO_FUNC_LOGE("alloca failed!");
        return HDF_FAILURE;
    }
    if ((ret = snd_hctl_open(&handle, cardCtlName, 0)) < 0) {
        AUDIO_FUNC_LOGE("Control %{public}s open error: %{public}s", cardCtlName, snd_strerror(ret));
        return ret;
    }
    if ((ret = snd_hctl_load(handle)) < 0) {
        AUDIO_FUNC_LOGE("Control %{public}s local error: %{public}s\n", cardCtlName, snd_strerror(ret));
        return ret;
    }
    /* Obtain the path information of the sound card in the control node */
    for (elem = snd_hctl_first_elem(handle); elem != NULL; elem = snd_hctl_elem_next(elem)) {
        if ((ret = snd_hctl_elem_info(elem, info)) < 0) {
            AUDIO_FUNC_LOGE("Control %{public}s snd_hctl_elem_info error: %{public}s.", cardCtlName, snd_strerror(ret));
            return ret;
        }
        if (snd_ctl_elem_info_is_inactive(info)) {
            continue;
        }
        snd_hctl_elem_get_id(elem, id);
        const char *name = snd_ctl_elem_id_get_name(id);
        if (strncmp(name, pathName, strlen(pathName)) == 0) {
            *numId = snd_ctl_elem_id_get_numid(id);
            (void)snd_hctl_close(handle);
            return ret;
        }
    }
    AUDIO_FUNC_LOGE("The set ctlName was not found!");
    (void)snd_hctl_close(handle);
    return HDF_FAILURE;
}

static int32_t AudioCtlElemWrite(const char *ctlName, uint32_t numId, uint32_t item)
{
    int32_t ret;
    snd_ctl_t *ctlHandle = NULL;
    snd_ctl_elem_value_t *ctlElemValue = NULL;

    if (ctlName == NULL) {
        AUDIO_FUNC_LOGE("The parameter is NULL!");
        return HDF_FAILURE;
    }
    ret = snd_ctl_elem_value_malloc(&ctlElemValue);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snd_ctl_elem_value_malloc error: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }

    ret = snd_ctl_open(&ctlHandle, ctlName, 0);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snd_ctl_open error: %{public}s", snd_strerror(ret));
        snd_ctl_elem_value_free(ctlElemValue);
        return HDF_FAILURE;
    }
    snd_ctl_elem_value_set_numid(ctlElemValue, numId);
    snd_ctl_elem_value_set_interface(ctlElemValue, SND_CTL_ELEM_IFACE_MIXER);
    snd_ctl_elem_value_set_integer(ctlElemValue, 0, item); // 0 is index of the member
    ret = snd_ctl_elem_write(ctlHandle, ctlElemValue);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snd_ctl_elem_write error: %{public}s", snd_strerror(ret));
    }

    snd_ctl_elem_value_free(ctlElemValue);
    (void)snd_ctl_close(ctlHandle);
    return ret;
}

int32_t EnableAudioRenderRoute(const struct AudioHwRenderParam *renderData)
{
    struct AudioCardInfo *cardIns = NULL;
    uint32_t numId;
    const char *pathName = NULL;
    int32_t itemValue;
    if (renderData == NULL) {
        AUDIO_FUNC_LOGE("The parameter is NULL!");
        return HDF_FAILURE;
    }

    const char *adapterName = renderData->renderMode.hwInfo.adapterName;
    cardIns = AudioGetCardInstance(adapterName);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("AudioRenderGetCardIns failed.");
        return HDF_FAILURE;
    }

    int32_t devCount = renderData->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (devCount < 0 || devCount > PATHPLAN_COUNT - 1) {
        AUDIO_FUNC_LOGE("devCount is error!");
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < devCount; i++) {
        pathName = renderData->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[i].deviceSwitch;
        itemValue = renderData->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[i].value;
        if (AlsaControls(cardIns->ctrlName, pathName, &numId) < 0) {
            AUDIO_FUNC_LOGE("AlsaControls failed, pathName: %{public}s.", pathName);
            return HDF_FAILURE;
        }
        if (AudioCtlElemWrite(cardIns->ctrlName, numId, itemValue) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("AudioCtlElemWrite failed.");
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t EnableAudioCaptureRoute(const struct AudioHwCaptureParam *captureData)
{
    uint32_t numId;
    int32_t itemValue;
    struct AudioCardInfo *cardIns = NULL;
    const char *capturePathName = NULL;

    if (captureData == NULL) {
        AUDIO_FUNC_LOGE("The parameter is NULL!");
        return HDF_FAILURE;
    }

    const char *adapterName = captureData->captureMode.hwInfo.adapterName;
    cardIns = AudioGetCardInstance(adapterName);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("AudioCaptureGetCardIns failed.");
        return HDF_FAILURE;
    }

    int32_t devCount = captureData->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (devCount < 0 || devCount > PATHPLAN_COUNT - 1) {
        AUDIO_FUNC_LOGE("deviceIndex is error!");
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < devCount; i++) {
        capturePathName = captureData->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[i].deviceSwitch;
        itemValue = captureData->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[i].value;
        if (AlsaControls(cardIns->ctrlName, capturePathName, &numId) < 0) {
            AUDIO_FUNC_LOGE("AlsaControls failed, pathName: %{public}s!", capturePathName);
            return HDF_FAILURE;
        }
        if (AudioCtlElemWrite(cardIns->ctrlName, numId, itemValue) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("AudioCtlElemWrite failed!");
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}
