/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "alsa_lib_render.h"
#include "audio_common.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_LIB

#define MAX_PERIOD_SIZE            (8 * 1024)
#define MIN_PERIOD_SIZE            (4 * 1024)
#define AUDIO_RENDER_RECOVER_DELAY (10 * 1000)

static snd_pcm_sframes_t g_bufferSize = 0;
static snd_pcm_sframes_t g_periodSize = 0;
static unsigned int g_bufferTime = 500000; /* (0.5s): ring buffer length in us */
static unsigned int g_periodTime = 100000; /* (0.1s): period time in us */
static int g_resample = 1;                 /* enable alsa-lib resampling */
static bool g_periodEvent = false;              /* produce poll event after each period */
static int g_canPause = 0;                 /* 0 Hardware doesn't support pause, 1 Hardware supports pause */

static int32_t GetHwParams(struct AudioCardInfo *cardIns, const struct AudioHwRenderParam *handleData)
{
    if (cardIns == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    cardIns->hwRenderParams.streamType = AUDIO_RENDER_STREAM;
    cardIns->hwRenderParams.channels = handleData->frameRenderMode.attrs.channelCount;
    cardIns->hwRenderParams.rate = handleData->frameRenderMode.attrs.sampleRate;
    cardIns->hwRenderParams.periodSize = handleData->frameRenderMode.periodSize;
    cardIns->hwRenderParams.periodCount = handleData->frameRenderMode.periodCount;
    cardIns->hwRenderParams.format = handleData->frameRenderMode.attrs.format;
    cardIns->hwRenderParams.period = handleData->frameRenderMode.attrs.period;
    cardIns->hwRenderParams.frameSize = handleData->frameRenderMode.attrs.frameSize;
    cardIns->hwRenderParams.isBigEndian = handleData->frameRenderMode.attrs.isBigEndian;
    cardIns->hwRenderParams.isSignedData = handleData->frameRenderMode.attrs.isSignedData;
    cardIns->hwRenderParams.startThreshold = handleData->frameRenderMode.attrs.startThreshold;
    cardIns->hwRenderParams.stopThreshold = handleData->frameRenderMode.attrs.stopThreshold;
    cardIns->hwRenderParams.silenceThreshold = handleData->frameRenderMode.attrs.silenceThreshold;
    return HDF_SUCCESS;
}

static int32_t AudioSetMixerVolume(snd_mixer_elem_t *pcmElemen, long vol)
{
    int32_t ret;

    if (pcmElemen == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    // Judge whether it is mono or stereo
    if (snd_mixer_selem_is_playback_mono(pcmElemen)) {
        ret = snd_mixer_selem_set_playback_volume(pcmElemen, SND_MIXER_SCHN_FRONT_LEFT, vol);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("AudioSetMixerVolume failed: %{public}s.", snd_strerror(ret));
            return HDF_FAILURE;
        }
    } else {
        ret = snd_mixer_selem_set_playback_volume_all(pcmElemen, vol);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("AudioSetMixerVolume failed: %{public}s.", snd_strerror(ret));
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetVolume(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    long vol;
    int32_t ret;
    struct AudioCardInfo *cardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameters!!");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    cardIns = GetCardIns(adapterName);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("Get card instance failed!");
        return HDF_FAILURE;
    }

    vol = (long)handleData->renderMode.ctlParam.volume;
    if (cardIns->ctrlLeftVolume != NULL) {
        ret = AudioSetMixerVolume(cardIns->ctrlLeftVolume, vol);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("AudioSetMixerVolume left fail!");
            return HDF_FAILURE;
        }
    }

    if (cardIns->ctrlRightVolume != NULL) {
        ret = AudioSetMixerVolume(cardIns->ctrlRightVolume, vol);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("AudioSetMixerVolume right fail!");
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

static int32_t AudioRenderGetVolumeSub(struct AudioCardInfo *cardIns, long *vol)
{
    long volLeft = MIN_VOLUME;
    long volRight = MIN_VOLUME;

    if (cardIns == NULL || vol == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    if (cardIns->ctrlLeftVolume == NULL || cardIns->mixer == NULL) {
        AUDIO_FUNC_LOGE("cardIns's ctrlLeftVolume or mixer is null!");
        return HDF_FAILURE;
    }

    // Handling events
    int32_t ret = snd_mixer_handle_events(cardIns->mixer);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snd_mixer_handle_events fail!");
        return HDF_FAILURE;
    }

    // Left channel
    ret = snd_mixer_selem_get_playback_volume(cardIns->ctrlLeftVolume, SND_MIXER_SCHN_FRONT_LEFT, &volLeft);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set left channel fail!");
        return HDF_FAILURE;
    }
    // right channel
    ret = snd_mixer_selem_get_playback_volume(cardIns->ctrlLeftVolume, SND_MIXER_SCHN_FRONT_RIGHT, &volRight);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set right channel fail!");
        return HDF_FAILURE;
    }
    *vol = (volLeft + volRight) >> 1;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolume(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    long vol;
    struct AudioCardInfo *cardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    cardIns = GetCardIns(adapterName);
    ret = AudioRenderGetVolumeSub(cardIns, &vol);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioRenderGetVolumeSub failed!");
        return HDF_FAILURE;
    }

    handleData->renderMode.ctlParam.volume = (float)vol;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetPauseStu(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    /* The hardware does not support pause/resume,
     * so a success message is returned.
     * The software processing scheme is implemented
     * in AudioOutputRenderWrite interface.
     */
    return HDF_SUCCESS;
}

static int32_t RenderSetMuteStuSub(struct AudioCardInfo *cardIns, int32_t muteState)
{
    int32_t ret;

    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("cardIns is NULL!");
        return HDF_FAILURE;
    }

    /* Mono (Front left alias) */
    if (cardIns->ctrlLeftVolume == NULL) {
        AUDIO_FUNC_LOGE("Unable to get Mono.");
        return HDF_FAILURE;
    }

    ret = snd_mixer_selem_has_playback_switch(cardIns->ctrlLeftVolume);
    if (ret == 1) { // 1: Controlled switch
        ret = snd_mixer_selem_set_playback_switch_all(cardIns->ctrlLeftVolume, muteState);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Unable to play mixer  switch ");
            return HDF_FAILURE;
        }
    } else { // 0: no control
        AUDIO_FUNC_LOGE("it's no control is present");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioPrimarySetMuteState(struct AudioCardInfo *cardIns, int32_t muteState, float volume)
{
    long vol;
    long alsaVol;
    float volRangeMin = 0.0;
    float volRangeMax = 100.0;
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("cardIns is NULL!");
        return HDF_FAILURE;
    }
    int32_t ret = RenderSetMuteStuSub(cardIns, muteState);
    /* ret return HDF_FAILURE : no control is present */
    if (ret != HDF_SUCCESS) {
        /* Try to set the volume is 0 to change the mute state */
        ret = AudioRenderGetVolumeSub(cardIns, &vol);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("AudioRenderGetVolumeSub error!");
            return HDF_FAILURE;
        }

        if (muteState == false) {
            alsaVol = 0; /* 0 for mute */
            cardIns->tempVolume = (float)vol;
        } else {
            if (volume > volRangeMin && volume <= volRangeMax) {
                alsaVol = (long)volume;
            } else {
                alsaVol = (long)cardIns->tempVolume;
            }
        }

        if (cardIns->ctrlLeftVolume != NULL) {
            ret = AudioSetMixerVolume(cardIns->ctrlLeftVolume, alsaVol);
            if (ret < 0) {
                AUDIO_FUNC_LOGE("AudioSetMixerVolume left fail!");
                return HDF_FAILURE;
            }
        }

        if (cardIns->ctrlRightVolume != NULL) {
            ret = AudioSetMixerVolume(cardIns->ctrlRightVolume, alsaVol);
            if (ret < 0) {
                AUDIO_FUNC_LOGE("AudioSetMixerVolume right fail!");
                return HDF_FAILURE;
            }
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetMuteStu(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    int32_t muteState;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    struct AudioCardInfo *cardIns = GetCardIns(adapterName);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("GetCardIns error!!!");
        return HDF_FAILURE;
    }

    muteState = cardIns->renderMuteValue;
    if (strncmp(adapterName, PRIMARY, strlen(PRIMARY)) == 0) {
        ret = AudioPrimarySetMuteState(cardIns, muteState, handleData->renderMode.ctlParam.volume);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Render primary sound card SetMute failed!");
            return HDF_FAILURE;
        }
    }

    if (strncmp(adapterName, USB, strlen(USB)) == 0) {
        ret = RenderSetMuteStuSub(cardIns, muteState);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Render usb sound card SetMute failed!");
            return HDF_FAILURE;
        }
    }
    cardIns->renderMuteValue = (int32_t)handleData->renderMode.ctlParam.mute;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetMuteStu(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    struct AudioCardInfo *cardInstance = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    cardInstance = GetCardIns(adapterName);
    if (cardInstance == NULL) {
        AUDIO_FUNC_LOGE("cardInstance is NULL!");
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.mute = (bool)cardInstance->renderMuteValue;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetGainStu(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetGainStu(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneSelect(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    enum AudioPortPin descPins;
    struct AudioCardInfo *cardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameters!");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    cardIns = GetCardIns(adapterName);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("Cant't get card Instance!");
        return HDF_FAILURE;
    }

    descPins = handleData->renderMode.hwInfo.deviceDescript.pins;
    switch (descPins) {
        case PIN_OUT_SPEAKER:
            return AudioMixerSetCtrlMode(
                cardIns, adapterName, "Digital Playback Path", SND_PLAY_PATH, SND_OUT_CARD_SPK);
        case PIN_OUT_HEADSET:
            return AudioMixerSetCtrlMode(cardIns, adapterName, "Digital Playback Path", SND_PLAY_PATH, SND_OUT_CARD_HP);
        default:
            AUDIO_FUNC_LOGE("This mode is not currently supported!");
            break;
    }

    return HDF_FAILURE;
}

int32_t AudioCtlRenderSceneGetGainThreshold(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolThreshold(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    long volMin = MIN_VOLUME;
    long volMax = MIN_VOLUME;
    struct AudioCardInfo *cardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    char *adapterName = handleData->renderMode.hwInfo.adapterName;
    cardIns = GetCardIns(adapterName);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("cardIns is NULL!");
        return HDF_FAILURE;
    }

    ret = snd_mixer_selem_get_playback_volume_range(cardIns->ctrlLeftVolume, &volMin, &volMax);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get playback volume range fail: %{public}s.", snd_strerror(ret));
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.volThreshold.volMin = (int)volMin;
    handleData->renderMode.ctlParam.volThreshold.volMax = (int)volMax;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetChannelMode(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetChannelMode(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibCtlRender(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    if (cmdId < AUDIODRV_CTL_IOCTL_ELEM_INFO || cmdId > AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ) {
        AUDIO_FUNC_LOGE("cmdId Not Supported!");
        return HDF_FAILURE;
    }

    switch (cmdId) {
        case AUDIODRV_CTL_IOCTL_ELEM_READ:
            return (AudioCtlRenderGetVolume(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_ELEM_WRITE:
            return (AudioCtlRenderSetVolume(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_MUTE_READ:
            return (AudioCtlRenderGetMuteStu(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_MUTE_WRITE:
            return (AudioCtlRenderSetMuteStu(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ:
            return (AudioCtlRenderGetChannelMode(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE:
            return (AudioCtlRenderSetChannelMode(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_GAIN_WRITE:
            return (AudioCtlRenderSetGainStu(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_GAIN_READ:
            return (AudioCtlRenderGetGainStu(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE:
            return (AudioCtlRenderSceneSelect(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ:
            return (AudioCtlRenderSceneGetGainThreshold(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ:
            return (AudioCtlRenderGetVolThreshold(handle, cmdId, handleData));
        default:
            AUDIO_FUNC_LOGE("Output Mode not support!");
            break;
    }

    return HDF_FAILURE;
}

static int32_t SetHWParamsSub(
    snd_pcm_t *handle, snd_pcm_hw_params_t *params, struct AudioPcmHwParams hwParams, snd_pcm_access_t access)
{
    int32_t ret;
    snd_pcm_format_t pcmFormat = SND_PCM_FORMAT_S16_LE;

    if (handle == NULL || params == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    /* set hardware resampling */
    ret = snd_pcm_hw_params_set_rate_resample(handle, params, g_resample);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Resampling setup failed for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    /* set the interleaved read/write format */
    ret = snd_pcm_hw_params_set_access(handle, params, access);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Access type not available for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    ret = CheckParaFormat(hwParams, &pcmFormat);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CheckParaFormat error.");
        return HDF_FAILURE;
    }
    /* set the sample format */
    ret = snd_pcm_hw_params_set_format(handle, params, pcmFormat);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Sample format not available for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    /* set the count of channels */
    ret = snd_pcm_hw_params_set_channels(handle, params, hwParams.channels);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Channels count (%{public}u) not available for playbacks: %{public}s", hwParams.channels,
            snd_strerror(ret));
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t SetHWRate(snd_pcm_t *handle, snd_pcm_hw_params_t *params, uint32_t *rate)
{
    int32_t ret;
    uint32_t rRate;
    int dir = 0; /* dir Value range (-1,0,1) */

    if (handle == NULL || params == NULL || rate == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    /* set the stream rate */
    rRate = *rate;
    ret = snd_pcm_hw_params_set_rate_near(handle, params, &rRate, &dir);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Rate %{public}uHz not available for playback: %{public}s.", *rate, snd_strerror(ret));
        return HDF_FAILURE;
    }

    if (rRate != *rate) {
        ret = snd_pcm_hw_params_set_rate_near(handle, params, &rRate, &dir);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Rate %{public}uHz not available for playback: %{public}s.", *rate, snd_strerror(ret));
            return HDF_FAILURE;
        }
    }
    /* Update to hardware supported rate */
    *rate = rRate;
    g_canPause = snd_pcm_hw_params_can_pause(params);

    return HDF_SUCCESS;
}
static int32_t SetHWParams(
    snd_pcm_t *handle, snd_pcm_hw_params_t *params, struct AudioPcmHwParams hwParams, snd_pcm_access_t access)
{
    int ret;
    int dir = 0; /* dir Value range (-1,0,1) */
    if (handle == NULL || params == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }
    snd_pcm_uframes_t size;
    ret = snd_pcm_hw_params_any(handle, params); // choose all parameters
    if (ret < 0) {
        AUDIO_FUNC_LOGE("No configurations available: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    if (SetHWParamsSub(handle, params, hwParams, access) < 0) {
        AUDIO_FUNC_LOGE("SetHWParamsSub failed!");
        return HDF_FAILURE;
    }
    if (SetHWRate(handle, params, &(hwParams.rate)) < 0) {
        AUDIO_FUNC_LOGE("SetHWRate failed!");
        return HDF_FAILURE;
    }
    ret = snd_pcm_hw_params_set_buffer_time_near(handle, params, &g_bufferTime, &dir);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set buffer time %{public}u failed: %{public}s", g_bufferTime, snd_strerror(ret));
        return HDF_FAILURE;
    }
    ret = snd_pcm_hw_params_get_buffer_size(params, &size);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Unable to get buffer size for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    g_bufferSize = size;
    ret = snd_pcm_hw_params_set_period_time_near(handle, params, &g_periodTime, &dir);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set period time %{public}u failed: %{public}s", g_bufferTime, snd_strerror(ret));
        return HDF_FAILURE;
    }
    ret = snd_pcm_hw_params_get_period_size(params, &size, &dir);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Unable to get period size for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    g_periodSize = size;
    ret = snd_pcm_hw_params(handle, params); // write the parameters to device
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Unable to set hw params for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SetSWParams(snd_pcm_t *handle, snd_pcm_sw_params_t *swparams)
{
    int32_t ret;
    int32_t val = 1; /* val 0 = disable period event, 1 = enable period event */

    if (handle == NULL || swparams == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    /* get the current swparams */
    ret = snd_pcm_sw_params_current(handle, swparams);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Unable to determine current swparams for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    /* start the transfer when the buffer is almost full: */
    /* (buffer_size / avail_min) * avail_min */
    if (g_periodSize == 0) {
        AUDIO_FUNC_LOGE("g_periodSize=0");
        return HDF_FAILURE;
    }
    ret = snd_pcm_sw_params_set_start_threshold(handle, swparams, (g_bufferSize / g_periodSize) * g_periodSize);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Unable to set start threshold mode for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }
    /* allow the transfer when at least period_size samples can be processed */
    /* or disable this mechanism when period event is enabled (aka interrupt like style processing) */
    ret = snd_pcm_sw_params_set_avail_min(handle, swparams, g_periodEvent ? g_bufferSize : g_periodSize);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Unable to set avail min for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }

    /* enable period events when requested */
    if (g_periodEvent) {
        ret = snd_pcm_sw_params_set_period_event(handle, swparams, val);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Unable to set period event: %{public}s", snd_strerror(ret));
            return HDF_FAILURE;
        }
    }

    /* write the parameters to the playback device */
    ret = snd_pcm_sw_params(handle, swparams);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Unable to set sw params for playback: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioResetParams(snd_pcm_t *handle, struct AudioPcmHwParams audioHwParams, snd_pcm_access_t access)
{
    int32_t ret;
    snd_pcm_hw_params_t *hwParams = NULL;
    snd_pcm_sw_params_t *swParams = NULL;

    if (handle == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    snd_pcm_hw_params_alloca(&hwParams);
    snd_pcm_sw_params_alloca(&swParams);
    ret = SetHWParams(handle, hwParams, audioHwParams, access);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Setting of hwparams failed.");
        return ret;
    }

    ret = SetSWParams(handle, swParams);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Setting of swparams failed.");
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderHwParams(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AudioCardInfo *cardIns = NULL;
    snd_pcm_hw_params_t *hwParams = NULL;
    snd_pcm_sw_params_t *swParams = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    const char *cardName = handleData->renderMode.hwInfo.adapterName;
    cardIns = GetCardIns(cardName);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("cardIns is NULL!");
        return HDF_FAILURE;
    }

    ret = (int32_t)snd_pcm_state(cardIns->renderPcmHandle);
    if (ret >= SND_PCM_STATE_RUNNING) {
        AUDIO_FUNC_LOGE("Unable to set parameters during playback!");
        return HDF_FAILURE;
    }

    ret = GetHwParams(cardIns, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetHwParams error.");
        return HDF_FAILURE;
    }

    snd_pcm_hw_params_alloca(&hwParams);
    snd_pcm_sw_params_alloca(&swParams);
    ret = SetHWParams(cardIns->renderPcmHandle, hwParams, cardIns->hwRenderParams, SND_PCM_ACCESS_RW_INTERLEAVED);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Setting of hwparams failed.");
        return HDF_FAILURE;
    }

    ret = SetSWParams(cardIns->renderPcmHandle, swParams);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Setting of swparams failed.");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioRenderWriteFrameSub(snd_pcm_t *pcm, char *dataBuf, size_t bufSize)
{
    int32_t ret;
    long frames;
    int32_t tryNum = AUDIO_ALSALIB_RETYR;

    if (pcm == NULL || dataBuf == NULL || bufSize == 0) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    do {
        /* Write interleaved frames to a PCM. */
        frames = snd_pcm_writei(pcm, dataBuf, bufSize);
        if (frames > 0) {
            return HDF_SUCCESS;
        }

        if (frames == -EBADFD) {
            /* not #SND_PCM_STATE_PREPARED or #SND_PCM_STATE_RUNNING */
            AUDIO_FUNC_LOGE("render PCM is not in the right state: %{public}s", snd_strerror(frames));
            ret = snd_pcm_prepare(pcm);
            if (ret < 0) {
                AUDIO_FUNC_LOGE("render snd_pcm_prepare fail: %{public}s", snd_strerror(ret));
                return HDF_FAILURE;
            }
        } else {
            /* -ESTRPIPE: a suspend event occurred,
             * stream is suspended and waiting for an application recovery.
             * -EPIPE: an underrun occurred.
             */
            ret = snd_pcm_recover(pcm, frames, 0); // 0 for open render recover log.
            if (ret < 0) {
                AUDIO_FUNC_LOGE("snd_pcm_writei failed: %{public}s", snd_strerror(ret));
                return HDF_FAILURE;
            }
            usleep(AUDIO_RENDER_RECOVER_DELAY);
        }
        tryNum--;
    } while (tryNum > 0);

    return HDF_SUCCESS;
}

static int32_t AudioRenderWriteFrame(snd_pcm_t *pcm, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    size_t sbufFrameSize;
    snd_pcm_state_t state;

    if (pcm == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    /* Check whether the PCM status is normal */
    state = snd_pcm_state(pcm);
    if (state == SND_PCM_STATE_SETUP) {
        ret = snd_pcm_prepare(pcm);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("snd_pcm_prepare fail: %{public}s", snd_strerror(ret));
            return HDF_FAILURE;
        }
    }

    sbufFrameSize = (size_t)handleData->frameRenderMode.bufferFrameSize;
    ret = AudioRenderWriteFrameSub(pcm, handleData->frameRenderMode.buffer, sbufFrameSize);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioRenderWriteFrameSub failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderWrite(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AudioCardInfo *cardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    if (g_canPause == 0) { /* Hardware does not support pause, enable soft solution */
        if (handleData->renderMode.ctlParam.pause) {
            AUDIO_FUNC_LOGE("Currently in pause, please check!");
            return HDF_FAILURE;
        }
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    cardIns = GetCardIns(adapterName);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("cardIns is NULL!");
        return HDF_FAILURE;
    }

    if (!cardIns->renderMmapFlag) {
        ret = AudioResetParams(cardIns->renderPcmHandle, cardIns->hwRenderParams, SND_PCM_ACCESS_RW_INTERLEAVED);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("AudioSetParamsMmap failed!");
            return HDF_FAILURE;
        }
        cardIns->renderMmapFlag = true;
    }

    ret = AudioRenderWriteFrame(cardIns->renderPcmHandle, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioRenderWriteFrame failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderPrepare(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AudioCardInfo *sndCardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    const char *sndCardName = handleData->renderMode.hwInfo.adapterName;
    sndCardIns = GetCardIns(sndCardName);
    if (sndCardIns == NULL) {
        AUDIO_FUNC_LOGE("sndCardIns is NULL!");
        return HDF_FAILURE;
    }

    ret = snd_pcm_prepare(sndCardIns->renderPcmHandle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snd_pcm_prepare fail: %{public}s", snd_strerror(ret));
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t InitMixerCtrlVolumeRange(struct AudioCardInfo *cardIns)
{
    int32_t ret;
    long volMin = MIN_VOLUME;
    long volMax = MIN_VOLUME;

    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }
    /** cardIns->ctrlLeftVolume is Mono (Front left alias) */
    if (cardIns->ctrlLeftVolume == NULL && cardIns->ctrlRightVolume == NULL) {
        AUDIO_FUNC_LOGE("InitMixerCtrlVolumeRange error.");
        return HDF_FAILURE;
    }
    if (cardIns->ctrlLeftVolume != NULL) {
        ret = snd_mixer_selem_get_playback_volume_range(cardIns->ctrlLeftVolume, &volMin, &volMax);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Failed to get playback volume range: %{public}s", snd_strerror(ret));
            return HDF_FAILURE;
        }

        ret = snd_mixer_selem_set_playback_volume_range(cardIns->ctrlLeftVolume, MIN_VOLUME, MAX_VOLUME);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Failed to set playback volume range: %{public}s", snd_strerror(ret));
            return HDF_FAILURE;
        }
    }

    if (cardIns->ctrlRightVolume != NULL) {
        ret = snd_mixer_selem_get_playback_volume_range(cardIns->ctrlRightVolume, &volMin, &volMax);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Failed to get playback volume range");
            return HDF_FAILURE;
        }
        ret = snd_mixer_selem_set_playback_volume_range(cardIns->ctrlRightVolume, MIN_VOLUME, MAX_VOLUME);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Failed to set playback volume range");
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

static int32_t InitMixerCtlElement(const char *adapterName, struct AudioCardInfo *cardIns, snd_mixer_t *mixer)
{
    int32_t ret;
    snd_mixer_elem_t *pcmElement = NULL;

    if (adapterName == NULL || cardIns == NULL || mixer == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    if (strncmp(adapterName, PRIMARY, strlen(PRIMARY)) == 0) {
        pcmElement = snd_mixer_first_elem(mixer);
        if (pcmElement == NULL) {
            AUDIO_FUNC_LOGE("snd_mixer_first_elem failed.");
            return HDF_FAILURE;
        }

        ret = GetPriMixerCtlElement(cardIns, pcmElement);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Render GetPriMixerCtlElement failed.");
            return HDF_FAILURE;
        }
    } else if (strncmp(adapterName, USB, strlen(USB)) == 0) {
        cardIns->ctrlLeftVolume = AudioUsbFindElement(mixer);
    } else {
        AUDIO_FUNC_LOGE("The selected sound card not supported, please check!");
        return HDF_FAILURE;
    }

    ret = InitMixerCtrlVolumeRange(cardIns);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("InitMixerCtrlVolumeRange failed!");
        return HDF_FAILURE;
    }

    ret = AudioMixerSetCtrlMode(cardIns, adapterName, "Digital Playback Path", SND_PLAY_PATH, SND_OUT_CARD_SPK_HP);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioMixerSetCtrlMode failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

/*
 * brief: Opens a PCM
 * param mode Open mode (see #SND_PCM_NONBLOCK, #SND_PCM_ASYNC)
 */
int32_t AudioOutputRenderOpen(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AudioCardInfo *cardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("The parameter is empty.");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    cardIns = AudioGetCardInfo(adapterName, SND_PCM_STREAM_PLAYBACK);
    if (cardIns == NULL) {
        AUDIO_FUNC_LOGE("AudioRenderGetCardIns failed.");
        return HDF_FAILURE;
    }

    if (cardIns->renderPcmHandle != NULL) {
        AUDIO_FUNC_LOGE("Resource busy!!");
        return HDF_ERR_DEVICE_BUSY;
    }

    ret = snd_pcm_open(&cardIns->renderPcmHandle, cardIns->devName, SND_PCM_STREAM_PLAYBACK, 0);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioOutputRenderOpen fail: %{public}s!", snd_strerror(ret));
        CheckCardStatus(cardIns);
        (void)DestroyCardList();
        return HDF_FAILURE;
    }

    InitSound(&cardIns->mixer, cardIns->ctrlName);
    ret = InitMixerCtlElement(adapterName, cardIns, cardIns->mixer);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("InitMixerCtlElement failed!");
        (void)CloseMixerHandle(cardIns->mixer);
        CheckCardStatus(cardIns);
        (void)DestroyCardList();
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderStop(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AudioCardInfo *cardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("The parameter is empty.");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    cardIns = GetCardIns(adapterName);
    if (cardIns == NULL || cardIns->renderPcmHandle == NULL) {
        AUDIO_FUNC_LOGE("cardIns is NULL!");
        return HDF_FAILURE;
    }
    /**For playback, snd_ pcm_ Drain will wait for all pending data frames to be broadcast before turning off PCM */
    ret = snd_pcm_drain(cardIns->renderPcmHandle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioOutputRenderStop fail!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderClose(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AudioCardInfo *alsaCardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("parameter error!!");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    /* Gets the specified sound card instance */
    alsaCardIns = GetCardIns(adapterName);
    if (alsaCardIns == NULL) {
        AUDIO_FUNC_LOGE("cardInstance is empty pointer!");
        return HDF_FAILURE;
    }

    if (alsaCardIns->renderPcmHandle != NULL) {
        ret = snd_pcm_close(alsaCardIns->renderPcmHandle);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("snd_pcm_close fail: %{public}s", snd_strerror(ret));
        }
        alsaCardIns->renderPcmHandle = NULL;
    }

    if (alsaCardIns->cardStatus > 0) {
        alsaCardIns->cardStatus -= 1;
    }
    if (alsaCardIns->cardStatus == 0) {
        if (alsaCardIns->mixer != NULL) {
            ret = snd_mixer_close(alsaCardIns->mixer);
            if (ret < 0) {
                AUDIO_FUNC_LOGE("snd_mixer_close fail: %{public}s", snd_strerror(ret));
            }
            alsaCardIns->mixer = NULL;
        }
        (void)memset_s(alsaCardIns->cardName, MAX_CARD_NAME_LEN + 1, 0, MAX_CARD_NAME_LEN + 1);
        ret = DestroyCardList();
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("DestroyCardList failed, reason: %{public}d.", ret);
            return ret;
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderStart(const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t RenderWriteiMmap(const struct AudioHwRenderParam *handleData, struct AudioCardInfo *cardIns)
{
    int32_t ret;
    uint32_t frameSize;
    uint32_t totalSize;
    uint32_t lastBuffSize;
    uint32_t loopTimes;
    uint32_t looper = 0;
    uint32_t copyLen;
    int32_t count = 0;
    struct AudioMmapBufferDescripter *mmapBufDesc = NULL;

    if (handleData == NULL || cardIns == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    frameSize = cardIns->hwRenderParams.channels * cardIns->hwRenderParams.format;
    if (frameSize == 0) {
        AUDIO_FUNC_LOGE("frame size = 0!");
        return HDF_FAILURE;
    }
    mmapBufDesc = (struct AudioMmapBufferDescripter *)&(handleData->frameRenderMode.mmapBufDesc);
    totalSize = (uint32_t)mmapBufDesc->totalBufferFrames * frameSize;
    lastBuffSize = ((totalSize % MIN_PERIOD_SIZE) == 0) ? MIN_PERIOD_SIZE : (totalSize % MIN_PERIOD_SIZE);
    loopTimes = (lastBuffSize == MIN_PERIOD_SIZE) ? (totalSize / MIN_PERIOD_SIZE) : (totalSize / MIN_PERIOD_SIZE + 1);
    while (looper < loopTimes) {
        copyLen = (looper < (loopTimes - 1)) ? MIN_PERIOD_SIZE : lastBuffSize;
        snd_pcm_uframes_t frames = (snd_pcm_uframes_t)(copyLen / frameSize);
        ret = snd_pcm_mmap_writei(
            cardIns->renderPcmHandle, (char *)mmapBufDesc->memoryAddress + mmapBufDesc->offset, frames);
        if (ret == -EAGAIN) {
            count++;
            if (count > AUDIO_ALSALIB_MMAP_MAX) {
                AUDIO_FUNC_LOGE("loop > max !");
                return HDF_FAILURE;
            }
            continue;
        }
        count = 0;
        if (ret < 0) {
            AUDIO_FUNC_LOGE("Write error: %{public}s\n", snd_strerror(ret));
            return HDF_FAILURE;
        }
        looper++;
        mmapBufDesc->offset += copyLen;
        cardIns->renderMmapFrames += (uint64_t)frames;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderReqMmapBuffer(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AudioCardInfo *mmapCardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    mmapCardIns = GetCardIns(adapterName);
    if (mmapCardIns == NULL) {
        AUDIO_FUNC_LOGE("cardInstance is NULL!");
        return HDF_FAILURE;
    }
    mmapCardIns->renderMmapFlag = false;

    ret = AudioResetParams(mmapCardIns->renderPcmHandle, mmapCardIns->hwRenderParams, SND_PCM_ACCESS_MMAP_INTERLEAVED);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioSetParamsMmap failed!");
        return HDF_FAILURE;
    }

    ret = RenderWriteiMmap(handleData, mmapCardIns);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderWriteiMmap error!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderGetMmapPosition(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    struct AudioCardInfo *alsaMmapCardIns = NULL;

    (void)cmdId;
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    /* Get the ALSA sound card instance corresponding to AdapterName */
    const char *adapterName = handleData->renderMode.hwInfo.adapterName;
    alsaMmapCardIns = GetCardIns(adapterName);
    if (alsaMmapCardIns == NULL) {
        AUDIO_FUNC_LOGE("Can't find card Instance!");
        return HDF_FAILURE;
    }
    handleData->frameRenderMode.frames = alsaMmapCardIns->renderMmapFrames;

    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibOutputRender(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    if (handle->object == NULL) {
        AUDIO_FUNC_LOGE("handle's object is null!");
        return HDF_FAILURE;
    }

    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
            ret = AudioOutputRenderHwParams(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_WRITE:
            ret = AudioOutputRenderWrite(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_STOP:
            ret = AudioOutputRenderStop(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_START:
            ret = AudioOutputRenderStart(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_PREPARE:
            ret = AudioOutputRenderPrepare(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE:
            ret = AudioOutputRenderClose(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN:
            ret = AudioOutputRenderOpen(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE:
            ret = AudioCtlRenderSetPauseStu(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER:
            ret = AudioOutputRenderReqMmapBuffer(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION:
            ret = (AudioOutputRenderGetMmapPosition(handle, cmdId, handleData));
            break;
        default:
            AUDIO_FUNC_LOGE("Output Mode not support!");
            ret = HDF_FAILURE;
            break;
    }

    return ret;
}

int32_t AudioBindServiceRenderObject(struct DevHandle *handle, const char *name)
{
    int32_t ret;
    struct HdfIoService *service = NULL;

    if (handle == NULL || name == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    char *serviceName = (char *)OsalMemCalloc(NAME_LEN);
    if (serviceName == NULL) {
        AUDIO_FUNC_LOGE("Failed to OsalMemCalloc memory!");
        return HDF_FAILURE;
    }

    ret = snprintf_s(serviceName, NAME_LEN - 1, SERVIC_NAME_MAX_LEN + 1, "hdf_audio_%s", name);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Render: Failed to snprintf_s");
        AudioMemFree((void **)&serviceName);
        return HDF_FAILURE;
    }

    service = HdfIoServiceBindName(serviceName);
    if (service == NULL) {
        AUDIO_FUNC_LOGE("Render: Failed to get service!");
        AudioMemFree((void **)&serviceName);
        return HDF_FAILURE;
    }
    AudioMemFree((void **)&serviceName);
    handle->object = service;

    return HDF_SUCCESS;
}

/* CreatRender for Bind handle */
struct DevHandle *AudioBindServiceRender(const char *name)
{
    int32_t ret;

    if (name == NULL) {
        AUDIO_FUNC_LOGE("service name NULL!");
        return NULL;
    }

    struct DevHandle *handle = (struct DevHandle *)OsalMemCalloc(sizeof(struct DevHandle));
    if (handle == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc handle failed!!!");
        return NULL;
    }

    ret = AudioBindServiceRenderObject(handle, name);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Bind Service Render Object failed!");
        AudioMemFree((void **)&handle);
        return NULL;
    }

    /* Render: Parsing primary sound card from configuration file */
    ret = CardInfoParseFromConfig();
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render: parse config file failed!");
        AudioMemFree((void **)&handle);
        return NULL;
    }
    AUDIO_FUNC_LOGI("BIND SERVICE SUCCESS!");

    return handle;
}

void AudioCloseServiceRender(const struct DevHandle *handle)
{
    if (handle != NULL) {
        if (handle->object == NULL) {
            AUDIO_FUNC_LOGE("Render handle or handle->object is NULL");
        }
        AudioMemFree((void **)&handle);
    }
}

int32_t AudioInterfaceLibModeRender(const struct DevHandle *handle, struct AudioHwRenderParam *handleData, int cmdId)
{
    if (handle == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }

    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
        case AUDIO_DRV_PCM_IOCTL_WRITE:
        case AUDIO_DRV_PCM_IOCTRL_STOP:
        case AUDIO_DRV_PCM_IOCTRL_START:
        case AUDIO_DRV_PCM_IOCTL_PREPARE:
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE:
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER:
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION:
        case AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN:
        case AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE:
            return (AudioInterfaceLibOutputRender(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_ELEM_WRITE:
        case AUDIODRV_CTL_IOCTL_ELEM_READ:
        case AUDIODRV_CTL_IOCTL_MUTE_WRITE:
        case AUDIODRV_CTL_IOCTL_MUTE_READ:
        case AUDIODRV_CTL_IOCTL_GAIN_WRITE:
        case AUDIODRV_CTL_IOCTL_GAIN_READ:
        case AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE:
        case AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ:
        case AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE:
        case AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ:
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ:
            return (AudioInterfaceLibCtlRender(handle, cmdId, handleData));
        default:
            AUDIO_FUNC_LOGE("Mode Error!");
            break;
    }
    return HDF_ERR_NOT_SUPPORT;
}
