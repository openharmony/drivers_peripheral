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

#include "audio_capture_vdi.h"

#include <limits.h>
#include "osal_mem.h"
#include "securec.h"
#include <hdf_base.h>
#include "audio_uhdf_log.h"
#include "audio_common_vdi.h"
#include "audio_dfx.h"
#include "stub_collector.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL
static pthread_rwlock_t g_rwVdiCaptureLock = PTHREAD_RWLOCK_INITIALIZER;
struct AudioCaptureInfo {
    struct IAudioCapture capture;
    struct AudioDeviceDescriptor desc;
    enum AudioCategory streamType;
    unsigned int sampleRate;
    unsigned int channelCount;
    int sourceType;
    struct IAudioCaptureVdi *vdiCapture;
    uint32_t captureId;
    unsigned int usrCount;
};

struct AudioCapturePrivVdi {
    struct AudioCaptureInfo *captureInfos[AUDIO_VDI_STREAM_NUM_MAX];
    uint32_t captureCnt;
};

static struct AudioCapturePrivVdi g_audioCapturePrivVdi;

static struct AudioCapturePrivVdi *AudioCaptureGetPrivVdi(void)
{
    return &g_audioCapturePrivVdi;
}

pthread_rwlock_t* GetCaptureLock(void)
{
    return &g_rwVdiCaptureLock;
}

struct IAudioCaptureVdi *AudioGetVdiCaptureByIdVdi(uint32_t captureId)
{
    struct AudioCapturePrivVdi *priv = AudioCaptureGetPrivVdi();
    if (priv->captureInfos[captureId] == NULL) {
        AUDIO_FUNC_LOGE("not match capture");
        return NULL;
    }

    return priv->captureInfos[captureId]->vdiCapture;
}

int32_t AudioCaptureFrameVdi(struct IAudioCapture *capture, int8_t *frame, uint32_t *frameLen, uint64_t *replyBytes)
{
    SetThreadPriority();
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frame, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frameLen, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(replyBytes, HDF_ERR_INVALID_PARAM);
    pthread_rwlock_rdlock(&g_rwVdiCaptureLock);
    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    if (vdiCapture == NULL || vdiCapture->CaptureFrame == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t id = SetTimer("Hdi:CaptureFrame");
    HdfAudioStartTrace("Hdi:AudioCaptureFrameVdi", 0);
    struct timeval startTime = AudioDfxSysEventGetTimeStamp();
    int32_t ret = vdiCapture->CaptureFrame(vdiCapture, frame, frameLen, replyBytes);
    AudioDfxSysEventError("CaptureFrame", startTime, TIME_THRESHOLD, ret);
    HdfAudioFinishTrace();
    CancelTimer(id);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture frame fail, ret=%{public}d", ret);
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return ret;
    }
    pthread_rwlock_unlock(&g_rwVdiCaptureLock);
    return HDF_SUCCESS;
}

int32_t AudioCaptureFrameEcVdi(struct IAudioCapture *capture, const struct AudioFrameLen *frameLen,
    struct AudioCaptureFrameInfo *frameInfo)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frameLen, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frameInfo, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->CaptureFrameEc, HDF_ERR_INVALID_PARAM);
    struct AudioCaptureFrameInfoVdi frameInfoVdi;
    (void)memset_s((void *)&frameInfoVdi, sizeof(frameInfoVdi), 0, sizeof(frameInfoVdi));
    int32_t ret = AudioCommonFrameInfoToVdiFrameInfoVdi(frameLen, &frameInfoVdi);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture FrameInfo To VdiFrameInfo fail");
        return ret;
    }

    HdfAudioStartTrace("Hdi:AudioCaptureFrameEcVdi", 0);
    ret = vdiCapture->CaptureFrameEc(vdiCapture, &frameInfoVdi);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)frameInfoVdi.frame);
        OsalMemFree((void *)frameInfoVdi.frameEc);
        AUDIO_FUNC_LOGE("audio capture EC frame fail, ret=%{public}d", ret);
        return ret;
    }

    ret = AudioCommonVdiFrameInfoToFrameInfoVdi(&frameInfoVdi, frameInfo);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture VdiFrameInfo To FrameInfo fail");
    }
    OsalMemFree((void *)frameInfoVdi.frame);
    OsalMemFree((void *)frameInfoVdi.frameEc);

    return ret;
}

int32_t AudioGetCapturePositionVdi(struct IAudioCapture *capture, uint64_t *frames, struct AudioTimeStamp *time)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetCapturePosition, HDF_ERR_INVALID_PARAM);

    HdfAudioStartTrace("Hdi:AudioGetCapturePositionVdi", 0);
    int32_t ret = vdiCapture->GetCapturePosition(vdiCapture, frames, (struct AudioTimeStampVdi *)time);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture get position fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureCheckSceneCapabilityVdi(struct IAudioCapture *capture, const struct AudioSceneDescriptor* scene,
    bool* supported)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supported, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->CheckSceneCapability, HDF_ERR_INVALID_PARAM);

    struct AudioSceneDescriptorVdi vdiScene;
    (void)memset_s((void *)&vdiScene, sizeof(vdiScene), 0, sizeof(vdiScene));
    int32_t ret = AudioCommonSceneToVdiSceneVdi(scene, &vdiScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture scene To vdiScene fail");
        return HDF_FAILURE;
    }

    ret = vdiCapture->CheckSceneCapability(vdiCapture, &vdiScene, supported);
    OsalMemFree((void *)vdiScene.desc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture CheckSceneCapability fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureSelectSceneVdi(struct IAudioCapture *capture, const struct AudioSceneDescriptor* scene)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->SelectScene, HDF_ERR_INVALID_PARAM);

    struct AudioSceneDescriptorVdi vdiScene;
    (void)memset_s((void *)&vdiScene, sizeof(vdiScene), 0, sizeof(vdiScene));
    int32_t ret = AudioCommonSceneToVdiSceneVdi(scene, &vdiScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio vdiAdapter scene To vdiScene fail");
        return HDF_FAILURE;
    }

    int32_t id = SetTimer("Hdi:SelectScene");
    ret = vdiCapture->SelectScene(vdiCapture, &vdiScene);
    CancelTimer(id);
    OsalMemFree((void *)vdiScene.desc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture select scene fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureSetMuteVdi(struct IAudioCapture *capture, bool mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->SetMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->SetMute(vdiCapture, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetMute fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetMuteVdi(struct IAudioCapture *capture, bool *mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(mute, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetMute(vdiCapture, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetMute fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureSetVolumeVdi(struct IAudioCapture *capture, float volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->SetVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->SetVolume(vdiCapture, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetVolume fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetVolumeVdi(struct IAudioCapture *capture, float *volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(volume, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetVolume(vdiCapture, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetVolume fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetGainThresholdVdi(struct IAudioCapture *capture, float *min, float *max)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(min, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(max, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetGainThreshold, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetGainThreshold(vdiCapture, min, max);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetGainThreshold fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetGainVdi(struct IAudioCapture *capture, float *gain)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(gain, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetGain, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetGain(vdiCapture, gain);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetGain fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureSetGainVdi(struct IAudioCapture *capture, float gain)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->SetGain, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->SetGain(vdiCapture, gain);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetGain fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetFrameSizeVdi(struct IAudioCapture *capture, uint64_t *size)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(size, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetFrameSize, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetFrameSize(vdiCapture, size);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetFrameSize fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetFrameCountVdi(struct IAudioCapture *capture, uint64_t *count)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(count, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetFrameCount, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetFrameCount(vdiCapture, count);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetFrameCount fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureSetSampleAttributesVdi(struct IAudioCapture *capture, const struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->SetSampleAttributes, HDF_ERR_INVALID_PARAM);

    struct AudioSampleAttributesVdi vdiAttrs;
    (void)memset_s((void *)&vdiAttrs, sizeof(vdiAttrs), 0, sizeof(vdiAttrs));
    int32_t ret = AudioCommonSampleAttrToVdiSampleAttrVdi(attrs, &vdiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SampleAttr to vdisampleAttr fail, ret=%{public}d", ret);
        return ret;
    }

    ret = vdiCapture->SetSampleAttributes(vdiCapture, &vdiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetSampleAttributes fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetSampleAttributesVdi(struct IAudioCapture *capture, struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetSampleAttributes, HDF_ERR_INVALID_PARAM);

    struct AudioSampleAttributesVdi vdiAttrs;
    (void)memset_s((void *)&vdiAttrs, sizeof(vdiAttrs), 0, sizeof(vdiAttrs));
    int32_t ret = vdiCapture->GetSampleAttributes(vdiCapture, &vdiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetSampleAttributes fail, ret=%{public}d", ret);
        return ret;
    }

    ret = AudioCommonVdiSampleAttrToSampleAttrVdi(&vdiAttrs, attrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture vdiSampleAttr to SampleAttr fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetCurrentChannelIdVdi(struct IAudioCapture *capture, uint32_t *channelId)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(channelId, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetCurrentChannelId, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetCurrentChannelId(vdiCapture, channelId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetCurrentChannelId fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureSetExtraParamsVdi(struct IAudioCapture *capture, const char *keyValueList)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(keyValueList, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->SetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->SetExtraParams(vdiCapture, keyValueList);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetExtraParams fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetExtraParamsVdi(struct IAudioCapture *capture, char *keyValueList, uint32_t keyValueListLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(keyValueList, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetExtraParams(vdiCapture, keyValueList, keyValueListLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetExtraParams fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureReqMmapBufferVdi(struct IAudioCapture *capture, int32_t reqSize,
    struct AudioMmapBufferDescriptor *desc)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->ReqMmapBuffer, HDF_ERR_INVALID_PARAM);

    struct AudioMmapBufferDescriptorVdi vdiDesc = {0};
    int32_t ret = vdiCapture->ReqMmapBuffer(vdiCapture, reqSize, &vdiDesc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture ReqMmapBuffer fail, ret=%{pubilc}d", ret);
        return ret;
    }

    desc->memoryFd = vdiDesc.memoryFd;
    desc->totalBufferFrames = vdiDesc.totalBufferFrames;
    desc->transferFrameSize = vdiDesc.transferFrameSize;
    desc->isShareable = vdiDesc.isShareable;
    desc->filePath = strdup("");  // which will be released after send reply
    if (desc->filePath == NULL) {
        AUDIO_FUNC_LOGE("strdup fail");
        return HDF_FAILURE;
    }
    if (desc->totalBufferFrames < 0) {
        // make the totalBufferFrames valid
        desc->totalBufferFrames *= -1;
        desc->isShareable = 1;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetMmapPositionVdi(struct IAudioCapture *capture, uint64_t *frames, struct AudioTimeStamp *time)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    struct AudioTimeStampVdi vdiTime;
    vdiTime.tvSec = 0;
    vdiTime.tvNSec = 0;

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetMmapPosition, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetMmapPosition(vdiCapture, frames, &vdiTime);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetMmapPosition fail, ret=%{public}d", ret);
        return ret;
    }

    time->tvSec = vdiTime.tvSec;
    time->tvNSec = vdiTime.tvNSec;

    return HDF_SUCCESS;
}

int32_t AudioCaptureAddAudioEffectVdi(struct IAudioCapture *capture, uint64_t effectid)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->AddAudioEffect, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->AddAudioEffect(vdiCapture, effectid);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture AddAudioEffect fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureRemoveAudioEffectVdi(struct IAudioCapture *capture, uint64_t effectid)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->RemoveAudioEffect, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->RemoveAudioEffect(vdiCapture, effectid);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture RemoveAudioEffect fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureGetFrameBufferSizeVdi(struct IAudioCapture *capture, uint64_t *bufferSize)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(bufferSize, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->GetFrameBufferSize, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->GetFrameBufferSize(vdiCapture, bufferSize);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetFrameBufferSize fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureStartVdi(struct IAudioCapture *capture)
{
    AUDIO_FUNC_LOGI("hdi start enter");
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    pthread_rwlock_rdlock(&g_rwVdiCaptureLock);
    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    if (vdiCapture == NULL || vdiCapture->Start == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return HDF_ERR_INVALID_PARAM;
    }
    HdfAudioStartTrace("Hdi:AudioCaptureStartVdi", 0);
    struct timeval startTime = AudioDfxSysEventGetTimeStamp();
    int32_t ret = vdiCapture->Start(vdiCapture);
    AudioDfxSysEventError("Capture Start", startTime, TIME_THRESHOLD, ret);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Start fail, ret=%{public}d", ret);
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return ret;
    }
    pthread_rwlock_unlock(&g_rwVdiCaptureLock);
    return HDF_SUCCESS;
}

int32_t AudioCaptureStopVdi(struct IAudioCapture *capture)
{
    AUDIO_FUNC_LOGI("hdi stop enter");
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    pthread_rwlock_rdlock(&g_rwVdiCaptureLock);
    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    if (vdiCapture == NULL || vdiCapture->Stop == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return HDF_ERR_INVALID_PARAM;
    }
    HdfAudioStartTrace("Hdi:AudioCaptureStopVdi", 0);
    struct timeval startTime = AudioDfxSysEventGetTimeStamp();
    int32_t ret = vdiCapture->Stop(vdiCapture);
    AudioDfxSysEventError("Capture Stop", startTime, TIME_THRESHOLD, ret);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Stop fail, ret=%{public}d", ret);
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return HDF_ERR_NOT_SUPPORT;
    }
    pthread_rwlock_unlock(&g_rwVdiCaptureLock);
    return HDF_SUCCESS;
}

int32_t AudioCapturePauseVdi(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    pthread_rwlock_rdlock(&g_rwVdiCaptureLock);
    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    if (vdiCapture == NULL || vdiCapture->Pause == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = vdiCapture->Pause(vdiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Pause fail, ret=%{public}d", ret);
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return ret;
    }
    pthread_rwlock_unlock(&g_rwVdiCaptureLock);
    return HDF_SUCCESS;
}

int32_t AudioCaptureResumeVdi(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    pthread_rwlock_rdlock(&g_rwVdiCaptureLock);
    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    if (vdiCapture == NULL || vdiCapture->Resume == NULL) {
        AUDIO_FUNC_LOGE("invalid param");
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = vdiCapture->Resume(vdiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Resume fail, ret=%{public}d", ret);
        pthread_rwlock_unlock(&g_rwVdiCaptureLock);
        return ret;
    }
    pthread_rwlock_unlock(&g_rwVdiCaptureLock);
    return HDF_SUCCESS;
}

int32_t AudioCaptureFlushVdi(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->Flush, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->Flush(vdiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Flush fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureTurnStandbyModeVdi(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->TurnStandbyMode, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->TurnStandbyMode(vdiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture TurnStandbyMode fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureAudioDevDumpVdi(struct IAudioCapture *capture, int32_t range, int32_t fd)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->AudioDevDump, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->AudioDevDump(vdiCapture, range, fd);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture AudioDevDump fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioCaptureIsSupportsPauseAndResumeVdi(struct IAudioCapture *capture, bool *supportPause, bool *supportResume)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supportPause, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supportResume, HDF_ERR_INVALID_PARAM);

    struct AudioCaptureInfo *captureInfo = (struct AudioCaptureInfo *)(capture);
    struct IAudioCaptureVdi *vdiCapture = captureInfo->vdiCapture;
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiCapture->IsSupportsPauseAndResume, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiCapture->IsSupportsPauseAndResume(vdiCapture, supportPause, supportResume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture IsSupportsPauseAndResume fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

static void AudioInitCaptureInstanceVdi(struct IAudioCapture *capture)
{
    capture->CaptureFrame = AudioCaptureFrameVdi;
    capture->CaptureFrameEc = AudioCaptureFrameEcVdi;
    capture->GetCapturePosition = AudioGetCapturePositionVdi;
    capture->CheckSceneCapability = AudioCaptureCheckSceneCapabilityVdi;
    capture->SelectScene = AudioCaptureSelectSceneVdi;
    capture->SetMute = AudioCaptureSetMuteVdi;
    capture->GetMute = AudioCaptureGetMuteVdi;
    capture->SetVolume = AudioCaptureSetVolumeVdi;
    capture->GetVolume = AudioCaptureGetVolumeVdi;
    capture->GetGainThreshold = AudioCaptureGetGainThresholdVdi;
    capture->GetGain = AudioCaptureGetGainVdi;
    capture->SetGain = AudioCaptureSetGainVdi;
    capture->GetFrameSize = AudioCaptureGetFrameSizeVdi;
    capture->GetFrameCount = AudioCaptureGetFrameCountVdi;
    capture->SetSampleAttributes = AudioCaptureSetSampleAttributesVdi;
    capture->GetSampleAttributes = AudioCaptureGetSampleAttributesVdi;
    capture->GetCurrentChannelId = AudioCaptureGetCurrentChannelIdVdi;
    capture->SetExtraParams = AudioCaptureSetExtraParamsVdi;
    capture->GetExtraParams = AudioCaptureGetExtraParamsVdi;
    capture->ReqMmapBuffer = AudioCaptureReqMmapBufferVdi;
    capture->GetMmapPosition = AudioCaptureGetMmapPositionVdi;
    capture->AddAudioEffect = AudioCaptureAddAudioEffectVdi;
    capture->RemoveAudioEffect = AudioCaptureRemoveAudioEffectVdi;
    capture->GetFrameBufferSize = AudioCaptureGetFrameBufferSizeVdi;
    capture->Start = AudioCaptureStartVdi;
    capture->Stop = AudioCaptureStopVdi;
    capture->Pause = AudioCapturePauseVdi;
    capture->Resume = AudioCaptureResumeVdi;
    capture->Flush = AudioCaptureFlushVdi;
    capture->TurnStandbyMode = AudioCaptureTurnStandbyModeVdi;
    capture->AudioDevDump = AudioCaptureAudioDevDumpVdi;
    capture->IsSupportsPauseAndResume = AudioCaptureIsSupportsPauseAndResumeVdi;
}

static uint32_t GetAvailableCaptureId(struct AudioCapturePrivVdi *capturePriv)
{
    uint32_t captureId = AUDIO_VDI_STREAM_NUM_MAX;
    if (capturePriv == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return captureId;
    }

    if (capturePriv->captureCnt < AUDIO_VDI_STREAM_NUM_MAX) {
        captureId = capturePriv->captureCnt;
        capturePriv->captureCnt++;
    } else {
        for (uint32_t index = 0; index < AUDIO_VDI_STREAM_NUM_MAX; index++) {
            if (capturePriv->captureInfos[index] == NULL) {
                captureId = index;
                break;
            }
        }
    }

    return captureId;
}

struct IAudioCapture *AudioCreateCaptureByIdVdi(const struct AudioSampleAttributes *attrs, uint32_t *captureId,
    struct IAudioCaptureVdi *vdiCapture, const struct AudioDeviceDescriptor *desc)
{
    if (attrs == NULL || captureId == NULL || vdiCapture == NULL || desc == NULL) {
        AUDIO_FUNC_LOGE("audio capture is null");
        return NULL;
    }

    *captureId = AUDIO_VDI_STREAM_NUM_MAX;
    struct IAudioCapture *capture = NULL;
    struct AudioCapturePrivVdi *priv = AudioCaptureGetPrivVdi();

    *captureId = GetAvailableCaptureId(priv);
    if (*captureId >= AUDIO_VDI_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdicapture capture capture index fail, captureId=%{public}d", *captureId);
        return NULL;
    }

    priv->captureInfos[*captureId] = (struct AudioCaptureInfo *)OsalMemCalloc(sizeof(struct AudioCaptureInfo));
    if (priv->captureInfos[*captureId] == NULL) {
        AUDIO_FUNC_LOGE("audio Vdicapture malloc captureInfos fail");
        return NULL;
    }

    priv->captureInfos[*captureId]->vdiCapture = vdiCapture;
    priv->captureInfos[*captureId]->streamType = attrs->type;
    priv->captureInfos[*captureId]->sampleRate = attrs->sampleRate;
    priv->captureInfos[*captureId]->channelCount = attrs->channelCount;
    priv->captureInfos[*captureId]->sourceType = attrs->sourceType;
    priv->captureInfos[*captureId]->desc.portId = desc->portId;
    priv->captureInfos[*captureId]->desc.pins = desc->pins;
    priv->captureInfos[*captureId]->desc.desc = strdup(desc->desc);
    if (priv->captureInfos[*captureId]->desc.desc == NULL) {
        AUDIO_FUNC_LOGE("strdup fail, desc->desc = %{public}s", desc->desc);
        OsalMemFree(priv->captureInfos[*captureId]);
        priv->captureInfos[*captureId] = NULL;
        return NULL;
    }
    priv->captureInfos[*captureId]->captureId = *captureId;
    priv->captureInfos[*captureId]->usrCount = 1;
    capture = &(priv->captureInfos[*captureId]->capture);
    AudioInitCaptureInstanceVdi(capture);

    AUDIO_FUNC_LOGD("audio create capture success");
    return capture;
};

uint32_t DecreaseCaptureUsrCount(uint32_t captureId)
{
    uint32_t usrCnt = 0;
    if (captureId >= AUDIO_VDI_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio check capture index fail, descIndex=%{public}d", captureId);
        return usrCnt;
    }
    struct AudioCapturePrivVdi *priv = AudioCaptureGetPrivVdi();
    if (priv->captureInfos[captureId] == NULL) {
        AUDIO_FUNC_LOGE("audio check capture index fail, descIndex=%{public}d", captureId);
        return usrCnt;
    }

    priv->captureInfos[captureId]->usrCount--;
    usrCnt = priv->captureInfos[captureId]->usrCount;
    return usrCnt;
}

void AudioDestroyCaptureByIdVdi(uint32_t captureId)
{
    if (captureId >= AUDIO_VDI_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiCapture destroy capture index fail, captureId=%{public}d", captureId);
        return;
    }
    struct AudioCapturePrivVdi *priv = AudioCaptureGetPrivVdi();
    if (priv->captureInfos[captureId] == NULL) {
        AUDIO_FUNC_LOGE("audio vdiCapture destroy capture index fail, captureId=%{public}d", captureId);
        return;
    }

    OsalMemFree((void *)priv->captureInfos[captureId]->desc.desc);
    priv->captureInfos[captureId]->vdiCapture = NULL;
    priv->captureInfos[captureId]->desc.desc = NULL;
    priv->captureInfos[captureId]->desc.portId = UINT_MAX;
    priv->captureInfos[captureId]->desc.pins = PIN_NONE;
    StubCollectorRemoveObject(IAUDIOCAPTURE_INTERFACE_DESC, &(priv->captureInfos[captureId]->capture));

    OsalMemFree(priv->captureInfos[captureId]);
    priv->captureInfos[captureId] = NULL;
    AUDIO_FUNC_LOGI("audio destroy capture success, captureId = [%{public}u]", captureId);
}
