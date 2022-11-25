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

#include "audio_proxy_common_fun_test.h"
#include <climits>
#include <unistd.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "hdf_remote_service.h"

namespace commonfun {
void *GetDynamicLibHandle(const std::string path)
{
    char absPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), absPath) == nullptr) {
        return nullptr;
    }
    void *handleSo = dlopen(absPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return nullptr;
    }
    return handleSo;
}

int32_t InitPort(struct AudioPort &portIndex)
{
    portIndex.dir = PORT_OUT;
    portIndex.portId = 1;
    portIndex.portName = "usb";
    return HDF_SUCCESS;
}

int32_t InitHwRender(struct AudioHwRender &hwRender, const struct AudioDeviceDescriptor &desc,
                     const struct AudioSampleAttributes &attrs)
{
    hwRender.renderParam.renderMode.hwInfo.deviceDescript = desc;
    hwRender.renderParam.frameRenderMode.attrs = attrs;
    hwRender.renderParam.renderMode.ctlParam.audioGain.gainMax = 15; // gainMax 15
    hwRender.renderParam.renderMode.ctlParam.audioGain.gainMin = 0;
    hwRender.renderParam.frameRenderMode.frames = 0;
    hwRender.renderParam.frameRenderMode.time.tvNSec = 0;
    hwRender.renderParam.frameRenderMode.time.tvSec = 0;
    hwRender.renderParam.frameRenderMode.byteRate = DEFAULT_RENDER_SAMPLING_RATE;
    hwRender.renderParam.frameRenderMode.periodSize = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    hwRender.renderParam.frameRenderMode.periodCount = DEEP_BUFFER_RENDER_PERIOD_COUNT;
    hwRender.renderParam.frameRenderMode.attrs.period = attrs.period;
    hwRender.renderParam.frameRenderMode.attrs.frameSize = attrs.frameSize;
    hwRender.renderParam.frameRenderMode.attrs.startThreshold = attrs.startThreshold;
    hwRender.renderParam.frameRenderMode.attrs.stopThreshold = attrs.stopThreshold;
    hwRender.renderParam.frameRenderMode.attrs.silenceThreshold = attrs.silenceThreshold;
    hwRender.renderParam.frameRenderMode.attrs.isBigEndian = attrs.isBigEndian;
    hwRender.renderParam.frameRenderMode.attrs.isSignedData = attrs.isSignedData;
    return HDF_SUCCESS;
}

int32_t InitHwCapture(struct AudioHwCapture &hwCapture, const struct AudioDeviceDescriptor &desc,
                      const struct AudioSampleAttributes &attrs)
{
    hwCapture.captureParam.captureMode.hwInfo.deviceDescript = desc;
    hwCapture.captureParam.frameCaptureMode.attrs = attrs;
    hwCapture.captureParam.captureMode.ctlParam.audioGain.gainMax = 15; // gainMax 15
    hwCapture.captureParam.captureMode.ctlParam.audioGain.gainMin = 0;
    hwCapture.captureParam.frameCaptureMode.frames = 0;
    hwCapture.captureParam.frameCaptureMode.time.tvNSec = 0;
    hwCapture.captureParam.frameCaptureMode.time.tvSec = 0;
    hwCapture.captureParam.frameCaptureMode.byteRate = DEFAULT_RENDER_SAMPLING_RATE;
    hwCapture.captureParam.frameCaptureMode.periodSize = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    hwCapture.captureParam.frameCaptureMode.periodCount = DEEP_BUFFER_RENDER_PERIOD_COUNT;
    hwCapture.captureParam.frameCaptureMode.attrs.period = attrs.period;
    hwCapture.captureParam.frameCaptureMode.attrs.frameSize = attrs.frameSize;
    hwCapture.captureParam.frameCaptureMode.attrs.startThreshold = attrs.startThreshold;
    hwCapture.captureParam.frameCaptureMode.attrs.stopThreshold = attrs.stopThreshold;
    hwCapture.captureParam.frameCaptureMode.attrs.silenceThreshold = attrs.silenceThreshold;
    hwCapture.captureParam.frameCaptureMode.attrs.isBigEndian = attrs.isBigEndian;
    hwCapture.captureParam.frameCaptureMode.attrs.isSignedData = attrs.isSignedData;
    return HDF_SUCCESS;
}

void InitAttrsCommon(struct AudioSampleAttributes &attrs)
{
    /* Initialization of audio parameters for playback */
    attrs.sampleRate = AUDIO_SAMPLE_RATE_48K;
}

int32_t InitAttrs(struct AudioSampleAttributes &attrs)
{
    InitAttrsCommon(attrs);
    attrs.format = AUDIO_FORMAT_PCM_32_BIT;
    attrs.channelCount = AUDIO_CHANNELCOUNT;
    attrs.interleaved = 1;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.silenceThreshold = 0;
    return HDF_SUCCESS;
}

int32_t InitDevDesc(struct AudioDeviceDescriptor &devDesc)
{
    /* Initialization of audio parameters for playback */
    devDesc.portId = 0;
    devDesc.pins = PIN_OUT_SPEAKER;
    devDesc.desc = NULL;
    return HDF_SUCCESS;
}

int32_t InitDevDesc(struct AudioDeviceDescriptor &devDesc, const uint32_t portId, int pins)
{
    devDesc.portId = portId;
    devDesc.pins = (enum AudioPortPin)pins;
    devDesc.desc = nullptr;
    return HDF_SUCCESS;
}

int32_t InitAttrsCapture(struct AudioSampleAttributes &attrs)
{
    InitAttrsCommon(attrs);
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.channelCount = AUDIO_CAPTURE_CHANNELCOUNT;
    attrs.silenceThreshold = SILENCE_THRESHOLD;
    return HDF_SUCCESS;
}

int32_t InitDevDescCapture(struct AudioDeviceDescriptor &devDesc)
{
    /* Initialization of audio parameters for playback */
    devDesc.portId = 0;
    devDesc.pins = PIN_IN_MIC;
    devDesc.desc = NULL;
    return HDF_SUCCESS;
}

int32_t AudioRenderCallbackUtTest(enum AudioCallbackType type, void *reserved, void *cookie)
{
    (void)reserved;
    (void)cookie;
    switch (type) {
        case AUDIO_NONBLOCK_WRITE_COMPELETED:
            return HDF_SUCCESS;
        case AUDIO_RENDER_FULL:
            return HDF_SUCCESS;
        case AUDIO_FLUSH_COMPLETED:
            return HDF_SUCCESS;
        case AUDIO_ERROR_OCCUR:
            return HDF_FAILURE;
        case AUDIO_DRAIN_COMPELETED:
            return HDF_FAILURE;
        default:
            return HDF_FAILURE;
    }
    return HDF_FAILURE;
}

int32_t SwitchAdapter(struct AudioAdapterDescriptor *descs, const std::string &adapterNameCase,
                      int portFlag, struct AudioPort *&audioPort, int size)
{
    if (descs == nullptr || size > ADAPTER_COUNT) {
        return HDF_FAILURE;
    }

    for (int index = 0; index < size; index++) {
        struct AudioAdapterDescriptor *desc = &descs[index];
        if (desc == nullptr || desc->adapterName == nullptr) {
            continue;
        }
        if (strcmp(desc->adapterName, adapterNameCase.c_str())) {
            continue;
        }
        for (uint32_t port = 0; port < desc->portNum; port++) {
            if (desc->ports[port].dir == portFlag) {
                audioPort = &desc->ports[port];
                return index;
            }
        }
    }
    return HDF_FAILURE;
}

int32_t GetAdapters(TestAudioManager *manager, struct AudioAdapterDescriptor **descs, int &size)
{
    if (descs == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = manager->GetAllAdapters(manager, descs, &size);
    if (ret < 0) {
        return ret;
    }
    if (*descs == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t GetLoadAdapter(TestAudioManager *manager, int portType,
                       const std::string &adapterName, struct AudioAdapter **adapter, struct AudioPort *&audioPort)
{
    int size = 0;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    if (adapter == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = GetAdapters(manager, &descs, size);
    if (ret < 0) {
        return ret;
    }
    if (descs == nullptr) {
        return HDF_FAILURE;
    }

    int index = SwitchAdapter(descs, adapterName, portType, audioPort, size);
    if (index < 0) {
        return HDF_FAILURE;
    }
    desc = &descs[index];
    if (desc == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    ret = manager->LoadAdapter(manager, desc, adapter);
    if (ret < 0) {
        return ret;
    }
    if (*adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
}
