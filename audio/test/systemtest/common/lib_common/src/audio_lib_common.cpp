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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Test audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver ADM interface lib.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_lib_common.h
 *
 * @brief Declares APIs for operations related to the audio ADM interface lib.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_lib_common.h"

using namespace std;

namespace OHOS {
namespace Audio {
int32_t InitRenderFramepara(struct AudioFrameRenderMode& frameRenderMode)
{
    InitAttrs(frameRenderMode.attrs);
    frameRenderMode.frames = AUDIO_FORMAT_PCM_16_BIT;
    frameRenderMode.mode = AUDIO_CHANNEL_BOTH_RIGHT;
    frameRenderMode.periodSize = G_PERIODSIZE;
    frameRenderMode.periodCount = G_PERIODCOUNT;
    frameRenderMode.byteRate = G_BYTERATE;
    frameRenderMode.bufferFrameSize = G_BUFFERFRAMESIZE;
    frameRenderMode.bufferSize = G_BUFFERSIZE1;
    frameRenderMode.buffer = NULL;
    frameRenderMode.silenceThreshold = frameRenderMode.periodSize * frameRenderMode.periodCount;
    frameRenderMode.silenceSize = G_SILENCETHRESHOLE;
    frameRenderMode.startThreshold = frameRenderMode.periodSize;
    frameRenderMode.stopThreshold = frameRenderMode.periodSize * frameRenderMode.periodCount;
    return HDF_SUCCESS;
}

int32_t InitHwCaptureFramepara(struct AudioFrameCaptureMode& frameCaptureMode)
{
    InitAttrs(frameCaptureMode.attrs);
    frameCaptureMode.mode = AUDIO_CHANNEL_BOTH_RIGHT;
    frameCaptureMode.byteRate = G_BYTERATE;
    frameCaptureMode.periodSize = G_PERIODSIZE;
    frameCaptureMode.periodCount = G_PERIODCOUNT;
    frameCaptureMode.startThreshold = frameCaptureMode.periodSize;
    frameCaptureMode.stopThreshold = frameCaptureMode.periodSize * frameCaptureMode.periodCount;
    frameCaptureMode.silenceThreshold = frameCaptureMode.periodSize * frameCaptureMode.periodCount;
    frameCaptureMode.silenceSize = G_SILENCETHRESHOLE;
    frameCaptureMode.buffer = NULL;
    frameCaptureMode.bufferFrameSize = G_BUFFERFRAMESIZE;
    frameCaptureMode.bufferSize = G_BUFFERSIZE1;
    return HDF_SUCCESS;
}

int32_t InitHwRenderMode(struct AudioHwRenderMode& renderMode)
{
    int codePrimaryLen = strlen(HDF_AUDIO_CODEC_PRIMARY.c_str());
    int32_t ret = strncpy_s(renderMode.hwInfo.cardServiceName, NAME_LEN - 1,
        HDF_AUDIO_CODEC_PRIMARY.c_str(), codePrimaryLen);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    renderMode.hwInfo.portDescript.dir = PORT_OUT;
    renderMode.hwInfo.portDescript.portId = G_PORTID;
    renderMode.hwInfo.portDescript.portName = "AOP";
    renderMode.hwInfo.deviceDescript.portId = G_PORTID;
    renderMode.hwInfo.deviceDescript.pins = PIN_OUT_SPEAKER;
    renderMode.hwInfo.deviceDescript.desc = nullptr;
    return HDF_SUCCESS;
}

int32_t InitHwCaptureMode(struct AudioHwCaptureMode& captureMode)
{
    int codePrimaryLen = strlen(HDF_AUDIO_CODEC_PRIMARY.c_str());
    int32_t ret = strncpy_s(captureMode.hwInfo.cardServiceName, NAME_LEN - 1,
        HDF_AUDIO_CODEC_PRIMARY.c_str(), codePrimaryLen);
    if (ret != 0) {
        return HDF_FAILURE;
    }

    captureMode.hwInfo.portDescript.dir = PORT_IN;
    captureMode.hwInfo.portDescript.portId = 0;
    captureMode.hwInfo.portDescript.portName = "AIP";
    captureMode.hwInfo.deviceDescript.portId = 0;
    captureMode.hwInfo.deviceDescript.pins = PIN_IN_MIC;
    captureMode.hwInfo.deviceDescript.desc = nullptr;
    return HDF_SUCCESS;
}

uint32_t InitHwRender(struct AudioHwRender *&hwRender, const std::string adapterNameCase)
{
    int ret = -1;
    if (hwRender == nullptr) {
        return HDF_FAILURE;
    }
    if (InitHwRenderMode(hwRender->renderParam.renderMode) ||
        InitRenderFramepara(hwRender->renderParam.frameRenderMode)) {
        return HDF_FAILURE;
    }
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    ret = strcpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName,
        NAME_LEN, adapterNameCase.c_str());
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

uint32_t InitHwCapture(struct AudioHwCapture *&hwCapture, const std::string adapterNameCase)
{
    int ret = -1;
    if (hwCapture == nullptr) {
        return HDF_FAILURE;
    }
    if (InitHwCaptureMode(hwCapture->captureParam.captureMode) ||
        InitHwCaptureFramepara(hwCapture->captureParam.frameCaptureMode)) {
        return HDF_FAILURE;
    }
    ret = strcpy_s(hwCapture->captureParam.captureMode.hwInfo.adapterName,
        NAME_LEN, adapterNameCase.c_str());
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
int32_t CaptureReqMmapBufferInit(struct AudioFrameCaptureMode &frameCaptureMode,
                                 const std::string path, const int64_t fileSize)
{
    FILE *file = fopen(path.c_str(), "wb+");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    int fd = fileno(file);
    if (fd == -1) {
        (void)fclose(file);
        return HDF_FAILURE;
    }
    uint32_t formatBits = PcmFormatToBits(frameCaptureMode.attrs.format);

    ftruncate(fd, FILE_CAPTURE_SIZE);
    frameCaptureMode.mmapBufDesc.memoryAddress = mmap(NULL, fileSize, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0);
    if (frameCaptureMode.mmapBufDesc.memoryAddress == NULL ||
        frameCaptureMode.mmapBufDesc.memoryAddress == reinterpret_cast<void *>(-1)) {
        (void)fclose(file);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    frameCaptureMode.mmapBufDesc.totalBufferFrames = fileSize /
        (frameCaptureMode.attrs.channelCount * (formatBits >> MOVE_RIGHT_NUM));
    frameCaptureMode.mmapBufDesc.memoryFd = fd;
    frameCaptureMode.mmapBufDesc.transferFrameSize = DEEP_BUFFER_RENDER_PERIOD_SIZE / FRAME_COUNT;
    frameCaptureMode.mmapBufDesc.isShareable = 1;
    frameCaptureMode.mmapBufDesc.offset = 0;
    (void)fclose(file);
    return AUDIO_HAL_SUCCESS;
}

int32_t RenderReqMmapBufferInit(struct AudioFrameRenderMode &frameRenderMode, const std::string path, int64_t &fileSize)
{
    char absPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), absPath) == nullptr) {
        return HDF_FAILURE;
    }

    FILE *file = fopen(absPath, "rb+");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    int fd = fileno(file);
    if (fd == -1) {
        (void)fclose(file);
        return HDF_FAILURE;
    }
    uint32_t formatBits = PcmFormatToBits(frameRenderMode.attrs.format);
    (void)fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    frameRenderMode.mmapBufDesc.memoryAddress = mmap(NULL, fileSize, PROT_READ,
        MAP_SHARED, fd, 0);
    if (frameRenderMode.mmapBufDesc.memoryAddress == NULL ||
        frameRenderMode.mmapBufDesc.memoryAddress == reinterpret_cast<void *>(-1)) {
        (void)fclose(file);
        return HDF_FAILURE;
    }
    frameRenderMode.mmapBufDesc.totalBufferFrames = fileSize /
        (frameRenderMode.attrs.channelCount * (formatBits >> MOVE_RIGHT_NUM));
    frameRenderMode.mmapBufDesc.memoryFd = fd;
    frameRenderMode.mmapBufDesc.transferFrameSize = DEEP_BUFFER_RENDER_PERIOD_SIZE / FRAME_COUNT;
    frameRenderMode.mmapBufDesc.isShareable = 1;
    struct AudioHeadInfo wavHeadInfo = {};
    frameRenderMode.mmapBufDesc.offset = sizeof(wavHeadInfo);
    (void)fclose(file);
    return AUDIO_HAL_SUCCESS;
}
}
}
