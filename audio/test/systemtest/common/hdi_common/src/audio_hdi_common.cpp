/**
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
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter, and rendering and capturing audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_adapter.h
 *
 * @brief Declares APIs for operations related to the audio adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"

using namespace std;

static int turnOff = 0;
static int g_captureState = 1;
namespace HMOS {
namespace Audio {
int32_t InitAttrs(struct AudioSampleAttributes& attrs)
{
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.channelCount = CHANNELCOUNT;
    attrs.sampleRate = SAMPLERATE;
    attrs.interleaved = 0;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = PCM_16_BIT * CHANNELCOUNT / MOVE_LEFT_NUM;
    attrs.isBigEndian = false;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (PCM_16_BIT * attrs.channelCount / MOVE_LEFT_NUM);
    attrs.stopThreshold = INT_32_MAX;
    attrs.silenceThreshold = 0;
    return HDF_SUCCESS;
}
uint32_t StringToInt(std::string flag)
{
    uint32_t temp = flag[0];
    for (int i = flag.size() - 1; i >= 0; i--) {
        temp <<= MOVE_LEFT_NUM;
        temp += flag[i];
    }
    return temp;
}

int32_t InitDevDesc(struct AudioDeviceDescriptor& devDesc, const uint32_t portId, enum AudioPortPin pins)
{
    devDesc.portId = portId;
    devDesc.pins = pins;
    devDesc.desc = nullptr;
    return HDF_SUCCESS;
}

int32_t SwitchAdapter(struct AudioAdapterDescriptor *descs, const std::string adapterNameCase,
    enum AudioPortDirection portFlag, struct AudioPort& audioPort, int size)
{
    if (descs == nullptr) {
        return HDF_FAILURE;
    }
    int count = size;
    for (int index = 0; index < count; index++) {
        struct AudioAdapterDescriptor *desc = &descs[index];
        if (strcmp(desc->adapterName, adapterNameCase.c_str())) {
            continue;
        }
        for (uint32_t port = 0; ((desc != nullptr) && (port < desc->portNum)); port++) {
            if (desc->ports[port].dir == portFlag) {
                audioPort = desc->ports[port];
                return index;
            }
        }
    }
    return HDF_FAILURE;
}

uint32_t PcmFormatToBits(enum AudioFormat format)
{
    switch (format) {
        case AUDIO_FORMAT_PCM_16_BIT:
            return PCM_16_BIT;
        case AUDIO_FORMAT_PCM_8_BIT:
            return PCM_8_BIT;
        default:
            return PCM_8_BIT;
    };
}

void StreamClose(int sig)
{
    /* allow the stream to be closed gracefully */
    signal(sig, SIG_IGN);
    turnOff = 1;
}

uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs)
{
    uint32_t ret = 1024 * 4 * (attrs.channelCount) * (PcmFormatToBits(attrs.format) >> 3);
    return ret;
}

int32_t WavHeadAnalysis(struct AudioHeadInfo& wavHeadInfo, FILE *file, struct AudioSampleAttributes& attrs)
{
    int ret = 0;
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = fread(&wavHeadInfo, sizeof(wavHeadInfo), 1, file);
    if (ret != 1) {
        return HDF_FAILURE;
    }
    uint32_t audioRiffId = StringToInt(AUDIO_RIFF);
    uint32_t audioFileFmt = StringToInt(AUDIO_WAVE);
    uint32_t aduioDataId = StringToInt(AUDIO_DATA);
    if (wavHeadInfo.testFileRiffId != audioRiffId || wavHeadInfo.testFileFmt != audioFileFmt ||
        wavHeadInfo.dataId != aduioDataId) {
        return HDF_FAILURE;
        }
    attrs.channelCount = wavHeadInfo.audioChannelNum;
    attrs.sampleRate = wavHeadInfo.audioSampleRate;
    switch (wavHeadInfo.audioBitsPerSample) {
        case PCM_8_BIT: {
            attrs.format = AUDIO_FORMAT_PCM_8_BIT;
            break;
        }
        case PCM_16_BIT: {
            attrs.format = AUDIO_FORMAT_PCM_16_BIT;
            break;
        }
        case PCM_24_BIT: {
            attrs.format = AUDIO_FORMAT_PCM_24_BIT;
            break;
        }
        case PCM_32_BIT: {
            attrs.format = AUDIO_FORMAT_PCM_32_BIT;
            break;
        }
        default:
            return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t FrameStart(struct AudioHeadInfo wavHeadInfo, struct AudioRender* render, FILE* file,
    struct AudioSampleAttributes attrs)
{
    int32_t ret = 0;
    int bufferSize = 0;
    int readSize = 0;
    int remainingDataSize = 0;
    int numRead = 0;
    uint64_t replyBytes = 0;
    if (render == nullptr || render->control.Start == nullptr || render->RenderFrame == nullptr || file == nullptr) {
        return HDF_FAILURE;
    }
    ret = render->control.Start((AudioHandle)render);
    if (ret) {
        return HDF_FAILURE;
    }
    remainingDataSize = wavHeadInfo.dataSize;
    bufferSize = PcmFramesToBytes(attrs);
    if (bufferSize <= 0) {
        return HDF_FAILURE;
    }
    char *frame = nullptr;
    frame = (char *)calloc(1, bufferSize);
    if (frame == nullptr) {
        return HDF_FAILURE;
    }
    signal(SIGINT, StreamClose);
    do {
        readSize = (remainingDataSize) > (bufferSize) ? (bufferSize) : (remainingDataSize);
        numRead = fread(frame, 1, readSize, file);
        if (numRead > 0) {
            ret = render->RenderFrame(render, frame, numRead, &replyBytes);
            if (ret < 0) {
                if (ret == -1) {
                    continue;
                }
                free(frame);
                return HDF_FAILURE;
            }
            remainingDataSize -= numRead;
        }
    } while (!turnOff && numRead > 0 && remainingDataSize > 0);
    free(frame);
    return HDF_SUCCESS;
}

int32_t FrameStartCapture(struct AudioCapture *capture, FILE *file, const struct AudioSampleAttributes attrs)
{
    int32_t ret = 0;
    int bufferSize = 0;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = 0;
    if (capture == nullptr || capture->control.Start == nullptr || capture->CaptureFrame == nullptr) {
        return HDF_FAILURE;
    }
    ret = capture->control.Start((AudioHandle)capture);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    bufferSize = PcmFramesToBytes(attrs);
    char *frame = nullptr;
    frame = (char *)calloc(1, bufferSize);
    if (frame == nullptr) {
        return HDF_FAILURE;
    }
    requestBytes = bufferSize;
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    if (ret < 0) {
        free(frame);
        return HDF_FAILURE;
    }
    fwrite(frame, requestBytes, 1, file);
    free(frame);
    return HDF_SUCCESS;
}

int32_t RenderFramePrepare(const std::string path, char *&frame, uint64_t& numRead)
{
    int32_t ret = -1;
    int readSize = 0;
    int bufferSize = 0;
    int remainingDataSize = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioHeadInfo headInfo = {};
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    char absPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), absPath) == nullptr) {
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = WavHeadAnalysis(headInfo, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    bufferSize = PcmFramesToBytes(attrs);
    if (bufferSize <= 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    frame = (char *)calloc(1, bufferSize);
    if (frame == nullptr) {
        fclose(file);
        return HDF_FAILURE;
    }
    remainingDataSize = headInfo.dataSize;
    readSize = (remainingDataSize) > (bufferSize) ? (bufferSize) : (remainingDataSize);
    numRead = fread(frame, 1, readSize, file);
    if (numRead < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

void CaptureFrameStatus(int status)
{
    g_captureState = status;
    return;
}

int32_t StartRecord(struct AudioCapture *capture, FILE *file, uint64_t filesize)
{
    int32_t ret = 0;
    int bufferSize = BUFFER_LENTH;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_LENTH;
    uint64_t totalSize = 0;
    if (capture == nullptr || capture->control.Start == nullptr ||
        capture->CaptureFrame == nullptr ||file == nullptr) {
        return HDF_FAILURE;
    }
    ret = capture->control.Start((AudioHandle)capture);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    char *frame = (char *)calloc(1, bufferSize);
    if (frame == nullptr) {
        return HDF_FAILURE;
    }
    do {
        if (g_captureState) {
            ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
            if (ret < 0) {
                if (ret == -1) {
                    continue;
                }
                free(frame);
                frame = nullptr;
                return HDF_FAILURE;
            }
            uint32_t replyByte = static_cast<uint32_t>(replyBytes);
            ret = fwrite(frame, replyByte, 1, file);
            if (ret < 0) {
                free(frame);
                frame = nullptr;
                return HDF_FAILURE;
            }
            totalSize += replyBytes;
        } else {
            totalSize += 0;
        }
    } while (totalSize <= filesize * MEGABYTE);
    free(frame);
    frame = nullptr;
    return HDF_SUCCESS;
}

int32_t WriteIdToBuf(struct HdfSBuf *sBuf, struct AudioCtlElemId id)
{
    if (!HdfSbufWriteInt32(sBuf, id.iface)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, id.cardServiceName)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, id.itemName)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WriteEleValueToBuf(struct HdfSBuf *sBuf, struct AudioCtlElemValue elemvalue)
{
    int32_t ret = -1;
    if (sBuf == nullptr) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemvalue.value[0])) {
        return HDF_FAILURE;
    }
    ret = WriteIdToBuf(sBuf, elemvalue.id);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ChangeRegisterStatus(struct AudioCtlElemValue elemValue)
{
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBuf = nullptr;
    struct HdfSBuf *reply = nullptr;
    int32_t ret = -1;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    if (service == nullptr) {
        return HDF_FAILURE;
    }
    sBuf = HdfSBufObtainDefaultSize();
    if (sBuf == nullptr) {
        HdfIoServiceRecycle(service);
        return HDF_FAILURE;
    }
    ret = WriteEleValueToBuf(sBuf, elemValue);
    if (ret < 0) {
        HdfSBufRecycle(sBuf);
        HdfIoServiceRecycle(service);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIODRV_CTRL_IOCTRL_ELEM_WRITE, sBuf, reply);
    if (ret < 0) {
        HdfSBufRecycle(sBuf);
        HdfIoServiceRecycle(service);
        return HDF_FAILURE;
    }
    HdfSBufRecycle(sBuf);
    HdfIoServiceRecycle(service);
    return HDF_SUCCESS;
}

int32_t QueryRegisterStatus(struct AudioCtlElemId id, struct AudioCtlElemValue &elemValue)
{
    struct HdfIoService *service = nullptr;
    struct HdfSBuf *sBuf = nullptr;
    struct HdfSBuf *reply = nullptr;
    int32_t ret = -1;
    service = HdfIoServiceBind(HDF_CONTROL_SERVICE.c_str());
    if (service == nullptr) {
        return HDF_FAILURE;
    }
    sBuf = HdfSBufObtainDefaultSize();
    if (sBuf == nullptr) {
        HdfIoServiceRecycle(service);
        return HDF_FAILURE;
    }
    ret = WriteIdToBuf(sBuf, id);
    if (ret < 0) {
        HdfSBufRecycle(sBuf);
        HdfIoServiceRecycle(service);
        return HDF_FAILURE;
    }
    reply = HdfSBufObtainDefaultSize();
    if (reply == nullptr) {
        HdfSBufRecycle(sBuf);
        HdfIoServiceRecycle(service);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, AUDIODRV_CTRL_IOCTRL_ELEM_READ, sBuf, reply);
    if (ret < 0) {
        HdfSBufRecycle(sBuf);
        HdfSBufRecycle(reply);
        HdfIoServiceRecycle(service);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &elemValue.value[0])) {
        HdfSBufRecycle(sBuf);
        HdfSBufRecycle(reply);
        HdfIoServiceRecycle(service);
        return HDF_FAILURE;
    }
    HdfSBufRecycle(sBuf);
    HdfSBufRecycle(reply);
    HdfIoServiceRecycle(service);
    return HDF_SUCCESS;
}

int32_t PowerOff(struct AudioCtlElemValue firstElemValue, struct AudioCtlElemValue secondElemValue)
{
    int32_t ret = -1;
    ret = ChangeRegisterStatus(firstElemValue);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = ChangeRegisterStatus(secondElemValue);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CheckRegisterStatus(const struct AudioCtlElemId firstId, const struct AudioCtlElemId secondId,
    const int firstStatus, const int secondStatus)
{
    int32_t ret = -1;
    struct AudioCtlElemValue elemValue[2] = {{}, {}};
    ret = QueryRegisterStatus(firstId, elemValue[0]);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    if (firstStatus != elemValue[0].value[0]) {
        return HDF_FAILURE;
    }
    ret = QueryRegisterStatus(secondId, elemValue[1]);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    if (secondStatus != elemValue[1].value[0]) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
}
}