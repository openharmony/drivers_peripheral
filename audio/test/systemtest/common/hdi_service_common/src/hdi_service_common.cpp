/**
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
#include "hdi_service_common.h"
#include <sys/stat.h>
#include "hdf_log.h"
#include "osal_mem.h"

#define SREREO_CHANNEL 2
#define MONO_CHANNEL   1

using namespace std;

static int g_frameStatus = 1;
static int g_writeCompleted = 0;
static int g_renderFull = 0;
static int g_flushCompleted = 0;
namespace OHOS {
namespace Audio {
int32_t InitAttrs(struct AudioSampleAttributes &attrs)
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
    attrs.silenceThreshold = BUFFER_LENTH;
    return HDF_SUCCESS;
}
int32_t InitAttrsUpdate(struct AudioSampleAttributes &attrs, int format, uint32_t channelCount,
    uint32_t sampleRate, uint32_t silenceThreshold)
{
    InitAttrs(attrs);
    attrs.format = (enum AudioFormat)format;
    attrs.sampleRate = sampleRate;
    attrs.channelCount = channelCount;
    attrs.silenceThreshold = silenceThreshold;
    return HDF_SUCCESS;
}
int32_t AudioRenderSetGetSampleAttributes(struct AudioSampleAttributes attrs, struct AudioSampleAttributes &attrsValue,
    struct IAudioRender *render)
{
    int32_t ret = -1;
    if (render == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    ret = render->SetSampleAttributes(render, &attrs);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:Set sampleattributes failed\n", __func__);
        return ret;
    }
    ret = render->GetSampleAttributes(render, &attrsValue);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:Get sampleattributes failed\n", __func__);
        return ret;
    }
    return HDF_SUCCESS;
}
int32_t AudioCaptureSetGetSampleAttributes(struct AudioSampleAttributes attrs, struct AudioSampleAttributes &attrsValue,
    struct IAudioCapture *capture)
{
    int32_t ret = -1;
    if (capture == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    ret = capture->SetSampleAttributes(capture, &attrs);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:Set sampleattributes failed\n", __func__);
        return ret;
    }
    ret = capture->GetSampleAttributes(capture, &attrsValue);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:Get sampleattributes failed\n", __func__);
        return ret;
    }
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

int32_t InitDevDesc(struct AudioDeviceDescriptor &devDesc, const uint32_t portId, int pins)
{
    devDesc.portId = portId;
    devDesc.pins = (enum AudioPortPin)pins;
    devDesc.desc = strdup("cardname");
    return HDF_SUCCESS;
}

int32_t SwitchAdapter(struct AudioAdapterDescriptor *descs, const std::string &adapterNameCase,
    int portFlag, struct AudioPort &audioPort, int size)
{
    if (descs == nullptr || size > ADAPTER_COUNT) {
        HDF_LOGE("%{public}s: AUDIO_TEST:parms is invalid\n", __func__);
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
        for (uint32_t port = 0; port < desc->portsLen; port++) {
            if (desc->ports[port].dir == portFlag) {
                audioPort.dir = desc->ports[port].dir;
                audioPort.portId = desc->ports[port].portId;
                audioPort.portName = strdup(desc->ports[port].portName);
                return index;
            }
        }
    }
    return HDF_FAILURE;
}

uint32_t PcmFormatToBits(int format)
{
    switch (format) {
        case AUDIO_FORMAT_PCM_8_BIT:
            return PCM_8_BIT;
        case AUDIO_FORMAT_PCM_16_BIT:
            return PCM_16_BIT;
        case AUDIO_FORMAT_PCM_24_BIT:
            return PCM_24_BIT;
        case AUDIO_FORMAT_PCM_32_BIT:
            return PCM_32_BIT;
        default:
            return PCM_16_BIT;
    }
}

uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs)
{
    if (attrs.channelCount < MONO_CHANNEL || attrs.channelCount > SREREO_CHANNEL) {
        HDF_LOGE("%{public}s: AUDIO_TEST:channelCount is invalid\n", __func__);
        return 0;
    }
    uint32_t formatBits = PcmFormatToBits(attrs.format);
    if (formatBits < PCM_8_BIT || formatBits > PCM_32_BIT) {
        HDF_LOGE("%{public}s: AUDIO_TEST:formatBits is invalid\n", __func__);
        return 0;
    }
    uint32_t ret = FRAME_SIZE * (attrs.channelCount) * (formatBits >> MOVE_RIGHT_NUM);
    return ret;
}

int32_t WavHeadAnalysis(struct AudioHeadInfo &wavHeadInfo, FILE *file, struct AudioSampleAttributes &attrs)
{
    size_t ret = 0;
    if (file == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:params is invalid\n", __func__);
        return HDF_FAILURE;
    }
    ret = fread(&wavHeadInfo, sizeof(wavHeadInfo), 1, file);
    if (ret != 1) {
        HDF_LOGE("%{public}s: AUDIO_TEST:fread failed\n", __func__);
        return HDF_FAILURE;
    }
    uint32_t audioRiffId = StringToInt(AUDIO_RIFF);
    uint32_t audioFileFmt = StringToInt(AUDIO_WAVE);
    uint32_t audioDataId = StringToInt(AUDIO_DATA);
    if (wavHeadInfo.testFileRiffId != audioRiffId || wavHeadInfo.testFileFmt != audioFileFmt ||
        wavHeadInfo.dataId != audioDataId) {
        HDF_LOGE("%{public}s: AUDIO_TEST:audio file is not wav format\n", __func__);
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

static void TestAudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (dataBlock->adapterName != NULL) {
        OsalMemFree(dataBlock->adapterName);
        dataBlock->adapterName = NULL;
    }

    if (dataBlock->ports != NULL) {
        OsalMemFree(dataBlock->ports);
        dataBlock->ports = NULL;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void TestReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if (descsLen > 0 && descs != nullptr && (*descs) != nullptr) {
        for (uint32_t i = 0; i < descsLen; i++) {
            TestAudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = nullptr;
    }
}
int32_t GetAdapters(TestAudioManager *manager, struct AudioAdapterDescriptor *&descs, uint32_t &descsLen)
{
    int32_t ret = -1;
    if (descsLen < AUDIO_ADAPTER_MAX_NUM) {
        HDF_LOGE("%{public}s: AUDIO_TEST:descsLen is little than AUDIO_ADAPTER_MAX_NUM\n", __func__);
        return HDF_FAILURE;
    }
    descs = reinterpret_cast<struct AudioAdapterDescriptor*>(OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (descsLen)));
    if (descs == NULL) {
        return HDF_FAILURE;
    }
    ret = manager->GetAllAdapters(manager, descs, &descsLen);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:GetAllAdapters failed\n", __func__);
        OsalMemFree(descs);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t GetLoadAdapter(TestAudioManager *manager, int portType,
    const std::string &adapterName, struct IAudioAdapter **adapter, struct AudioPort &audioPort)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    if (manager == nullptr || adapter == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:params is invalid\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetAdapters(manager, descs, descsLen);
    if (ret < 0) {
        return ret;
    }

    int index = SwitchAdapter(descs, adapterName, portType, audioPort, descsLen);
    if (index < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:switch adapter failed\n", __func__);
        TestReleaseAdapterDescs(&descs, descsLen);
        return HDF_FAILURE;
    }

    desc = &descs[index];
    if (desc == nullptr) {
        TestReleaseAdapterDescs(&descs, descsLen);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = manager->LoadAdapter(manager, desc, adapter);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:load adapter failed\n", __func__);
        TestReleaseAdapterDescs(&descs, descsLen);
        return ret;
    }
    if (*adapter == nullptr) {
        TestReleaseAdapterDescs(&descs, descsLen);
        return HDF_FAILURE;
    }
    TestReleaseAdapterDescs(&descs, descsLen);
    return HDF_SUCCESS;
}

int32_t AudioCreateRender(TestAudioManager *manager, int pins, const std::string &adapterName,
    struct IAudioAdapter **adapter, struct IAudioRender **render)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioPort audioPort = {};
    if (adapter == nullptr || render == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetLoadAdapter(manager, PORT_OUT, adapterName, adapter, audioPort);
    if (ret < 0) {
        if (audioPort.portName != nullptr) {
            free(audioPort.portName);
        }
        return ret;
    }
    if (*adapter == nullptr || (*adapter)->CreateRender == nullptr) {
        free(audioPort.portName);
        return HDF_FAILURE;
    }
    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, pins);
    ret = (*adapter)->CreateRender(*adapter, &devDesc, &attrs, render);
    if (ret < 0 || *render == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:Create render failed\n", __func__);
        manager->UnloadAdapter(manager, adapterName.c_str());
        IAudioAdapterRelease(*adapter, IS_STUB);
        free(audioPort.portName);
        free(devDesc.desc);
        return ret;
    }
    free(audioPort.portName);
    free(devDesc.desc);
    return HDF_SUCCESS;
}

int32_t AudioRenderStartAndOneFrame(struct IAudioRender *render)
{
    int32_t ret = -1;
    char *frame = nullptr;
    uint64_t numRead = 0;
    uint64_t replyBytes = 0;
    if (render == nullptr || render->Start == nullptr || render->RenderFrame == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:params is invlaid\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = render->Start(render);
    if (ret) {
        return ret;
    }
    ret = RenderFramePrepare(AUDIO_FILE, frame, numRead);
    if (ret < 0) {
        if (frame != nullptr) {
            free(frame);
            frame = nullptr;
        }
        return HDF_FAILURE;
    }
    ret = render->RenderFrame(render, reinterpret_cast<int8_t *>(frame), numRead, &replyBytes);
    if (ret < 0) {
        if (frame != nullptr) {
            free(frame);
            frame = nullptr;
        }
        HDF_LOGE("%{public}s: AUDIO_TEST:render frame failed\n", __func__);
        return ret;
    }
    free(frame);
    frame = nullptr;
    return HDF_SUCCESS;
}

int32_t AudioCreateCapture(TestAudioManager *manager, int pins, const std::string &adapterName,
    struct IAudioAdapter **adapter, struct IAudioCapture **capture)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioPort audioPort = {};
    if (adapter == nullptr || capture == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetLoadAdapter(manager, PORT_IN, adapterName, adapter, audioPort);
    if (ret < 0) {
        if (audioPort.portName != nullptr) {
            free(audioPort.portName);
        }
        return ret;
    }
    if (*adapter == nullptr || (*adapter)->CreateCapture == nullptr) {
        return HDF_FAILURE;
    }
    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, pins);
    ret = (*adapter)->CreateCapture(*adapter, &devDesc, &attrs, capture);
    if (ret < 0 || *capture == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:Create capture failed\n", __func__);
        manager->UnloadAdapter(manager, adapterName.c_str());
        IAudioAdapterRelease(*adapter, IS_STUB);
        free(audioPort.portName);
        free(devDesc.desc);
        return ret;
    }
    free(audioPort.portName);
    free(devDesc.desc);
    return HDF_SUCCESS;
}

int32_t AudioCaptureStartAndOneFrame(struct IAudioCapture *capture)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    InitAttrs(attrs);
    FILE *file = fopen(AUDIO_CAPTURE_FILE.c_str(), "wb+");
    if (file == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:foen failed\n", __func__);
        return HDF_FAILURE;
    }
    ret = FrameStartCapture(capture, file, attrs);
    if (ret < 0) {
        fclose(file);
        return ret;
    }
    (void) fclose(file);
    return HDF_SUCCESS;
}
static int32_t RenderTryOneFrame(struct IAudioRender *render,
    int8_t *frame,  uint32_t requestBytes, uint64_t *replyBytes)
{
    int32_t tryNumFrame = 0;
    int32_t ret;

    if (render == nullptr || render->RenderFrame == nullptr ||
        frame == nullptr || replyBytes == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:params is invalid\n", __func__);
        return HDF_FAILURE;
    }
    do {
        ret = render->RenderFrame(render, frame, requestBytes, replyBytes);
        if (ret == -1) {
            tryNumFrame++;
            if (tryNumFrame <= TRY_NUM_FRAME) {
                continue;
            } else {
                return ret;
            }
        }
        return ret;
    } while (true);
}
int32_t FrameStart(struct AudioHeadInfo wavHeadInfo, struct IAudioRender *render, FILE *file,
    struct AudioSampleAttributes attrs)
{
    uint32_t readSize = 0;
    size_t numRead = 0;
    uint64_t replyBytes = 0;
    if (render == nullptr || render->Start == nullptr || render->RenderFrame == nullptr || file == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:params is invalid\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = render->Start(render);
    if (ret) {
        HDF_LOGE("%{public}s: AUDIO_TEST:start failed\n", __func__);
        return ret;
    }
    uint32_t remainingDataSize = wavHeadInfo.dataSize;
    uint32_t bufferSize = PcmFramesToBytes(attrs);
    if (bufferSize == 0) {
        return HDF_FAILURE;
    }
    char *frame = nullptr;
    frame = reinterpret_cast<char *>(calloc(1, bufferSize));
    if (frame == nullptr) {
        return HDF_ERR_MALLOC_FAIL;
    }
    do {
        if (g_frameStatus) {
            readSize = (remainingDataSize) > (bufferSize) ? (bufferSize) : (remainingDataSize);
            numRead = fread(frame, readSize, 1, file);
            if (numRead == 0) {
                free(frame);
                return HDF_FAILURE;
            }
            ret = RenderTryOneFrame(render, reinterpret_cast<int8_t *>(frame), readSize, &replyBytes);
            if (ret < 0) {
                free(frame);
                return ret;
            }
            remainingDataSize -= readSize;
        }
    } while (readSize > 0 && remainingDataSize > 0);
    free(frame);
    return HDF_SUCCESS;
}

int32_t FrameStartCapture(struct IAudioCapture *capture, FILE *file, const struct AudioSampleAttributes attrs)
{
    int32_t ret = 0;
    uint32_t bufferSize = 0;
    uint32_t replyBytes = 0;
    uint64_t requestBytes = 0;
    if (capture == nullptr || capture->Start == nullptr || capture->CaptureFrame == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:params is invalid\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = capture->Start(capture);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:start failed\n", __func__);
        return ret;
    }
    uint32_t pcmBytes = PcmFramesToBytes(attrs);
    if (pcmBytes < PCM_BYTE_MIN || pcmBytes > PCM_BYTE_MAX) {
        return HDF_FAILURE;
    }
    bufferSize = FRAME_COUNT * pcmBytes;
    if (bufferSize == 0) {
        return HDF_FAILURE;
    }
    char *frame = nullptr;
    frame = reinterpret_cast<char *>(calloc(1, bufferSize));
    if (frame == nullptr) {
        return HDF_ERR_MALLOC_FAIL;
    }
    requestBytes = bufferSize;
    replyBytes = bufferSize;
    ret = capture->CaptureFrame(capture, reinterpret_cast<int8_t *>(frame), &replyBytes, requestBytes);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:CaptureFrame failed\n", __func__);
        free(frame);
        return ret;
    }
    uint32_t requestByte = static_cast<uint32_t>(replyBytes);
    (void) fwrite(frame, requestByte, 1, file);
    free(frame);
    return HDF_SUCCESS;
}

int32_t RenderFramePrepare(const std::string &path, char *&frame, uint64_t &readSize)
{
    int32_t ret = -1;
    size_t numRead = 0;
    uint32_t bufferSize = 4096;
    uint32_t remainingDataSize = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioHeadInfo headInfo = {};
    InitAttrs(attrs);
    char absPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), absPath) == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:file not exist\n", __func__);
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:fopen failed\n", __func__);
        return HDF_FAILURE;
    }
    ret = WavHeadAnalysis(headInfo, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    frame = reinterpret_cast<char *>(calloc(1, bufferSize));
    if (frame == nullptr) {
        fclose(file);
        return HDF_ERR_MALLOC_FAIL;
    }
    remainingDataSize = headInfo.dataSize;
    readSize = (remainingDataSize) > (bufferSize) ? (bufferSize) : (remainingDataSize);
    size_t readSizes = static_cast<size_t>(readSize);
    numRead = fread(frame, readSizes, 1, file);
    if (numRead < 1) {
        free(frame);
        frame = nullptr;
        fclose(file);
        return HDF_FAILURE;
    }
    (void) fclose(file);
    return HDF_SUCCESS;
}

void FrameStatus(int status)
{
    g_frameStatus = status;
    return;
}

static int32_t CaptureTryOneFrame(struct IAudioCapture *capture,
    int8_t *frame, uint32_t *replyBytes, uint64_t requestBytes)
{
    int32_t tryNum = 0;
    int32_t ret;

    if (capture == nullptr || capture->CaptureFrame == nullptr ||
        frame == nullptr || replyBytes == nullptr) {
        return HDF_FAILURE;
    }
    do {
        ret = capture->CaptureFrame(capture, frame, replyBytes, requestBytes);
        if (ret == HDF_FAILURE) {
            tryNum++;
            if (tryNum <= TRY_NUM_FRAME) {
                continue;
            } else {
                return ret;
            }
        }
        return ret;
    } while (true);
}

int32_t StartRecord(struct IAudioCapture *capture, FILE *file, uint64_t filesize)
{
    uint32_t replyBytes = BUFFER_LENTH;
    uint64_t requestBytes = BUFFER_LENTH;
    uint64_t totalSize = 0;
    if (capture == nullptr || capture->Start == nullptr ||
        capture->CaptureFrame == nullptr || file == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:param is invalid\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = capture->Start(capture);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:start failed\n", __func__);
        return ret;
    }
    char *frame = reinterpret_cast<char *>(calloc(1, BUFFER_LENTH));
    if (frame == nullptr) {
        return HDF_ERR_MALLOC_FAIL;
    }
    do {
        if (g_frameStatus) {
            ret = CaptureTryOneFrame(capture, reinterpret_cast<int8_t *>(frame), &replyBytes, requestBytes);
            if (ret < 0) {
                free(frame);
                return ret;
            }
            uint32_t replyByte = static_cast<uint32_t>(replyBytes);
            size_t writeRet = fwrite(frame, replyByte, 1, file);
            if (writeRet == 0) {
                free(frame);
                return HDF_FAILURE;
            }
            totalSize += replyBytes;
        } else {
            totalSize += 0;
        }
    } while (totalSize <= filesize * MEGABYTE);
    free(frame);
    return HDF_SUCCESS;
}

int32_t StopAudio(struct PrepareAudioPara &audiopara)
{
    int32_t ret = -1;
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->Stop(audiopara.capture);
        HDF_LOGE("%{public}s: AUDIO_TEST:capture stop failed\n", __func__);
        return ret;
    }
    if (audiopara.render != nullptr) {
        ret = audiopara.render->Stop(audiopara.render);
        HDF_LOGE("%{public}s: AUDIO_TEST:render stop failed\n", __func__);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t ThreadRelease(struct PrepareAudioPara &audiopara)
{
    int32_t ret = -1;
    pthread_join(audiopara.tids, &audiopara.result);
    ret = (intptr_t)audiopara.result;
    if (ret < 0) {
        StopAudio(audiopara);
        return ret;
    }
    ret = StopAudio(audiopara);
    return ret;
}
int32_t PlayAudioFile(struct PrepareAudioPara &audiopara)
{
    int32_t ret = -1;
    char absPath[PATH_MAX] = {0};
    if (realpath(audiopara.path, absPath) == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:file not exist\n", __func__);
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    if (WavHeadAnalysis(audiopara.headInfo, file, audiopara.attrs) < 0) {
        (void)fclose(file);
        return HDF_FAILURE;
    }
    ret = FrameStart(audiopara.headInfo, audiopara.render, file, audiopara.attrs);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: AUDIO_TEST:FrameStart failed\n", __func__);
        (void)fclose(file);
        return ret;
    }
    (void)fclose(file);
    return HDF_SUCCESS;
}

int32_t RecordAudio(struct PrepareAudioPara &audiopara)
{
    int32_t ret = -1;
    if (audiopara.capture == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:param is invalid\n", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    bool isMute = false;
    ret = audiopara.capture->SetMute(audiopara.capture, isMute);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:SetMute failed\n", __func__);
        return ret;
    }

    FILE *file = fopen(audiopara.path, "wb+");
    if (file == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:fopen failed\n", __func__);
        return HDF_FAILURE;
    }
    ret = StartRecord(audiopara.capture, file, audiopara.fileSize);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:StartRecord failed\n", __func__);
        fclose(file);
        return ret;
    }
    (void) fclose(file);
    return HDF_SUCCESS;
}
int32_t InitMmapDesc(const string &path, struct AudioMmapBufferDescripter &desc, int32_t &reqSize, bool isRender)
{
    FILE *fp;
    if (isRender) {
        (void)chmod(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        fp = fopen(path.c_str(), "rb+");
    } else {
        fp = fopen(path.c_str(), "wb+");
        (void)chmod(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    }
    if (fp == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:fopen failed\n", __func__);
        return HDF_FAILURE;
    }
    int fd = fileno(fp);
    if (fd == -1) {
        fclose(fp);
        HDF_LOGE("%{public}s: AUDIO_TEST:fd is invalid\n", __func__);
        return HDF_FAILURE;
    }
    if (isRender) {
        struct AudioHeadInfo wavHeadInfo = {};
        fseek(fp, 0, SEEK_END);
        reqSize = ftell(fp);
        desc.offset = sizeof(wavHeadInfo);
    } else {
        reqSize = FILE_CAPTURE_SIZE;
        ftruncate(fd, FILE_CAPTURE_SIZE);
        desc.offset = 0;
    }
    desc.filePath = strdup(path.c_str());
    desc.memoryFd = fd;
    desc.isShareable = 1;
    desc.transferFrameSize = DEEP_BUFFER_RENDER_PERIOD_SIZE / FRAME_COUNT;
    (void) fclose(fp);
    return HDF_SUCCESS;
}

int32_t PlayMapAudioFile(struct PrepareAudioPara &audiopara)
{
    int32_t ret = -1;
    int32_t reqSize = 0;
    bool isRender = true;
    FrameStatus(1);
    struct AudioMmapBufferDescripter desc = {};
    if (audiopara.render == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitMmapDesc(audiopara.path, desc, reqSize, isRender);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = audiopara.render->Start(audiopara.render);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:start failed\n", __func__);
        return ret;
    }
    ret = audiopara.render->ReqMmapBuffer(audiopara.render, reqSize, &desc);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    return ret;
}
int32_t RecordMapAudio(struct PrepareAudioPara &audiopara)
{
    int32_t ret = -1;
    int32_t reqSize = 0;
    bool isRender = false;
    struct AudioMmapBufferDescripter desc = {};
    if (audiopara.capture == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:param is invlaid\n", __func__);
        return HDF_FAILURE;
    }
    ret = InitMmapDesc(audiopara.path, desc, reqSize, isRender);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = audiopara.capture->Start(audiopara.capture);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AUDIO_TEST:start failed\n", __func__);
        return ret;
    }
    ret = audiopara.capture->ReqMmapBuffer(audiopara.capture, reqSize, &desc);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    return ret;
}
int32_t AudioRenderCallback(struct IAudioCallback *self, AudioCallbackType type, int8_t* reserved,
    int8_t* cookie)
{
    (void)self;
    (void)reserved;
    (void)cookie;
    switch (type) {
        case AUDIO_NONBLOCK_WRITE_COMPELETED:
            g_writeCompleted = AUDIO_WRITE_COMPELETED_VALUE;
            return HDF_SUCCESS;
        case AUDIO_RENDER_FULL:
            g_renderFull = AUDIO_RENDER_FULL_VALUE;
            return HDF_SUCCESS;
        case AUDIO_FLUSH_COMPLETED:
            g_flushCompleted = AUDIO_FLUSH_COMPLETED_VALUE;
            return HDF_SUCCESS;
        case AUDIO_ERROR_OCCUR:
            return HDF_FAILURE;
        case AUDIO_DRAIN_COMPELETED:
            return HDF_FAILURE;
        default:
            return HDF_FAILURE;
    }
}
int32_t CheckWriteCompleteValue()
{
    if (g_writeCompleted == AUDIO_WRITE_COMPELETED_VALUE)
        return HDF_SUCCESS;
    else
        return HDF_FAILURE;
}
int32_t CheckRenderFullValue()
{
    if (g_renderFull == AUDIO_RENDER_FULL_VALUE)
        return HDF_SUCCESS;
    else
        return HDF_FAILURE;
}
int32_t CheckFlushValue()
{
    if (g_flushCompleted == AUDIO_FLUSH_COMPLETED_VALUE)
        return HDF_SUCCESS;
    else
        return HDF_FAILURE;
}

void TestAudioSubPortCapabilityFree(struct AudioSubPortCapability *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (dataBlock->desc != NULL) {
        OsalMemFree(dataBlock->desc);
        dataBlock->desc = NULL;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void TestAudioPortCapabilityFree(struct AudioPortCapability *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (dataBlock->formatsLen > 0 && dataBlock->formats != NULL) {
        OsalMemFree(dataBlock->formats);
    }

    if (dataBlock->subPortsLen > 0 && dataBlock->subPorts != NULL) {
        for (uint32_t i = 0; i < dataBlock->subPortsLen; i++) {
            TestAudioSubPortCapabilityFree(&dataBlock->subPorts[i], false);
        }
        OsalMemFree(dataBlock->subPorts);
    }

    if (dataBlock->supportSampleFormatsLen > 0 && dataBlock->supportSampleFormats != NULL) {
        OsalMemFree(dataBlock->supportSampleFormats);
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

int32_t ReleaseCaptureSource(TestAudioManager *manager, struct IAudioAdapter *&adapter,
    struct IAudioCapture *&capture)
{
    if (manager == nullptr || adapter == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:param is nullptr\n", __func__);
        return HDF_FAILURE;
    }
    if (manager->UnloadAdapter == nullptr || adapter->DestroyCapture == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:fuction is nullptr\n", __func__);
        return HDF_FAILURE;
    }
    struct AudioDeviceDescriptor devDesc;
    InitDevDesc(devDesc, 0, PIN_IN_MIC);
    int32_t ret = adapter->DestroyCapture(adapter, &devDesc);
    if (ret != HDF_SUCCESS) {
        free(devDesc.desc);
        HDF_LOGE("%{public}s: AUDIO_TEST:DestroyCapture failed\n", __func__);
        return HDF_FAILURE;
    }
    IAudioCaptureRelease(capture, IS_STUB);
    capture = nullptr;
    free(devDesc.desc);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: AUDIO_TEST:UnloadAdapter failed\n", __func__);
        return HDF_FAILURE;
    }
    IAudioAdapterRelease(adapter, IS_STUB);
    adapter = nullptr;
    return HDF_SUCCESS;
}

int32_t ReleaseRenderSource(TestAudioManager *manager, struct IAudioAdapter *&adapter, struct IAudioRender *&render)
{
    if (manager == nullptr || adapter == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:param is nullptr\n", __func__);
        return HDF_FAILURE;
    }

    struct AudioDeviceDescriptor devDesc;
    InitDevDesc(devDesc, 0, PIN_OUT_SPEAKER);
    if (manager->UnloadAdapter == nullptr || adapter->DestroyRender == nullptr) {
        HDF_LOGE("%{public}s: AUDIO_TEST:fuction is nullptr\n", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = adapter->DestroyRender(adapter, &devDesc);
    if (ret != HDF_SUCCESS) {
        free(devDesc.desc);
        HDF_LOGE("%{public}s: AUDIO_TEST:DestroyRender failed\n", __func__);
        return HDF_FAILURE;
    }
    IAudioRenderRelease(render, IS_STUB);
    render = nullptr;
    free(devDesc.desc);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: AUDIO_TEST:UnloadAdapter failed\n", __func__);
        return HDF_FAILURE;
    }
    IAudioAdapterRelease(adapter, IS_STUB);
    adapter = nullptr;
    return HDF_SUCCESS;
}
}
}
