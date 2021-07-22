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
 * @brief Defines audio ADM test-related APIs, including data types and functions for writting data
to buffer.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_adm_common.h
 *
 * @brief Declares APIs for operations related to the audio ADM testing.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_adm_common.h"

using namespace std;

namespace HMOS {
namespace Audio {
int32_t WriteIdToBuf(struct HdfSBuf *sBuf, struct AudioCtlElemId id)
{
    if (sBuf == nullptr) {
        return HDF_FAILURE;
    }
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

int32_t WriteHwParamsToBuf(struct HdfSBuf *sBuf, struct AudioPcmHwParams hwParams)
{
    if (sBuf == nullptr) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)hwParams.streamType)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.channels)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.rate)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.periodSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.periodCount)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(hwParams.format))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, hwParams.cardServiceName)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.period)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.frameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(hwParams.isBigEndian))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(hwParams.isSignedData))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.startThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.stopThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, hwParams.silenceThreshold)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t InitAttrs(struct AudioSampleAttributes& attrs)
{
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.channelCount = G_CHANNELCOUNT;
    attrs.sampleRate = G_SAMPLERATE;
    attrs.interleaved = 0;
    attrs.type = AUDIO_IN_MEDIA;
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

uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs)
{
    uint32_t ret = 512 * (attrs.channelCount) * (PcmFormatToBits(attrs.format) >> 3);
    return ret;
}

uint32_t FormatToBits(enum AudioFormat format)
{
    switch (format) {
        case AUDIO_FORMAT_PCM_16_BIT:
            return G_PCM16BIT;
        case AUDIO_FORMAT_PCM_8_BIT:
            return G_PCM8BIT;
        default:
            return G_PCM16BIT;
    }
}

int32_t AdmRenderFramePrepare(const std::string path, char *&frame, unsigned long& numRead, unsigned long& frameSize)
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
    frameSize = numRead / (attrs.channelCount * (FormatToBits(attrs.format) >> Move_Right));
    fclose(file);
    return HDF_SUCCESS;
}

int32_t WriteFrameToSBuf(struct HdfSBuf *&sBufT, char *buf, unsigned long bufsize,
    unsigned long frameSize, const std::string path)
{
    int32_t ret = -1;
    sBufT = HdfSBufObtainDefaultSize();
    if (sBufT == NULL) {
        return HDF_FAILURE;
    }

    ret = AdmRenderFramePrepare(path, buf, bufsize, frameSize);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(sBufT, (uint32_t)(frameSize))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteBuffer(sBufT, buf, bufsize)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ObtainBuf(struct HdfSBuf *&writeBuf, struct HdfSBuf *&readBuf, struct HdfSBuf *&readReply)
{
    writeBuf = HdfSBufObtainDefaultSize();
    if (writeBuf == nullptr) {
        return HDF_FAILURE;
    }
    readBuf = HdfSBufObtainDefaultSize();
    if (readBuf == nullptr) {
        HdfSBufRecycle(writeBuf);
        return HDF_FAILURE;
    }
    readReply = HdfSBufObtainDefaultSize();
    if (readReply == nullptr) {
        HdfSBufRecycle(writeBuf);
        HdfSBufRecycle(readBuf);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
}
}