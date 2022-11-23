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

#include "component_common.h"
#include <hdf_log.h>
#include <hdf_base.h>
#include "codec_omx_ext.h"

namespace OHOS {
namespace Codec {
namespace Common {
static AvCodecMime ConvertAudioCodingTypeToMimeType(OMX_AUDIO_CODINGTYPE codingType)
{
    AvCodecMime codecMime = MEDIA_MIMETYPE_INVALID;
    switch (codingType) {
        case OMX_AUDIO_CodingPCM:
            codecMime = MEDIA_MIMETYPE_AUDIO_PCM;
            break;
        case OMX_AUDIO_CodingG711:
            codecMime = MEDIA_MIMETYPE_AUDIO_G711A;
            break;
        case OMX_AUDIO_CodingG726:
            codecMime = MEDIA_MIMETYPE_AUDIO_G726;
            break;
        case OMX_AUDIO_CodingAAC:
            codecMime = MEDIA_MIMETYPE_AUDIO_AAC;
            break;
        case OMX_AUDIO_CodingMP3:
            codecMime = MEDIA_MIMETYPE_AUDIO_MP3;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport codingType[%{public}d]", __func__, codingType);
            break;
    }

    return codecMime;
}

static AvCodecMime ConvertVideoCodingTypeToMimeType(int32_t codingType)
{
    AvCodecMime codecMime = MEDIA_MIMETYPE_INVALID;
    switch (codingType) {
        case OMX_VIDEO_CodingAVC:
            codecMime = MEDIA_MIMETYPE_VIDEO_AVC;
            break;
        case CODEC_OMX_VIDEO_CodingHEVC:
            codecMime = MEDIA_MIMETYPE_VIDEO_HEVC;
            break;
        case OMX_VIDEO_CodingMPEG4:
            codecMime = MEDIA_MIMETYPE_VIDEO_MPEG4;
            break;
        default:
            HDF_LOGW("%{public}s warn, unsupport codingType[%{public}d]", __func__, codingType);
            break;
    }

    return codecMime;
}

static AvCodecMime ConvertImageCodingTypeToMimeType(OMX_IMAGE_CODINGTYPE codingType)
{
    AvCodecMime codecMime = MEDIA_MIMETYPE_INVALID;
    switch (codingType) {
        case OMX_IMAGE_CodingJPEG:
            codecMime = MEDIA_MIMETYPE_IMAGE_JPEG;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport codingType[%{public}d]", __func__, codingType);
            break;
    }

    return codecMime;
}

static int32_t ConvertMimeTypeToCodingType(AvCodecMime mimeType)
{
    int32_t codingType = 0;
    switch (mimeType) {
        case MEDIA_MIMETYPE_IMAGE_JPEG:
            codingType = OMX_IMAGE_CodingJPEG;
            break;
        case MEDIA_MIMETYPE_VIDEO_AVC:
            codingType = OMX_VIDEO_CodingAVC;
            break;
        case MEDIA_MIMETYPE_VIDEO_HEVC:
            codingType = CODEC_OMX_VIDEO_CodingHEVC;
            break;
        case MEDIA_MIMETYPE_VIDEO_MPEG4:
            codingType = OMX_VIDEO_CodingMPEG4;
            break;
        case MEDIA_MIMETYPE_AUDIO_PCM:
            codingType = OMX_AUDIO_CodingPCM;
            break;
        case MEDIA_MIMETYPE_AUDIO_G711A:
        case MEDIA_MIMETYPE_AUDIO_G711U:
            codingType = OMX_AUDIO_CodingG711;
            break;
        case MEDIA_MIMETYPE_AUDIO_G726:
            codingType = MEDIA_MIMETYPE_AUDIO_G726;
            break;
        case MEDIA_MIMETYPE_AUDIO_AAC:
            codingType = MEDIA_MIMETYPE_AUDIO_AAC;
            break;
        case MEDIA_MIMETYPE_AUDIO_MP3:
            codingType = MEDIA_MIMETYPE_AUDIO_MP3;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport codingType[%{public}d]", __func__, mimeType);
            break;
    }
    return codingType;
}

static CodecPixelFormat ConvertColorFormatToPixelFormat(OMX_COLOR_FORMATTYPE formatType)
{
    CodecPixelFormat pixelFormat = PIXEL_FORMAT_NONE;
    switch (formatType) {
        case OMX_COLOR_FormatYUV422SemiPlanar:
            pixelFormat = PIXEL_FORMAT_YCBCR_422_SP;
            break;
        case OMX_COLOR_FormatYUV420SemiPlanar:
            pixelFormat = PIXEL_FORMAT_YCBCR_420_SP;
            break;
        case OMX_COLOR_FormatYUV422Planar:
            pixelFormat = PIXEL_FORMAT_YCBCR_422_P;
            break;
        case OMX_COLOR_FormatYUV420Planar:
            pixelFormat = PIXEL_FORMAT_YCBCR_420_P;
            break;
        case OMX_COLOR_FormatYCbYCr:
            pixelFormat = PIXEL_FORMAT_YUYV_422_PKG;
            break;
        case OMX_COLOR_FormatCbYCrY:
            pixelFormat = PIXEL_FORMAT_UYVY_422_PKG;
            break;
        case OMX_COLOR_FormatYCrYCb:
            pixelFormat = PIXEL_FORMAT_YVYU_422_PKG;
            break;
        case OMX_COLOR_FormatCrYCbY:
            pixelFormat = PIXEL_FORMAT_VYUY_422_PKG;
            break;

        default:
            HDF_LOGW("%{public}s: unspupport format[%{public}d]", __func__, formatType);
            break;
    }

    return pixelFormat;
}

static OMX_COLOR_FORMATTYPE ConvertPixelFormatToColorFormat(CodecPixelFormat pixelFormat)
{
    OMX_COLOR_FORMATTYPE formatType = OMX_COLOR_FormatUnused;
    switch (pixelFormat) {
        case PIXEL_FORMAT_YCBCR_422_SP:
            formatType = OMX_COLOR_FormatYUV422SemiPlanar;
            break;
        case PIXEL_FORMAT_YCBCR_420_SP:
            formatType = OMX_COLOR_FormatYUV420SemiPlanar;
            break;
        case PIXEL_FORMAT_YCBCR_422_P:
            formatType = OMX_COLOR_FormatYUV422Planar;
            break;
        case PIXEL_FORMAT_YCBCR_420_P:
            formatType = OMX_COLOR_FormatYUV420Planar;
            break;
        case PIXEL_FORMAT_YUYV_422_PKG:
            formatType = OMX_COLOR_FormatYCbYCr;
            break;
        case PIXEL_FORMAT_UYVY_422_PKG:
            formatType = OMX_COLOR_FormatCbYCrY;
            break;
        case PIXEL_FORMAT_YVYU_422_PKG:
            formatType = OMX_COLOR_FormatYCrYCb;
            break;
        case PIXEL_FORMAT_VYUY_422_PKG:
            formatType = OMX_COLOR_FormatCrYCbY;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport pixelFormat[%{public}d]", __func__, pixelFormat);
            break;
    }
    return formatType;
}

static AudioSoundMode ConvertChannelModeToSoundMode(OMX_AUDIO_CHANNELMODETYPE modeType)
{
    AudioSoundMode soundMode = AUD_SOUND_MODE_INVALID;
    switch (modeType) {
        case OMX_AUDIO_ChannelModeStereo:
            soundMode = AUD_SOUND_MODE_STEREO;
            break;
        case OMX_AUDIO_ChannelModeMono:
            soundMode = AUD_SOUND_MODE_MONO;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport modeType[%{public}d]", __func__, modeType);
            break;
    }

    return soundMode;
}

static OMX_AUDIO_CHANNELMODETYPE ConvertSoundModeToChannelMode(AudioSoundMode soundMode)
{
    OMX_AUDIO_CHANNELMODETYPE modeType = OMX_AUDIO_ChannelModeMax;
    switch (soundMode) {
        case AUD_SOUND_MODE_STEREO:
            modeType = OMX_AUDIO_ChannelModeStereo;
            break;
        case AUD_SOUND_MODE_MONO:
            modeType = OMX_AUDIO_ChannelModeMono;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport soundMode[%{public}d]", __func__, soundMode);
            break;
    }
    return modeType;
}

static Profile ConvertAacProfileToProfile(OMX_AUDIO_AACPROFILETYPE profileType)
{
    Profile profile = INVALID_PROFILE;
    switch (profileType) {
        case OMX_AUDIO_AACObjectLC:
            profile = AAC_LC_PROFILE;
            break;
        case OMX_AUDIO_AACObjectMain:
            profile = AAC_MAIN_PROFILE;
            break;
        case OMX_AUDIO_AACObjectHE:
            profile = AAC_HE_V1_PROFILE;
            break;
        case OMX_AUDIO_AACObjectHE_PS:
            profile = AAC_HE_V2_PROFILE;
            break;
        case OMX_AUDIO_AACObjectLD:
            profile = AAC_LD_PROFILE;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport profileType[%{public}d]", __func__, profileType);
            break;
    }

    return profile;
}

static Profile ConvertAvcProfileToProfile(OMX_VIDEO_AVCPROFILETYPE profileType)
{
    Profile profile = INVALID_PROFILE;
    switch (profileType) {
        case OMX_VIDEO_AVCProfileBaseline:
            profile = AVC_BASELINE_PROFILE;
            break;
        case OMX_VIDEO_AVCProfileMain:
            profile = AVC_MAIN_PROFILE;
            break;
        case OMX_VIDEO_AVCProfileHigh:
            profile = AVC_HIGH_PROFILE;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport profileType[%{public}d]", __func__, profileType);
            break;
    }

    return profile;
}

static int32_t ConvertProfileToOmxProfile(Profile profile)
{
    int32_t profileType = 0;
    switch (profile) {
        case AVC_BASELINE_PROFILE:
            profileType = OMX_VIDEO_AVCProfileBaseline;
            break;
        case AVC_MAIN_PROFILE:
            profileType = OMX_VIDEO_AVCProfileMain;
            break;
        case AVC_HIGH_PROFILE:
            profileType = OMX_VIDEO_AVCProfileHigh;
            break;
        case AAC_LC_PROFILE:
            profileType = OMX_AUDIO_AACObjectLC;
            break;
        case AAC_MAIN_PROFILE:
            profileType = OMX_AUDIO_AACObjectMain;
            break;
        case AAC_HE_V1_PROFILE:
            profileType = OMX_AUDIO_AACObjectHE;
            break;
        case AAC_HE_V2_PROFILE:
            profileType = OMX_AUDIO_AACObjectHE_PS;
            break;
        case AAC_LD_PROFILE:
            profileType = OMX_AUDIO_AACObjectLD;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport profileType[%{public}d]", __func__, profile);
            break;
    }
    return profileType;
}

static VideoCodecRcMode ConvertRateTypeToRcMode(OMX_VIDEO_CONTROLRATETYPE rateType)
{
    VideoCodecRcMode rcMode = VID_CODEC_RC_CBR;
    switch (rateType) {
        case OMX_Video_ControlRateVariable:
            rcMode = VID_CODEC_RC_VBR;
            break;
        case OMX_Video_ControlRateConstant:
            rcMode = VID_CODEC_RC_CBR;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport rateType[%{public}d]", __func__, rateType);
            break;
    }

    return rcMode;
}

static OMX_VIDEO_CONTROLRATETYPE ConvertRcModeToRateType(VideoCodecRcMode rcMode)
{
    OMX_VIDEO_CONTROLRATETYPE rateType = OMX_Video_ControlRateMax;
    switch (rcMode) {
        case VID_CODEC_RC_VBR:
            rateType = OMX_Video_ControlRateVariable;
            break;
        case VID_CODEC_RC_CBR:
            rateType = OMX_Video_ControlRateConstant;
            break;

        default:
            HDF_LOGW("%{public}s warn, unsupport rcMode[%{public}d]", __func__, rcMode);
            break;
    }
    return rateType;
}

static void SplitParamPortDefinitionVideo(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_PARAM_PORTDEFINITIONTYPE *param = reinterpret_cast<OMX_PARAM_PORTDEFINITIONTYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_BUFFERSIZE;
    paramOut[index].val = setMark ? (void *)&(param->nBufferSize) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nBufferSize) : 0;
    index++;
    paramOut[index].key = KEY_MIMETYPE;
    param->format.video.eCompressionFormat =
                (OMX_VIDEO_CODINGTYPE)ConvertVideoCodingTypeToMimeType(param->format.video.eCompressionFormat);
    paramOut[index].val = setMark ? (void *)&(param->format.video.eCompressionFormat) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->format.video.eCompressionFormat) : 0;
    index++;
    paramOut[index].key = KEY_VIDEO_WIDTH;
    paramOut[index].val = setMark ? (void *)&(param->format.video.nFrameWidth) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->format.video.nFrameWidth) : 0;
    index++;
    paramOut[index].key = KEY_VIDEO_HEIGHT;
    paramOut[index].val = setMark ? (void *)&(param->format.video.nFrameHeight) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->format.video.nFrameHeight) : 0;
    index++;
    paramOut[index].key = KEY_VIDEO_STRIDE;
    paramOut[index].val = setMark ? (void *)&(param->format.video.nStride) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->format.video.nStride) : 0;
    index++;
    paramOut[index].key = KEY_BITRATE;
    paramOut[index].val = setMark ? (void *)&(param->format.video.nBitrate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->format.video.nBitrate) : 0;
    index++;
    paramOut[index].key = KEY_VIDEO_FRAME_RATE;
    paramOut[index].val = setMark ? (void *)&(param->format.video.xFramerate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->format.video.xFramerate) : 0;
    index++;
    param->format.video.eColorFormat =
                (OMX_COLOR_FORMATTYPE)ConvertColorFormatToPixelFormat(param->format.video.eColorFormat);
    if ((CodecPixelFormat)param->format.video.eColorFormat != PIXEL_FORMAT_NONE || !setMark) {
        paramOut[index].key = KEY_PIXEL_FORMAT;
        paramOut[index].val = setMark ? (void *)&(param->format.video.eColorFormat) : nullptr;
        paramOut[index].size = setMark ? sizeof(param->format.video.eColorFormat) : 0;
        index++;
    }
    paramCnt = index;
}

static void SplitParamPortDefinitionAudio(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_PARAM_PORTDEFINITIONTYPE *param = reinterpret_cast<OMX_PARAM_PORTDEFINITIONTYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_BUFFERSIZE;
    paramOut[index].val = setMark ? (void *)&(param->nBufferSize) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nBufferSize) : 0;
    index++;
    paramOut[index].key = KEY_MIMETYPE;
    param->format.audio.eEncoding =
        (OMX_AUDIO_CODINGTYPE)ConvertAudioCodingTypeToMimeType(param->format.audio.eEncoding);
    paramOut[index].val = setMark ? (void *)&(param->format.audio.eEncoding) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->format.audio.eEncoding) : 0;
    index++;
    paramCnt = index;
}

static void SplitParamPortDefinition(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark, CodecType type)
{
    if (type == VIDEO_DECODER || type == VIDEO_ENCODER) {
        SplitParamPortDefinitionVideo(paramIn, paramOut, paramCnt, setMark);
    } else if (type == AUDIO_DECODER || type == AUDIO_ENCODER) {
        SplitParamPortDefinitionAudio(paramIn, paramOut, paramCnt, setMark);
    }
}

static void SplitParamAudioPortFormat(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_AUDIO_PARAM_PORTFORMATTYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_PORTFORMATTYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_MIMETYPE;
    param->eEncoding = (OMX_AUDIO_CODINGTYPE)ConvertAudioCodingTypeToMimeType(param->eEncoding);
    paramOut[index].val = setMark ? (void *)&(param->eEncoding) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->eEncoding) : 0;
    index++;

    paramCnt = index;
}

static void SplitParamAudioPcm(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_AUDIO_PARAM_PCMMODETYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_PCMMODETYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_AUDIO_CHANNEL_COUNT;
    paramOut[index].val = setMark ? (void *)&(param->nChannels) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nChannels) : 0;
    index++;
    paramOut[index].key = KEY_AUDIO_POINTS_PER_FRAME;
    paramOut[index].val = setMark ? (void *)&(param->nBitPerSample) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nBitPerSample) : 0;
    index++;
    paramOut[index].key = KEY_AUDIO_SAMPLE_RATE;
    paramOut[index].val = setMark ? (void *)&(param->nSamplingRate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nSamplingRate) : 0;
    index++;

    paramCnt = index;
}

static void SplitParamAudioAac(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_AUDIO_PARAM_AACPROFILETYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_AACPROFILETYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_AUDIO_CHANNEL_COUNT;
    paramOut[index].val = setMark ? (void *)&(param->nChannels) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nChannels) : 0;
    index++;
    paramOut[index].key = KEY_AUDIO_SAMPLE_RATE;
    paramOut[index].val = setMark ? (void *)&(param->nSampleRate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nSampleRate) : 0;
    index++;
    paramOut[index].key = KEY_BITRATE;
    paramOut[index].val = setMark ? (void *)&(param->nBitRate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nBitRate) : 0;
    index++;
    paramOut[index].key = KEY_AUDIO_PROFILE;
    param->eAACProfile = (OMX_AUDIO_AACPROFILETYPE)ConvertAacProfileToProfile(param->eAACProfile);
    paramOut[index].val = setMark ? (void *)&(param->eAACProfile) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->eAACProfile) : 0;
    index++;
    paramOut[index].key = KEY_AUDIO_SOUND_MODE;
    param->eChannelMode = (OMX_AUDIO_CHANNELMODETYPE)ConvertChannelModeToSoundMode(param->eChannelMode);
    paramOut[index].val = setMark ? (void *)&(param->eChannelMode) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->eChannelMode) : 0;
    index++;

    paramCnt = index;
}

static void SplitParamAudioMp3(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_AUDIO_PARAM_MP3TYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_MP3TYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_AUDIO_CHANNEL_COUNT;
    paramOut[index].val = setMark ? (void *)&(param->nChannels) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nChannels) : 0;
    index++;
    paramOut[index].key = KEY_AUDIO_SAMPLE_RATE;
    paramOut[index].val = setMark ? (void *)&(param->nSampleRate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nSampleRate) : 0;
    index++;
    paramOut[index].key = KEY_BITRATE;
    paramOut[index].val = setMark ? (void *)&(param->nBitRate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nBitRate) : 0;
    index++;
    paramOut[index].key = KEY_AUDIO_SOUND_MODE;
    param->eChannelMode = (OMX_AUDIO_CHANNELMODETYPE)ConvertChannelModeToSoundMode(param->eChannelMode);
    paramOut[index].val = setMark ? (void *)&(param->eChannelMode) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->eChannelMode) : 0;
    index++;

    paramCnt = index;
}

static void SplitParamAudioG726(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_AUDIO_PARAM_G726TYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_G726TYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_AUDIO_CHANNEL_COUNT;
    paramOut[index].val = setMark ? (void *)&(param->nChannels) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nChannels) : 0;
    index++;

    paramCnt = index;
}

static void SplitParamImagePortFormat(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_IMAGE_PARAM_PORTFORMATTYPE *param = reinterpret_cast<OMX_IMAGE_PARAM_PORTFORMATTYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_MIMETYPE;
    param->eCompressionFormat = (OMX_IMAGE_CODINGTYPE)ConvertImageCodingTypeToMimeType(param->eCompressionFormat);
    paramOut[index].val = setMark ? (void *)&(param->eCompressionFormat) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->eCompressionFormat) : 0;
    index++;
    param->eColorFormat = (OMX_COLOR_FORMATTYPE)ConvertColorFormatToPixelFormat(param->eColorFormat);
    if ((CodecPixelFormat)param->eColorFormat != PIXEL_FORMAT_NONE || !setMark) {
        paramOut[index].key = KEY_PIXEL_FORMAT;
        paramOut[index].val = setMark ? (void *)&(param->eColorFormat) : nullptr;
        paramOut[index].size = setMark ? sizeof(param->eColorFormat) : 0;
        index++;
    }
    paramCnt = index;
}

static void SplitParamQfactor(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_IMAGE_PARAM_QFACTORTYPE *param = reinterpret_cast<OMX_IMAGE_PARAM_QFACTORTYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_IMAGE_Q_FACTOR;
    paramOut[index].val = setMark ? (void *)&(param->nQFactor) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->nQFactor) : 0;
    index++;

    paramCnt = index;
}

static void SplitParamVideoPortFormat(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_VIDEO_PARAM_PORTFORMATTYPE *param = reinterpret_cast<OMX_VIDEO_PARAM_PORTFORMATTYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_MIMETYPE;
    param->eCompressionFormat = (OMX_VIDEO_CODINGTYPE)ConvertVideoCodingTypeToMimeType(param->eCompressionFormat);
    paramOut[index].val = setMark ? (void *)&(param->eCompressionFormat) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->eCompressionFormat) : 0;
    index++;
    paramOut[index].key = KEY_VIDEO_FRAME_RATE;
    paramOut[index].val = setMark ? (void *)&(param->xFramerate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->xFramerate) : 0;
    index++;
    param->eColorFormat = static_cast<OMX_COLOR_FORMATTYPE>(ConvertColorFormatToPixelFormat(param->eColorFormat));
    if ((CodecPixelFormat)param->eColorFormat != PIXEL_FORMAT_NONE || !setMark) {
        paramOut[index].key = KEY_PIXEL_FORMAT;
        paramOut[index].val = setMark ? (void *)&(param->eColorFormat) : nullptr;
        paramOut[index].size = setMark ? sizeof(param->eColorFormat) : 0;
        index++;
    }

    paramCnt = index;
}

static void SplitParamVideoAvc(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_VIDEO_PARAM_AVCTYPE *param = reinterpret_cast<OMX_VIDEO_PARAM_AVCTYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_VIDEO_PROFILE;
    param->eProfile = static_cast<OMX_VIDEO_AVCPROFILETYPE>(ConvertAvcProfileToProfile(param->eProfile));
    paramOut[index].val = setMark ? (void *)&(param->eProfile) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->eProfile) : 0;
    index++;

    paramCnt = index;
}

static void SplitParamVideoBitrate(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    OMX_VIDEO_PARAM_BITRATETYPE *param = reinterpret_cast<OMX_VIDEO_PARAM_BITRATETYPE *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = KEY_VIDEO_RC_MODE;
    param->eControlRate = (OMX_VIDEO_CONTROLRATETYPE)ConvertRateTypeToRcMode(param->eControlRate);
    paramOut[index].val = setMark ? (void *)&(param->eControlRate) : nullptr;
    paramOut[index].size = setMark ? sizeof(param->eControlRate) : 0;
    index++;

    paramCnt = index;
}

static void SplitParamPassthrough(int8_t *paramIn, Param *paramOut, int32_t &paramCnt, bool setMark)
{
    PassthroughParam *param = reinterpret_cast<PassthroughParam *>(paramIn);
    int32_t index = 0;
    paramOut[index].key = (ParamKey)param->key;
    paramOut[index].val = param->val;
    paramOut[index].size = param->size;
    index++;

    paramCnt = index;
}

int32_t SplitParam(int32_t paramIndex, int8_t *paramIn, Param *paramOut, int32_t &paramCnt, CodecType type)
{
    if (paramIn == nullptr || paramOut == nullptr) {
        HDF_LOGE("%{public}s error, paramIn or paramOut is null", __func__);
        return HDF_FAILURE;
    }
    bool setMark = (paramCnt == 1);
    switch (paramIndex) {
        case OMX_IndexParamPortDefinition:
            SplitParamPortDefinition(paramIn, paramOut, paramCnt, setMark, type);
            break;
        case OMX_IndexParamAudioPortFormat:
            SplitParamAudioPortFormat(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamAudioPcm:
            SplitParamAudioPcm(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamAudioAac:
            SplitParamAudioAac(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamAudioMp3:
            SplitParamAudioMp3(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamAudioG726:
            SplitParamAudioG726(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamImagePortFormat:
            SplitParamImagePortFormat(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamQFactor:
            SplitParamQfactor(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamVideoPortFormat:
            SplitParamVideoPortFormat(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamVideoAvc:
            SplitParamVideoAvc(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamVideoBitrate:
            SplitParamVideoBitrate(paramIn, paramOut, paramCnt, setMark);
            break;
        case OMX_IndexParamPassthrough:
            SplitParamPassthrough(paramIn, paramOut, paramCnt, setMark);
            break;
        default:
            HDF_LOGE("%{public}s error, paramIndex[%{public}d] is not support!", __func__, paramIndex);
            return HDF_ERR_NOT_SUPPORT;
    }
    return HDF_SUCCESS;
}

static int32_t ParseParamPortDefinitionVideo(Param *paramIn, int8_t *paramOut, int32_t paramCnt, CodecExInfo info)
{
    OMX_PARAM_PORTDEFINITIONTYPE *param = reinterpret_cast<OMX_PARAM_PORTDEFINITIONTYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_BUFFERSIZE: {
                param->nBufferSize =
                         param->nPortIndex == INPUT_PORTINDEX ? info.inputBufferSize : info.outputBufferSize;
                param->nBufferCountActual =
                         param->nPortIndex == INPUT_PORTINDEX ? info.inputBufferCount : info.outputBufferCount;
                param->bEnabled = OMX_TRUE;
                break;
            }
            case KEY_MIMETYPE: {
                int32_t codingType = ConvertMimeTypeToCodingType(*(reinterpret_cast<AvCodecMime *>(paramIn[i].val)));
                param->format.video.eCompressionFormat = (OMX_VIDEO_CODINGTYPE)codingType;
                break;
            }
            case KEY_VIDEO_WIDTH:
                param->format.video.nFrameWidth = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_VIDEO_HEIGHT:
                param->format.video.nFrameHeight = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_VIDEO_STRIDE:
                param->format.video.nStride = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_BITRATE:
                param->format.video.nBitrate = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_VIDEO_FRAME_RATE:
                param->format.video.xFramerate = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_PIXEL_FORMAT:
                param->format.video.eColorFormat =
                         ConvertPixelFormatToColorFormat(*(reinterpret_cast<CodecPixelFormat *>(paramIn[i].val)));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamPortDefinitionAudio(Param *paramIn, int8_t *paramOut, int32_t paramCnt, CodecExInfo info)
{
    OMX_PARAM_PORTDEFINITIONTYPE *param = reinterpret_cast<OMX_PARAM_PORTDEFINITIONTYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_BUFFERSIZE: {
                param->nBufferSize =
                         param->nPortIndex == INPUT_PORTINDEX ? info.inputBufferSize : info.outputBufferSize;
                param->nBufferCountActual =
                         param->nPortIndex == INPUT_PORTINDEX ? info.inputBufferCount : info.outputBufferCount;
                param->bEnabled = OMX_TRUE;
                break;
            }
            case KEY_MIMETYPE: {
                int32_t codingType = ConvertMimeTypeToCodingType(*(reinterpret_cast<AvCodecMime *>(paramIn[i].val)));
                param->format.audio.eEncoding = static_cast<OMX_AUDIO_CODINGTYPE>(codingType);
                break;
            }

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamPortDefinition(Param *paramIn, int8_t *paramOut, int32_t paramCnt, CodecExInfo info)
{
    int32_t ret = HDF_FAILURE;
    if (info.type == VIDEO_DECODER || info.type == VIDEO_ENCODER) {
        ret = ParseParamPortDefinitionVideo(paramIn, paramOut, paramCnt, info);
    } else if (info.type == AUDIO_DECODER || info.type == AUDIO_ENCODER) {
        ret = ParseParamPortDefinitionAudio(paramIn, paramOut, paramCnt, info);
    }
    return ret;
}

static int32_t ParseParamAudioPortFormat(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_AUDIO_PARAM_PORTFORMATTYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_PORTFORMATTYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_MIMETYPE: {
                    int32_t codingType =
                        ConvertMimeTypeToCodingType(*(reinterpret_cast<AvCodecMime *>(paramIn[i].val)));
                    param->eEncoding = (OMX_AUDIO_CODINGTYPE)codingType;
                break;
            }

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamAudioPcm(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_AUDIO_PARAM_PCMMODETYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_PCMMODETYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_AUDIO_CHANNEL_COUNT:
                param->nChannels = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_AUDIO_POINTS_PER_FRAME:
                param->nBitPerSample = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_AUDIO_SAMPLE_RATE:
                param->nSamplingRate = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamAudioAac(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_AUDIO_PARAM_AACPROFILETYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_AACPROFILETYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_AUDIO_CHANNEL_COUNT:
                param->nChannels = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_AUDIO_SAMPLE_RATE:
                param->nSampleRate = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_BITRATE:
                param->nBitRate = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_AUDIO_PROFILE:
                param->eAACProfile = (OMX_AUDIO_AACPROFILETYPE)
                    ConvertProfileToOmxProfile(*(reinterpret_cast<Profile *>(paramIn[i].val)));
                break;
            case KEY_AUDIO_SOUND_MODE:
                param->eChannelMode =
                    ConvertSoundModeToChannelMode(*(reinterpret_cast<AudioSoundMode *>(paramIn[i].val)));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamAudioMp3(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_AUDIO_PARAM_MP3TYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_MP3TYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_AUDIO_CHANNEL_COUNT:
                param->nChannels = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_AUDIO_SAMPLE_RATE:
                param->nSampleRate = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_BITRATE:
                param->nBitRate = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;
            case KEY_AUDIO_SOUND_MODE:
                param->eChannelMode =
                    ConvertSoundModeToChannelMode(*(reinterpret_cast<AudioSoundMode *>(paramIn[i].val)));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamAudioG726(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_AUDIO_PARAM_G726TYPE *param = reinterpret_cast<OMX_AUDIO_PARAM_G726TYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_AUDIO_CHANNEL_COUNT:
                param->nChannels = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamImagePortFormat(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_IMAGE_PARAM_PORTFORMATTYPE *param = reinterpret_cast<OMX_IMAGE_PARAM_PORTFORMATTYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_MIMETYPE:
                param->eCompressionFormat = (OMX_IMAGE_CODINGTYPE)
                    ConvertMimeTypeToCodingType(*(reinterpret_cast<AvCodecMime *>(paramIn[i].val)));
                break;
            case KEY_PIXEL_FORMAT:
                param->eColorFormat =
                    ConvertPixelFormatToColorFormat(*(reinterpret_cast<CodecPixelFormat *>(paramIn[i].val)));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamQfactor(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_IMAGE_PARAM_QFACTORTYPE *param = reinterpret_cast<OMX_IMAGE_PARAM_QFACTORTYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_IMAGE_Q_FACTOR:
                param->nQFactor = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamVideoPortFormat(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_VIDEO_PARAM_PORTFORMATTYPE *param = reinterpret_cast<OMX_VIDEO_PARAM_PORTFORMATTYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_MIMETYPE:
                param->eCompressionFormat = (OMX_VIDEO_CODINGTYPE)
                    ConvertMimeTypeToCodingType(*(reinterpret_cast<AvCodecMime *>(paramIn[i].val)));
                break;
            case KEY_PIXEL_FORMAT:
                param->eColorFormat =
                    ConvertPixelFormatToColorFormat(*(reinterpret_cast<CodecPixelFormat *>(paramIn[i].val)));
                break;
            case KEY_VIDEO_FRAME_RATE:
                param->xFramerate = *(reinterpret_cast<OMX_U32 *>(paramIn[i].val));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamVideoAvc(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_VIDEO_PARAM_AVCTYPE *param = reinterpret_cast<OMX_VIDEO_PARAM_AVCTYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_VIDEO_PROFILE:
                param->eProfile = static_cast<OMX_VIDEO_AVCPROFILETYPE>
                    (ConvertProfileToOmxProfile(*(reinterpret_cast<Profile *>(paramIn[i].val))));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamVideoBitrate(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    OMX_VIDEO_PARAM_BITRATETYPE *param = reinterpret_cast<OMX_VIDEO_PARAM_BITRATETYPE *>(paramOut);
    int32_t validCount = 0;
    for (int32_t i = 0; i < paramCnt; i++) {
        if (paramIn[i].val == nullptr) {
            continue;
        }
        validCount++;
        switch (paramIn[i].key) {
            case KEY_VIDEO_RC_MODE:
                param->eControlRate =
                    ConvertRcModeToRateType(*(reinterpret_cast<VideoCodecRcMode *>(paramIn[i].val)));
                break;

            default: {
                validCount--;
                HDF_LOGW("%{public}s warn, unsupport key[%{public}d]", __func__, paramIn[i].key);
                break;
            }
        }
    }
    return (validCount > 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t ParseParamPassthrough(Param *paramIn, int8_t *paramOut, int32_t paramCnt)
{
    PassthroughParam *param = reinterpret_cast<PassthroughParam *>(paramOut);

    int32_t index = 0;
    if (paramIn[index].val == nullptr) {
        return HDF_FAILURE;
    }
    param->key = paramIn[index].key;
    param->val = paramIn[index].val;
    param->size = paramIn[index].size;
    return HDF_SUCCESS;
}

int32_t ParseParam(int32_t paramIndex, Param *paramIn, int32_t paramCnt, int8_t *paramOut, CodecExInfo info)
{
    if (paramIn == nullptr || paramOut == nullptr) {
        HDF_LOGE("%{public}s error, paramIn or paramOut is null", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = HDF_SUCCESS;
    switch (paramIndex) {
        case OMX_IndexParamPortDefinition:
            ret = ParseParamPortDefinition(paramIn, paramOut, paramCnt, info);
            break;
        case OMX_IndexParamAudioPortFormat:
            ret = ParseParamAudioPortFormat(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamAudioPcm:
            ret = ParseParamAudioPcm(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamAudioAac:
            ret = ParseParamAudioAac(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamAudioMp3:
            ret = ParseParamAudioMp3(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamAudioG726:
            ret = ParseParamAudioG726(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamImagePortFormat:
            ret = ParseParamImagePortFormat(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamQFactor:
            ret = ParseParamQfactor(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamVideoPortFormat:
            ret = ParseParamVideoPortFormat(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamVideoAvc:
            ret = ParseParamVideoAvc(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamVideoBitrate:
            ret = ParseParamVideoBitrate(paramIn, paramOut, paramCnt);
            break;
        case OMX_IndexParamPassthrough:
            ret = ParseParamPassthrough(paramIn, paramOut, paramCnt);
            break;

        default:
            HDF_LOGE("%{public}s error, unsupport paramIndex[%{public}d]", __func__, paramIndex);
            ret = HDF_ERR_NOT_SUPPORT;
            break;
    }
    return ret;
}

static int32_t ConvertBufferTypeToOmxBufferType(BufferType type)
{
    CodecBufferType bufferType;
    switch (type) {
        case BUFFER_TYPE_VIRTUAL:
            bufferType = CODEC_BUFFER_TYPE_VIRTUAL_ADDR;
            break;
        case BUFFER_TYPE_FD:
            bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;
            break;
        case BUFFER_TYPE_HANDLE:
            bufferType = CODEC_BUFFER_TYPE_HANDLE;
            break;

        default: {
            HDF_LOGW("%{public}s warn, unsupport bufferType[%{public}d]", __func__, type);
            bufferType = CODEC_BUFFER_TYPE_INVALID;
            break;
        }
    }
    return bufferType;
}

int32_t ConvertOmxBufferTypeToBufferType(int32_t type, BufferType &bufferType)
{
    int32_t ret = HDF_SUCCESS;
    switch (type) {
        case CODEC_BUFFER_TYPE_VIRTUAL_ADDR:
            bufferType = BUFFER_TYPE_VIRTUAL;
            break;
        case CODEC_BUFFER_TYPE_AVSHARE_MEM_FD:
            bufferType = BUFFER_TYPE_FD;
            break;
        case CODEC_BUFFER_TYPE_HANDLE:
            bufferType = BUFFER_TYPE_HANDLE;
            break;

        default: {
            HDF_LOGE("%{public}s warn, unsupport bufferType[%{public}d]", __func__, type);
            bufferType = BUFFER_TYPE_VIRTUAL;
            ret = HDF_FAILURE;
            break;
        }
    }
    return ret;
}

void ConvertOmxCodecBufferToCodecBuffer(const OmxCodecBuffer &omxBuffer, CodecBuffer &codecBuffer)
{
    codecBuffer.bufferId = omxBuffer.bufferId;
    codecBuffer.timeStamp = omxBuffer.pts;
    if (omxBuffer.flag & OMX_BUFFERFLAG_EOS) {
        codecBuffer.flag = STREAM_FLAG_EOS;
    } else {
        codecBuffer.flag = STREAM_FLAG_CODEC_SPECIFIC_INF;
    }
    codecBuffer.bufferCnt = 1;
    ConvertOmxBufferTypeToBufferType(omxBuffer.bufferType, codecBuffer.buffer[0].type);
    codecBuffer.buffer[0].buf = (intptr_t)omxBuffer.buffer;
    codecBuffer.buffer[0].offset = omxBuffer.offset;
    codecBuffer.buffer[0].length = omxBuffer.filledLen;
    codecBuffer.buffer[0].capacity = omxBuffer.allocLen;
}

void ConvertCodecBufferToOmxCodecBuffer(OmxCodecBuffer &omxBuffer, CodecBuffer &codecBuffer)
{
    omxBuffer.bufferId = codecBuffer.bufferId;
    omxBuffer.pts = codecBuffer.timeStamp;
    if (codecBuffer.flag & STREAM_FLAG_EOS) {
        omxBuffer.flag = OMX_BUFFERFLAG_EOS;
    }
    omxBuffer.bufferType = (CodecBufferType)ConvertBufferTypeToOmxBufferType(codecBuffer.buffer[0].type);
    omxBuffer.buffer = (uint8_t *)codecBuffer.buffer[0].buf;
    omxBuffer.offset = codecBuffer.buffer[0].offset;
    omxBuffer.filledLen = codecBuffer.buffer[0].length;
    omxBuffer.allocLen = codecBuffer.buffer[0].capacity;
    omxBuffer.bufferLen = codecBuffer.buffer[0].capacity;
}
}  // namespace Common
}  // namespace Codec
}  // namespace OHOS