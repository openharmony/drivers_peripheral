/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_utils.h"
#include <securec.h>
#include "hdf_base.h"
#include "hdf_log.h"

#define HDF_LOG_TAG codec_hdi_demo_utils
#define CMD_OPTION_MARK_OFFSET  0
#define CMD_OPTION_NAME_OFFSET  1
#define STRTOL_BASE  10

static int32_t GetCodecName(CodecCmd* cmd)
{
    int32_t codecNum = 0;
    CodecTypeAndName *codecs;
    CodecTypeAndName encoders[] = {
        {{"avc", "AVC"}, CODEC_NAME_AVC_HW_ENCODER, MEDIA_MIMETYPE_VIDEO_AVC},
        {{"hevc", "HEVC"}, CODEC_NAME_HEVC_HW_ENCODER, MEDIA_MIMETYPE_VIDEO_HEVC},
        {{"vp9", "VP9"}, CODEC_NAME_VP9_HW_ENCODER, MEDIA_MIMETYPE_INVALID},    // MIMETYPE NOT DEFINED YET
        {{"vp8", "VP8"}, CODEC_NAME_VP8_HW_ENCODER, MEDIA_MIMETYPE_INVALID},    // MIMETYPE NOT DEFINED YET
        {{"mpeg4", "MPEG4"}, CODEC_NAME_MPEG4_HW_ENCODER, MEDIA_MIMETYPE_VIDEO_MPEG4}
    };
    CodecTypeAndName decoders[] = {
        {{"avc", "AVC"}, CODEC_NAME_AVC_HW_DECODER, MEDIA_MIMETYPE_VIDEO_AVC},
        {{"hevc", "HEVC"}, CODEC_NAME_HEVC_HW_DECODER, MEDIA_MIMETYPE_VIDEO_HEVC},
        {{"vp9", "VP9"}, CODEC_NAME_VP9_HW_DECODER, MEDIA_MIMETYPE_INVALID},    // MIMETYPE NOT DEFINED YET
        {{"vp8", "VP8"}, CODEC_NAME_VP8_HW_DECODER, MEDIA_MIMETYPE_INVALID},    // MIMETYPE NOT DEFINED YET
        {{"mpeg4", "MPEG4"}, CODEC_NAME_MPEG4_HW_DECODER, MEDIA_MIMETYPE_VIDEO_MPEG4}
    };

    if (cmd->type == VIDEO_ENCODER) {
        codecNum = sizeof(encoders) / sizeof(CodecTypeAndName);
        codecs = encoders;
    } else if (cmd->type == VIDEO_DECODER) {
        codecNum = sizeof(decoders) / sizeof(CodecTypeAndName);
        codecs = decoders;
    }

    for (int32_t i = 0; i < codecNum; i++) {
        if (strstr(cmd->codecName, codecs[i].codecType[0]) || strstr(cmd->codecName, codecs[i].codecType[1])) {
            int32_t ret = strcpy_s(cmd->codecName, TYPE_NAME_LENGTH, codecs[i].codecName);
            if (ret != EOK) {
                HDF_LOGE("%{public}s, failed to strcpy_s codecName. ret:%{public}d", __func__, ret);
                return HDF_FAILURE;
            }
            cmd->mime = codecs[i].mimeType;
            return HDF_SUCCESS;
        }
    }

    HDF_LOGE("%{public}s: not support coding codecName", __func__);
    return HDF_FAILURE;
}

static int32_t ParseCmdOption(CodecCmd* cmd, const char *opt, const char *next)
{
    int32_t ret = HDF_SUCCESS;
    if (cmd == NULL || opt == NULL || next == NULL) {
        return HDF_FAILURE;
    }
    switch (*opt) {
        case 'i': {
            int32_t len = strnlen(next, MAX_FILE_NAME_LENGTH);
            if (len) {
                strcpy_s(cmd->fileInput, MAX_FILE_NAME_LENGTH, next);
            } else {
                ret = HDF_FAILURE;
            }
            } break;
        case 'o': {
            int32_t len = strnlen(next, MAX_FILE_NAME_LENGTH);
            if (len) {
                strcpy_s(cmd->fileOutput, MAX_FILE_NAME_LENGTH, next);
            } else {
                ret = HDF_FAILURE;
            }
            } break;
        case 'w': {
            cmd->width = (int32_t)strtol(next, NULL, STRTOL_BASE);
            } break;
        case 'h': {
            cmd->height = (int32_t)strtol(next, NULL, STRTOL_BASE);
            } break;
        case 't': {
            int32_t len = strnlen(next, TYPE_NAME_LENGTH);
            if (len) {
                strcpy_s(cmd->codecName, TYPE_NAME_LENGTH, next);
                ret = GetCodecName(cmd);
            } else {
                ret = HDF_FAILURE;
            }
            } break;
        case 'f': {
            cmd->fps = (int32_t)strtol(next, NULL, STRTOL_BASE);
            } break;
        case 'p': {
            cmd->pixFmt = (int32_t)strtol(next, NULL, STRTOL_BASE);
            } break;
        default:
            break;
    }
    return ret;
}

int32_t ParseArguments(CodecCmd* cmd, int argc, char **argv)
{
    int32_t optindex = 1;
    int32_t ret = HDF_SUCCESS;

    if ((argc <= 1) || (cmd == NULL)) {
        return ret;
    }

    /* parse options */
    while (optindex < argc) {
        const char *opt = (const char*)argv[optindex++];
        const char *next = (const char*)argv[optindex];
        int32_t optMark = CMD_OPTION_MARK_OFFSET;
        int32_t optName = CMD_OPTION_NAME_OFFSET;

        if ((opt[optMark] == '-') && (opt[optName] != '\0')) {
            optMark++;
            optName++;
            if ((opt[optMark] == '-') && (opt[optName] != '\0')) {
                opt++;
            }
            if ((opt[optMark] == '-') && (opt[optName] == '\0')) {
                ret = HDF_FAILURE;
                break;
            }

            opt++;
            if (ParseCmdOption(cmd, opt, next) == HDF_FAILURE) {
                ret = HDF_FAILURE;
                break;
            }
            optindex++;
        }
    }
    return ret;
}

void FreeParams(Param *params, int32_t paramCnt)
{
    if (params == NULL || paramCnt <= 0) {
        HDF_LOGE("%{public}s: params is null or invalid count!", __func__);
        return;
    }
    for (int32_t j = 0; j < paramCnt; j++) {
        if (params[j].val != NULL && params[j].size > 0) {
            OsalMemFree(params[j].val);
            params[j].val = NULL;
        }
    }
    OsalMemFree(params);
}

