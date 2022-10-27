/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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

static int32_t GetCodecName(CodecCmd* cmd)
{
    int32_t ret = HDF_SUCCESS;
    if (strstr(cmd->codecName, "avc") || strstr(cmd->codecName, "AVC")) {
        if (cmd->type == VIDEO_ENCODER) {
            strcpy_s(cmd->codecName, TYPE_NAME_LENGTH, "codec.avc.hardware.encoder");
        } else {
            strcpy_s(cmd->codecName, TYPE_NAME_LENGTH, "codec.avc.hardware.decoder");
        }
    } else if (strstr(cmd->codecName, "hevc") || strstr(cmd->codecName, "HEVC")) {
        if (cmd->type == VIDEO_ENCODER) {
            strcpy_s(cmd->codecName, TYPE_NAME_LENGTH, "codec.hevc.hardware.encoder");
        } else {
            strcpy_s(cmd->codecName, TYPE_NAME_LENGTH, "codec.hevc.hardware.decoder");
        }
    } else {
        memset_s(cmd->codecName, TYPE_NAME_LENGTH, 0, TYPE_NAME_LENGTH);
        HDF_LOGE("%{public}s: not support coding codecName", __func__);
        ret = HDF_FAILURE;
    }
    return ret;
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
            cmd->width = atoi(next);
            } break;
        case 'h': {
            cmd->height = atoi(next);
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
        default:
            break;
    }
    return ret;
}

int32_t ParseArguments(CodecCmd* cmd, int argc, char **argv)
{
    int32_t optindex = 1;
    int32_t ret = HDF_SUCCESS;

    if ((argc <= 1) || (cmd == NULL))
        return ret;

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