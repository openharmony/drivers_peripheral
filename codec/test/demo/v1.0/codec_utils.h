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

#ifndef CODEC_UTILS_H
#define CODEC_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include "hdf_types.h"
#include "codec_type.h"
#include "osal_mem.h"

#define MAX_FILE_NAME_LENGTH        256
#define TYPE_NAME_LENGTH            256
#define CODEC_NAME_ALIAS_NUM        2
#define CODEC_NAME_AVC_HW_DECODER   "codec.avc.hardware.decoder"
#define CODEC_NAME_HEVC_HW_DECODER  "codec.hevc.hardware.decoder"
#define CODEC_NAME_VP9_HW_DECODER   "codec.vp9.hardware.decoder"
#define CODEC_NAME_VP8_HW_DECODER   "codec.vp8.hardware.decoder"
#define CODEC_NAME_MPEG4_HW_DECODER "codec.mpeg4.hardware.decoder"
#define CODEC_NAME_AVC_HW_ENCODER   "codec.avc.hardware.encoder"
#define CODEC_NAME_HEVC_HW_ENCODER  "codec.hevc.hardware.encoder"
#define CODEC_NAME_VP9_HW_ENCODER   "codec.vp9.hardware.encoder"
#define CODEC_NAME_VP8_HW_ENCODER   "codec.vp8.hardware.encoder"
#define CODEC_NAME_MPEG4_HW_ENCODER "codec.mpeg4.hardware.encoder"

typedef struct {
    char            *codecName;
    /* end of stream flag when set quit the loop */
    unsigned int    loopEnd;
    /* input and output */
    FILE            *fpInput;
    FILE            *fpOutput;
    int32_t         frameNum;
    uint32_t        bufferSize;
    uint32_t        inputBufferCount;
    uint32_t        outputBufferCount;
    CodecCallback   cb;
} CodecEnvData;

/* For overall configure setup */
typedef struct {
    CodecType   type;
    char        fileInput[MAX_FILE_NAME_LENGTH];
    char        fileOutput[MAX_FILE_NAME_LENGTH];
    char        codecName[TYPE_NAME_LENGTH];
    AvCodecMime mime;
    int32_t     width;
    int32_t     height;
    int32_t     fps;
    PixelFormat pixFmt;
} CodecCmd;

typedef struct {
    char        *codecType[CODEC_NAME_ALIAS_NUM];
    char        *codecName;
    AvCodecMime mimeType;
} CodecTypeAndName;

int32_t ParseArguments(CodecCmd* cmd, int argc, char **argv);
void FreeParams(Param *params, int32_t paramCnt);

#endif  // CODEC_UTILS_H
