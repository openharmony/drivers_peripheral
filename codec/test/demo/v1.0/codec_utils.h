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

#ifndef CODEC_UTILS_H
#define CODEC_UTILS_H

#include "hdf_types.h"
#include "codec_type.h"

#define MAX_FILE_NAME_LENGTH        256
#define TYPE_NAME_LENGTH            256

/* For overall configure setup */
typedef struct {
    CodecType   type;
    char        fileInput[MAX_FILE_NAME_LENGTH];
    char        fileOutput[MAX_FILE_NAME_LENGTH];
    char        codecName[TYPE_NAME_LENGTH];
    int32_t     width;
    int32_t     height;
} CodecCmd;

int32_t ParseArguments(CodecCmd* cmd, int argc, char **argv);

#endif  // CODEC_UTILS_H
