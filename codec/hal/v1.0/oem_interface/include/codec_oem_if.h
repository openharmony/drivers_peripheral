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

#ifndef CODEC_OEM_IF_H
#define CODEC_OEM_IF_H

#include "hdf_base.h"
#include "codec_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef int32_t (*CodecInitType)(void);
typedef int32_t (*CodecDeinitType)(void);
typedef int32_t (*CodecCreateType)(const char* name, const Param *attr, int32_t len, CODEC_HANDLETYPE *handle);
typedef int32_t (*CodecDestroyType)(CODEC_HANDLETYPE handle);
typedef int32_t (*CodecSetPortModeType)(CODEC_HANDLETYPE handle, DirectionType type, BufferMode mode);
typedef int32_t (*CodecSetParameterType)(CODEC_HANDLETYPE handle, const Param *params, int32_t paramCnt);
typedef int32_t (*CodecGetParameterType)(CODEC_HANDLETYPE handle, Param *params, int32_t paramCnt);
typedef int32_t (*CodecStartType)(CODEC_HANDLETYPE handle);
typedef int32_t (*CodecStopType)(CODEC_HANDLETYPE handle);
typedef int32_t (*CodecFlushType)(CODEC_HANDLETYPE handle, DirectionType directType);
typedef int32_t (*CodecSetCallbackType)(CODEC_HANDLETYPE handle, const CodecCallback *cb, UINTPTR instance);
typedef int32_t (*CodecDecodeType)(CODEC_HANDLETYPE handle, InputInfo inputData, OutputInfo outInfo,
    uint32_t timeoutMs);
typedef int32_t (*CodecEncodeType)(CODEC_HANDLETYPE handle, InputInfo inputData, OutputInfo outInfo,
    uint32_t timeoutMs);
typedef int32_t (*CodecEncodeHeaderType)(CODEC_HANDLETYPE handle, OutputInfo outInfo, uint32_t timeoutMs);

struct CodecOemIf {
    CodecInitType CodecInit;
    CodecDeinitType CodecDeinit;
    CodecCreateType CodecCreate;
    CodecDestroyType CodecDestroy;
    CodecSetPortModeType CodecSetPortMode;
    CodecSetParameterType CodecSetParameter;
    CodecGetParameterType CodecGetParameter;
    CodecStartType CodecStart;
    CodecStopType CodecStop;
    CodecFlushType CodecFlush;
    CodecSetCallbackType CodecSetCallback;
    CodecDecodeType CodecDecode;
    CodecEncodeType CodecEncode;
    CodecEncodeHeaderType CodecEncodeHeader;
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */
#endif  // CODEC_OEM_IF_H