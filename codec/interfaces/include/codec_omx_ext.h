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
 
#ifndef CODEC_OMX_EXT_H
#define CODEC_OMX_EXT_H
#include <OMX_IVCommon.h>
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */
/**
 * @brief Enumerates the extended codec codingtyps.
 */
enum CodecOmxVideoExType {
    CODEC_OMX_VIDEO_CodingHEVC = 11, /** HEVC Index in Codec HDI */
};

/**
 * @brief Enumerates the extended codec color format.
 */
enum CodecOmxColorFormatExt {
    CODEC_OMX_COLOR_FORMAT_RGBA8888 = OMX_COLOR_FormatVendorStartUnused + 100,
};

/**
 * @brief Enumerates the buffer types.
 */
enum CodecBufferType {
    /** Invalid buffer type. */
    CODEC_BUFFER_TYPE_INVALID = 0,
    /** Virtual address type. */
    CODEC_BUFFER_TYPE_VIRTUAL_ADDR = 0x1,
    /** Shared memory. */
    CODEC_BUFFER_TYPE_AVSHARE_MEM_FD = 0x2,
    /** Handle. */
    CODEC_BUFFER_TYPE_HANDLE = 0x4,
    /** Dynamic handle. */
    CODEC_BUFFER_TYPE_DYNAMIC_HANDLE = 0x8,
};

/**
 * @brief Defines the <b>SupportBuffer</b>.
 */
struct SupportBufferType {
    uint32_t size;                 /** Size of the structure */
    union OMX_VERSIONTYPE version; /** Component version */
    uint32_t portIndex;            /** Port index */
    uint32_t bufferTypes;          /** Supported buffer types */
};

/**
 * @brief Define the <b>UseBuffer</b>.
 */
struct UseBufferType {
    uint32_t size;                 /** Size of the structure */
    union OMX_VERSIONTYPE version; /** Component version */
    uint32_t portIndex;            /** Port index */
    uint32_t bufferType;           /** Buffer type */
};

/**
 * @brief Defines the <b>BufferHandleUsage</b>.
 */
struct GetBufferHandleUsageParams {
    uint32_t size;                 /** Size of the structure */
    union OMX_VERSIONTYPE version; /** Component version */
    uint32_t portIndex;            /** Port index */
    uint64_t usage;                /** Usage */
};

/**
 * @brief Defines the <b>CodecVideoPortFormatParam</b>.
 */
struct CodecVideoPortFormatParam {
    uint32_t size;                                         /** Size of the structure */
    union OMX_VERSIONTYPE version;                         /** Component version */
    uint32_t portIndex;                                    /** Port index */
    uint32_t codecColorFormat;                             /** Color format defined in Display */
    uint32_t codecCompressFormat;                          /** See  */
    uint32_t framerate;                                    /** Q16 format */
};

/**
 * @brief Defines the <b>ControlRateConstantQuality</b>.
 */
struct ControlRateConstantQuality {
    uint32_t size;                                         /** Size of the structure */
    union OMX_VERSIONTYPE version;                         /** Component version */
    uint32_t portIndex;                                    /** Port index */
    uint32_t qualityValue;                                 /** Control rate constant quality */
};

/**
 * @brief Defines the <b>PassthroughParam</b>.
 */
struct PassthroughParam {
    int32_t key;   /**< Parameter type index */
    void *val;     /**< Pointer to the parameter value */
    int size;      /**< Parameter value size */
};

/**
 * @brief Enumerates the extended codec indexes.
 */
enum OmxIndexCodecExType {
    /** Extended BufferType index */
    OMX_IndexExtBufferTypeStartUnused = OMX_IndexKhronosExtensions + 0x00a00000,
    /** SupportBuffer */
    OMX_IndexParamSupportBufferType,
    /** UseBuffer */
    OMX_IndexParamUseBufferType,
    /** GetBufferHandleUsage */
    OMX_IndexParamGetBufferHandleUsage,
    /** CodecVideoPortFormatParam */
    OMX_IndexCodecVideoPortFormat,
    /** ControlRateConstantQuality */
    OMX_IndexParamControlRateConstantQuality,
    /** PassthroughParam */
    OMX_IndexParamPassthrough,
};
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif  // CODEC_OMX_EXT_H