/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file display_format.h
 *
 * @brief Declares display format-related enumeration.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef DISPLAY_FORMAT_H
#define DISPLAY_FORMAT_H

#include <cstdint>

namespace OHOS::Camera {

enum BufferUsage : uint64_t {
    HBM_USE_CPU_READ = (1ULL << 0),
    HBM_USE_CPU_WRITE = (1ULL << 1),
    HBM_USE_MEM_MMZ = (1ULL << 2),
    HBM_USE_MEM_DMA = (1ULL << 3),
    HBM_USE_MEM_SHARE = (1ULL << 4),
    HBM_USE_MEM_MMZ_CACHE = (1ULL << 5),
    HBM_USE_MEM_FB = (1ULL << 6),
    HBM_USE_ASSIGN_SIZE = (1ULL << 7),
    HBM_USE_HW_RENDER = (1ULL << 8),
    HBM_USE_HW_TEXTURE = (1ULL << 9),
    HBM_USE_HW_COMPOSER = (1ULL << 10),
    HBM_USE_PROTECTED = (1ULL << 11),
    HBM_USE_CAMERA_READ = (1ULL << 12),
    HBM_USE_CAMERA_WRITE = (1ULL << 13),
    HBM_USE_VIDEO_ENCODER = (1ULL << 14),
    HBM_USE_VIDEO_DECODER = (1ULL << 15),
    HBM_USE_CPU_READ_OFTEN = (1ULL << 16),
    HBM_USE_VENDOR_PRI0 = (1ULL << 44),
    HBM_USE_VENDOR_PRI1 = (1ULL << 45),
    HBM_USE_VENDOR_PRI2 = (1ULL << 46),
    HBM_USE_VENDOR_PRI3 = (1ULL << 47),
    HBM_USE_VENDOR_PRI4 = (1ULL << 48),
    HBM_USE_VENDOR_PRI5 = (1ULL << 49),
    HBM_USE_VENDOR_PRI6 = (1ULL << 50),
    HBM_USE_VENDOR_PRI7 = (1ULL << 51),
    HBM_USE_VENDOR_PRI8 = (1ULL << 52),
    HBM_USE_VENDOR_PRI9 = (1ULL << 53),
    HBM_USE_VENDOR_PRI10 = (1ULL << 54),
    HBM_USE_VENDOR_PRI11 = (1ULL << 55),
    HBM_USE_VENDOR_PRI12 = (1ULL << 56),
    HBM_USE_VENDOR_PRI13 = (1ULL << 57),
    HBM_USE_VENDOR_PRI14 = (1ULL << 58),
    HBM_USE_VENDOR_PRI15 = (1ULL << 59),
    HBM_USE_VENDOR_PRI16 = (1ULL << 60),
    HBM_USE_VENDOR_PRI17 = (1ULL << 61),
    HBM_USE_VENDOR_PRI18 = (1ULL << 62),
    HBM_USE_VENDOR_PRI19 = (1ULL << 63),
};

enum PixelFormat : int32_t {
    PIXEL_FMT_CLUT8 = 0,
    PIXEL_FMT_CLUT1,
    PIXEL_FMT_CLUT4,
    PIXEL_FMT_RGB_565,
    PIXEL_FMT_RGBA_5658,
    PIXEL_FMT_RGBX_4444,
    PIXEL_FMT_RGBA_4444,
    PIXEL_FMT_RGB_444,
    PIXEL_FMT_RGBX_5551,
    PIXEL_FMT_RGBA_5551,
    PIXEL_FMT_RGB_555,
    PIXEL_FMT_RGBX_8888,
    PIXEL_FMT_RGBA_8888,
    PIXEL_FMT_RGB_888,
    PIXEL_FMT_BGR_565,
    PIXEL_FMT_BGRX_4444,
    PIXEL_FMT_BGRA_4444,
    PIXEL_FMT_BGRX_5551,
    PIXEL_FMT_BGRA_5551,
    PIXEL_FMT_BGRX_8888,
    PIXEL_FMT_BGRA_8888,
    PIXEL_FMT_YUV_422_I,
    PIXEL_FMT_YCBCR_422_SP,
    PIXEL_FMT_YCRCB_422_SP,
    PIXEL_FMT_YCBCR_420_SP,
    PIXEL_FMT_YCRCB_420_SP,
    PIXEL_FMT_YCBCR_422_P,
    PIXEL_FMT_YCRCB_422_P,
    PIXEL_FMT_YCBCR_420_P,
    PIXEL_FMT_YCRCB_420_P,
    PIXEL_FMT_YUYV_422_PKG,
    PIXEL_FMT_UYVY_422_PKG,
    PIXEL_FMT_YVYU_422_PKG,
    PIXEL_FMT_VYUY_422_PKG,
    PIXEL_FMT_RGBA_1010102,
    PIXEL_FMT_YCBCR_P010,
    PIXEL_FMT_YCRCB_P010,
    PIXEL_FMT_RAW10,
    PIXEL_FMT_BLOB,
    PIXEL_FMT_VENDER_MASK = 0X7FFF0000,
    PIXEL_FMT_BUTT = 0X7FFFFFFF,
};

enum OhosColorSpace {
    OHOS_CAMERA_COLORSPACE_NONE,
    // COLORPRIMARIES_BT709   | (TRANSFUNC_BT709 << 8) | (MATRIX_BT709   << 16) | (RANGE_FULL << 21)
    OHOS_CAMERA_BT709_FULL          = 1 | (1 << 8) | (1 << 16) | (1 << 21),
    // COLORPRIMARIES_BT2020  | (TRANSFUNC_HLG   << 8) | (MATRIX_BT2020  << 16) | (RANGE_FULL << 21)
    OHOS_CAMERA_BT2020_HLG_FULL     = 4 | (5 << 8) | (4 << 16) | (1 << 21),
    // COLORPRIMARIES_BT2020  | (TRANSFUNC_PQ    << 8) | (MATRIX_BT2020  << 16) | (RANGE_FULL << 21)
    OHOS_CAMERA_BT2020_PQ_FULL      = 4 | (4 << 8) | (4 << 16) | (1 << 21),
    // COLORPRIMARIES_SRGB    | (TRANSFUNC_SRGB  << 8) | (MATRIX_BT601_N << 16) | (RANGE_FULL << 21)
    OHOS_CAMERA_SRGB_FULL           = 1 | (2 << 8) | (3 << 16) | (1 << 21),
    // COLORPRIMARIES_P3_D65  | (TRANSFUNC_SRGB  << 8) | (MATRIX_P3      << 16) | (RANGE_FULL << 21)
    OHOS_CAMERA_P3_FULL             = 6 | (2 << 8) | (3 << 16) | (1 << 21),
};

} // end namespace OHOS::Camera
#endif
