/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef DISPLAY_COMMON_FUZZER_H
#define DISPLAY_COMMON_FUZZER_H

#include "v1_0/display_composer_type.h"
#include "v1_2/display_buffer_type.h"
#include "v1_2/include/idisplay_buffer.h"
#include "buffer_handle.h"
#include "hdf_log.h"

namespace OHOS {
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
const size_t THRESHOLD = 10;
const int32_t ALPHA_VALUE_RANGE = 256; // ranging from 0 to 255
const uint32_t WIDTH = 128;
const uint32_t HEIGHT = 128;

const PixelFormat CONVERT_TABLE_FORMAT[] = {
    PIXEL_FMT_CLUT8, PIXEL_FMT_CLUT1,
    PIXEL_FMT_CLUT4, PIXEL_FMT_RGB_565,
    PIXEL_FMT_RGBA_5658, PIXEL_FMT_RGBX_4444,
    PIXEL_FMT_RGBA_4444, PIXEL_FMT_RGB_444,
    PIXEL_FMT_RGBX_5551, PIXEL_FMT_RGBA_5551,
    PIXEL_FMT_RGB_555, PIXEL_FMT_RGBX_8888,
    PIXEL_FMT_RGBA_8888, PIXEL_FMT_RGB_888,
    PIXEL_FMT_BGR_565, PIXEL_FMT_BGRX_4444,
    PIXEL_FMT_BGRA_4444, PIXEL_FMT_BGRX_5551,
    PIXEL_FMT_BGRA_5551, PIXEL_FMT_BGRX_8888,
    PIXEL_FMT_BGRA_8888, PIXEL_FMT_YUV_422_I,
    PIXEL_FMT_YCBCR_422_SP, PIXEL_FMT_YCRCB_422_SP,
    PIXEL_FMT_YCBCR_420_SP, PIXEL_FMT_YCRCB_420_SP,
    PIXEL_FMT_YCBCR_422_P, PIXEL_FMT_YCRCB_422_P,
    PIXEL_FMT_YCBCR_420_P, PIXEL_FMT_YCRCB_420_P,
    PIXEL_FMT_YUYV_422_PKG, PIXEL_FMT_UYVY_422_PKG,
    PIXEL_FMT_YVYU_422_PKG, PIXEL_FMT_VYUY_422_PKG,
    PIXEL_FMT_VENDER_MASK, PIXEL_FMT_BUTT,
};

const BufferUsage CONVERT_TABLE_USAGE[] = {
    HBM_USE_CPU_READ, HBM_USE_CPU_WRITE,
    HBM_USE_MEM_MMZ, HBM_USE_MEM_DMA,
    HBM_USE_MEM_SHARE, HBM_USE_MEM_MMZ_CACHE,
    HBM_USE_MEM_FB, HBM_USE_ASSIGN_SIZE,
    HBM_USE_HW_RENDER, HBM_USE_HW_TEXTURE,
    HBM_USE_HW_COMPOSER, HBM_USE_PROTECTED,
    HBM_USE_CAMERA_READ, HBM_USE_CAMERA_WRITE,
    HBM_USE_VIDEO_ENCODER, HBM_USE_VIDEO_DECODER,
    HBM_USE_VENDOR_PRI0, HBM_USE_VENDOR_PRI1,
    HBM_USE_VENDOR_PRI2, HBM_USE_VENDOR_PRI3,
    HBM_USE_VENDOR_PRI4, HBM_USE_VENDOR_PRI5,
    HBM_USE_VENDOR_PRI6, HBM_USE_VENDOR_PRI7,
    HBM_USE_VENDOR_PRI8, HBM_USE_VENDOR_PRI9,
    HBM_USE_VENDOR_PRI10, HBM_USE_VENDOR_PRI11,
    HBM_USE_VENDOR_PRI12, HBM_USE_VENDOR_PRI13,
    HBM_USE_VENDOR_PRI14, HBM_USE_VENDOR_PRI15,
    HBM_USE_VENDOR_PRI16, HBM_USE_VENDOR_PRI17,
    HBM_USE_VENDOR_PRI18, HBM_USE_VENDOR_PRI19,
};

template<class T>
uint32_t GetArrLength(T& arr)
{
    if (arr == nullptr) {
        HDF_LOGE("%{public}s: The array length is equal to 0", __func__);
        return 0;
    }
    return sizeof(arr) / sizeof(arr[0]);
}

} // OHOS
#endif // DISPLAY_COMMON_FUZZER_H
