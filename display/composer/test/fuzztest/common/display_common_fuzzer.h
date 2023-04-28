/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "v1_0/include/idisplay_buffer.h"
#include "v1_0/include/idisplay_composer_interface.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "buffer_handle.h"
#include "hdf_log.h"

namespace OHOS {
using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;

const uint32_t PARAM_VOIDPTR_LEN = 10;
const int32_t ALPHAVALUERANGE = 256; // ranging from 0 to 255
const uint32_t WIDTH = 128;
const uint32_t HEIGHT = 128;
const uint64_t RANDOM_BOOL = 2;
const uint32_t OFFSET = 4; // Move the offset of the pointer to read the next data
const size_t THRESHOLD = 10;

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


const LayerType CONVERT_TABLE_LAYER_TYPE[] = {
    LAYER_TYPE_GRAPHIC, LAYER_TYPE_OVERLAY,
    LAYER_TYPE_SDIEBAND, LAYER_TYPE_CURSOR,
    LAYER_TYPE_BUTT,
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

bool GetRandBoolValue(uint8_t data)
{
    return data % RANDOM_BOOL == 0;
}

bool GetRandBoolValue(uint32_t data)
{
    return data % RANDOM_BOOL == 0;
}

bool GetRandBoolValue(uint64_t data)
{
    return data % RANDOM_BOOL == 0;
}

inline void* ShiftPointer(uint8_t* data, int32_t offset)
{
    void* resultData = reinterpret_cast<void*>(data + offset);
    if (resultData == nullptr) {
        HDF_LOGE("function %{public}s failed", __func__);
        return data;
    }
    return resultData;
}

uint32_t Convert2Uint32(const uint8_t* ptr, size_t size)
{
    if ((ptr == nullptr) || (OFFSET > size)) {
        HDF_LOGE("function %{public}s failed", __func__);
        return 0;
    }

    const uint32_t PTR_MOVE_24 = 24;
    const uint32_t PTR_MOVE_16 = 16;
    const uint32_t PTR_MOVE_8 = 8;
    const uint32_t SECOND_PTR = 2;
    const uint32_t THIRD_PTR = 3;

    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[0] << PTR_MOVE_24) | (ptr[1] << PTR_MOVE_16) | (ptr[SECOND_PTR] << PTR_MOVE_8) | (ptr[THIRD_PTR]);
}

int32_t GetAllocInfo(AllocInfo& info, uint8_t* data, size_t size)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    // This will be read width, height, usage and format of alloc info,
    // so we determine whether the size of the data is sufficient.
    size_t usedLen = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(PixelFormat);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t tempWidth = *reinterpret_cast<uint32_t*>(ShiftPointer(data, 0));
    uint32_t tempHeight = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempWidth)));
    uint32_t tempUsageIndex = *reinterpret_cast<uint32_t*>(ShiftPointer(data, sizeof(tempWidth) + sizeof(tempHeight)));
    uint32_t lenUsage = GetArrLength(CONVERT_TABLE_USAGE);
    if (lenUsage == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_USAGE length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }
    uint32_t tempFormatIndex = *reinterpret_cast<uint32_t*>(
        ShiftPointer(data, sizeof(tempWidth) + sizeof(tempHeight) + sizeof(tempUsageIndex)));
    uint32_t lenFormat = GetArrLength(CONVERT_TABLE_FORMAT);
    if (lenFormat == 0) {
        HDF_LOGE("%{public}s: CONVERT_TABLE_FORMAT length is equal to 0", __func__);
        return DISPLAY_FAILURE;
    }

    info.width = tempWidth % WIDTH;
    info.height = tempHeight % HEIGHT;
    info.usage = CONVERT_TABLE_USAGE[tempUsageIndex % lenUsage];
    info.format = CONVERT_TABLE_FORMAT[tempFormatIndex % lenFormat];
    info.expectedSize = info.width * info.height;
    return DISPLAY_SUCCESS;
}

BufferHandle* UsingAllocmem(uint8_t* data, size_t size)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return nullptr;
    }

    AllocInfo info = { 0 };
    int32_t ret = GetAllocInfo(info, data, size);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function GetAllocInfo failed", __func__);
        return nullptr;
    }

    std::shared_ptr<IDisplayBuffer> bufferInterface = nullptr;
    bufferInterface.reset(IDisplayBuffer::Get());
    if (bufferInterface == nullptr) {
        HDF_LOGE("get bufferInterface is null");
        return nullptr;
    }

    BufferHandle* handle = nullptr;
    ret = bufferInterface->AllocMem(info, handle);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: function AllocMem failed", __func__);
        return nullptr;
    }
    return handle;
}

int32_t GetIRect(IRect& rect, uint8_t* data, size_t size)
{
    if (data == nullptr) {
        HDF_LOGE("function %{public}s data is null", __func__);
        return DISPLAY_FAILURE;
    }

    size_t usedLen = sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t);
    if (usedLen > size) {
        HDF_LOGE("%{public}s: usedLen greater than size", __func__);
        return DISPLAY_FAILURE;
    }

    int32_t tempX = *reinterpret_cast<int32_t*>(ShiftPointer(data, 0));
    int32_t tempY = *reinterpret_cast<int32_t*>(ShiftPointer(data, sizeof(tempX)));
    int32_t tempW = *reinterpret_cast<int32_t*>(ShiftPointer(data, sizeof(tempX) + sizeof(tempY)));
    int32_t tempH = *reinterpret_cast<int32_t*>(ShiftPointer(data, sizeof(tempX) + sizeof(tempY) + sizeof(tempW)));

    rect.x = tempX;
    rect.y = tempY;
    rect.w = tempW;
    rect.h = tempH;
    return DISPLAY_SUCCESS;
}
} // OHOS
#endif // DISPLAY_COMMON_FUZZER_H
