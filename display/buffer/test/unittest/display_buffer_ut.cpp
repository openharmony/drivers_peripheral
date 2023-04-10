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
#include "display_buffer_ut.h"
#include <securec.h>

#include "gtest/gtest.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/include/idisplay_buffer.h"
#include "hdf_base.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;

#ifndef DISPLAY_TEST_CHK_RETURN
#define DISPLAY_TEST_CHK_RETURN(val, ret, ...) \
    do {                                       \
        if (val) {                             \
            __VA_ARGS__;                       \
            return (ret);                      \
        }                                      \
    } while (0)
#endif

const uint32_t ALLOC_SIZE_1080 = 1080; // alloc size 1080
const uint32_t ALLOC_SIZE_1920 = 1920; // alloc size 1920
const uint32_t ALLOC_SIZE_1280 = 1280; // alloc size 1280
const uint32_t ALLOC_SIZE_720 = 720; // alloc size 720

const AllocInfo DISPLAY_BUFFER_TEST_SETS[] = {
    // num0
    {
        .width = ALLOC_SIZE_1920,
        .height = ALLOC_SIZE_1080,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num1
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num2
    {
        .width = ALLOC_SIZE_1280,
        .height = ALLOC_SIZE_720,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num3
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBA_8888
    },
    // num4
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRA_8888
    },
    
    // num5
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCBCR_420_SP
    },
    // num6
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCRCB_420_SP
    },
    // num7
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCBCR_420_P
    },
    // num8
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCRCB_420_P
    },
    // num9
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num10
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num11
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_8888
    },
#ifdef DISPLAY_COMMUNITY
     // num12
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGB_888
    },
    // num13
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_8888
    },
    // num14
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBA_4444
    },
    // num15
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_4444
    },
    // num16
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRA_4444
    },
    // num17
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_4444
    },
    // num18
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGR_565
    },
    // num19
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRA_5551
    },
    // num20
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_5551
    },
#endif // DISPLAY_COMMUNITY
};

void DisplayBufferUt::SetUp()
{
    displayBuffer_ = IDisplayBuffer::Get();
    if (displayBuffer_ == nullptr) {
        HDF_LOGE("IDisplayBuffer get failed");
        ASSERT_TRUE(0);
    }
}

void DisplayBufferUt::TearDown()
{
}

int32_t DisplayBufferUt::AllocMemTest(AllocInfo& info)
{
    int ret;
    BufferHandle *buffer = nullptr;
    const int TEST_COUNT = 40; // test 40 times
    for (int i = 0; i < TEST_COUNT; i++) {
        ret = displayBuffer_->AllocMem(info, buffer);
        if (ret != DISPLAY_SUCCESS || buffer == nullptr) {
            HDF_LOGE("AllocMem failed");
            return ret;
        }
        void *vAddr = displayBuffer_->Mmap(*buffer);
        if (vAddr == nullptr) {
            HDF_LOGE("Mmap failed");
            return DISPLAY_FAILURE;
        }

        if (info.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
            ret = displayBuffer_->InvalidateCache(*buffer);
            if (ret != DISPLAY_SUCCESS) {
                HDF_LOGE("InvalidateCache failed");
                return ret;
            }
        }
        if (memset_s(vAddr, buffer->size, 0, buffer->size) != EOK) {
            HDF_LOGE("Insufficient memory");
            return DISPLAY_NOMEM;
        }

        if (info.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
            ret = displayBuffer_->FlushCache(*buffer);
            if (ret != DISPLAY_SUCCESS) {
                HDF_LOGE("FlushCache failed");
                return ret;
            }
        }
        displayBuffer_->Unmap(*buffer);
        displayBuffer_->FreeMem(*buffer);
    }
    return DISPLAY_SUCCESS;
}

TEST_P(DisplayBufferUt, DisplayBufferUt)
{
    AllocInfo params = GetParam();
    int ret = AllocMemTest(params);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS);
}

INSTANTIATE_TEST_SUITE_P(AllocTest, DisplayBufferUt, ::testing::ValuesIn(DISPLAY_BUFFER_TEST_SETS));
} // OHOS
} // HDI
} // DISPLAY
} // TEST
