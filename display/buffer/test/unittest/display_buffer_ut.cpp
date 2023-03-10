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

#define ALIGN_UP(x, a) ((((x) + ((a)-1)) / (a)) * (a))

#ifndef DISPLAY_TEST_CHK_RETURN
#define DISPLAY_TEST_CHK_RETURN(val, ret, ...) \
    do {                                       \
        if (val) {                             \
            __VA_ARGS__;                       \
            return (ret);                      \
        }                                      \
    } while (0)
#endif

const uint32_t HEIGHT_ALIGN = 2U; // height align
const uint32_t ALLOC_SIZE_1080 = 1080; // alloc size 1080
const uint32_t ALLOC_SIZE_1920 = 1920; // alloc size 1920
const uint32_t ALLOC_SIZE_1280 = 1280; // alloc size 1280
const uint32_t ALLOC_SIZE_720 = 720; // alloc size 720
const uint32_t EXPECT_STRIDE = 1088; // expect image stride
const uint32_t EXPECT_STRIDE_SCALE_4 = 4; // 4 times of expect image stride
const uint32_t EXPECT_STRIDE_SCALE_3 = 3; // 3 times of expect image stride
const uint32_t EXPECT_STRIDE_SCALE_2 = 2; // 2 times of expect image stride


const AllocTestPrms DISPLAY_BUFFER_TEST_SETS[] = {
    // num0
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1920,
            .height = ALLOC_SIZE_1080,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = ALLOC_SIZE_1920 * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1920 * ALLOC_SIZE_1080 * EXPECT_STRIDE_SCALE_4
    },
    // num1
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4
    },
    // num2
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1280,
            .height = ALLOC_SIZE_720,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = ALLOC_SIZE_1280 * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1280 * ALLOC_SIZE_720 * EXPECT_STRIDE_SCALE_4
    },
    // num3
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBA_8888
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4
    },
    // num4
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGB_888
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_3,
        .expectSize =  ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_3
    },
    // num5
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_8888
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4
    },
    // num6
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_8888
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4
    },
    // num7
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBA_4444
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2
    },
    // num8
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_4444
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2
    },
    // num9
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_4444
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2
    },
    // num10
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_4444
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2
    },
    // num11
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGR_565
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2
    },
    // num12
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_5551
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2
    },
    // num13
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_5551
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_2
    },
    // num14
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCBCR_420_SP
        },
        .expectStride = EXPECT_STRIDE,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_3 / EXPECT_STRIDE_SCALE_2,
    },
    // num15
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCRCB_420_SP
        },
        .expectStride = EXPECT_STRIDE,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_3 / EXPECT_STRIDE_SCALE_2,
    },
    // num16
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCBCR_420_P
        },
        .expectStride = EXPECT_STRIDE,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_3 / EXPECT_STRIDE_SCALE_2
    },
    // num17
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCRCB_420_P
        },
        .expectStride = EXPECT_STRIDE,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_3 / EXPECT_STRIDE_SCALE_2
    },
    // num18
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4
    },
    // num19
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4
    },
    // num20
    {
        .allocInfo = {
            .width = ALLOC_SIZE_1080,
            .height = ALLOC_SIZE_1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4,
        .expectSize = ALLOC_SIZE_1920 * EXPECT_STRIDE * EXPECT_STRIDE_SCALE_4
    },
};

static bool CheckBufferHandle(AllocTestPrms &info, BufferHandle &buffer)
{
    if (buffer.stride != (ALIGN_UP(info.expectStride, HEIGHT_ALIGN))) {
        HDF_LOGE("stride check failed stride %{public}d, expect stride %{public}d ", buffer.stride, info.expectStride);
        HDF_LOGE("stride check failed format %{public}d width %{public}d, height %{public}d ", info.allocInfo.format,
            info.allocInfo.width, info.allocInfo.height);
        return false;
    }

    if (buffer.size != info.expectSize) {
        HDF_LOGE("size check failed size %{public}d, expect size %{public}d ", buffer.size, info.expectSize);
        HDF_LOGE("stride check failed format %{public}d width %{public}d, height %{public}d ", info.allocInfo.format,
            info.allocInfo.width, info.allocInfo.height);
        return false;
    }
    return true;
}

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

int32_t DisplayBufferUt::AllocMemTest(AllocTestPrms& info)
{
    int ret;
    BufferHandle *buffer = nullptr;
    const int TEST_COUNT = 40; // test 40 times
    for (int i = 0; i < TEST_COUNT; i++) {
        ret = displayBuffer_->AllocMem(info.allocInfo, buffer);
        if (ret != DISPLAY_SUCCESS) {
            HDF_LOGE("AllocMem failed");
            return ret;
        }
        void *vAddr = displayBuffer_->Mmap(*buffer);
        if (vAddr == nullptr) {
            HDF_LOGE("Mmap failed");
            return DISPLAY_FAILURE;
        }

        if (info.allocInfo.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
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
        DISPLAY_TEST_CHK_RETURN(!CheckBufferHandle(info, *buffer), DISPLAY_FAILURE,
            HDF_LOGE("buffer check failed"));
        if (info.allocInfo.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
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
    AllocTestPrms params = GetParam();
    int ret = AllocMemTest(params);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS);
}

INSTANTIATE_TEST_SUITE_P(AllocTest, DisplayBufferUt, ::testing::ValuesIn(DISPLAY_BUFFER_TEST_SETS));
} // OHOS
} // HDI
} // DISPLAY
} // TEST
