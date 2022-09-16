/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "hdf_base.h"
#include "hdf_log.h"
#include "gtest/gtest.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/include/idisplay_buffer.h"
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::Buffer::V1_0;

#define ALIGN_UP(x, a) ((((x) + ((a)-1)) / (a)) * (a))
#define WIDTH_ALIGN 8U

#ifndef DISPLAY_TEST_CHK_RETURN
#define DISPLAY_TEST_CHK_RETURN(val, ret, ...) \
    do {                                       \
        if (val) {                             \
            __VA_ARGS__;                       \
            return (ret);                      \
        }                                      \
    } while (0)
#endif

namespace {
const AllocTestPrms DISPLAY_BUFFER_TEST_SETS[] = {
    // 0
    {
        .allocInfo = {
            .width = 1920,
            .height = 1080,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 1920 * 4,
        .expectSize = 1920 * 1080 * 4
    },
    // 1
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
            },
        .expectStride = 4352,
        .expectSize = 8355840
    },
    // 2
    {
        .allocInfo = {
            .width = 1280,
            .height = 720,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 1280 * 4,
        .expectSize = 1280 * 720 * 4
    },
    // 3
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBA_8888
            },
        .expectStride = 4352,
        .expectSize = 8355840
    },
    // 4
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGB_888
        },
        .expectStride = 3264,
        .expectSize = 6266880
    },
    // 5
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_8888
            },
        .expectStride = 4352,
        .expectSize = 8355840
    },
    // 6
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_8888
        },
        .expectStride = 4352,
        .expectSize = 8355840
    },
    // 7
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBA_4444
        },
        .expectStride = 2176,
        .expectSize = 4177920
    },
    // 8
    {
        .allocInfo =
        {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_4444
        },
        .expectStride = 2176,
        .expectSize = 4177920
    },
    // 9
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_4444
        },
        .expectStride = 2176,
        .expectSize = 4177920
    },
    // 10
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_4444
        },
        .expectStride = 2176,
        .expectSize = 4177920
    },
    // 11
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGR_565
        },
        .expectStride = 2176,
        .expectSize = 4177920
    },
    // 12
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_5551
        },
        .expectStride = 2176,
        .expectSize = 4177920
    },
    // 13
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_5551
        },
        .expectStride = 2176,
        .expectSize = 4177920
    },
    // 14
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCBCR_420_SP
        },
        .expectStride = 1664,
        .expectSize = 3194880
    },
    // 15
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCRCB_420_SP
        },
        .expectStride = 1664,
        .expectSize = 3194880
    },
    // 16
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCBCR_420_P
        },
        .expectStride = 1664,
        .expectSize = 3194880
    },
    // 17
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCRCB_420_P
        },
        .expectStride = 1664,
        .expectSize = 3194880
    },
    // 18
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 4352,
        .expectSize = 8355840
    },
    // 19
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 4352,
        .expectSize = 8355840
    },
    // 20
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 4352,
        .expectSize = 8355840
    },
};

static bool CheckBufferHandle(AllocTestPrms &info, BufferHandle &buffer)
{
    if (buffer.stride != (ALIGN_UP(info.expectStride, WIDTH_ALIGN))) {
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
        fprintf(stderr, "IDisplayBuffer get failed\n");
        ASSERT_TRUE(0);
    }
}

void DisplayBufferUt::TearDown()
{
}

int32_t DisplayBufferUt::AllocMemTest(AllocTestPrms &info)
{
    int ret;
    BufferHandle *buffer = nullptr;
    const int testCount = 1; // test 40 times
    for (int i = 0; i < testCount; i++) {
        ret = displayBuffer_->AllocMem(info.allocInfo, buffer);
        if (ret != DISPLAY_SUCCESS) {
            return ret;
        }
        void *vAddr = displayBuffer_->Mmap(*buffer);
        if (vAddr == nullptr) {
            return DISPLAY_FAILURE;
        }

        if (info.allocInfo.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
            ret = displayBuffer_->InvalidateCache(*buffer);
            if (ret != DISPLAY_SUCCESS) {
                return ret;
            }
        }
        if (memset_s(vAddr, buffer->size, 0, buffer->size) != EOK) {
            return DISPLAY_NOMEM;
        }
        DISPLAY_TEST_CHK_RETURN(!CheckBufferHandle(info, *buffer), DISPLAY_FAILURE,
            HDF_LOGE("buffer check failed"));
        if (info.allocInfo.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
            ret = displayBuffer_->FlushCache(*buffer);
            if (ret != DISPLAY_SUCCESS) {
                return ret;
            }
        }
        displayBuffer_->Unmap((*buffer));
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

INSTANTIATE_TEST_CASE_P(AllocTest, DisplayBufferUt, ::testing::ValuesIn(DISPLAY_BUFFER_TEST_SETS));
}
