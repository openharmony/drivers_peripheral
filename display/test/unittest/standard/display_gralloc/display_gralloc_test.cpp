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

#include "display_gralloc_test.h"
#include <securec.h>
#include "gtest/gtest.h"
#include "display_gralloc.h"
#include "display_test.h"

namespace {
#define ALIGN_UP(x, a) ((((x) + ((a)-1)) / (a)) * (a))
#define HEIGHT_ALIGN 2U

const AllocTestPrms GRALLOC_TEST_SETS[] = {
    // num0
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
    // num1
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 1088 * 4,
        .expectSize = 1920 * 1088 * 4
    },
    // num2
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
    // num3
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBA_8888
        },
        .expectStride = 1088 * 4,
        .expectSize = 1920 * 1088 * 4
    },
    // num4
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGB_888
        },
        .expectStride = 1088 * 3,
        .expectSize =  1920 * 1088 * 3
    },
    // num5
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_8888
        },
        .expectStride = 1088 * 4,
        .expectSize = 1920 * 1088 * 4
    },
    // num6
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_8888
        },
        .expectStride = 1088 * 4,
        .expectSize = 1920 * 1088 * 4
    },
    // num7
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBA_4444
        },
        .expectStride = 1088 * 2,
        .expectSize = 1920 * 1088 * 2
    },
    // num8
    {
        .allocInfo =
        {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_4444
        },
        .expectStride = 1088 * 2,
        .expectSize = 1920 * 1088 * 2
    },
    // num9
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_4444
        },
        .expectStride = 1088 * 2,
        .expectSize = 1920 * 1088 * 2
    },
    // num10
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_4444
        },
        .expectStride = 1088 * 2,
        .expectSize = 1920 * 1088 * 2
    },
    // num11
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGR_565
        },
        .expectStride = 1088 * 2,
        .expectSize = 1920 * 1088 * 2
    },
    // num12
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRA_5551
        },
        .expectStride = 1088 * 2,
        .expectSize = 1920 * 1088 * 2
    },
    // num13
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_BGRX_5551
        },
        .expectStride = 1088 * 2,
        .expectSize = 1920 * 1088 * 2
    },
    // num14
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCBCR_420_SP
        },
        .expectStride = 1088,
        .expectSize = 1920 * 1088 * 3 / 2
    },
    // num15
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCRCB_420_SP
        },
        .expectStride = 1088,
        .expectSize = 1920 * 1088 * 3 / 2
    },
    // num16
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCBCR_420_P
        },
        .expectStride = 1088,
        .expectSize = 1920 * 1088 * 3 / 2
    },
    // num17
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_YCRCB_420_P
        },
        .expectStride = 1088,
        .expectSize = 1920 * 1088 * 3 / 2
    },
    // num18
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 1088 * 4,
        .expectSize = 1920 * 1088 * 4
    },
    // num19
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 1088 * 4,
        .expectSize = 1920 * 1088 * 4
    },
    // num20
    {
        .allocInfo = {
            .width = 1080,
            .height = 1920,
            .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_WRITE,
            .format = PIXEL_FMT_RGBX_8888
        },
        .expectStride = 1088 * 4,
        .expectSize = 1920 * 1088 * 4
    },
};

static bool CheckBufferHandle(AllocTestPrms &info, BufferHandle &buffer)
{
    if (buffer.stride != (ALIGN_UP(info.expectStride, HEIGHT_ALIGN))) {
        DISPLAY_TEST_LOGE("stride check failed stride %d, expect stride %d ", buffer.stride, info.expectStride);
        DISPLAY_TEST_LOGE("stride check failed format %d width %d, height %d ", info.allocInfo.format,
            info.allocInfo.width, info.allocInfo.height);
        return false;
    }

    if (buffer.size != info.expectSize) {
        DISPLAY_TEST_LOGE("size check failed size %d, expect size %d ", buffer.size, info.expectSize);
        DISPLAY_TEST_LOGE("stride check failed format %d width %d, height %d ", info.allocInfo.format,
            info.allocInfo.width, info.allocInfo.height);
        return false;
    }
    return true;
}

void GrallocAllocTest::SetUp()
{
    if (GrallocInitialize(&mGrallocFuncs) != DISPLAY_SUCCESS) {
        DISPLAY_TEST_LOGE("DisplayInit failure\n");
        ASSERT_TRUE(0);
    }
}

void GrallocAllocTest::TearDown()
{
    if (GrallocUninitialize(mGrallocFuncs) != DISPLAY_SUCCESS) {
        DISPLAY_TEST_LOGE("DisplayUninit failure\n");
        ASSERT_TRUE(0);
    }
}

int32_t GrallocAllocTest::AllocMemTest(AllocTestPrms &info)
{
    int ret;
    BufferHandle *buffer = nullptr;
    const int testCount = 21; // test 40 times
    for (int i = 0; i < testCount; i++) {
        ret = mGrallocFuncs->AllocMem(&info.allocInfo, &buffer);
        if (ret != DISPLAY_SUCCESS) {
            return ret;
        }
        void *vAddr = mGrallocFuncs->Mmap(buffer);
        if (vAddr == nullptr) {
            return DISPLAY_FAILURE;
        }

        if (info.allocInfo.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
            ret = mGrallocFuncs->InvalidateCache(buffer);
            if (ret != DISPLAY_SUCCESS) {
                return ret;
            }
        }
        if (memset_s(vAddr, buffer->size, 0, buffer->size) != EOK) {
            return DISPLAY_NOMEM;
        }
        DISPLAY_TEST_CHK_RETURN(!CheckBufferHandle(info, *buffer), DISPLAY_FAILURE,
            DISPLAY_TEST_LOGE("buffer check failed"));
        if (info.allocInfo.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
            ret = mGrallocFuncs->FlushCache(buffer);
            if (ret != DISPLAY_SUCCESS) {
                return ret;
            }
        }
        mGrallocFuncs->Unmap((buffer));
        mGrallocFuncs->FreeMem(buffer);
    }

    return DISPLAY_SUCCESS;
}

TEST(GrallocAllocTest, NULLPTR)
{
    int ret = GrallocInitialize(nullptr);
    ASSERT_TRUE(ret != DISPLAY_SUCCESS);

    GrallocFuncs *grallocFuncs;
    AllocInfo allocInfo;
    BufferHandle *hdl;
    ret = GrallocInitialize(&grallocFuncs);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS);
    ret = grallocFuncs->AllocMem(nullptr, nullptr);
    ASSERT_TRUE(ret != DISPLAY_SUCCESS);
    ret = grallocFuncs->AllocMem(&allocInfo, nullptr);
    ASSERT_TRUE(ret != DISPLAY_SUCCESS);
    ret = grallocFuncs->AllocMem(nullptr, &hdl);
    ASSERT_TRUE(ret != DISPLAY_SUCCESS);
    ret = grallocFuncs->InvalidateCache(nullptr);
    ASSERT_TRUE(ret != DISPLAY_SUCCESS);
    ret = grallocFuncs->FlushCache(nullptr);
    ASSERT_TRUE(ret != DISPLAY_SUCCESS);
    grallocFuncs->FreeMem(nullptr);
    void *vAddr = grallocFuncs->Mmap(nullptr);
    ASSERT_TRUE(vAddr == nullptr);
    ret = grallocFuncs->Unmap(nullptr);
    ASSERT_TRUE(ret != DISPLAY_SUCCESS);
    ret = GrallocUninitialize(nullptr);
    ASSERT_TRUE(ret != DISPLAY_SUCCESS);

    ret = GrallocUninitialize(grallocFuncs);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS);
}

TEST_P(GrallocAllocTest, GrallocAlloc)
{
    AllocTestPrms params = GetParam();
    int ret = AllocMemTest(params);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS);
}

INSTANTIATE_TEST_SUITE_P(AllocTest, GrallocAllocTest, ::testing::ValuesIn(GRALLOC_TEST_SETS));
}
