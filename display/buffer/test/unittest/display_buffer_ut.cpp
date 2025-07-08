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
#include "v1_2/display_composer_type.h"
#include "hdf_base.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace TEST {
using namespace testing::ext;
using namespace OHOS::HDI::Display::Composer::V1_2;
using namespace OHOS::HDI::Display::Buffer::V1_1;
using OHOS::HDI::Display::Buffer::V1_0::AllocInfo;
using OHOS::HDI::Display::Composer::V1_2::HBM_USE_MEM_DMA;
using OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_READ;
using OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_WRITE;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_RGBX_8888;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_RGBA_8888;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_BGRA_8888;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCBCR_420_SP;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCRCB_420_SP;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCBCR_420_P;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCRCB_420_P;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_RGB_888;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_BGRX_8888;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_RGBA_4444;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_RGBX_4444;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_BGRA_4444;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_BGRX_4444;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_BGR_565;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_BGRA_5551;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_BGRX_5551;
using OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_RGBA_1010102;
#define TEST_INFO (1<<27)
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
    //HBM_USE_CPU_HW_BOTH
    // num12
    {
        .width = ALLOC_SIZE_1920,
        .height = ALLOC_SIZE_1080,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num13
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num14
    {
        .width = ALLOC_SIZE_1280,
        .height = ALLOC_SIZE_720,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num15
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBA_8888
    },
    // num16
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRA_8888
    },
    // num17
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCBCR_420_SP
    },
    // num18
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCRCB_420_SP
    },
    // num19
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCBCR_420_P
    },
    // num20
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCRCB_420_P
    },
    // num21
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num22
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ,
        .format = PIXEL_FMT_RGBX_8888
    },
    // num23
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_8888
    },
#ifdef DISPLAY_COMMUNITY
     // num24
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGB_888
    },
    // num25
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_8888
    },
    // num26
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBA_4444
    },
    // num27
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_4444
    },
    // num28
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRA_4444
    },
    // num29
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_4444
    },
    // num30
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGR_565
    },
    // num31
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRA_5551
    },
    // num32
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_5551
    },
    //HBM_USE_CPU_HW_BOTH
    // num33
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGB_888
    },
    // num34
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_8888
    },
    // num35
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBA_4444
    },
    // num36
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBX_4444
    },
    // num37
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRA_4444
    },
    // num38
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_4444
    },
    // num39
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGR_565
    },
    // num40
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRA_5551
    },
    // num41
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_BGRX_5551
    },
#else
    // num42
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBA_1010102
    },
    //HBM_USE_CPU_HW_BOTH
    // num43
    {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_CPU_HW_BOTH | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_RGBA_1010102
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

void DisplayBufferUt::MetadataTest(BufferHandle& handle)
{
    int32_t ret = displayBuffer_->RegisterBuffer(handle);
    EXPECT_TRUE(ret == DISPLAY_NOT_SUPPORT || ret == DISPLAY_SUCCESS);

    uint32_t key = 1;
    std::vector<uint8_t> values = {1, 2, 3};
    std::vector<uint32_t> keys = {};
    std::vector<uint8_t> rets = {};
    ret = displayBuffer_->SetMetadata(handle, key, values);
    EXPECT_TRUE(ret == DISPLAY_NOT_SUPPORT || ret == DISPLAY_SUCCESS);
    ret = displayBuffer_->GetMetadata(handle, key, rets);
    EXPECT_TRUE(ret == DISPLAY_NOT_SUPPORT || ret == DISPLAY_SUCCESS);
    if (ret != DISPLAY_NOT_SUPPORT) {
        EXPECT_TRUE(rets == values);
    }

    ret = displayBuffer_->ListMetadataKeys(handle, keys);
    EXPECT_TRUE(ret == DISPLAY_NOT_SUPPORT || ret == DISPLAY_SUCCESS);
    if (ret != DISPLAY_NOT_SUPPORT) {
        EXPECT_TRUE(keys.size() == 1 && keys[0] == key);
    }

    ret = displayBuffer_->EraseMetadataKey(handle, key);
    EXPECT_TRUE(ret == DISPLAY_NOT_SUPPORT || ret == DISPLAY_SUCCESS);
    if (ret != DISPLAY_NOT_SUPPORT) {
        rets = {};
        ret = displayBuffer_->GetMetadata(handle, key, rets);
        EXPECT_TRUE(ret != DISPLAY_SUCCESS);
    }
}

int32_t DisplayBufferUt::AllocMemTest(AllocInfo& info)
{
    int ret;
    BufferHandle *buffer = nullptr;
    const int TEST_COUNT = 40; // test 40 times
    for (int i = 0; i < TEST_COUNT; i++) {
        ret = displayBuffer_->AllocMem(info, buffer);
        if (ret == DISPLAY_NOT_SUPPORT) {
            HDF_LOGE("%{public}s: AllocMem not support, ret=%{public}d", __func__, ret);
            return DISPLAY_SUCCESS;
        }
        if (ret != DISPLAY_SUCCESS || buffer == nullptr) {
            HDF_LOGE("AllocMem failed");
            return ret;
        }
        MetadataTest(*buffer);
        void *vAddr = displayBuffer_->Mmap(*buffer);
        if (vAddr == nullptr) {
            HDF_LOGE("Mmap failed");
            displayBuffer_->FreeMem(*buffer);
            return DISPLAY_FAILURE;
        }
        if (info.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
            ret = displayBuffer_->InvalidateCache(*buffer);
            if (ret != DISPLAY_SUCCESS) {
                HDF_LOGE("InvalidateCache failed");
                displayBuffer_->Unmap(*buffer);
                displayBuffer_->FreeMem(*buffer);
                return ret;
            }
        }
        if (memset_s(vAddr, buffer->size, 0, buffer->size) != EOK) {
            HDF_LOGE("Insufficient memory");
            displayBuffer_->Unmap(*buffer);
            displayBuffer_->FreeMem(*buffer);
            return DISPLAY_NOMEM;
        }
        if (info.usage & (HBM_USE_CPU_READ | HBM_USE_CPU_WRITE)) {
            ret = displayBuffer_->FlushCache(*buffer);
            if (ret != DISPLAY_SUCCESS) {
                HDF_LOGE("FlushCache failed");
                displayBuffer_->Unmap(*buffer);
                displayBuffer_->FreeMem(*buffer);
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

HWTEST_F(DisplayBufferUt, test_ReAllocMemTest, TestSize.Level1)
{
    int ret;
    AllocInfo info = {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
        .format = PIXEL_FMT_YCBCR_420_P
    }
    BufferHandle* inBuffer = nullptr;
    ret = displayBuffer_->AllocMem(info, inBuffer);
    EXPECT_TRUE(ret == DISPLAY_SUCCESS);
    EXPECT_NE(inBuffer, nullptr);

    BuuferHandle* outBuffer = nullptr;
    AllocInfo newinfo = {
        .width = ALLOC_SIZE_1920,
        .height = ALLOC_SIZE_1080,
        .usage = HBM_USE_MEM_DMA | HBM_USE_VIDEO_DECODER | HBM_USE_HW_COMPOSER,
        .format = PIXEL_FMT_YCBCR_420_P
    }

    ret = displayBuffer_->ReAllocMem(newInfo, nullptr, outBuffer);
    EXPECT_TRUE(ret != DISPLAY_SUCCESS);

    ret = displayBuffer_->ReAllocMem(newInfo, *inBuffer, outBuffer);
    EXPECT_TRUE(ret == DISPLAY_SUCCESS);
    EXPECT_NE(inBuffer, nullptr);
    EXPECT_NE(outBuffer, nullptr);

    EXPECT_EQ(outBuffer->size, inBuffer->size);
    EXPECT_NE(outBuffer->fd, inBuffer->fd);

    AllocInfo nullInfo = new AllocInfo();
    ret = displayBuffer_->ReAllocMem(nullInfo, *inBuffer, outBuffer);
    EXPECT_TRUE(ret != DISPLAY_SUCCESS);

    displayBuffer->FreeMem(*inBuffer);
    displayBuffer->FreeMem(outBuffer);
}

int32_t DisplayBufferUt::PassthroughTest(AllocInfo& info)
{
    int ret;
    BufferHandle *buffer = nullptr;
    ret = displayBuffer_->AllocMem(info, buffer);
    if (ret == DISPLAY_NOT_SUPPORT) {
        HDF_LOGE("%{public}s: AllocMem not support, ret=%{public}d", __func__, ret);
        return DISPLAY_SUCCESS;
    }
    if (ret != DISPLAY_SUCCESS || buffer == nullptr) {
        HDF_LOGE("AllocMem failed");
        return ret;
    }
    displayBuffer_->FreeMem(*buffer);
    return DISPLAY_SUCCESS;
}

HWTEST_F(DisplayBufferUt, test_PassthroughTest, TestSize.Level1)
{
    AllocInfo info = {
        .width = ALLOC_SIZE_1080,
        .height = ALLOC_SIZE_1920,
        .usage = TEST_INFO,
        .format = PIXEL_FMT_YCBCR_420_P
    }
    int ret = PassthroughTest(info);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS);
}
} // OHOS
} // HDI
} // DISPLAY
} // TEST