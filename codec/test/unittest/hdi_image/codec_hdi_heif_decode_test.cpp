/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "hdf_log.h"
#include "ashmem.h"
#include "v2_1/icodec_image.h"
#include "v1_2/display_composer_type.h"
#include "v1_2/display_buffer_type.h"
#include "v1_2/include/idisplay_buffer.h"

#define HDF_LOG_TAG codec_heif_decode_test

namespace {
using namespace std;
using namespace testing::ext;
using namespace OHOS::HDI::Codec::Image::V2_1;
using namespace OHOS::HDI::Display::Buffer::V1_2;
using namespace OHOS::HDI::Display::Composer::V1_2;

static OHOS::sptr<ICodecImage> hdiHeifDecoder_ = nullptr;
static OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer* bufferMgr_ = nullptr;

class CodecHdiHeifDecodeTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        hdiHeifDecoder_ = ICodecImage::Get();
        bufferMgr_ = OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer::Get();
    }
    static void TearDownTestCase()
    {
        hdiHeifDecoder_ = nullptr;
        bufferMgr_ = nullptr;
    }
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }

    sptr<NativeBuffer> AllocateOutputBuffer(uint32_t width, uint32_t height, int32_t pixelFmt)
    {
        uint64_t usage = OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_READ |
                         OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_WRITE |
                         OHOS::HDI::Display::Composer::V1_2::HBM_USE_MEM_DMA |
                         OHOS::HDI::Display::Composer::V1_2::HBM_USE_MEM_MMZ_CACHE;
        AllocInfo alloc = {
            .width = width,
            .height = height,
            .usage =  usage,
            .format = pixelFmt
        };
        BufferHandle *handle = nullptr;
        int32_t ret = bufferMgr_->AllocMem(alloc, handle);
        if (ret != HDF_SUCCESS || handle == nullptr) {
            return nullptr;
        }
        sptr<NativeBuffer> output = new NativeBuffer(handle);
        return output;
    }
public:
};

// [fail] output is null
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_001, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo {};
    sptr<NativeBuffer> output = nullptr;
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] displaySize == 0
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_002, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 0,
        .displayHeight = 0,
        .enableGrid = false,
        .cols = 0,
        .rows = 0,
        .tileWidth = 0,
        .tileHeight = 0
    };
    decInfo.sampleSize = 1;
    sptr<NativeBuffer> output = AllocateOutputBuffer(128, 128,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] gridCnt == 0
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_003, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 128,
        .displayHeight = 128,
        .enableGrid = true,
        .cols = 0,
        .rows = 0,
        .tileWidth = 128,
        .tileHeight = 128
    };
    decInfo.sampleSize = 1;
    sptr<NativeBuffer> output = AllocateOutputBuffer(128, 128,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] gridSize == 0
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_004, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 128,
        .displayHeight = 128,
        .enableGrid = true,
        .cols = 1,
        .rows = 1,
        .tileWidth = 0,
        .tileHeight = 0
    };
    decInfo.sampleSize = 1;
    sptr<NativeBuffer> output = AllocateOutputBuffer(128, 128,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] displaySize > gridSize * gridCnt
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_005, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 512,
        .displayHeight = 512,
        .enableGrid = true,
        .cols = 1,
        .rows = 1,
        .tileWidth = 256,
        .tileHeight = 256
    };
    decInfo.sampleSize = 1;
    sptr<NativeBuffer> output = AllocateOutputBuffer(512, 512,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] not enough input (no grid)
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_006, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 512,
        .displayHeight = 512,
        .enableGrid = false,
        .cols = 1,
        .rows = 1,
        .tileWidth = 512,
        .tileHeight = 512
    };
    decInfo.sampleSize = 1;
    sptr<NativeBuffer> output = AllocateOutputBuffer(512, 512,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    inputs.push_back(Ashmem::CreateAshmem("", 512 * 512));
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] not enough input (grid)
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_007, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 512,
        .displayHeight = 512,
        .enableGrid = true,
        .cols = 1,
        .rows = 2,
        .tileWidth = 512,
        .tileHeight = 256
    };
    decInfo.sampleSize = 1;
    sptr<NativeBuffer> output = AllocateOutputBuffer(512, 512,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    inputs.push_back(Ashmem::CreateAshmem("", 512 * 512));
    inputs.push_back(Ashmem::CreateAshmem("", 512 * 512));
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] sampleSize = 1, output is too small
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_008, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 512,
        .displayHeight = 512,
        .enableGrid = false,
        .cols = 1,
        .rows = 1,
        .tileWidth = 512,
        .tileHeight = 512
    };
    decInfo.sampleSize = 1;
    sptr<NativeBuffer> output = AllocateOutputBuffer(128, 128,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] unsupported sampleSize
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_009, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 512,
        .displayHeight = 512,
        .enableGrid = false,
        .cols = 1,
        .rows = 1,
        .tileWidth = 512,
        .tileHeight = 512
    };
    decInfo.sampleSize = 3;
    sptr<NativeBuffer> output = AllocateOutputBuffer(512, 512,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] displaySize % sampleSize != 0
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_010, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 511,
        .displayHeight = 511,
        .enableGrid = false,
        .cols = 1,
        .rows = 1,
        .tileWidth = 512,
        .tileHeight = 512
    };
    decInfo.sampleSize = 4;
    sptr<NativeBuffer> output = AllocateOutputBuffer(128, 128,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP);
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}

// [fail] unsupported output pixel format
HWTEST_F(CodecHdiHeifDecodeTest, HdfCodecHdiDoHeifDecodeTest_011, TestSize.Level1)
{
    ASSERT_TRUE(hdiHeifDecoder_ != nullptr);
    CodecHeifDecInfo decInfo;
    decInfo.gridInfo = {
        .displayWidth = 512,
        .displayHeight = 512,
        .enableGrid = false,
        .cols = 1,
        .rows = 1,
        .tileWidth = 512,
        .tileHeight = 512
    };
    decInfo.sampleSize = 2;
    sptr<NativeBuffer> output = AllocateOutputBuffer(256, 256,
                                                     OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YUV_422_I);
    vector<sptr<Ashmem>> inputs;
    int32_t ret = hdiHeifDecoder_->DoHeifDecode(inputs, output, decInfo);
    ASSERT_NE(ret, HDF_SUCCESS);
}
}