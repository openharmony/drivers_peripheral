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

#include "dbuffer_manager_test.h"

#include "dbuffer_manager.h"
#include "dimage_buffer.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DBufferManagerTest::SetUpTestCase(void)
{
}

void DBufferManagerTest::TearDownTestCase(void)
{
}

void DBufferManagerTest::SetUp(void)
{
}

void DBufferManagerTest::TearDown(void)
{
}

/**
 * @tc.name: AddBuffer_001
 * @tc.desc: Verify AddBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DBufferManagerTest, AddBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DBufferManager> dbMgr = std::make_shared<DBufferManager>();
    ASSERT_NE(nullptr, dbMgr);
    std::shared_ptr<DImageBuffer> buffer = std::make_shared<DImageBuffer>();
    dbMgr->idleList_.emplace_back(buffer);
    dbMgr->busyList_.emplace_back(buffer);
    dbMgr->idleList_.emplace_back(buffer);
    dbMgr->busyList_.emplace_back(buffer);
    dbMgr->idleList_.emplace_back(buffer);
    dbMgr->busyList_.emplace_back(buffer);
    dbMgr->idleList_.emplace_back(buffer);
    dbMgr->busyList_.emplace_back(buffer);
    auto ret = dbMgr->AddBuffer(buffer);
    EXPECT_EQ(ret, RC_ERROR);
}

/**
 * @tc.name: RemoveBuffer_001
 * @tc.desc: Verify RemoveBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DBufferManagerTest, RemoveBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DBufferManager> dbMgr = std::make_shared<DBufferManager>();
    ASSERT_NE(nullptr, dbMgr);
    std::shared_ptr<DImageBuffer> buffer = std::make_shared<DImageBuffer>();
    auto ret = dbMgr->RemoveBuffer(buffer);
    EXPECT_EQ(ret, RC_ERROR);

    dbMgr->busyList_.emplace_back(buffer);
    ret = dbMgr->RemoveBuffer(buffer);
    EXPECT_EQ(ret, RC_OK);
}

/**
 * @tc.name: SurfaceBufferToDImageBuffer_001
 * @tc.desc: Verify SurfaceBufferToDImageBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DBufferManagerTest, SurfaceBufferToDImageBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DBufferManager> dbMgr = std::make_shared<DBufferManager>();
    ASSERT_NE(nullptr, dbMgr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    std::shared_ptr<DImageBuffer> buffer = nullptr;
    auto ret = dbMgr->SurfaceBufferToDImageBuffer(surfaceBuffer, buffer);
    EXPECT_EQ(ret, RC_ERROR);
}

/**
 * @tc.name: PixelFormatToDCameraFormat_001
 * @tc.desc: Verify PixelFormatToDCameraFormat
 * @tc.type: FUNC
 */
HWTEST_F(DBufferManagerTest, PixelFormatToDCameraFormat_001, TestSize.Level1)
{
    std::shared_ptr<DBufferManager> dbMgr = std::make_shared<DBufferManager>();
    ASSERT_NE(nullptr, dbMgr);
    OHOS::HDI::Display::Composer::V1_1::PixelFormat format =
        OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_RGBA_8888;
    auto ret = dbMgr->PixelFormatToDCameraFormat(format);
    EXPECT_EQ(ret, OHOS_CAMERA_FORMAT_RGBA_8888);

    format = OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCBCR_420_SP;
    ret = dbMgr->PixelFormatToDCameraFormat(format);
    EXPECT_EQ(ret, OHOS_CAMERA_FORMAT_YCBCR_420_888);

    format = OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCRCB_420_SP;
    ret = dbMgr->PixelFormatToDCameraFormat(format);
    EXPECT_EQ(ret, OHOS_CAMERA_FORMAT_YCRCB_420_SP);
    
    format = OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_CLUT8;
    ret = dbMgr->PixelFormatToDCameraFormat(format);
    EXPECT_EQ(ret, OHOS_CAMERA_FORMAT_INVALID);

    format = OHOS::HDI::Display::Composer::V1_1::PIXEL_FMT_YCRCB_P010;
    ret = dbMgr->PixelFormatToDCameraFormat(format);
    EXPECT_EQ(ret, OHOS_CAMERA_FORMAT_YCBCB_P010);
}

/**
 * @tc.name: DImageBufferToDCameraBuffer_001
 * @tc.desc: Verify DImageBufferToDCameraBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DBufferManagerTest, DImageBufferToDCameraBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DBufferManager> dbMgr = std::make_shared<DBufferManager>();
    ASSERT_NE(nullptr, dbMgr);
    std::shared_ptr<DImageBuffer> imageBuffer = std::make_shared<DImageBuffer>();
    imageBuffer->bufHandle_ = nullptr;
    DCameraBuffer buffer;
    auto ret = dbMgr->DImageBufferToDCameraBuffer(imageBuffer, buffer);
    EXPECT_EQ(ret, RC_ERROR);

    BufferHandle bufHandle;
    bufHandle.size = 0;
    imageBuffer->SetBufferHandle(&bufHandle);
    ret = dbMgr->DImageBufferToDCameraBuffer(imageBuffer, buffer);
    EXPECT_EQ(ret, RC_ERROR);
}

/**
 * @tc.name: DImageBufferToDCameraBuffer_002
 * @tc.desc: Verify DImageBufferToDCameraBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DBufferManagerTest, DImageBufferToDCameraBuffer_002, TestSize.Level1)
{
    std::shared_ptr<DBufferManager> dbMgr = std::make_shared<DBufferManager>();
    ASSERT_NE(nullptr, dbMgr);
    BufferHandle bufHandle;
    bufHandle.size = 0;
    std::shared_ptr<DImageBuffer> imageBuffer = std::make_shared<DImageBuffer>();
    imageBuffer->SetBufferHandle(&bufHandle);
    DCameraBuffer buffer;
    auto ret = dbMgr->DImageBufferToDCameraBuffer(imageBuffer, buffer);
    EXPECT_EQ(ret, RC_ERROR);

    bufHandle.size = 1;
    bufHandle.width = 0;
    imageBuffer->SetBufferHandle(&bufHandle);
    ret = dbMgr->DImageBufferToDCameraBuffer(imageBuffer, buffer);
    EXPECT_EQ(ret, RC_ERROR);

    bufHandle.width = 1;
    bufHandle.height = 0;
    imageBuffer->SetBufferHandle(&bufHandle);
    ret = dbMgr->DImageBufferToDCameraBuffer(imageBuffer, buffer);
    EXPECT_EQ(ret, RC_ERROR);

    bufHandle.height = 1;
    bufHandle.usage = 0;
    imageBuffer->SetBufferHandle(&bufHandle);
    ret = dbMgr->DImageBufferToDCameraBuffer(imageBuffer, buffer);
    EXPECT_EQ(ret, RC_ERROR);

    bufHandle.usage = 1;
    imageBuffer->SetBufferHandle(&bufHandle);
    ret = dbMgr->DImageBufferToDCameraBuffer(imageBuffer, buffer);
    EXPECT_EQ(ret, RC_OK);
}

/**
 * @tc.name: DImageBuffer_001
 * @tc.desc: Verify DImageBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DBufferManagerTest, DImageBuffer_001, TestSize.Level1)
{
    DImageBuffer buffer1;
    DImageBuffer buffer2;
    buffer2.phyAddr_ = 0;
    EXPECT_TRUE(buffer1 == buffer2);

    buffer2.phyAddr_ = 1;
    buffer1.phyAddr_ = 0;
    EXPECT_TRUE(buffer1 == buffer2);

    buffer2.phyAddr_ = 1;
    buffer1.phyAddr_ = 1;
    EXPECT_TRUE(buffer1 == buffer2);
}
}
}
