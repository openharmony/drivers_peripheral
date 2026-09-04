/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <vector>
#include "exif_utils.h"

using namespace OHOS::Camera;
using namespace testing::ext;

class ExifUtilsCapacityTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

static std::vector<unsigned char> MakeMinimalJpeg(int32_t frameSize)
{
    // SOI(FFD8) + APP0(FFE0) + JFIF identifier(4A464946) at bytes 0-9
    static constexpr unsigned char jpegHeader[] = {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00, 0x4A, 0x46, 0x49, 0x46};
    std::vector<unsigned char> buf(frameSize, 0xAA);
    for (int i = 0; i < static_cast<int>(sizeof(jpegHeader)) && i < frameSize; ++i) {
        buf[i] = jpegHeader[i];
    }
    return buf;
}

static exif_data MakeTestExifData(int32_t frameSize)
{
    constexpr double testLatitude = 39.9042;
    constexpr double testLongitude = 116.4074;
    constexpr double testAltitude = 50.0;
    exif_data info;
    info.latitude = testLatitude;
    info.longitude = testLongitude;
    info.altitude = testAltitude;
    info.frame_size = frameSize;
    return info;
}

/**
 * @tc.name: AfterFix_MemcpyDestMaxUsesRealCapacity
 * @tc.desc: Sufficient capacity, AddCustomExifInfo succeeds and securec guard works.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(ExifUtilsCapacityTest, AfterFix_MemcpyDestMaxUsesRealCapacity, TestSize.Level0)
{
    constexpr int32_t frameSize = 4096;
    constexpr uint32_t exifExpansionSize = 4096;
    uint32_t capacity = frameSize + exifExpansionSize;
    auto buffer = MakeMinimalJpeg(capacity);
    exif_data info = MakeTestExifData(frameSize);

    int32_t bufferSize = static_cast<int32_t>(capacity);
    uint32_t ret = ExifUtils::AddCustomExifInfo(info, buffer.data(), bufferSize);

    EXPECT_EQ(ret, RC_OK);
    EXPECT_GT(bufferSize, frameSize);
    EXPECT_LE(static_cast<uint32_t>(bufferSize), capacity);
}
