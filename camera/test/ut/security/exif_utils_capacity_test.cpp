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
#include <algorithm>
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

static std::vector<unsigned char> MakeExifJpeg(int32_t frameSize)
{
    // SOI(FFD8) + APP0(FFE0) + "Exif" identifier at bytes 6-9
    static constexpr unsigned char exifHeader[] = {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00, 0x45, 0x78, 0x69, 0x66};
    std::vector<unsigned char> buf(frameSize, 0xAA);
    for (int i = 0; i < static_cast<int>(sizeof(exifHeader)) && i < frameSize; ++i) {
        buf[i] = exifHeader[i];
    }
    return buf;
}

/**
 * @tc.name: AfterFix_0001_MemcpyDestMaxUsesRealCapacity
 * @tc.desc: Sufficient capacity, AddCustomExifInfo succeeds and securec guard works.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(ExifUtilsCapacityTest, AfterFix_0001_MemcpyDestMaxUsesRealCapacity, TestSize.Level0)
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

/**
 * @tc.name: AfterFix_0002_NullAddressReturnsError
 * @tc.desc: Passing a null address must be rejected by IsJpegPicture.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Robustness
 */
HWTEST_F(ExifUtilsCapacityTest, AfterFix_0002_NullAddressReturnsError, TestSize.Level0)
{
    constexpr int32_t frameSize = 4096;
    uint32_t capacity = static_cast<uint32_t>(frameSize);
    exif_data info = MakeTestExifData(frameSize);

    int32_t bufferSize = static_cast<int32_t>(capacity);
    uint32_t ret = ExifUtils::AddCustomExifInfo(info, nullptr, bufferSize);

    EXPECT_EQ(ret, RC_ERROR);
    EXPECT_EQ(bufferSize, static_cast<int32_t>(capacity));
}

/**
 * @tc.name: AfterFix_0003_TinyFrameSizeReturnsError
 * @tc.desc: frame_size smaller than the JPEG header check threshold must be rejected.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Robustness
 */
HWTEST_F(ExifUtilsCapacityTest, AfterFix_0003_TinyFrameSizeReturnsError, TestSize.Level0)
{
    constexpr int32_t frameSize = 5;
    constexpr uint32_t exifExpansionSize = 4096;
    uint32_t capacity = static_cast<uint32_t>(frameSize) + exifExpansionSize;
    auto buffer = MakeMinimalJpeg(static_cast<int32_t>(capacity));
    exif_data info = MakeTestExifData(frameSize);

    int32_t bufferSize = static_cast<int32_t>(capacity);
    uint32_t ret = ExifUtils::AddCustomExifInfo(info, buffer.data(), bufferSize);

    EXPECT_EQ(ret, RC_ERROR);
    EXPECT_EQ(bufferSize, static_cast<int32_t>(capacity));
}

/**
 * @tc.name: AfterFix_0004_NotJpegDataReturnsError
 * @tc.desc: Data without the JPEG SOI marker (FFD8) must not get EXIF appended.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Robustness
 */
HWTEST_F(ExifUtilsCapacityTest, AfterFix_0004_NotJpegDataReturnsError, TestSize.Level0)
{
    constexpr int32_t frameSize = 4096;
    constexpr uint32_t exifExpansionSize = 4096;
    uint32_t capacity = static_cast<uint32_t>(frameSize) + exifExpansionSize;
    std::vector<unsigned char> buffer(static_cast<size_t>(capacity), 0xAA);
    exif_data info = MakeTestExifData(frameSize);

    int32_t bufferSize = static_cast<int32_t>(capacity);
    uint32_t ret = ExifUtils::AddCustomExifInfo(info, buffer.data(), bufferSize);

    EXPECT_EQ(ret, RC_ERROR);
    EXPECT_EQ(bufferSize, static_cast<int32_t>(capacity));
    // 容量充足时 RC_ERROR 只能来自 SOI(FFD8) 校验；错误路径不得改写地址内容
    EXPECT_TRUE(std::all_of(buffer.begin(), buffer.end(),
        [](unsigned char c) { return c == 0xAA; }));
}

/**
 * @tc.name: AfterFix_0005_AlreadyHasExifReturnsError
 * @tc.desc: Data that already contains the Exif identifier must not be overwritten.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Robustness
 */
HWTEST_F(ExifUtilsCapacityTest, AfterFix_0005_AlreadyHasExifReturnsError, TestSize.Level0)
{
    constexpr int32_t frameSize = 4096;
    constexpr uint32_t exifExpansionSize = 4096;
    uint32_t capacity = static_cast<uint32_t>(frameSize) + exifExpansionSize;
    auto buffer = MakeExifJpeg(static_cast<int32_t>(capacity));
    exif_data info = MakeTestExifData(frameSize);

    int32_t bufferSize = static_cast<int32_t>(capacity);
    uint32_t ret = ExifUtils::AddCustomExifInfo(info, buffer.data(), bufferSize);

    EXPECT_EQ(ret, RC_ERROR);
    EXPECT_EQ(bufferSize, static_cast<int32_t>(capacity));
    // 容量充足时 RC_ERROR 只能来自 Exif 标识校验；错误路径不得改写既有 Exif
    EXPECT_EQ(buffer[0], 0xFF);
    EXPECT_EQ(buffer[1], 0xD8);
    EXPECT_EQ(buffer[6], 'E');
    EXPECT_EQ(buffer[7], 'x');
    EXPECT_EQ(buffer[8], 'i');
    EXPECT_EQ(buffer[9], 'f');
}

/**
 * @tc.name: AfterFix_0006_InsufficientCapacityReturnsError
 * @tc.desc: Output capacity exactly equal to frame_size is too small to hold EXIF expansion.
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Robustness
 */
HWTEST_F(ExifUtilsCapacityTest, AfterFix_0006_InsufficientCapacityReturnsError, TestSize.Level0)
{
    constexpr int32_t frameSize = 4096;
    uint32_t capacity = static_cast<uint32_t>(frameSize);
    auto buffer = MakeMinimalJpeg(static_cast<int32_t>(capacity));
    exif_data info = MakeTestExifData(frameSize);

    int32_t bufferSize = static_cast<int32_t>(capacity);
    uint32_t ret = ExifUtils::AddCustomExifInfo(info, buffer.data(), bufferSize);

    EXPECT_EQ(ret, RC_ERROR);
    EXPECT_EQ(bufferSize, static_cast<int32_t>(capacity));
}
