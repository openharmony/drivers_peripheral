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
#include "camera.h"
#include "usb_device_filter.h"

using namespace OHOS::Camera;
using namespace testing::ext;

class UsbDeviceFilterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void UsbDeviceFilterTest::SetUpTestCase(void)
{
    CAMERA_LOGD("UsbDeviceFilterTest SetUpTestCase");
}

void UsbDeviceFilterTest::TearDownTestCase(void)
{
    CAMERA_LOGD("UsbDeviceFilterTest TearDownTestCase");
}

void UsbDeviceFilterTest::SetUp(void)
{
    CAMERA_LOGD("UsbDeviceFilterTest SetUp");
    // Reset filter before each test
    UsbDeviceFilter::GetInstance().Reset();
}

void UsbDeviceFilterTest::TearDown(void)
{
    CAMERA_LOGD("UsbDeviceFilterTest TearDown");
    // Reset filter after each test
    UsbDeviceFilter::GetInstance().Reset();
}

/**
 * @tc.name: HexToUint16_0001
 * @tc.desc: Test HexToUint16 with "0000"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, HexToUint16_0001, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest HexToUint16_0001");
    uint16_t result = UsbDeviceFilter::GetInstance().HexToUint16("0000");
    EXPECT_EQ(result, 0x0000);
}

/**
 * @tc.name: HexToUint16_0002
 * @tc.desc: Test HexToUint16 with "FFFF"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, HexToUint16_0002, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest HexToUint16_0002");
    uint16_t result = UsbDeviceFilter::GetInstance().HexToUint16("FFFF");
    EXPECT_EQ(result, 0xFFFF);
}

/**
 * @tc.name: HexToUint16_0003
 * @tc.desc: Test HexToUint16 with lowercase "0bda"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, HexToUint16_0003, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest HexToUint16_0003");
    uint16_t result = UsbDeviceFilter::GetInstance().HexToUint16("0bda");
    EXPECT_EQ(result, 0x0BDA);
}

/**
 * @tc.name: HexToUint16_0004
 * @tc.desc: Test HexToUint16 with uppercase "0BDA"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, HexToUint16_0004, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest HexToUint16_0004");
    uint16_t result = UsbDeviceFilter::GetInstance().HexToUint16("0BDA");
    EXPECT_EQ(result, 0x0BDA);
}

/**
 * @tc.name: HexToUint16_0005
 * @tc.desc: Test HexToUint16 with "1214"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, HexToUint16_0005, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest HexToUint16_0005");
    uint16_t result = UsbDeviceFilter::GetInstance().HexToUint16("1214");
    EXPECT_EQ(result, 0x1214);
}

/**
 * @tc.name: HexToUint16_0006
 * @tc.desc: Test HexToUint16 with empty string
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, HexToUint16_0006, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest HexToUint16_0006");
    uint16_t result = UsbDeviceFilter::GetInstance().HexToUint16("");
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: HexToUint16_0007
 * @tc.desc: Test HexToUint16 with invalid characters "XYZ"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, HexToUint16_0007, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest HexToUint16_0007");
    uint16_t result = UsbDeviceFilter::GetInstance().HexToUint16("XYZ");
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: ParseConfig_0001
 * @tc.desc: Test ParseConfig with single pair "1214:5678"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, ParseConfig_0001, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest ParseConfig_0001");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:5678");
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0x1214, 0x5678));
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0xABCD, 0x1234));
}

/**
 * @tc.name: ParseConfig_0002
 * @tc.desc: Test ParseConfig with two pairs "1214:5678,abcd:1234"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, ParseConfig_0002, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest ParseConfig_0002");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:5678,abcd:1234");
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0x1214, 0x5678));
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0xABCD, 0x1234));
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0x1234, 0x5678));
}

/**
 * @tc.name: ParseConfig_0003
 * @tc.desc: Test ParseConfig with empty string
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, ParseConfig_0003, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest ParseConfig_0003");
    UsbDeviceFilter::GetInstance().ParseConfig("");
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0x1214, 0x5678));
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0xABCD, 0x1234));
}

/**
 * @tc.name: ParseConfig_0004
 * @tc.desc: Test ParseConfig with uppercase "0BDA:1234"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, ParseConfig_0004, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest ParseConfig_0004");
    UsbDeviceFilter::GetInstance().ParseConfig("0BDA:1234");
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0x0BDA, 0x1234));
}

/**
 * @tc.name: ParseConfig_0005
 * @tc.desc: Test ParseConfig with multiple pairs including uppercase
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, ParseConfig_0005, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest ParseConfig_0005");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:5678,0BDA:ABCD");
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0x1214, 0x5678));
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0x0BDA, 0xABCD));
}

/**
 * @tc.name: ParseConfig_0006
 * @tc.desc: Test ParseConfig with missing pid "1214"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, ParseConfig_0006, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest ParseConfig_0006");
    UsbDeviceFilter::GetInstance().ParseConfig("1214");
    // Invalid token should be skipped, no filters added
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0x1214, 0x5678));
}

/**
 * @tc.name: ParseConfig_0007
 * @tc.desc: Test ParseConfig with missing vid ":5678"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, ParseConfig_0007, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest ParseConfig_0007");
    UsbDeviceFilter::GetInstance().ParseConfig(":5678");
    // Invalid token should be skipped, no filters added
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0x0000, 0x5678));
}

/**
 * @tc.name: ParseConfig_0008
 * @tc.desc: Test ParseConfig with missing pid value "1214:"
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, ParseConfig_0008, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest ParseConfig_0008");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:");
    // Invalid token should be skipped, no filters added
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0x1214, 0x0000));
}

/**
 * @tc.name: IsBlocked_0001
 * @tc.desc: Test IsBlocked with matching VID/PID
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, IsBlocked_0001, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest IsBlocked_0001");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:5678");
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0x1214, 0x5678));
}

/**
 * @tc.name: IsBlocked_0002
 * @tc.desc: Test IsBlocked with non-matching VID/PID
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, IsBlocked_0002, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest IsBlocked_0002");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:5678");
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0xABCD, 0x1234));
}

/**
 * @tc.name: IsBlocked_0003
 * @tc.desc: Test IsBlocked with multiple filters
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, IsBlocked_0003, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest IsBlocked_0003");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:5678,abcd:1234,0bda:0001");
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0x1214, 0x5678));
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0xABCD, 0x1234));
    EXPECT_TRUE(UsbDeviceFilter::GetInstance().IsBlocked(0x0BDA, 0x0001));
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlocked(0x1234, 0x5678));
}

/**
 * @tc.name: IsBlockedByVideoPath_0001
 * @tc.desc: Test IsBlockedByVideoPath when sysfs node does not exist
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, IsBlockedByVideoPath_0001, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest IsBlockedByVideoPath_0001");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:5678");
    // Test with non-existent video path, should return false (not blocked)
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlockedByVideoPath("/dev/video99"));
}

/**
 * @tc.name: IsBlockedByVideoPath_0002
 * @tc.desc: Test IsBlockedByVideoPath with valid path but no sysfs data
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(UsbDeviceFilterTest, IsBlockedByVideoPath_0002, TestSize.Level0)
{
    CAMERA_LOGI("UsbDeviceFilterTest IsBlockedByVideoPath_0002");
    UsbDeviceFilter::GetInstance().ParseConfig("1214:5678");
    // Test with invalid path that cannot read VID/PID
    EXPECT_FALSE(UsbDeviceFilter::GetInstance().IsBlockedByVideoPath("/invalid/path"));
}