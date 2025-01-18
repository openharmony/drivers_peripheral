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

#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>

#include "usb_driver_manager.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::HDI::Usb::Ddk;

namespace {
class UsbDdkServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void UsbDdkServiceTest::SetUpTestCase()
{
}

void UsbDdkServiceTest::TearDownTestCase()
{
}

void UsbDdkServiceTest::SetUp()
{
}

void UsbDdkServiceTest::TearDown()
{
}

HWTEST_F(UsbDdkServiceTest, UpdateDriverInfo001, TestSize.Level1)
{
    V1_1::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid12345";
    bool ret = V1_1::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_FALSE(ret);

    driverInfo.driverUid = "driverUid-12345";
    driverInfo.vids = { 1001 };
    ret = V1_1::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 12345;
    V1_1::DriverAbilityInfo queriedDriverInfo;
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(driverInfo.driverUid, queriedDriverInfo.driverUid);
    auto iter = std::find(queriedDriverInfo.vids.begin(), queriedDriverInfo.vids.end(), 1001);
    EXPECT_NE(queriedDriverInfo.vids.end(), iter);
}

HWTEST_F(UsbDdkServiceTest, UpdateDriverInfo002, TestSize.Level1)
{
    V1_1::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    driverInfo.vids = { 1001 };
    bool ret = V1_1::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 12345;
    V1_1::DriverAbilityInfo queriedDriverInfo;
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1, queriedDriverInfo.vids.size());

    driverInfo.vids = { 1001, 1002 };
    ret = V1_1::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(2, queriedDriverInfo.vids.size());
    auto iter = std::find(queriedDriverInfo.vids.begin(), queriedDriverInfo.vids.end(), 1002);
    EXPECT_NE(queriedDriverInfo.vids.end(), iter);
}

HWTEST_F(UsbDdkServiceTest, RemoveDriverInfo001, TestSize.Level1)
{
    V1_1::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    bool ret = V1_1::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);
    uint32_t tokenId = 12345;
    V1_1::DriverAbilityInfo queriedDriverInfo;
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);

    std::string driverUid = "driverUid12345";
    ret = V1_1::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_FALSE(ret);
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);

    driverUid = "driverUid-12345";
    ret = V1_1::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_FALSE(ret);
}

HWTEST_F(UsbDdkServiceTest, RemoveDriverInfo002, TestSize.Level1)
{
    V1_1::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    bool ret = V1_1::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);
    uint32_t tokenId = 12345;
    V1_1::DriverAbilityInfo queriedDriverInfo;
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);

    std::string driverUid = "driverUid-11111";
    ret = V1_1::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);

    driverUid = "driverUid-12345";
    ret = V1_1::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_FALSE(ret);
}

HWTEST_F(UsbDdkServiceTest, QueryDriverInfo001, TestSize.Level1)
{
    V1_1::DriverAbilityInfo queriedDriverInfo;
    bool ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(11111, queriedDriverInfo);
    EXPECT_FALSE(ret);

    V1_1::DriverAbilityInfo updateDriverInfo;
    updateDriverInfo.driverUid = "driverUid-11111";
    ret = V1_1::UsbDriverManager::GetInstance().UpdateDriverInfo(updateDriverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 22222;
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_FALSE(ret);

    tokenId = 11111;
    ret = V1_1::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(updateDriverInfo.driverUid, queriedDriverInfo.driverUid);
}
}