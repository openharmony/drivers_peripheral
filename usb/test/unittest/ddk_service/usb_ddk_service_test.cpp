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

#include "v1_2/iusb_ddk.h"
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
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid12345";
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_FALSE(ret);

    driverInfo.driverUid = "driverUid-12345";
    driverInfo.vids = { 1001 };
    ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 12345;
    V1_2::DriverAbilityInfo queriedDriverInfo;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(driverInfo.driverUid, queriedDriverInfo.driverUid);
    auto iter = std::find(queriedDriverInfo.vids.begin(), queriedDriverInfo.vids.end(), 1001);
    EXPECT_NE(queriedDriverInfo.vids.end(), iter);
}

HWTEST_F(UsbDdkServiceTest, UpdateDriverInfo002, TestSize.Level1)
{
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    driverInfo.vids = { 1001 };
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 12345;
    V1_2::DriverAbilityInfo queriedDriverInfo;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1, queriedDriverInfo.vids.size());

    driverInfo.vids = { 1001, 1002 };
    ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(2, queriedDriverInfo.vids.size());
    auto iter = std::find(queriedDriverInfo.vids.begin(), queriedDriverInfo.vids.end(), 1002);
    EXPECT_NE(queriedDriverInfo.vids.end(), iter);
}

HWTEST_F(UsbDdkServiceTest, RemoveDriverInfo001, TestSize.Level1)
{
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);
    uint32_t tokenId = 12345;
    V1_2::DriverAbilityInfo queriedDriverInfo;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);

    std::string driverUid = "driverUid12345";
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_FALSE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);

    driverUid = "driverUid-12345";
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_FALSE(ret);
}

HWTEST_F(UsbDdkServiceTest, RemoveDriverInfo002, TestSize.Level1)
{
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);
    uint32_t tokenId = 12345;
    V1_2::DriverAbilityInfo queriedDriverInfo;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);

    std::string driverUid = "driverUid-11111";
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);

    driverUid = "driverUid-12345";
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_FALSE(ret);
}

HWTEST_F(UsbDdkServiceTest, QueryDriverInfo001, TestSize.Level1)
{
    V1_2::DriverAbilityInfo queriedDriverInfo;
    bool ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(11111, queriedDriverInfo);
    EXPECT_FALSE(ret);

    V1_2::DriverAbilityInfo updateDriverInfo;
    updateDriverInfo.driverUid = "driverUid-11111";
    ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(updateDriverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 22222;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_FALSE(ret);

    tokenId = 11111;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedDriverInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(updateDriverInfo.driverUid, queriedDriverInfo.driverUid);
}

HWTEST_F(UsbDdkServiceTest, ControlTransferTest001, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    ASSERT_NE(usbDdk, nullptr);

    uint64_t deviceId = 0;
    V1_2::UsbControlRequestSetup setup;
    std::vector<uint8_t> data;
    uint32_t timeout = 1000;
    uint32_t transferredLength = 0;

    setup.requestType = 0x80;
    setup.requestCmd = 0x06;
    setup.value = 0x0100;
    setup.index = 0x0000;
    setup.length = 0x0012;

    int32_t ret = usbDdk->ControlTransfer(deviceId, setup, timeout, data, transferredLength);
    EXPECT_NE(ret, 0);
}

HWTEST_F(UsbDdkServiceTest, ControlTransferTest002, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    ASSERT_NE(usbDdk, nullptr);

    uint64_t deviceId = 0xFFFFFFFFFFFFFFFF;
    V1_2::UsbControlRequestSetup setup;
    std::vector<uint8_t> data;
    uint32_t timeout = 1000;
    uint32_t transferredLength = 0;

    setup.requestType = 0x80;
    setup.requestCmd = 0x06;
    setup.value = 0x0100;
    setup.index = 0x0000;
    setup.length = 0x0012;

    int32_t ret = usbDdk->ControlTransfer(deviceId, setup, timeout, data, transferredLength);
    EXPECT_NE(ret, 0);
}

HWTEST_F(UsbDdkServiceTest, GetNonRootHubsTest001, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    ASSERT_NE(usbDdk, nullptr);

    std::vector<uint64_t> nonRootHubIds;
    int32_t ret = usbDdk->GetNonRootHubs(nonRootHubIds);
    EXPECT_EQ(ret, HDF_ERR_NOPERM);
    EXPECT_GE(nonRootHubIds.size(), 0);
}

HWTEST_F(UsbDdkServiceTest, GetNonRootHubsTest002, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    ASSERT_NE(usbDdk, nullptr);

    std::vector<uint64_t> nonRootHubIds1;
    std::vector<uint64_t> nonRootHubIds2;

    int32_t ret1 = usbDdk->GetNonRootHubs(nonRootHubIds1);
    int32_t ret2 = usbDdk->GetNonRootHubs(nonRootHubIds2);

    EXPECT_EQ(ret1, HDF_ERR_NOPERM);
    EXPECT_EQ(ret2, HDF_ERR_NOPERM);
    EXPECT_EQ(nonRootHubIds1.size(), nonRootHubIds2.size());
}

HWTEST_F(UsbDdkServiceTest, ControlTransferDifferentRequestTypesTest001, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    ASSERT_NE(usbDdk, nullptr);

    uint64_t deviceId = 0;
    uint32_t timeout = 1000;
    uint32_t transferredLength = 0;

    V1_2::UsbControlRequestSetup setup;
    std::vector<uint8_t> data;

    setup.requestType = 0x80;
    setup.requestCmd = 0x08;
    setup.value = 0x0000;
    setup.index = 0x0000;
    setup.length = 0x0001;

    int32_t ret = usbDdk->ControlTransfer(deviceId, setup, timeout, data, transferredLength);
    EXPECT_NE(ret, 0);

    setup.requestType = 0x80;
    setup.requestCmd = 0x00;
    setup.value = 0x0000;
    setup.index = 0x0000;
    setup.length = 0x0001;

    ret = usbDdk->ControlTransfer(deviceId, setup, timeout, data, transferredLength);
    EXPECT_NE(ret, 0);
}

HWTEST_F(UsbDdkServiceTest, ControlTransferTimeoutTest001, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    ASSERT_NE(usbDdk, nullptr);

    uint64_t deviceId = 0;
    V1_2::UsbControlRequestSetup setup;
    std::vector<uint8_t> data;
    uint32_t transferredLength = 0;

    setup.requestType = 0x80;
    setup.requestCmd = 0x06;
    setup.value = 0x0100;
    setup.index = 0x0000;
    setup.length = 0x0012;

    int32_t ret = usbDdk->ControlTransfer(deviceId, setup, 0, data, transferredLength);
    EXPECT_NE(ret, 0);

    ret = usbDdk->ControlTransfer(deviceId, setup, 10, data, transferredLength);
    EXPECT_NE(ret, 0);

    ret = usbDdk->ControlTransfer(deviceId, setup, 10000, data, transferredLength);
    EXPECT_NE(ret, 0);
}
}