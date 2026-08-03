/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "hdf_log.h"
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
    std::vector<uint16_t> queriedVids;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);
    auto iter = std::find(queriedVids.begin(), queriedVids.end(), 1001);
    EXPECT_NE(queriedVids.end(), iter);
}

HWTEST_F(UsbDdkServiceTest, UpdateDriverInfo002, TestSize.Level1)
{
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    driverInfo.vids = { 1001 };
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 12345;
    std::vector<uint16_t> queriedVids;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);
    EXPECT_EQ(queriedVids.size(), 1);

    driverInfo.vids = { 1001, 1002 };
    ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);
    EXPECT_EQ(2, queriedVids.size());
    auto iter = std::find(queriedVids.begin(), queriedVids.end(), 1002);
    EXPECT_NE(queriedVids.end(), iter);
}

HWTEST_F(UsbDdkServiceTest, UpdateDriverInfo003, TestSize.Level1)
{
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-abcde";
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_FALSE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverInfo.driverUid);
    EXPECT_FALSE(ret);

    V1_2::DriverAbilityInfo usbDriverInfo1;
    usbDriverInfo1.driverUid = "usbDriver-55555";
    usbDriverInfo1.vids = { 100, 200, 300 };
    ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(usbDriverInfo1);
    EXPECT_TRUE(ret);

    V1_2::DriverAbilityInfo usbDriverInfo2;
    usbDriverInfo2.driverUid = "usbCameraDriver-55555";
    usbDriverInfo2.vids = { 200, 400, 500 };
    ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(usbDriverInfo2);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 55555;
    std::vector<uint16_t> queriedVids;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);
    EXPECT_EQ(queriedVids.size(), 5);
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 100), queriedVids.end());
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 200), queriedVids.end());
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 300), queriedVids.end());
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 400), queriedVids.end());
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 500), queriedVids.end());

    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(12345, queriedVids);
    EXPECT_TRUE(ret);
    EXPECT_EQ(queriedVids.size(), 2);
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 1001), queriedVids.end());
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 1002), queriedVids.end());
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo("driverUid-12345");
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(12345, queriedVids);
    EXPECT_FALSE(ret);
    EXPECT_EQ(queriedVids.size(), 0);
}

HWTEST_F(UsbDdkServiceTest, UpdateDriverInfo004, TestSize.Level1)
{
    uint32_t tokenId = 55555;
    std::vector<uint16_t> queriedVids;

    bool ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo("usbStorageDriver-55555");
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);
    EXPECT_EQ(queriedVids.size(), 5);

    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo("usbDriver-55555");
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);
    EXPECT_EQ(queriedVids.size(), 3);
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 200), queriedVids.end());
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 400), queriedVids.end());
    EXPECT_NE(std::find(queriedVids.begin(), queriedVids.end(), 500), queriedVids.end());
    EXPECT_EQ(std::find(queriedVids.begin(), queriedVids.end(), 100), queriedVids.end());
    EXPECT_EQ(std::find(queriedVids.begin(), queriedVids.end(), 300), queriedVids.end());

    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo("usbCameraDriver-55555");
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_FALSE(ret);
    EXPECT_EQ(queriedVids.size(), 0);
}

HWTEST_F(UsbDdkServiceTest, UpdateDriverInfo005, TestSize.Level1)
{
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driver-88888";
    driverInfo.vids = { 5525 };
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);

    for (size_t i = 1; i < 255; ++i) {
        driverInfo.driverUid = "driver" + std::to_string(i) + "-88888";
        ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
        EXPECT_TRUE(ret);
    }

    const uint32_t tokenId = 88888;
    std::vector<uint16_t> queriedVids;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);

    driverInfo.driverUid = "driverExtra-88888";
    ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_FALSE(ret);

    for (size_t i = 1; i < 255; ++i) {
        ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo("driver" + std::to_string(i) + "-88888");
        EXPECT_TRUE(ret);
    }
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo("driverExtra-88888");
    EXPECT_TRUE(ret);
}

HWTEST_F(UsbDdkServiceTest, RemoveDriverInfo001, TestSize.Level1)
{
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);
    uint32_t tokenId = 12345;
    std::vector<uint16_t> queriedVids;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);

    std::string driverUid = "driverUid12345";
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_FALSE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);

    driverUid = "driverUid-12345";
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_FALSE(ret);
}

HWTEST_F(UsbDdkServiceTest, RemoveDriverInfo002, TestSize.Level1)
{
    V1_2::DriverAbilityInfo driverInfo;
    driverInfo.driverUid = "driverUid-12345";
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(driverInfo);
    EXPECT_TRUE(ret);
    uint32_t tokenId = 12345;
    std::vector<uint16_t> queriedVids;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);

    std::string driverUid = "driverUid-11111";
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);

    driverUid = "driverUid-12345";
    ret = V1_2::UsbDriverManager::GetInstance().RemoveDriverInfo(driverUid);
    EXPECT_TRUE(ret);
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_FALSE(ret);
}

HWTEST_F(UsbDdkServiceTest, QueryDriverInfo001, TestSize.Level1)
{
    std::vector<uint16_t> queriedVids;
    bool ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(11111, queriedVids);
    EXPECT_FALSE(ret);

    V1_2::DriverAbilityInfo updateDriverInfo;
    updateDriverInfo.driverUid = "driverUid-11111";
    ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(updateDriverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 22222;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_FALSE(ret);

    tokenId = 11111;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);
}

HWTEST_F(UsbDdkServiceTest, QueryDriverInfo002, TestSize.Level1)
{
    V1_2::DriverAbilityInfo updateDriverInfo;
    updateDriverInfo.driverUid = "driverUid-77777";
    updateDriverInfo.vids = { 100, 200, 300 };
    bool ret = V1_2::UsbDriverManager::GetInstance().UpdateDriverInfo(updateDriverInfo);
    EXPECT_TRUE(ret);

    uint32_t tokenId = 77777;
    std::vector<uint16_t> queriedVids;
    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(tokenId, queriedVids);
    EXPECT_TRUE(ret);
    EXPECT_EQ(queriedVids.size(), 3);
    ASSERT_NE(std::find(queriedVids.begin(), queriedVids.end(), 100), queriedVids.end());
    ASSERT_NE(std::find(queriedVids.begin(), queriedVids.end(), 200), queriedVids.end());
    ASSERT_NE(std::find(queriedVids.begin(), queriedVids.end(), 300), queriedVids.end());
}

HWTEST_F(UsbDdkServiceTest, QueryDriverInfo003, TestSize.Level1)
{
    std::vector<uint16_t> queriedVids;
    bool ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(99999, queriedVids);
    EXPECT_FALSE(ret);

    ret = V1_2::UsbDriverManager::GetInstance().QueryDriverInfo(66666, queriedVids);
    EXPECT_FALSE(ret);
}

HWTEST_F(UsbDdkServiceTest, ControlTransferTest001, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    if (usbDdk) {
        HDF_LOGI("%{public}s:IUsbDdk::Get() success.", __func__);
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
}

HWTEST_F(UsbDdkServiceTest, ControlTransferTest002, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    if (usbDdk) {
        HDF_LOGI("%{public}s:IUsbDdk::Get() success.", __func__);
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
}

HWTEST_F(UsbDdkServiceTest, GetNonRootHubsTest001, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    if (usbDdk) {
        HDF_LOGI("%{public}s:IUsbDdk::Get() success.", __func__);
        std::vector<uint64_t> nonRootHubIds;
        int32_t ret = usbDdk->GetNonRootHubs(nonRootHubIds);
        EXPECT_EQ(ret, HDF_ERR_NOPERM);
        EXPECT_GE(nonRootHubIds.size(), 0);
    }
}

HWTEST_F(UsbDdkServiceTest, GetNonRootHubsTest002, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    if (usbDdk) {
        HDF_LOGI("%{public}s:IUsbDdk::Get() success.", __func__);
        std::vector<uint64_t> nonRootHubIds1;
        std::vector<uint64_t> nonRootHubIds2;

        int32_t ret1 = usbDdk->GetNonRootHubs(nonRootHubIds1);
        int32_t ret2 = usbDdk->GetNonRootHubs(nonRootHubIds2);

        EXPECT_EQ(ret1, HDF_ERR_NOPERM);
        EXPECT_EQ(ret2, HDF_ERR_NOPERM);
        EXPECT_EQ(nonRootHubIds1.size(), nonRootHubIds2.size());
    }
}

HWTEST_F(UsbDdkServiceTest, ControlTransferDifferentRequestTypesTest001, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    if (usbDdk) {
        HDF_LOGI("%{public}s:IUsbDdk::Get() success.", __func__);
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
}

HWTEST_F(UsbDdkServiceTest, ControlTransferTimeoutTest001, TestSize.Level1)
{
    OHOS::sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    if (usbDdk) {
        HDF_LOGI("%{public}s:IUsbDdk::Get() success.", __func__);
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
}