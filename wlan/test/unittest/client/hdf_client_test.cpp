/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <osal_mem.h>
#include "wifi_driver_client.h"

using namespace testing::ext;

namespace ClientTest {
const uint32_t DEFAULT_COMBO_SIZE = 10;
const char *WLAN_IFNAME = "wlan0";
const uint32_t RESET_TIME = 20;
class WifiClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void WifiClientTest::SetUpTestCase()
{
}

void WifiClientTest::TearDownTestCase()
{
}

void WifiClientTest::SetUp()
{
    WifiDriverClientInit();
}

void WifiClientTest::TearDown()
{
    WifiDriverClientDeinit();
}

/**
 * @tc.name: WifiClientSetCountryCode001
 * @tc.desc: Wifi client set country code function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientSetCountryCode001, TestSize.Level1)
{
    int32_t ret;
    const char *code = "CN";
    const char *codeDigital = "99";
    uint32_t len = 2;

    ret = WifiSetCountryCode(WLAN_IFNAME, code, len);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    ret = WifiSetCountryCode(WLAN_IFNAME, codeDigital, len);
    bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientGetUsableNetworkInfo001
 * @tc.desc: Wifi client get usable networkInfo function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientGetUsableNetworkInfo001, TestSize.Level1)
{
    int32_t ret;
    struct NetworkInfoResult networkInfo;

    ret = GetUsableNetworkInfo(&networkInfo);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientIsSupportCombo001
 * @tc.desc: Wifi client is support combo function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientIsSupportCombo001, TestSize.Level1)
{
    int32_t ret;
    uint8_t isSupportCombo;

    ret = IsSupportCombo(&isSupportCombo);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetComboInfo001
 * @tc.desc: Wifi client get combo info function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientGetComboInfo001, TestSize.Level1)
{
    int32_t ret;
    uint64_t comboInfo[DEFAULT_COMBO_SIZE] = {};

    ret = GetComboInfo(comboInfo, DEFAULT_COMBO_SIZE);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetMacAddr001
 * @tc.desc: Wifi client set mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientSetMacAddr001, TestSize.Level1)
{
    int32_t ret;
    unsigned char mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    unsigned char errorMac[ETH_ADDR_LEN] = {0x11, 0x34, 0x56, 0x78, 0xab, 0xcd};

    ret = SetMacAddr(WLAN_IFNAME, mac, ETH_ADDR_LEN);
    bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_DEVICE_BUSY);
    ASSERT_TRUE(flag);
    ret = SetMacAddr(WLAN_IFNAME, errorMac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetDevMacAddr001
 * @tc.desc: Wifi client get mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientGetDevMacAddr001, TestSize.Level1)
{
    int32_t ret;
    unsigned char mac[ETH_ADDR_LEN] = {};
    int32_t type = WIFI_IFTYPE_STATION;

    ret = GetDevMacAddr(WLAN_IFNAME, type, mac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_FAILURE, ret);
}

/**
 * @tc.name: WifiClientGetDevMacAddr002
 * @tc.desc: Wifi client get mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetDevMacAddr002, TestSize.Level1)
{
    int32_t ret;
    unsigned char mac[ETH_ADDR_LEN] = {};
    int32_t type = WIFI_IFTYPE_AP;

    ret = GetDevMacAddr(WLAN_IFNAME, type, mac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_FAILURE, ret);
}

/**
 * @tc.name: WifiClientGetValidFreqByBand001
 * @tc.desc: Wifi client get valid freq function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientGetValidFreqByBand001, TestSize.Level1)
{
    int32_t ret;
    int32_t band = IEEE80211_BAND_2GHZ;
    int32_t bandNotSupport = IEEE80211_NUM_BANDS;
    struct FreqInfoResult result;
    uint32_t size = 14;
    uint32_t i;

    result.freqs = (uint32_t *)OsalMemCalloc(35 * sizeof(uint32_t));
    if (result.freqs == NULL) {
        printf("%s: OsalMemCalloc failed", __FUNCTION__);
        return;
    }

    result.txPower = (uint32_t *)OsalMemCalloc(35 * sizeof(uint32_t));
    if (result.txPower == NULL) {
        printf("%s: OsalMemCalloc failed", __FUNCTION__);
        OsalMemFree(result.freqs);
        return;
    }

    ret = GetValidFreqByBand(WLAN_IFNAME, bandNotSupport, &result, size);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = GetValidFreqByBand(WLAN_IFNAME, band, &result, size);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    if (ret == RET_CODE_SUCCESS) {
        printf("%s: num = %u\n", __func__, result.nums);
        for (i = 0; i < result.nums; i++) {
            printf("%s: freq[%d] = %d\n", __func__, i, result.freqs[i]);
        }
    }

    OsalMemFree(result.txPower);
    OsalMemFree(result.freqs);
}

/**
 * @tc.name: WifiClientSetTxPower001
 * @tc.desc: Wifi client set tx power function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientSetTxPower001, TestSize.Level1)
{
    int32_t ret;
    int32_t power = 10;

    ret = SetTxPower(WLAN_IFNAME, power);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetAssociatedStas001
 * @tc.desc: Wifi client get associated status function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetAssociatedStas001, TestSize.Level1)
{
    int32_t ret;
    struct AssocStaInfoResult result;

    ret = GetAssociatedStas(WLAN_IFNAME, &result);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientSetScanMacAddr001
 * @tc.desc: Wifi client set scan MAC address function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetScanMacAddr001, TestSize.Level1)
{
    int32_t ret;
    unsigned char scanMac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};

    ret = SetScanMacAddr(WLAN_IFNAME, scanMac, ETH_ADDR_LEN);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientAcquireChipId001
 * @tc.desc: Wifi client get chipId function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientAcquireChipId001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    uint8_t chipId = 0;

    ret = AcquireChipId(ifNameInvalid, &chipId);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = AcquireChipId(WLAN_IFNAME, &chipId);
    ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetIfNamesByChipId001
 * @tc.desc: Wifi client get ifName by chipId function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetIfNamesByChipId001, TestSize.Level1)
{
    int32_t ret;
    uint8_t chipId = 0;
    uint8_t chipIdInvalid = 100;
    char *ifNames = nullptr;
    uint32_t num = 0;

    ret = AcquireChipId(WLAN_IFNAME, &chipId);
    ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    ret = GetIfNamesByChipId(chipIdInvalid, &ifNames, &num);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = GetIfNamesByChipId(chipId, &ifNames, &num);
    EXPECT_NE(ifNames, nullptr);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    free(ifNames);
}

/**
 * @tc.name: WifiClientGetNetDeviceInfo001
 * @tc.desc: Wifi client get netDevice information function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetNetDeviceInfo001, TestSize.Level1)
{
    int32_t ret;
    struct NetDeviceInfoResult netDeviceInfoResult;

    ret = GetNetDeviceInfo(&netDeviceInfoResult);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetCurrentPowerMode001
 * @tc.desc: Wifi client get current power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetCurrentPowerMode001, TestSize.Level1)
{
    int32_t ret;
    uint8_t mode = 0;
    const char *ifNameInvalid = "wlanTest";

    ret = GetCurrentPowerMode(ifNameInvalid, &mode);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = GetCurrentPowerMode(WLAN_IFNAME, &mode);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetPowerMode001
 * @tc.desc: Wifi client set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetPowerMode001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";

    ret = SetPowerMode(ifNameInvalid, WIFI_POWER_MODE_SLEEPING);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = SetPowerMode(WLAN_IFNAME, WIFI_POWER_MODE_SLEEPING);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetPowerMode002
 * @tc.desc: Wifi client set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetPowerMode002, TestSize.Level1)
{
    int32_t ret;

    ret = SetPowerMode(WLAN_IFNAME, WIFI_POWER_MODE_GENERAL);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetPowerMode003
 * @tc.desc: Wifi client set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetPowerMode003, TestSize.Level1)
{
    int32_t ret;

    ret = SetPowerMode(WLAN_IFNAME, WIFI_POWER_MODE_THROUGH_WALL);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetPowerMode004
 * @tc.desc: Wifi client set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetPowerMode004, TestSize.Level1)
{
    int32_t ret;

    ret = SetPowerMode(WLAN_IFNAME, WIFI_POWER_MODE_NUM);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientSetResetDriver001
 * @tc.desc: Wifi client reset driver function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetResetDriver001, TestSize.Level1)
{
    int32_t ret;
    uint8_t chipId = 0;

    ret = AcquireChipId(WLAN_IFNAME, &chipId);
    ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);

    ret = SetResetDriver(chipId, WLAN_IFNAME);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    sleep(RESET_TIME);
}
};
