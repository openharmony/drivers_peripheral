/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hdf_wifi_test.h"
#include <gtest/gtest.h>
#include "hdf_uhdf_test.h"
#include "wifi_driver_client.h"

using namespace testing::ext;

namespace ClientTest {
const uint32_t DEFAULT_COMBO_SIZE = 10;
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

HWTEST_F(WifiClientTest, WifiClientSetCountryCode001, TestSize.Level0)
{
    int ret;

    ret = SetCountryCode("wlan0", "CN", 2);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

HWTEST_F(WifiClientTest, WifiClientGetUsableNetworkInfo001, TestSize.Level0)
{
    int ret;
    struct NetworkInfoResult networkInfo;

    ret = GetUsableNetworkInfo(&networkInfo);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

HWTEST_F(WifiClientTest, WifiClientIsSupportCombo001, TestSize.Level0)
{
    int ret;
    uint8_t isSupportCombo;

    ret = IsSupportCombo(&isSupportCombo);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

HWTEST_F(WifiClientTest, WifiClientGetComboInfo001, TestSize.Level0)
{
    int ret;
    uint64_t comboInfo[DEFAULT_COMBO_SIZE] = {};

    ret = GetComboInfo(comboInfo, DEFAULT_COMBO_SIZE);
    EXPECT_EQ(RET_CODE_NOT_SUPPORT, ret);
}

HWTEST_F(WifiClientTest, WifiClientSetMacAddr001, TestSize.Level0)
{
    int ret;
    unsigned char mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};

    ret = SetMacAddr("wlan0", mac, ETH_ADDR_LEN);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

HWTEST_F(WifiClientTest, WifiClientGetDevMacAddr001, TestSize.Level0)
{
    int ret;
    unsigned char mac[ETH_ADDR_LEN] = {};
    int32_t type = WIFI_IFTYPE_STATION;

    ret = GetDevMacAddr("wlan0", type, mac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_FAILURE, ret);
}

HWTEST_F(WifiClientTest, WifiClientGetValidFreqByBand001, TestSize.Level0)
{
    int ret;
    int32_t band = IEEE80211_BAND_2GHZ;
    struct FreqInfoResult result;

    ret = GetValidFreqByBand("wlan0", band, &result);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

HWTEST_F(WifiClientTest, WifiClientSetTxPower001, TestSize.Level0)
{
    int ret;
    int32_t power = 10;

    ret = SetTxPower("wlan0", power);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}
};
