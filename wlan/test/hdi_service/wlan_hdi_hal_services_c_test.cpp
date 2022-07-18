/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <servmgr_hdi.h>
#include "v1_0/iwlan_interface.h"
#include "wlan_callback_impl.h"
#include "wlan_impl.h"

#define HDF_LOG_TAG service_manager_test
using namespace testing::ext;

namespace HdiTest {
const int32_t WLAN_FREQ_MAX_NUM = 35;
const int32_t WLAN_TX_POWER = 160;
const int32_t DEFAULT_COMBO_SIZE = 6;
const int32_t WLAN_MAX_NUM_STA_WITH_AP = 4;
const uint32_t RESET_TIME = 20;

const char *WLAN_SERVICE_NAME = "wlan_hal_c_service";

class HdfWifiServiceCTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static struct IWlanInterface *g_wlanObj = nullptr;
struct IWlanCallback *g_wlanCallbackObj = nullptr;
void HdfWifiServiceCTest::SetUpTestCase()
{
    g_wlanObj = WlanInterfaceGetInstance(WLAN_SERVICE_NAME);
    g_wlanCallbackObj = WlanCallbackServiceGet();
    ASSERT_TRUE(g_wlanObj != nullptr);
    ASSERT_TRUE(g_wlanCallbackObj != nullptr);
}

void HdfWifiServiceCTest::TearDownTestCase()
{
    WlanInterfaceRelease(g_wlanObj);
    WlanCallbackServiceRelease(g_wlanCallbackObj);
}

void HdfWifiServiceCTest::SetUp()
{
    int32_t rc = g_wlanObj->Start(g_wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void HdfWifiServiceCTest::TearDown()
{
    int32_t rc = g_wlanObj->Stop(g_wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetSupportFeatureComboTest_001
 * @tc.desc: Wifi hdi get support feature and combo function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetSupportFeatureComboTest_001, TestSize.Level1)
{
    uint8_t supType[PROTOCOL_80211_IFTYPE_NUM + 1] = {0};
    uint32_t supTypeLen = PROTOCOL_80211_IFTYPE_NUM + 1;
    uint64_t combo[DEFAULT_COMBO_SIZE] = {0};

    int32_t rc = g_wlanObj->GetSupportFeature(g_wlanObj, supType, &supTypeLen);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetSupportCombo(g_wlanObj, combo);
    ASSERT_NE(rc, HDF_FAILURE);
}

/**
 * @tc.name: CreateFeatureTest_002
 * @tc.desc: Wifi hdi create feature function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, CreateFeatureTest_002, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    printf("ifname = %s\n", ifeature.ifName);
    printf("type = %d\n", ifeature.type);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetFeatureByIfNameTest_003
 * @tc.desc: Wifi hdi get feature by ifname function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetFeatureByIfNameTest_003, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetFeatureByIfName(g_wlanObj, ifeature.ifName, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetAsscociatedStasTest_004
 * @tc.desc: Wifi hdi get assoc stas function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetAsscociatedStasTest_004, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    struct HdfStaInfo staInfo[WLAN_MAX_NUM_STA_WITH_AP] = {{0}};
    uint32_t staInfoLen = WLAN_MAX_NUM_STA_WITH_AP;
    uint32_t num = 0;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetAsscociatedStas(g_wlanObj, &ifeature, staInfo, &staInfoLen, &num);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetCountryCodeTest_005
 * @tc.desc: Wifi hdi set country code function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, SetCountryCodeTest_005, TestSize.Level1)
{
    const char *code = "CN";
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->SetCountryCode(g_wlanObj, &ifeature, code, sizeof(code));
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetNetworkIfaceNameTest_006
 * @tc.desc: Wifi hdi get network interface name function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetNetworkIfaceNameTest_006, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    char ifNames[IFNAMSIZ] = {0};

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetNetworkIfaceName(g_wlanObj, &ifeature, ifNames, IFNAMSIZ);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetFeatureTypeTest_007
 * @tc.desc: Wifi hdi get feature type function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetFeatureTypeTest_007, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    int32_t featureType;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetFeatureType(g_wlanObj, &ifeature, &featureType);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetMacAddressTest_008
 * @tc.desc: Wifi hdi set mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, SetMacAddressTest_008, TestSize.Level1)
{
    uint8_t mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    uint32_t macLen = ETH_ADDR_LEN;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->SetMacAddress(g_wlanObj, &ifeature, mac, macLen);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
    ASSERT_TRUE(flag);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetDeviceMacAddressTest_009
 * @tc.desc: Wifi hdi get device mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetDeviceMacAddressTest_009, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    uint8_t mac[ETH_ADDR_LEN] = {0};
    uint32_t macLen = ETH_ADDR_LEN;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetDeviceMacAddress(g_wlanObj, &ifeature, mac, &macLen, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_SUCCESS);
    for (int i = 0; i < ETH_ADDR_LEN; i++) {
        printf("%s: mac[%d] = %02x\n", __func__, i, mac[i]);
    }
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetFreqsWithBandTest_010
 * @tc.desc: Wifi hdi get freqs function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetFreqsWithBandTest_010, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    struct HdfWifiInfo wifiInfo;
    int32_t freq[WLAN_FREQ_MAX_NUM] = {0};
    uint32_t freqLen = WLAN_FREQ_MAX_NUM ;
    wifiInfo.band = IEEE80211_BAND_2GHZ;
    wifiInfo.size = WLAN_FREQ_MAX_NUM;
    uint32_t i;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetFreqsWithBand(g_wlanObj, &ifeature, &wifiInfo, freq, &freqLen);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        for (i = 0; i < freqLen; i++) {
            printf("%s: freq[%d] = %d\n", __func__, i, freq[i]);
        }
    }

    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetTxPowerTest_011
 * @tc.desc: Wifi hdi set tx power function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, SetTxPowerTest_011, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    int32_t power = WLAN_TX_POWER;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->SetTxPower(g_wlanObj, &ifeature, power);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetChipIdTest_012
 * @tc.desc: Wifi hdi get chip id function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetChipIdTest_012, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    uint8_t chipId = 0;
    unsigned int num = 0;
    char ifNames[IFNAMSIZ] = {0};

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetChipId(g_wlanObj, &ifeature, &chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetIfNamesByChipId(g_wlanObj, chipId, ifNames, IFNAMSIZ, &num);
    printf("ifnames = %s\n", ifNames);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetScanningMacAddressTest_013
 * @tc.desc: Wifi hdi set scanning mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, SetScanningMacAddressTest_013, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    uint8_t scanMac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    uint32_t macLen = ETH_ADDR_LEN;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->SetScanningMacAddress(g_wlanObj, &ifeature, scanMac, macLen);
    ASSERT_NE(rc, HDF_FAILURE);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetNetdevInfoTest_014
 * @tc.desc: Wifi hdi get netdev info function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetNetdevInfoTest_014, TestSize.Level1)
{
    int32_t rc;
    struct HdfNetDeviceInfoResult netDeviceInfoResult;

    (void)memset_s(
        &netDeviceInfoResult, sizeof(struct HdfNetDeviceInfoResult), 0, sizeof(struct HdfNetDeviceInfoResult));
    rc = g_wlanObj->GetNetDevInfo(g_wlanObj, (struct HdfNetDeviceInfoResult *)&netDeviceInfoResult);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetPowerModeTest_015
 * @tc.desc: Wifi hdi get power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(HdfWifiServiceCTest, GetPowerModeTest_015, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = 0;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_AP, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetPowerMode(g_wlanObj, &ifeature, &mode);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
    ASSERT_TRUE(flag);
    printf("mode = 0x%02x\n", mode);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetPowerModeTest_016
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_016, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_SLEEPING;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_AP, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
    ASSERT_TRUE(flag);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: RegisterEventCallbackTest_017
 * @tc.desc: Wifi hdi reister event call back function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, RegisterEventCallbackTest_017, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc = g_wlanObj->RegisterEventCallback(g_wlanObj, g_wlanCallbackObj, ifName);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: ResetDriverTest_018
 * @tc.desc: Wifi hdi reset driver function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, ResetDriverTest_018, TestSize.Level1)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    const char *ifName = "wlan0";
    uint8_t chipId = 0;
    int32_t rc;

    rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetChipId(g_wlanObj, &ifeature, &chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->ResetDriver(g_wlanObj, chipId, ifName);
    ASSERT_EQ(rc, HDF_SUCCESS);
    sleep(RESET_TIME);
}

/**
 * @tc.name: StartScanTest_019
 * @tc.desc: Wifi hdi start scan function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, StartScanTest_019, TestSize.Level1)
{
    int32_t rc;
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    struct HdfWifiScan scan = {0};

    rc = g_wlanObj->CreateFeature(g_wlanObj, wlan_type, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->StartScan(g_wlanObj, &ifeature, &scan);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    sleep(10);
}

/**
 * @tc.name: UnregisterEventCallbackTest_020
 * @tc.desc: Wifi hdi unreister event call back function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, UnregisterEventCallbackTest_020, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc = g_wlanObj->UnregisterEventCallback(g_wlanObj, g_wlanCallbackObj, ifName);
    ASSERT_EQ(rc, HDF_SUCCESS);
}
};
