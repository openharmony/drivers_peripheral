/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <osal_mem.h>
#include "v1_3/iwlan_interface.h"
#include "wlan_callback_impl.h"
#include "securec.h"
#include "wlan_hdi_types.h"

#define HDF_LOG_TAG service_manager_test
using namespace testing::ext;

namespace HdiTest {
const int32_t WLAN_FREQ_MAX_NUM = 35;
const int32_t WLAN_TX_POWER = 160;
const int32_t DEFAULT_COMBO_SIZE = 6;
const int32_t WLAN_MAX_NUM_STA_WITH_AP = 4;
const uint32_t RESET_TIME = 3;
const uint32_t MEAS_CHANNEL_TIME = 1;
const uint32_t SCAN_TIME = 3;
const char *WLAN_SERVICE_NAME = "wlan_interface_service";

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
    g_wlanObj = IWlanInterfaceGetInstance(WLAN_SERVICE_NAME, false);
    g_wlanCallbackObj = WlanCallbackServiceGet();
    ASSERT_TRUE(g_wlanObj != nullptr);
    ASSERT_TRUE(g_wlanCallbackObj != nullptr);
}

void HdfWifiServiceCTest::TearDownTestCase()
{
    IWlanInterfaceReleaseInstance(WLAN_SERVICE_NAME, g_wlanObj, false);
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
    uint32_t supTypeLenInvalid = 6;

    int32_t rc = g_wlanObj->GetSupportFeature(g_wlanObj, supType, &supTypeLenInvalid);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wlanObj->GetSupportFeature(g_wlanObj, supType, &supTypeLen);
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
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        printf("ifname = %s\n", ifeature.ifName);
        printf("type = %d\n", ifeature.type);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetFeatureByIfNameTest_003
 * @tc.desc: Wifi hdi get feature by ifname function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetFeatureByIfNameTest_003, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    const char *ifNameInvalid = "wlanTest";

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetFeatureByIfName(g_wlanObj, ifNameInvalid, &ifeature);
        ASSERT_NE(rc, HDF_SUCCESS);
        rc = g_wlanObj->GetFeatureByIfName(g_wlanObj, ifeature.ifName, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetNetworkIfaceNameTest_004
 * @tc.desc: Wifi hdi get network interface name function test on AP feature
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetNetworkIfaceNameTest_004, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    char ifNames[IFNAMSIZ] = {0};

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetNetworkIfaceName(g_wlanObj, &ifeature, ifNames, IFNAMSIZ);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetFeatureTypeTest_005
 * @tc.desc: Wifi hdi get feature type function test on AP feature
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetFeatureTypeTest_005, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    int32_t featureType;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetFeatureType(g_wlanObj, &ifeature, &featureType);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetMacAddressTest_006
 * @tc.desc: Wifi hdi set mac addr function test on AP feature
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, SetMacAddressTest_006, TestSize.Level1)
{
    uint8_t mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    uint32_t macLen = ETH_ADDR_LEN;
    uint8_t errorMac[ETH_ADDR_LEN] = {0x11, 0x34, 0x56, 0x78, 0xab, 0xcd};

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetMacAddress(g_wlanObj, &ifeature, errorMac, macLen);
        ASSERT_NE(rc, HDF_SUCCESS);
        rc = g_wlanObj->SetMacAddress(g_wlanObj, &ifeature, mac, macLen);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_ERR_DEVICE_BUSY);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetDeviceMacAddressTest_007
 * @tc.desc: Wifi hdi get device mac addr function test on AP feature
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetDeviceMacAddressTest_007, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    uint8_t mac[ETH_ADDR_LEN] = {0};
    uint32_t macLen = ETH_ADDR_LEN;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetDeviceMacAddress(g_wlanObj, &ifeature, mac, &macLen, ETH_ADDR_LEN);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetFreqsWithBandTest_008
 * @tc.desc: Wifi hdi get freqs function test on AP feature
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetFreqsWithBandTest_008, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    struct HdfWifiInfo wifiInfo;
    int32_t freq[WLAN_FREQ_MAX_NUM] = {0};
    uint32_t freqLen = WLAN_FREQ_MAX_NUM ;
    wifiInfo.band = IEEE80211_BAND_2GHZ;
    wifiInfo.size = WLAN_FREQ_MAX_NUM;
    struct HdfWifiInfo wifiInfoInvalid;
    wifiInfoInvalid.band = IEEE80211_NUM_BANDS;
    wifiInfoInvalid.size = WLAN_FREQ_MAX_NUM;
    uint32_t i;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetFreqsWithBand(g_wlanObj, &ifeature, &wifiInfoInvalid, freq, &freqLen);
        ASSERT_NE(rc, HDF_SUCCESS);
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
}

/**
 * @tc.name: SetTxPowerTest_009
 * @tc.desc: Wifi hdi set tx power function test on AP feature
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, SetTxPowerTest_009, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    int32_t power = WLAN_TX_POWER;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetTxPower(g_wlanObj, &ifeature, power);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetChipIdTest_010
 * @tc.desc: Wifi hdi get chip id function test on STA feature
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetChipIdTest_010, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    uint8_t chipId = 0;
    uint8_t chipIdInvalid = 100;
    unsigned int num = 0;
    char ifNames[IFNAMSIZ] = {0};

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetChipId(g_wlanObj, &ifeature, &chipId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->GetIfNamesByChipId(g_wlanObj, chipIdInvalid, ifNames, IFNAMSIZ, &num);
        ASSERT_NE(rc, HDF_SUCCESS);
        rc = g_wlanObj->GetIfNamesByChipId(g_wlanObj, chipId, ifNames, IFNAMSIZ, &num);
        printf("ifnames = %s\n", ifNames);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetScanningMacAddressTest_011
 * @tc.desc: Wifi hdi set scanning mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, SetScanningMacAddressTest_011, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    uint8_t scanMac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    uint32_t macLen = ETH_ADDR_LEN;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetScanningMacAddress(g_wlanObj, &ifeature, scanMac, macLen);
        ASSERT_NE(rc, HDF_FAILURE);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetNetdevInfoTest_012
 * @tc.desc: Wifi hdi get netdev info function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, GetNetdevInfoTest_012, TestSize.Level1)
{
    int32_t rc;
    struct HdfNetDeviceInfoResult netDeviceInfoResult;

    (void)memset_s(
        &netDeviceInfoResult, sizeof(struct HdfNetDeviceInfoResult), 0, sizeof(struct HdfNetDeviceInfoResult));
    rc = g_wlanObj->GetNetDevInfo(g_wlanObj, (struct HdfNetDeviceInfoResult *)&netDeviceInfoResult);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetPowerModeTest_013
 * @tc.desc: Wifi hdi get power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(HdfWifiServiceCTest, GetPowerModeTest_013, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = 0;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_AP, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetPowerMode(g_wlanObj, &ifeature, &mode);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        printf("mode = 0x%02x\n", mode);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetPowerModeTest_014
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_014, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_SLEEPING;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_AP, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: RegisterEventCallbackTest_015
 * @tc.desc: Wifi hdi register event call back function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, RegisterEventCallbackTest_015, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc = g_wlanObj->RegisterEventCallback(g_wlanObj, g_wlanCallbackObj, ifName);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: ResetDriverTest_016
 * @tc.desc: Wifi hdi reset driver function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, ResetDriverTest_016, TestSize.Level1)
{
    int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    const char *ifName = "wlan0";
    uint8_t chipId = 0;
    int32_t rc;

    rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetChipId(g_wlanObj, &ifeature, &chipId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->ResetDriver(g_wlanObj, chipId, ifName);
        ASSERT_EQ(rc, HDF_SUCCESS);
        sleep(RESET_TIME);
    }
}

/**
 * @tc.name: StartScanTest_017
 * @tc.desc: Wifi hdi start scan function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, StartScanTest_017, TestSize.Level1)
{
    int32_t rc;
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    struct HdfWifiScan scan = {0};

    rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->StartScan(g_wlanObj, nullptr, &scan);
        ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
        rc = g_wlanObj->StartScan(g_wlanObj, &ifeature, nullptr);
        ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
        rc = g_wlanObj->StartScan(g_wlanObj, &ifeature, &scan);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
        sleep(SCAN_TIME);
    }
}

/**
 * @tc.name: UnregisterEventCallbackTest_018
 * @tc.desc: Wifi hdi unreister event call back function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, UnregisterEventCallbackTest_018, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc = g_wlanObj->UnregisterEventCallback(g_wlanObj, g_wlanCallbackObj, ifName);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetAssociatedStasTest_019
 * @tc.desc: Wifi hdi get assoc stas function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, GetAssociatedStasTest_019, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    struct HdfStaInfo staInfo[WLAN_MAX_NUM_STA_WITH_AP] = {{0}};
    uint32_t staInfoLen = WLAN_MAX_NUM_STA_WITH_AP;
    uint32_t num = 0;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetAssociatedStas(g_wlanObj, &ifeature, staInfo, &staInfoLen, &num);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetCountryCodeTest_020
 * @tc.desc: Wifi hdi set country code function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, SetCountryCodeTest_020, TestSize.Level1)
{
    const char *code = "CN";
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    const char *codeDigital = "99";
    uint32_t size = 2;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetCountryCode(g_wlanObj, &ifeature, codeDigital, size);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_TIMEOUT || rc == HDF_FAILURE);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->SetCountryCode(g_wlanObj, &ifeature, code, size);
        ASSERT_EQ(rc, HDF_ERR_TIMEOUT);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: CreateFeatureTest_021
 * @tc.desc: Wifi hdi create feature function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, CreateFeatureTest_021, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    int32_t wlanTypeInvalid = PROTOCOL_80211_IFTYPE_NUM;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanTypeInvalid, &ifeature);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        printf("ifname = %s\n", ifeature.ifName);
        printf("type = %d\n", ifeature.type);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetChipIdTest_022
 * @tc.desc: Wifi hdi get chip id function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, GetChipIdTest_022, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;
    uint8_t chipId = 0;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetChipId(g_wlanObj, &ifeature, &chipId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetDeviceMacAddressTest_023
 * @tc.desc: Wifi hdi get device mac addr function test on STA feature
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, GetDeviceMacAddressTest_023, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    uint8_t mac[ETH_ADDR_LEN] = {0};
    uint32_t macLen = ETH_ADDR_LEN;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetDeviceMacAddress(g_wlanObj, &ifeature, mac, &macLen, ETH_ADDR_LEN);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetFeatureByIfNameTest_024
 * @tc.desc: Wifi hdi get feature by ifname function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, GetFeatureByIfNameTest_024, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    const char *ifNameInvalid = "wlanTest";

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetFeatureByIfName(g_wlanObj, ifNameInvalid, &ifeature);
        ASSERT_NE(rc, HDF_SUCCESS);
        rc = g_wlanObj->GetFeatureByIfName(g_wlanObj, ifeature.ifName, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetMacAddressTest_025
 * @tc.desc: Wifi hdi set mac addr function test on STA feature
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, SetMacAddressTest_025, TestSize.Level1)
{
    uint8_t mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    uint32_t macLen = ETH_ADDR_LEN;
    uint8_t errorMac[ETH_ADDR_LEN] = {0x11, 0x34, 0x56, 0x78, 0xab, 0xcd};

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetMacAddress(g_wlanObj, &ifeature, errorMac, macLen);
        ASSERT_NE(rc, HDF_SUCCESS);
        rc = g_wlanObj->SetMacAddress(g_wlanObj, &ifeature, mac, macLen);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_ERR_DEVICE_BUSY);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetPowerModeTest_026
 * @tc.desc: Wifi hdi get power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, GetPowerModeTest_026, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = 0;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_STATION, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetPowerMode(g_wlanObj, &ifeature, &mode);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetPowerModeTest_027
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_027, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_GENERAL;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_AP, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetPowerModeTest_028
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_028, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_THROUGH_WALL;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_AP, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetPowerModeTest_029
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_029, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_NUM;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_AP, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
        ASSERT_NE(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetPowerModeTest_30
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_030, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_SLEEPING;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_STATION, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetPowerModeTest_031
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_031, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_GENERAL;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_STATION, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetPowerModeTest_032
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_032, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_THROUGH_WALL;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_STATION, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetPowerModeTest_033
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(HdfWifiServiceCTest, SetPowerModeTest_033, TestSize.Level1)
{
    struct HdfFeatureInfo ifeature;
    uint8_t mode = WIFI_POWER_MODE_NUM;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, PROTOCOL_80211_IFTYPE_STATION, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetPowerMode(g_wlanObj, &ifeature, mode);
        ASSERT_NE(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: StartChannelMeasTest_034
 * @tc.desc: Wifi hdi start channel meas and get meas result function test
 * @tc.type: FUNC
 * @tc.require: AR000H603J
 */
HWTEST_F(HdfWifiServiceCTest, StartChannelMeasTest_034, TestSize.Level1)
{
    const char *ifName = "wlan0";
    struct MeasChannelParam measChannelParam;
    struct MeasChannelResult measChannelResult = {0};

    measChannelParam.channelId = 1;
    measChannelParam.measTime = 15;
    int32_t rc = g_wlanObj->StartChannelMeas(g_wlanObj, ifName, &measChannelParam);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_DEV_ERR_NETDOWN);
    ASSERT_TRUE(flag);
    sleep(MEAS_CHANNEL_TIME);
    rc = g_wlanObj->GetChannelMeasResult(g_wlanObj, ifName, &measChannelResult);
    flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_DEV_ERR_NODATA);
    ASSERT_TRUE(flag);
    rc = g_wlanObj->StartChannelMeas(g_wlanObj, nullptr, &measChannelParam);
    ASSERT_NE(rc, HDF_SUCCESS);
    rc = g_wlanObj->StartChannelMeas(g_wlanObj, ifName, nullptr);
    ASSERT_NE(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetChannelMeasResult(g_wlanObj, nullptr, &measChannelResult);
    ASSERT_NE(rc, HDF_SUCCESS);
    rc = g_wlanObj->GetChannelMeasResult(g_wlanObj, ifName, nullptr);
    ASSERT_NE(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetProjectionScreenParam_035
 * @tc.desc: Wifi hdi set paramters to optimize projectino screen function test
 * @tc.type: FUNC
 * @tc.require: AR000HDUEE
 */
HWTEST_F(HdfWifiServiceCTest, SetProjectionScreenParam_035, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;
    struct ProjectionScreenCmdParam param;
    int8_t data = 0;
    (void)memset_s(&param, sizeof(struct ProjectionScreenCmdParam), 0, sizeof(struct ProjectionScreenCmdParam));

    param.buf = &data;
    param.bufLen = sizeof(data);
    param.cmdId = CMD_CLOSE_GO_CAC;
    rc = g_wlanObj->SetProjectionScreenParam(g_wlanObj, ifName, &param);
    printf("ScreenParam = %d, rc = %d.\n", CMD_CLOSE_GO_CAC, rc);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: SetProjectionScreenParam_036
 * @tc.desc: Wifi hdi set paramters to optimize projectino screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, SetProjectionScreenParam_036, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;
    struct ProjectionScreenCmdParam param;
    int8_t data = 0;
    (void)memset_s(&param, sizeof(struct ProjectionScreenCmdParam), 0, sizeof(struct ProjectionScreenCmdParam));

    param.buf = &data;
    param.bufLen = sizeof(data);
    param.cmdId = CMD_SET_GO_CSA_CHANNEL;
    rc = g_wlanObj->SetProjectionScreenParam(g_wlanObj, ifName, &param);
    printf("ScreenParam = %d, rc = %d.\n", CMD_SET_GO_CSA_CHANNEL, rc);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_DEV_ERR_NETDOWN);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: SetProjectionScreenParam_037
 * @tc.desc: Wifi hdi set paramters to optimize projectino screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, SetProjectionScreenParam_037, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;
    struct ProjectionScreenCmdParam param;
    int8_t data = 0;
    (void)memset_s(&param, sizeof(struct ProjectionScreenCmdParam), 0, sizeof(struct ProjectionScreenCmdParam));

    param.buf = &data;
    param.bufLen = sizeof(data);
    param.cmdId = CMD_SET_GO_RADAR_DETECT;
    rc = g_wlanObj->SetProjectionScreenParam(g_wlanObj, ifName, &param);
    printf("ScreenParam = %d, rc = %d.\n", CMD_SET_GO_RADAR_DETECT, rc);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_DEV_ERR_NETDOWN);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: SetProjectionScreenParam_038
 * @tc.desc: Wifi hdi set paramters to optimize projectino screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, SetProjectionScreenParam_038, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;
    struct ProjectionScreenCmdParam param;
    int8_t data = 0;
    (void)memset_s(&param, sizeof(struct ProjectionScreenCmdParam), 0, sizeof(struct ProjectionScreenCmdParam));

    param.buf = &data;
    param.bufLen = sizeof(data);
    param.cmdId = CMD_ID_MCC_STA_P2P_QUOTA_TIME;
    rc = g_wlanObj->SetProjectionScreenParam(g_wlanObj, ifName, &param);
    printf("ScreenParam = %d, rc = %d.\n", CMD_ID_MCC_STA_P2P_QUOTA_TIME, rc);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_DEV_ERR_NETDOWN);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: SetProjectionScreenParam_039
 * @tc.desc: Wifi hdi set paramters to optimize projectino screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, SetProjectionScreenParam_039, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;
    struct ProjectionScreenCmdParam param;
    int8_t data = 0;
    (void)memset_s(&param, sizeof(struct ProjectionScreenCmdParam), 0, sizeof(struct ProjectionScreenCmdParam));

    param.buf = &data;
    param.bufLen = sizeof(data);
    param.cmdId = CMD_ID_CTRL_ROAM_CHANNEL;
    rc = g_wlanObj->SetProjectionScreenParam(g_wlanObj, ifName, &param);
    printf("ScreenParam = %d, rc = %d.\n", CMD_ID_CTRL_ROAM_CHANNEL, rc);
    bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_DEV_ERR_NETDOWN);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: SendCmdIoctl_040
 * @tc.desc: Wifi hdi send ioctl command function test
 * @tc.type: FUNC
 * @tc.require: AR000HDUEE
 */
HWTEST_F(HdfWifiServiceCTest, SendCmdIoctl_040, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;
    bool flag;

    uint8_t deviceType = 5;
    rc = g_wlanObj->WifiSendCmdIoctl(g_wlanObj, ifName, CMD_HID2D_MODULE_INIT, (const int8_t *)&deviceType,
        sizeof(deviceType));
    printf("SendCmdIoctl MODULE_INIT, rc=%d.\n", rc);
    flag = ((rc == HDF_SUCCESS) || (rc == HDF_ERR_NOT_SUPPORT) || (rc == HDF_DEV_ERR_NETDOWN));
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: SendCmdIoctl_041
 * @tc.desc: Wifi hdi send ioctl command function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, SendCmdIoctl_041, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;
    bool flag;

    uint8_t batterylevel = 50;
    rc = g_wlanObj->WifiSendCmdIoctl(g_wlanObj, ifName, CMD_SET_BATTERY_LEVEL, (const int8_t *)&batterylevel,
        sizeof(batterylevel));
    printf("SendCmdIoctl BATTERY_LEVEL, rc=%d.\n", rc);
    flag = ((rc == HDF_SUCCESS) || (rc == HDF_ERR_NOT_SUPPORT) || (rc == HDF_DEV_ERR_NETDOWN));
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: SendCmdIoctl_042
 * @tc.desc: Wifi hdi send ioctl command function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, SendCmdIoctl_042, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;

    struct AdjustChannelInfo chanInfo;
    chanInfo.msgId = 5;
    chanInfo.chanNumber = 36;
    chanInfo.bandwidth = 80;
    chanInfo.switchType = 0;
    rc = g_wlanObj->WifiSendCmdIoctl(g_wlanObj, ifName, CMD_SET_CHAN_ADJUST, (const int8_t *)&chanInfo,
        sizeof(chanInfo));
    printf("SendCmdIoctl CHAN_ADJUST, rc=%d.\n", rc);
    ASSERT_EQ(rc, -1);
}

/**
 * @tc.name: GetStaInfo_043
 * @tc.desc: Wifi hdi get station information function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, GetStaInfo_043, TestSize.Level1)
{
    const char *ifName = "wlan0";
    int32_t rc;
    struct WifiStationInfo info;
    bool flag;
    uint8_t mac[ETH_ADDR_LEN] = {0};

    rc = g_wlanObj->GetStaInfo(g_wlanObj, ifName, &info, mac, ETH_ADDR_LEN);
    flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: GetFeatureTypeTest_044
 * @tc.desc: Wifi hdi get feature type function test on STA feature
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, GetFeatureTypeTest_044, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    int32_t featureType;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetFeatureType(g_wlanObj, &ifeature, &featureType);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetFreqsWithBandTest_045
 * @tc.desc: Wifi hdi get freqs function test on STA feature
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, GetFreqsWithBandTest_045, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    struct HdfWifiInfo wifiInfo;
    int32_t freq[WLAN_FREQ_MAX_NUM] = {0};
    uint32_t freqLen = WLAN_FREQ_MAX_NUM;
    wifiInfo.band = IEEE80211_BAND_2GHZ;
    wifiInfo.size = WLAN_FREQ_MAX_NUM;
    uint32_t i;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
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
}

/**
 * @tc.name: GetNetworkIfaceNameTest_046
 * @tc.desc: Wifi hdi get network interface name function test on STA feature
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, GetNetworkIfaceNameTest_046, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    char ifNames[IFNAMSIZ] = {0};

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetNetworkIfaceName(g_wlanObj, &ifeature, ifNames, IFNAMSIZ);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SetTxPowerTest_047
 * @tc.desc: Wifi hdi set tx power function test on STA feature
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, SetTxPowerTest_047, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    int32_t power = WLAN_TX_POWER;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->SetTxPower(g_wlanObj, &ifeature, power);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetSignalPollInfo_048
 * @tc.desc: Wifi hdi get signal information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, GetSignalPollInfo_048, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    const char *ifName = "wlan0";
    struct SignalPollResult signalResult;
    (void)memset_s(&signalResult, sizeof(struct SignalPollResult), 0, sizeof(struct SignalPollResult));

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetSignalPollInfo(g_wlanObj, ifName, &signalResult);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        printf("GetSignalPollInfo rc = %d.\n", rc);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: StartPnoScan_049
 * @tc.desc: Wifi hdi start pno scan
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, StartPnoScan_049, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    const char *ifName = "wlan0";
    string ssid1 = "xa-hw";
    string ssid2 = "xa-hw-03";
    struct PnoSettings pnoSettings;
    (void)memset_s(&pnoSettings, sizeof(struct PnoSettings), 0, sizeof(struct PnoSettings));
    pnoSettings.min2gRssi = -100;
    pnoSettings.min5gRssi = -120;
    pnoSettings.scanIntervalMs = 60000;
    pnoSettings.scanIterations = 3;

    pnoSettings.pnoNetworksLen = 2;
    pnoSettings.pnoNetworks = (struct PnoNetwork *)OsalMemCalloc(sizeof(struct PnoNetwork) * 2);
    pnoSettings.pnoNetworks[0].isHidden = 1;
    pnoSettings.pnoNetworks[0].ssid.ssid = const_cast<char*>(ssid1.c_str());
    pnoSettings.pnoNetworks[0].ssid.ssidLen = ssid1.length();
    pnoSettings.pnoNetworks[0].freqsLen = 2;
    pnoSettings.pnoNetworks[0].freqs = (int32_t *)OsalMemCalloc(sizeof(int32_t) * 2);
    pnoSettings.pnoNetworks[0].freqs[0] = 2412;
    pnoSettings.pnoNetworks[0].freqs[1] = 2447;
    pnoSettings.pnoNetworks[1].isHidden = 0;
    pnoSettings.pnoNetworks[1].ssid.ssid = const_cast<char*>(ssid2.c_str());
    pnoSettings.pnoNetworks[1].ssid.ssidLen = ssid2.length();

    int32_t rc = g_wlanObj->RegisterEventCallback(g_wlanObj, g_wlanCallbackObj, ifName);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->StartPnoScan(g_wlanObj, nullptr, &pnoSettings);
        ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
        rc = g_wlanObj->StartPnoScan(g_wlanObj, ifName, nullptr);
        ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
        rc = g_wlanObj->StartPnoScan(g_wlanObj, ifName, &pnoSettings);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    rc = g_wlanObj->UnregisterEventCallback(g_wlanObj, g_wlanCallbackObj, ifName);
    ASSERT_EQ(rc, HDF_SUCCESS);
    OsalMemFree(pnoSettings.pnoNetworks[0].freqs);
    OsalMemFree(pnoSettings.pnoNetworks);
}

/**
 * @tc.name: StopPnoScan_050
 * @tc.desc: Wifi hdi stop pno scan
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, StopPnoScan_050, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    struct HdfFeatureInfo ifeature;
    const char *ifName = "wlan0";

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->StopPnoScan(g_wlanObj, nullptr);
        ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
        rc = g_wlanObj->StopPnoScan(g_wlanObj, ifName);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: StartScanTest_051
 * @tc.desc: Wifi hdi start scan function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, StartScanTest_051, TestSize.Level1)
{
    int32_t rc;
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_STATION;
    string ssid1 = "xa-hw";
    struct HdfFeatureInfo ifeature;
    struct HdfWifiScan scan;

    (void)memset_s(&scan, sizeof(struct HdfWifiScan), 0, sizeof(struct HdfWifiScan));
    scan.ssidsLen = 1;
    scan.ssids = (HdfWifiDriverScanSsid *)OsalMemCalloc(sizeof(HdfWifiDriverScanSsid) * (scan.ssidsLen));
    scan.ssids[0].ssid = const_cast<char*>(ssid1.c_str());
    scan.ssids[0].ssidLen = ssid1.length();
    scan.freqsLen = 2;
    scan.freqs = (int32_t *)OsalMemCalloc(sizeof(int32_t) * (scan.freqsLen));
    scan.freqs[0] = 2412;
    scan.freqs[1] = 2447;
    scan.bssidLen = 6;
    scan.bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (scan.bssidLen));
    scan.bssid[0] = 0x12;
    scan.bssid[1] = 0x34;
    scan.bssid[2] = 0x56;
    scan.bssid[3] = 0x78;
    scan.bssid[4] = 0x9A;
    scan.bssid[5] = 0xBC;

    rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->StartScan(g_wlanObj, &ifeature, &scan);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
        sleep(SCAN_TIME);
    }
    OsalMemFree(scan.bssid);
    OsalMemFree(scan.freqs);
    OsalMemFree(scan.ssids);
}

/**
 * @tc.name: GetApBandwidthTest_052
 * @tc.desc: Wifi hdi get AP bandwidth function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, GetApBandwidthTest_052, TestSize.Level1)
{
    uint8_t bandwidth = 0;
    const char *ifName = "wlan0";

    struct HdfFeatureInfo ifeature;
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        rc = g_wlanObj->GetApBandwidth(g_wlanObj, nullptr, &bandwidth);
        ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);

        rc = g_wlanObj->GetApBandwidth(g_wlanObj, ifName, &bandwidth);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_FAILURE);
        ASSERT_TRUE(flag);

        printf("bandwidth: %u\n", bandwidth);

        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

/**
 * @tc.name: ResetToFactoryMacAddressTest_0053
 * @tc.desc: Wifi hdi reset to factory maca address function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfWifiServiceCTest, ResetToFactoryMacAddressTest_0053, TestSize.Level1)
{
    const int32_t wlanType = PROTOCOL_80211_IFTYPE_AP;
    struct HdfFeatureInfo ifeature;

    int32_t rc = g_wlanObj->CreateFeature(g_wlanObj, wlanType, &ifeature);
    if (rc == HDF_SUCCESS) {
        uint8_t mac[ETH_ADDR_LEN] = {0};
        uint32_t macLen = ETH_ADDR_LEN;
        rc = g_wlanObj->GetDeviceMacAddress(g_wlanObj, &ifeature, mac, &macLen, ETH_ADDR_LEN);
        ASSERT_EQ(rc, HDF_SUCCESS);

        uint8_t tmpMac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
        rc = g_wlanObj->SetMacAddress(g_wlanObj, &ifeature, tmpMac, macLen);
        bool flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_ERR_DEVICE_BUSY);
        ASSERT_TRUE(flag);

        const char *ifName = "wlan0";
        rc = g_wlanObj->ResetToFactoryMacAddress(g_wlanObj, ifName);
        flag = (rc == HDF_SUCCESS || rc == HDF_ERR_NOT_SUPPORT || rc == HDF_ERR_DEVICE_BUSY);
        ASSERT_TRUE(flag);

        rc = g_wlanObj->DestroyFeature(g_wlanObj, &ifeature);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

};
