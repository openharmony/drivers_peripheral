/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "wlan_hdi_service_stub.h"
#include "wlan_hal_c_proxy.h"
#include <gtest/gtest.h>
#include <servmgr_hdi.h>

#define HDF_LOG_TAG   service_manager_test
using namespace testing::ext;

namespace HdiTest {
const int32_t WLAN_FREQ_MAX_NUM = 14;
const int32_t WLAN_TX_POWER = 160;
const int32_t ETH_ADDR_LEN = 6;
const int32_t DEFAULT_COMBO_SIZE = 6;
const int32_t WLAN_MAX_NUM_STA_WITH_AP = 4;

const char *WLAN_SERVICE_NAME = "wlan_hal_c_service";

class WifiHdiHalServiceCTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void WifiHdiHalServiceCTest::SetUpTestCase()
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->Construct(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void WifiHdiHalServiceCTest::TearDownTestCase()
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->Destruct(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void WifiHdiHalServiceCTest::SetUp()
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->Start(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void WifiHdiHalServiceCTest::TearDown()
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->Stop(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetSupportFeatureComboTest_001
 * @tc.desc: Wifi hdi get support feature and combo function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, GetSupportFeatureComboTest_001, TestSize.Level1)
{

    uint8_t supType[PROTOCOL_80211_IFTYPE_NUM + 1] = {0};
    uint64_t combo[DEFAULT_COMBO_SIZE] = {0};

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->GetSupportFeature(wlanObj, supType);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetSupportCombo(wlanObj, combo);
    ASSERT_EQ(rc, HDF_ERR_NOT_SUPPORT);
}

/**
 * @tc.name: CreateFeatureTest_002
 * @tc.desc: Wifi hdi create feature function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, CreateFeatureTest_002, TestSize.Level1)
{
    struct WlanFeatureInfo *ifeature = nullptr;
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    printf("ifname = %s\n", ifeature->ifName);
    printf("type = %d\n", ifeature->wlanType);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetFeatureByIfNameTest_003
 * @tc.desc: Wifi hdi get feature by ifname function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, GetFeatureByIfNameTest_003, TestSize.Level1)
{
    const char *ifName = "wlan0";
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetFeatureByIfName(wlanObj, ifName, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetAsscociatedStasTest_004
 * @tc.desc: Wifi hdi get assoc stas function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, GetAsscociatedStasTest_004, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;
    struct StaInfo staInfo[WLAN_MAX_NUM_STA_WITH_AP] = {{0}};
    uint32_t num = 0;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetAsscociatedStas(wlanObj, ifeature, staInfo, WLAN_MAX_NUM_STA_WITH_AP, &num);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetCountryCodeTest_005
 * @tc.desc: Wifi hdi set country code function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, SetCountryCodeTest_005, TestSize.Level1)
{
    const char *code = "CN";
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->SetCountryCode(wlanObj, ifeature, code, sizeof(code));
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetNetworkIfaceNameTest_006
 * @tc.desc: Wifi hdi get network interface name function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, GetNetworkIfaceNameTest_006, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetNetworkIfaceName(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetFeatureTypeTest_007
 * @tc.desc: Wifi hdi get feature type function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, GetFeatureTypeTest_007, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetFeatureType(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetMacAddressTest_008
 * @tc.desc: Wifi hdi set mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, SetMacAddressTest_008, TestSize.Level1)
{
    uint8_t mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->SetMacAddress(wlanObj, (struct WlanFeatureInfo *)ifeature, mac, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetDeviceMacAddressTest_009
 * @tc.desc: Wifi hdi get device mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, GetDeviceMacAddressTest_009, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;
    uint8_t mac[ETH_ADDR_LEN] = {0};

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetDeviceMacAddress(wlanObj, (struct WlanFeatureInfo *)ifeature, mac, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetFreqsWithBandTest_010
 * @tc.desc: Wifi hdi get freqs function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, GetFreqsWithBandTest_010, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;
    int32_t freq[WLAN_FREQ_MAX_NUM] = {0};
    int32_t wlanBand = 0;
    uint32_t count = 0;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetFreqsWithBand(wlanObj, (struct WlanFeatureInfo *)ifeature, wlanBand, freq,
                                   WLAN_FREQ_MAX_NUM, &count);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetTxPowerTest_011
 * @tc.desc: Wifi hdi set tx power function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, SetTxPowerTest_011, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;
    int32_t power = WLAN_TX_POWER;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->SetTxPower(wlanObj, (struct WlanFeatureInfo *)ifeature, power);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetChipIdTest_012
 * @tc.desc: Wifi hdi get chip id function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, GetChipIdTest_012, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    struct WlanFeatureInfo *ifeature = nullptr;
    uint8_t chipId = 0;
    unsigned int num = 0;
    char *ifNames = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetChipId(wlanObj, (struct WlanFeatureInfo *)ifeature, &chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetIfNamesByChipId(wlanObj, chipId, &ifNames, &num);
    printf("ifnames = %s\n", ifNames);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetScanningMacAddressTest_013
 * @tc.desc: Wifi hdi set scanning mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, SetScanningMacAddressTest_013, TestSize.Level1)
{
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    struct WlanFeatureInfo *ifeature = nullptr;
    uint8_t scanMac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->SetScanningMacAddress(wlanObj, (struct WlanFeatureInfo *)ifeature, scanMac, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_ERR_NOT_SUPPORT);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

static int32_t g_resetStatus = -1;

static int32_t HalResetCallbackEvent(uint32_t event, void *data, const char *ifName)
{
    (void)event;
    (void)ifName;
    struct HdfSBuf *dataBuf = (struct HdfSBuf*)data;

    HdfSbufReadInt32(dataBuf, &g_resetStatus);
    printf("HalResetCallbackEvent: receive resetStatus=%d \n", g_resetStatus);
    return HDF_SUCCESS;
}

/**
 * @tc.name: RegisterEventCallbackTest_014
 * @tc.desc: Wifi hdi reister event call back function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, RegisterEventCallbackTest_014, TestSize.Level1)
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->RegisterEventCallback(wlanObj, HalResetCallbackEvent);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: UnregisterEventCallbackTest_015
 * @tc.desc: Wifi hdi unreister event call back function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, UnregisterEventCallbackTest_015, TestSize.Level1)
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->UnregisterEventCallback(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: ResetDriverTest_016
 * @tc.desc: Wifi hdi reset driver function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(WifiHdiHalServiceCTest, ResetDriverTest_016, TestSize.Level1)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    struct WlanFeatureInfo *ifeature = nullptr;
    uint8_t chipId= 0;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->RegisterEventCallback(wlanObj, HalResetCallbackEvent);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->CreateFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetChipId(wlanObj, (struct WlanFeatureInfo *)ifeature, &chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->ResetDriver(wlanObj, chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    EXPECT_EQ(HDF_SUCCESS, g_resetStatus);
    rc = wlanObj->UnregisterEventCallback(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}
};