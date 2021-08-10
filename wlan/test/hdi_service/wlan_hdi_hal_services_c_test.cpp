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
const int32_t DEFAULT_COMBO_SIZE = 6;
const int32_t WLAN_MAX_NUM_STA_WITH_AP = 4;

const char *WLAN_SERVICE_NAME = "wlan_hal_c_service";

class HdfWifiServiceCTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfWifiServiceCTest::SetUpTestCase()
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->construct(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void HdfWifiServiceCTest::TearDownTestCase()
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->destruct(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void HdfWifiServiceCTest::SetUp()
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->start(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void HdfWifiServiceCTest::TearDown()
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->stop(wlanObj);
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
    uint64_t combo[DEFAULT_COMBO_SIZE] = {0};

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->getSupportFeature(wlanObj, supType);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getSupportCombo(wlanObj, combo);
    ASSERT_EQ(rc, HDF_ERR_NOT_SUPPORT);
}

/**
 * @tc.name: CreateFeatureTest_002
 * @tc.desc: Wifi hdi create feature function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, CreateFeatureTest_002, TestSize.Level1)
{
    struct WlanFeatureInfo *ifeature = nullptr;
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    printf("ifname = %s\n", ifeature->ifName);
    printf("type = %d\n", ifeature->wlanType);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    const char *ifName = "wlan0";
    const int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getFeatureByIfName(wlanObj, ifName, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;
    struct StaInfo staInfo[WLAN_MAX_NUM_STA_WITH_AP] = {{0}};
    uint32_t num = 0;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getAsscociatedStas(wlanObj, ifeature, staInfo, WLAN_MAX_NUM_STA_WITH_AP, &num);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->setCountryCode(wlanObj, ifeature, code, sizeof(code));
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getNetworkIfaceName(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getFeatureType(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->setMacAddress(wlanObj, (struct WlanFeatureInfo *)ifeature, mac, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;
    uint8_t mac[ETH_ADDR_LEN] = {0};

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getDeviceMacAddress(wlanObj, (struct WlanFeatureInfo *)ifeature, mac, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;
    int32_t freq[WLAN_FREQ_MAX_NUM] = {0};
    int32_t wlanBand = 0;
    uint32_t count = 0;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getFreqsWithBand(wlanObj, (struct WlanFeatureInfo *)ifeature, wlanBand, freq,
                                   WLAN_FREQ_MAX_NUM, &count);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;
    int32_t power = WLAN_TX_POWER;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->setTxPower(wlanObj, (struct WlanFeatureInfo *)ifeature, power);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;
    uint8_t chipId = 0;
    unsigned int num = 0;
    char *ifNames = nullptr;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getChipId(wlanObj, (struct WlanFeatureInfo *)ifeature, &chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getIfNamesByChipId(wlanObj, chipId, &ifNames, &num);
    printf("ifnames = %s\n", ifNames);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
    struct WlanFeatureInfo *ifeature = nullptr;
    uint8_t scanMac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->setScanningMacAddress(wlanObj, (struct WlanFeatureInfo *)ifeature, scanMac, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_ERR_NOT_SUPPORT);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
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
HWTEST_F(HdfWifiServiceCTest, RegisterEventCallbackTest_014, TestSize.Level1)
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->registerEventCallback(wlanObj, HalResetCallbackEvent);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: UnregisterEventCallbackTest_015
 * @tc.desc: Wifi hdi unreister event call back function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJB
 */
HWTEST_F(HdfWifiServiceCTest, UnregisterEventCallbackTest_015, TestSize.Level1)
{
    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->unregisterEventCallback(wlanObj);
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
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    struct WlanFeatureInfo *ifeature = nullptr;
    uint8_t chipId= 0;

    struct IWifiInterface *wlanObj = HdIWifiInterfaceGet(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->registerEventCallback(wlanObj, HalResetCallbackEvent);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->createFeature(wlanObj, wlan_type, (struct WlanFeatureInfo **)&ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->getChipId(wlanObj, (struct WlanFeatureInfo *)ifeature, &chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->resetDriver(wlanObj, chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    EXPECT_EQ(HDF_SUCCESS, g_resetStatus);
    rc = wlanObj->unregisterEventCallback(wlanObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->destroyFeature(wlanObj, (struct WlanFeatureInfo *)ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}
};