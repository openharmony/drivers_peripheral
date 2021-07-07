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
#include "Iwifi_hal.h"
#include "wlan_hal_proxy.h"
#include <gtest/gtest.h>
#include <servmgr_hdi.h>

#define HDF_LOG_TAG   service_manager_test
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::HDI::WLAN::V1_0;

namespace HdiTest {
const int32_t WLAN_FREQ_MAX_NUM = 14;
const int32_t WLAN_TX_POWER = 160;
const int32_t ETH_ADDR_LEN = 6;

constexpr const char *WLAN_SERVICE_NAME = "wlan_hal_service";
class WifiHdiHalServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void WifiHdiHalServiceTest::SetUpTestCase()
{
    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->WifiConstruct();
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void WifiHdiHalServiceTest::TearDownTestCase()
{
    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->WifiDestruct();
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void WifiHdiHalServiceTest::SetUp()
{
    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->Start();
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void WifiHdiHalServiceTest::TearDown()
{
    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->Stop();
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, GetSupportFeatureComboTest_001, TestSize.Level0)
{

    std::vector<uint8_t> supType;
    std::vector<uint64_t> combo;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->GetSupportFeature(supType);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetSupportCombo(combo);
    ASSERT_EQ(rc, HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiHdiHalServiceTest, CreateFeatureTest_002, TestSize.Level0)
{
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, GetFeatureByIfNameTest_003, TestSize.Level0)
{
    std::string ifName = "wlan0";
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetFeatureByIfName(ifName, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, GetAsscociatedStasTest_004, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;
    std::shared_ptr<StaInfo> staInfo = nullptr;
    std::vector<uint32_t> num;
    uint32_t count = 0;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetAsscociatedStas(ifeature, staInfo, count, num);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, SetCountryCodeTest_005, TestSize.Level0)
{
    std::string code = "CN";
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->SetCountryCode(ifeature, code, sizeof(code));
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, GetNetworkIfaceNameTest_006, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetNetworkIfaceName(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, GetFeatureTypeTest_007, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetFeatureType(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, SetMacAddressTest_008, TestSize.Level0)
{
    std::vector<uint8_t> mac = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->SetMacAddress(ifeature, mac);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, GetDeviceMacAddressTest_009, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;
    std::vector<uint8_t> mac = {0};

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetDeviceMacAddress(ifeature, mac, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, GetFreqsWithBandTest_010, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> ifeature = nullptr;
    std::vector<int32_t> freq = {0};
    int32_t wlanBand = 0;
    uint32_t count = 0;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetFreqsWithBand(ifeature, wlanBand, freq, WLAN_FREQ_MAX_NUM, count);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(ifeature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, SetTxPowerTest_011, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_AP;
    std::shared_ptr<WifiFeatureInfo> feature = nullptr;
    int32_t power = WLAN_TX_POWER;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, feature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->SetTxPower(feature, power);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(feature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, GetChipIdTest_012, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    std::shared_ptr<WifiFeatureInfo> feature = nullptr;
    uint8_t chipId = 0;
    unsigned int num = 0;
    std::string ifName;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, feature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetChipId(feature, chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetIfNamesByChipId(chipId, ifName, num);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(feature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, SetScanningMacAddressTest_013, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    std::shared_ptr<WifiFeatureInfo> feature = nullptr;
    std::vector<uint8_t> scanMac = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->CreateFeature(wlan_type, feature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->SetScanningMacAddress(feature, scanMac, ETH_ADDR_LEN);
    ASSERT_EQ(rc, HDF_ERR_NOT_SUPPORT);
    rc = wlanObj->DestroyFeature(feature);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

static int32_t g_status = -1;

namespace{
    int32_t HalResetCallback(int32_t event, struct HdfSBuf *reqData) {
        HdfSbufReadInt32(reqData, &g_status);
        printf("status is %d\n", g_status);
        return HDF_SUCCESS;
    }
}

HWTEST_F(WifiHdiHalServiceTest, RegisterEventCallbackTest_014, TestSize.Level0)
{
    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->RegisterEventCallback(HalResetCallback);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, UnregisterEventCallbackTest_015, TestSize.Level0)
{
    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->UnregisterEventCallback();
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(WifiHdiHalServiceTest, ResetDriverTest_016, TestSize.Level0)
{
    int32_t wlan_type = PROTOCOL_80211_IFTYPE_STATION;
    std::shared_ptr<WifiFeatureInfo> feature = nullptr;
    uint8_t chipId= 0;

    auto wlanObj = IWlan::Get(WLAN_SERVICE_NAME);
    ASSERT_TRUE(wlanObj != nullptr);
    int32_t rc = wlanObj->RegisterEventCallback(HalResetCallback);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->CreateFeature(wlan_type, feature);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->GetChipId(feature, chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->ResetDriver(chipId);
    ASSERT_EQ(rc, HDF_SUCCESS);
    EXPECT_EQ(HDF_SUCCESS, g_status);
    rc = wlanObj->UnregisterEventCallback();
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = wlanObj->DestroyFeature(feature);
    ASSERT_EQ(rc, HDF_SUCCESS);

}
};