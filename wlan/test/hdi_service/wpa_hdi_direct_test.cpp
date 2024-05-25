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
#include "v1_1/iwpa_interface.h"
#include "wpa_callback_impl.h"
#include "securec.h"

#define IFNAME "wlan0"
#define CONFNAME "/data/service/el1/public/wifi/wpa_supplicant/wpa_supplicant.conf"

#define HDF_LOG_TAG service_manager_test
using namespace testing::ext;

namespace HdiWpaDirectTest {
const char *g_wlanServiceNameWpa = "wpa_interface_service";

class HdfWpaHostDirectTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static struct IWpaInterface *g_wpaObj = nullptr;
struct IWpaCallback *g_wpaCallbackObj = nullptr;
void HdfWpaHostDirectTest::SetUpTestCase()
{
    g_wpaObj = IWpaInterfaceGetInstance(g_wlanServiceNameWpa, true);
    g_wpaCallbackObj = WpaCallbackServiceGet();
    ASSERT_TRUE(g_wpaObj != nullptr);
    ASSERT_TRUE(g_wpaCallbackObj != nullptr);
}

void HdfWpaHostDirectTest::TearDownTestCase()
{
    IWpaInterfaceReleaseInstance(g_wlanServiceNameWpa, g_wpaObj, true);
    WpaCallbackServiceRelease(g_wpaCallbackObj);
}

void HdfWpaHostDirectTest::SetUp()
{
}

void HdfWpaHostDirectTest::TearDown()
{
}

HWTEST_F(HdfWpaHostDirectTest, AddWpaIfaceTest_001, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->AddWpaIface(g_wpaObj, nullptr, CONFNAME);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, ScanTest_002, TestSize.Level1)
{
    int32_t rc = g_wpaObj->Scan(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->Scan(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, ScanResultTest_003, TestSize.Level1)
{
    unsigned char *resultBuf = (unsigned char *)calloc(4096 * 10, sizeof(unsigned char));
    uint32_t resultBufLen = 4096 * 10;
    int32_t rc = g_wpaObj->ScanResult(g_wpaObj, IFNAME, resultBuf, &resultBufLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->ScanResult(g_wpaObj, nullptr, resultBuf, &resultBufLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->ScanResult(g_wpaObj, IFNAME, nullptr, &resultBufLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    free(resultBuf);
}

HWTEST_F(HdfWpaHostDirectTest, AddNetworkTest_004, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->AddNetwork(g_wpaObj, nullptr, &networkId);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, RemoveNetworkTest_005, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->RemoveNetwork(g_wpaObj, IFNAME, networkId);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->RemoveNetwork(g_wpaObj, nullptr, networkId);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, DisableNetworkTest_006, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->DisableNetwork(g_wpaObj, IFNAME, networkId);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->DisableNetwork(g_wpaObj, nullptr, networkId);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, SetNetworkTest_007, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "ssid", "WIFI_5G");
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, nullptr, "WPA-PSK");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "psk", nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, ListNetworksTest_008, TestSize.Level1)
{
    struct HdiWifiWpaNetworkInfo networkInfo;
    (void)memset_s(
        &networkInfo, sizeof(struct HdiWifiWpaNetworkInfo), 0, sizeof(struct HdiWifiWpaNetworkInfo));
    uint32_t networkInfoLen = 0;
    int32_t rc = g_wpaObj->ListNetworks(g_wpaObj, nullptr, (struct HdiWifiWpaNetworkInfo *)&networkInfo,
        &networkInfoLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->ListNetworks(g_wpaObj, IFNAME, (struct HdiWifiWpaNetworkInfo *)&networkInfo, &networkInfoLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->ListNetworks(g_wpaObj, IFNAME, nullptr, &networkInfoLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, SelectNetworkTest_009, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "ssid", "WIFI_5G");
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->SetNetwork(g_wpaObj, nullptr, networkId, "key_mgmt", "WPA-PSK");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, nullptr, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, EnableNetworkTest_010, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->EnableNetwork(g_wpaObj, IFNAME, networkId);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->EnableNetwork(g_wpaObj, nullptr, networkId);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, ReconnectTest_011, TestSize.Level1)
{
    int32_t rc = g_wpaObj->Reconnect(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->Reconnect(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, DisconnectTest_012, TestSize.Level1)
{
    int32_t rc = g_wpaObj->Disconnect(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->Disconnect(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, SaveConfigTest_013, TestSize.Level1)
{
    int32_t rc = g_wpaObj->SaveConfig(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->SaveConfig(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, SetPowerSaveTest_014, TestSize.Level1)
{
    int32_t rc = g_wpaObj->SetPowerSave(g_wpaObj, IFNAME, 0);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->SetPowerSave(g_wpaObj, nullptr, 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, AutoConnectTest_015, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AutoConnect(g_wpaObj, IFNAME, 0);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->AutoConnect(g_wpaObj, nullptr, 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, WifiStatusTest_016, TestSize.Level1)
{
    struct HdiWpaCmdStatus wifiStatus;
    (void)memset_s(
        &wifiStatus, sizeof(struct HdiWpaCmdStatus), 0, sizeof(struct HdiWpaCmdStatus));
    int32_t rc = g_wpaObj->WifiStatus(g_wpaObj, IFNAME, &wifiStatus);
    ASSERT_EQ(rc, HDF_SUCCESS);
    rc = g_wpaObj->WifiStatus(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->WifiStatus(g_wpaObj, nullptr, &wifiStatus);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, WpsPbcModeTest_017, TestSize.Level1)
{
    struct HdiWifiWpsParam wpsParam;
    (void)memset_s(&wpsParam, sizeof(struct HdiWifiWpsParam), 0, sizeof(struct HdiWifiWpsParam));
    wpsParam.anyFlag = 1;
    wpsParam.multiAp = 1;
    wpsParam.bssidLen = 6;
    wpsParam.bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (wpsParam.bssidLen));
    wpsParam.bssid[0] = 0x12;
    wpsParam.bssid[1] = 0x34;
    wpsParam.bssid[2] = 0x56;
    wpsParam.bssid[3] = 0x78;
    wpsParam.bssid[4] = 0xab;
    wpsParam.bssid[5] = 0xcd;

    int32_t rc = g_wpaObj->WpsPbcMode(g_wpaObj, IFNAME, &wpsParam);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->WpsPbcMode(g_wpaObj, IFNAME, NULL);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    OsalMemFree(wpsParam.bssid);
}

HWTEST_F(HdfWpaHostDirectTest, WpsPinModeTest_018, TestSize.Level1)
{
    struct HdiWifiWpsParam wpsParam;
    (void)memset_s(&wpsParam, sizeof(struct HdiWifiWpsParam), 0, sizeof(struct HdiWifiWpsParam));
    wpsParam.anyFlag = 1;
    wpsParam.multiAp = 1;
    wpsParam.bssidLen = 6;
    wpsParam.bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (wpsParam.bssidLen));
    wpsParam.bssid[0] = 0x12;
    wpsParam.bssid[1] = 0x34;
    wpsParam.bssid[2] = 0x56;
    wpsParam.bssid[3] = 0x78;
    wpsParam.bssid[4] = 0xab;
    wpsParam.bssid[5] = 0xcd;

    int pinCode = 0;
    int32_t rc = g_wpaObj->WpsPinMode(g_wpaObj, IFNAME, &wpsParam, &pinCode);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->WpsPinMode(g_wpaObj, IFNAME, NULL, &pinCode);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    OsalMemFree(wpsParam.bssid);
}

HWTEST_F(HdfWpaHostDirectTest, WpsCancelTest_019, TestSize.Level1)
{
    int32_t rc = g_wpaObj->WpsCancel(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->WpsCancel(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetCountryCodeTest_020, TestSize.Level1)
{
    char countryCode[3] = {0};
    int32_t rc = g_wpaObj->GetCountryCode(g_wpaObj, IFNAME, countryCode, 3);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetCountryCode(g_wpaObj, nullptr, countryCode, 3);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->GetCountryCode(g_wpaObj, IFNAME, nullptr, 3);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetNetworkTest_021, TestSize.Level1)
{
    int networkId = 0;
    char value[32] = {0};
    int32_t rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetNetwork(g_wpaObj, IFNAME, networkId, "ssid", value, 32);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->AddNetwork(g_wpaObj, nullptr, &networkId);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->GetNetwork(g_wpaObj, nullptr, networkId, "ssid", value, 32);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, BlocklistClearTest_022, TestSize.Level1)
{
    int32_t rc = g_wpaObj->BlocklistClear(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->BlocklistClear(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, SetSuspendModeTest_023, TestSize.Level1)
{
    int32_t rc = g_wpaObj->SetSuspendMode(g_wpaObj, IFNAME, 0);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->SetSuspendMode(g_wpaObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->SetSuspendMode(g_wpaObj, nullptr, 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->SetSuspendMode(g_wpaObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, RegisterEventCallbackTest_024, TestSize.Level1)
{
    int32_t rc = g_wpaObj->RegisterEventCallback(g_wpaObj, g_wpaCallbackObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, UnregisterEventCallbackTest_025, TestSize.Level1)
{
    int32_t rc = g_wpaObj->UnregisterEventCallback(g_wpaObj, g_wpaCallbackObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetConnectionCapabilitiesTest_026, TestSize.Level1)
{
    struct ConnectionCapabilities connectionCap;
    (void)memset_s(
        &connectionCap, sizeof(struct ConnectionCapabilities), 0, sizeof(struct ConnectionCapabilities));
    int32_t rc = g_wpaObj->GetConnectionCapabilities(g_wpaObj, IFNAME, &connectionCap);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetConnectionCapabilities(g_wpaObj, nullptr, &connectionCap);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->GetConnectionCapabilities(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetScanSsidTest_027, TestSize.Level1)
{
    int enable = 0;

    int32_t rc = g_wpaObj->GetScanSsid(g_wpaObj, IFNAME, &enable);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetScanSsid(g_wpaObj, nullptr, &enable);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetPskPassphraseTest_028, TestSize.Level1)
{
    char psk[32] = {0};

    int rc = g_wpaObj->GetPskPassphrase(g_wpaObj, IFNAME, psk, 32);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetPskPassphrase(g_wpaObj, nullptr, psk, 32);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetPskTest_029, TestSize.Level1)
{
    uint8_t psk[32] = {0};
    uint32_t pskLen = 32;
    int32_t rc = g_wpaObj->GetPsk(g_wpaObj, IFNAME, psk, &pskLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetPsk(g_wpaObj, nullptr, psk, &pskLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetWepKeyTest_030, TestSize.Level1)
{
    uint8_t wepKey[16] = {0};
    uint32_t wepKeyLen = 16;
    int32_t rc = g_wpaObj->GetWepKey(g_wpaObj, IFNAME, 0, wepKey, &wepKeyLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetWepKey(g_wpaObj, IFNAME, 1, wepKey, &wepKeyLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetWepKey(g_wpaObj, nullptr, 0, wepKey, &wepKeyLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->GetWepKey(g_wpaObj, nullptr, 1, wepKey, &wepKeyLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetWepTxKeyIdxTest_031, TestSize.Level1)
{
    int32_t keyIdx = 0;

    int32_t rc = g_wpaObj->GetWepTxKeyIdx(g_wpaObj, IFNAME, &keyIdx);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetWepTxKeyIdx(g_wpaObj, nullptr, &keyIdx);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, GetRequirePmfTest_032, TestSize.Level1)
{
    int32_t enable = 0;

    int32_t rc = g_wpaObj->GetRequirePmf(g_wpaObj, IFNAME, &enable);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->GetRequirePmf(g_wpaObj, nullptr, &enable);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, SetCountryCodeTest_033, TestSize.Level1)
{
    int32_t rc = g_wpaObj->SetCountryCode(g_wpaObj, IFNAME, "00");
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->SetCountryCode(g_wpaObj, IFNAME, "01");
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->SetCountryCode(g_wpaObj, nullptr, "00");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->SetCountryCode(g_wpaObj, nullptr, "01");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, ReassociateTest_034, TestSize.Level1)
{
    int32_t rc = g_wpaObj->Reassociate(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->Reassociate(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

HWTEST_F(HdfWpaHostDirectTest, StaShellCmdTest_035, TestSize.Level1)
{
    const char *cmd = "SET external_sim 1";
    int32_t rc = g_wpaObj->StaShellCmd(g_wpaObj, IFNAME, cmd);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_wpaObj->StaShellCmd(g_wpaObj, nullptr, cmd);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}
};
