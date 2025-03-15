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
#include "v2_0/iwpa_interface.h"
#include "wpa_callback_impl.h"
#include "securec.h"

#define IFNAME "wlan0"
#define CONFNAME "/data/service/el1/public/wifi/wpa_supplicant/wpa_supplicant.conf"

#define HDF_LOG_TAG service_manager_test
using namespace testing::ext;

namespace HdiTest {
const char *g_wlanServiceNameWpa = "wpa_interface_service";

class HdfWpaHostCTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static struct IWpaInterface *g_wpaObj = nullptr;
struct IWpaCallback *g_wpaCallbackObj = nullptr;
void HdfWpaHostCTest::SetUpTestCase()
{
    g_wpaObj = IWpaInterfaceGetInstance(g_wlanServiceNameWpa, false);
    g_wpaCallbackObj = WpaCallbackServiceGet();
    ASSERT_TRUE(g_wpaObj != nullptr);
    ASSERT_TRUE(g_wpaCallbackObj != nullptr);
}

void HdfWpaHostCTest::TearDownTestCase()
{
    IWpaInterfaceReleaseInstance(g_wlanServiceNameWpa, g_wpaObj, false);
    WpaCallbackServiceRelease(g_wpaCallbackObj);
}

void HdfWpaHostCTest::SetUp()
{
    int32_t rc = g_wpaObj->Start(g_wpaObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void HdfWpaHostCTest::TearDown()
{
    int32_t rc = g_wpaObj->Stop(g_wpaObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(HdfWpaHostCTest, AddWpaIfaceTest_001, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, ScanTest_002, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->Scan(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, ScanResultTest_003, TestSize.Level1)
{
    unsigned char *resultBuf = (unsigned char *)calloc(4096 * 10, sizeof(unsigned char));
    uint32_t resultBufLen = 4096 * 10;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->ScanResult(g_wpaObj, IFNAME, resultBuf, &resultBufLen);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    free(resultBuf);
}

HWTEST_F(HdfWpaHostCTest, AddNetworkTest_004, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, RemoveNetworkTest_005, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveNetwork(g_wpaObj, IFNAME, networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, DisableNetworkTest_006, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->DisableNetwork(g_wpaObj, IFNAME, networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, SetNetworkTest_007, TestSize.Level1)
{
    int networkId = 0;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "ssid", "WIFI_5G");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "key_mgmt", "WPA-PSK");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "psk", "123456789");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, ListNetworksTest_008, TestSize.Level1)
{
    int networkId = 0;
    struct HdiWifiWpaNetworkInfo networkInfo;
    (void)memset_s(
        &networkInfo, sizeof(struct HdiWifiWpaNetworkInfo), 0, sizeof(struct HdiWifiWpaNetworkInfo));
    const char *ifNameInvalid = "wlanTest";
    uint32_t networkInfoLen = 0;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->ListNetworks(g_wpaObj, ifNameInvalid, (struct HdiWifiWpaNetworkInfo *)&networkInfo,
	    &networkInfoLen);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->ListNetworks(g_wpaObj, IFNAME, (struct HdiWifiWpaNetworkInfo *)&networkInfo, &networkInfoLen);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, SelectNetworkTest_009, TestSize.Level1)
{
    int networkId = 0;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "ssid", "WIFI_5G");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "key_mgmt", "WPA-PSK");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "psk", "123456789");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SelectNetwork(g_wpaObj, IFNAME, networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, EnableNetworkTest_010, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->DisableNetwork(g_wpaObj, IFNAME, networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->EnableNetwork(g_wpaObj, IFNAME, networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, ReconnectTest_011, TestSize.Level1)
{
    int networkId = 0;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "ssid", "WIFI_5G");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "key_mgmt", "WPA-PSK");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "psk", "123456789");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SelectNetwork(g_wpaObj, IFNAME, networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->Reconnect(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, DisconnectTest_012, TestSize.Level1)
{
    int networkId = 0;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "ssid", "WIFI_5G");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "key_mgmt", "WPA-PSK");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "psk", "123456789");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SelectNetwork(g_wpaObj, IFNAME, networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->Disconnect(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, SaveConfigTest_013, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->SaveConfig(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, SetPowerSaveTest_014, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->SetPowerSave(g_wpaObj, IFNAME, 0);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetPowerSave(g_wpaObj, IFNAME, 1);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, AutoConnectTest_015, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AutoConnect(g_wpaObj, IFNAME, 0);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->AutoConnect(g_wpaObj, IFNAME, 1);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, WifiStatusTest_016, TestSize.Level1)
{
    struct HdiWpaCmdStatus wifiStatus;
    (void)memset_s(
        &wifiStatus, sizeof(struct HdiWpaCmdStatus), 0, sizeof(struct HdiWpaCmdStatus));

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->WifiStatus(g_wpaObj, IFNAME, &wifiStatus);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, WpsPbcModeTest_017, TestSize.Level1)
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

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->WpsPbcMode(g_wpaObj, IFNAME, &wpsParam);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->WpsPbcMode(g_wpaObj, IFNAME, NULL);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    OsalMemFree(wpsParam.bssid);
}

HWTEST_F(HdfWpaHostCTest, WpsPinModeTest_018, TestSize.Level1)
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
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->WpsPinMode(g_wpaObj, IFNAME, &wpsParam, &pinCode);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->WpsPinMode(g_wpaObj, IFNAME, NULL, &pinCode);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    OsalMemFree(wpsParam.bssid);
}

HWTEST_F(HdfWpaHostCTest, WpsCancelTest_019, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->WpsCancel(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, GetCountryCodeTest_020, TestSize.Level1)
{
    char countryCode[3] = {0};
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->GetCountryCode(g_wpaObj, IFNAME, countryCode, 3);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, GetNetworkTest_021, TestSize.Level1)
{
    int networkId = 0;
    char value[32] = {0};
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->GetNetwork(g_wpaObj, IFNAME, networkId, "ssid", value, 32);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, BlocklistClearTest_022, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->BlocklistClear(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, SetSuspendModeTest_023, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->SetSuspendMode(g_wpaObj, IFNAME, 0);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetSuspendMode(g_wpaObj, IFNAME, 1);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, RegisterEventCallbackTest_024, TestSize.Level1)
{
    int32_t rc = g_wpaObj->RegisterEventCallback(g_wpaObj, g_wpaCallbackObj, IFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(HdfWpaHostCTest, UnregisterEventCallbackTest_025, TestSize.Level1)
{
    int32_t rc = g_wpaObj->UnregisterEventCallback(g_wpaObj, g_wpaCallbackObj, IFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(HdfWpaHostCTest, GetConnectionCapabilitiesTest_026, TestSize.Level1)
{
    struct ConnectionCapabilities connectionCap;
    (void)memset_s(
        &connectionCap, sizeof(struct ConnectionCapabilities), 0, sizeof(struct ConnectionCapabilities));
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->GetConnectionCapabilities(g_wpaObj, IFNAME, &connectionCap);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, GetScanSsidTest_027, TestSize.Level1)
{
    int enable = 0;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->GetScanSsid(g_wpaObj, IFNAME, &enable);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, GetPskPassphraseTest_028, TestSize.Level1)
{
    char psk[32] = {0};

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->GetPskPassphrase(g_wpaObj, IFNAME, psk, 32);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, GetPskTest_029, TestSize.Level1)
{
    uint8_t psk[32] = {0};
    uint32_t pskLen = 32;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->GetPsk(g_wpaObj, IFNAME, psk, &pskLen);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, GetWepKeyTest_030, TestSize.Level1)
{
    uint8_t wepKey[16] = {0};
    uint32_t wepKeyLen = 16;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->GetWepKey(g_wpaObj, IFNAME, 0, wepKey, &wepKeyLen);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->GetWepKey(g_wpaObj, IFNAME, 1, wepKey, &wepKeyLen);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, GetWepTxKeyIdxTest_031, TestSize.Level1)
{
    int32_t keyIdx = 0;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->GetWepTxKeyIdx(g_wpaObj, IFNAME, &keyIdx);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, GetRequirePmfTest_032, TestSize.Level1)
{
    int32_t enable = 0;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->GetRequirePmf(g_wpaObj, IFNAME, &enable);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, SetCountryCodeTest_033, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->SetCountryCode(g_wpaObj, IFNAME, "00");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetCountryCode(g_wpaObj, IFNAME, "01");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, ReassociateTest_034, TestSize.Level1)
{
    int networkId = 0;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->AddNetwork(g_wpaObj, IFNAME, &networkId);
        printf("networkId = %d\n", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "ssid", "WIFI_5G");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "key_mgmt", "WPA-PSK");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SetNetwork(g_wpaObj, IFNAME, networkId, "psk", "123456789");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->SelectNetwork(g_wpaObj, IFNAME, networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->Reassociate(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfWpaHostCTest, StaShellCmdTest_035, TestSize.Level1)
{
    const char *cmd = "SET external_sim 1";
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->StaShellCmd(g_wpaObj, IFNAME, cmd);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}
};
