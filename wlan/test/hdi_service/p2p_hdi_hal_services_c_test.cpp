/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "p2p_callback_impl.h"
#include "securec.h"

#define IFNAME "wlan0"
#define CONFNAME "/data/service/el1/public/wifi/wpa_supplicant/wpa_supplicant.conf"

#define HDF_LOG_TAG service_manager_test
using namespace testing::ext;

namespace HdiP2pTest {
const char *g_wlanServiceNameP2p = "wpa_interface_service";

class HdfP2pHostCTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static struct IWpaInterface *g_wpaObj = nullptr;
struct IWpaCallback *g_wpaCallbackObj = nullptr;
void HdfP2pHostCTest::SetUpTestCase()
{
    g_wpaObj = IWpaInterfaceGetInstance(g_wlanServiceNameP2p, false);
    g_wpaCallbackObj = P2pCallbackServiceGet();
    ASSERT_TRUE(g_wpaObj != nullptr);
    ASSERT_TRUE(g_wpaCallbackObj != nullptr);
}

void HdfP2pHostCTest::TearDownTestCase()
{
    IWpaInterfaceReleaseInstance(g_wlanServiceNameP2p, g_wpaObj, false);
    P2pCallbackServiceRelease(g_wpaCallbackObj);
}

void HdfP2pHostCTest::SetUp()
{
    int32_t rc = g_wpaObj->Start(g_wpaObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

void HdfP2pHostCTest::TearDown()
{
    int32_t rc = g_wpaObj->Stop(g_wpaObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

HWTEST_F(HdfP2pHostCTest, P2pSetSsidPostfixNameTest_001, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetSsidPostfixName(g_wpaObj, "p2p-dev-wlan0", "test");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetWpsDeviceTypeTest_002, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetWpsDeviceType(g_wpaObj, "p2p-dev-wlan0", "1-0050F204-1");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetWpsConfigMethodsTest_003, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetWpsConfigMethods(g_wpaObj, "p2p-dev-wlan0", "test");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetGroupMaxIdleTest_004, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetGroupMaxIdle(g_wpaObj, "p2p-dev-wlan0", 1);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetWfdEnableTest_005, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetWfdEnable(g_wpaObj, "p2p-dev-wlan0", 0);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->P2pSetWfdEnable(g_wpaObj, "p2p-dev-wlan0", 1);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetPersistentReconnectTest_006, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetPersistentReconnect(g_wpaObj, "p2p-dev-wlan0", 1);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetWpsSecondaryDeviceTypeTest_007, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetWpsSecondaryDeviceType(g_wpaObj, "p2p-dev-wlan0", "1-0050F204-1");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetupWpsPbcTest_008, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetupWpsPbc(g_wpaObj, "p2p-dev-wlan0", "00:00:00:00:00:00");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetupWpsPinTest_009, TestSize.Level1)
{
    const char *pin = "00000000";
    char *resultBuf = (char *)calloc(REPLY_SIZE, sizeof(char));
    uint32_t resultBufLen = REPLY_SIZE;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetupWpsPin(g_wpaObj, "p2p-dev-wlan0", "00:00:00:00:00:00", pin, resultBuf, resultBufLen);
        printf("resultBuf: %s", resultBuf);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    free(resultBuf);
}

HWTEST_F(HdfP2pHostCTest, P2pSetPowerSaveTest_010, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetPowerSave(g_wpaObj, "p2p-dev-wlan0", 0);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetDeviceNameTest_011, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetDeviceName(g_wpaObj, "p2p-dev-wlan0", "test");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetWfdDeviceConfigTest_012, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetWfdDeviceConfig(g_wpaObj, "p2p-dev-wlan0", "all 0123456");
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetRandomMacTest_013, TestSize.Level1)
{
    int networkId = 1;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetRandomMac(g_wpaObj, "p2p-dev-wlan0", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pStartFindTest_014, TestSize.Level1)
{
    const int time = 120;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pStartFind(g_wpaObj, "p2p-dev-wlan0", time);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetExtListenTest_015, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetExtListen(g_wpaObj, "p2p-dev-wlan0", 0, 1, 1);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetListenChannelTest_016, TestSize.Level1)
{
    const int channel = 24;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetListenChannel(g_wpaObj, "p2p-dev-wlan0", channel, 1);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pProvisionDiscoveryTest_017, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pProvisionDiscovery(g_wpaObj, "p2p-dev-wlan0", "00:00:00:00:00:00", 0);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pAddGroupTest_018, TestSize.Level1)
{
    int networkId = 1;
    const int freq = 5220;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pAddGroup(g_wpaObj, "p2p-dev-wlan0", 0, networkId, freq);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pAddServiceTest_019, TestSize.Level1)
{
    struct HdiP2pServiceInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pServiceInfo), 0, sizeof(struct HdiP2pServiceInfo));
    info.mode = 0;
    info.version = 0;
    const int nameLen = 32;
    info.nameLen = nameLen;
    info.name = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * nameLen);
    strcpy_s((char *)info.name, sizeof(info.name), "p2p0");
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pAddService(g_wpaObj, "p2p-dev-wlan0", &info);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    OsalMemFree(info.name);
}

HWTEST_F(HdfP2pHostCTest, P2pRemoveServiceTest_020, TestSize.Level1)
{
    struct HdiP2pServiceInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pServiceInfo), 0, sizeof(struct HdiP2pServiceInfo));

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pRemoveService(g_wpaObj, "p2p-dev-wlan0", &info);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pStopFindTest_021, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pStopFind(g_wpaObj, "p2p-dev-wlan0");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pFlushTest_022, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pFlush(g_wpaObj, "p2p-dev-wlan0");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pFlushServiceTest_023, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pFlushService(g_wpaObj, "p2p-dev-wlan0");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pRemoveNetworkTest_024, TestSize.Level1)
{
    int networkId = -1;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pRemoveNetwork(g_wpaObj, "p2p-dev-wlan0", networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetGroupConfigTest_025, TestSize.Level1)
{
    int networkId = 1;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetGroupConfig(g_wpaObj, "p2p-dev-wlan0", networkId, "test_name", "test_value");
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pInviteTest_026, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pInvite(g_wpaObj, "p2p-dev-wlan0", "00:00:00:00:00:00", "11:11:11:11:11:11");
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pReinvokeTest_027, TestSize.Level1)
{
    int networkId = 1;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pReinvoke(g_wpaObj, "p2p-dev-wlan0", networkId, "00:00:00:00:00:00");
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pGetDeviceAddressTest_028, TestSize.Level1)
{
    char *deviceAddress = (char *)calloc(WPA_CMD_BUF_LEN, sizeof(char));
    uint32_t deviceAddressLen = WPA_CMD_BUF_LEN;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pGetDeviceAddress(g_wpaObj, "p2p-dev-wlan0", deviceAddress, deviceAddressLen);
        printf("deviceAddress: %s", deviceAddress);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    free(deviceAddress);
}

HWTEST_F(HdfP2pHostCTest, P2pReqServiceDiscoveryTest_029, TestSize.Level1)
{
    char *replyDisc = (char *)calloc(REPLY_SIZE, sizeof(char));
    uint32_t replyDiscLen = REPLY_SIZE;
    struct HdiP2pReqService reqService;
    (void)memset_s(
        &reqService, sizeof(struct HdiP2pReqService), 0, sizeof(struct HdiP2pReqService));
    reqService.bssidLen = ETH_ADDR_LEN;
    reqService.bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (reqService.bssidLen));
    reqService.bssid[0] = 0x12;
    reqService.bssid[1] = 0x34;
    reqService.bssid[2] = 0x56;
    reqService.bssid[3] = 0x78;
    reqService.bssid[4] = 0xab;
    reqService.bssid[5] = 0xcd;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pReqServiceDiscovery(g_wpaObj, "p2p-dev-wlan0", &reqService, replyDisc, replyDiscLen);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    free(replyDisc);
    OsalMemFree(reqService.bssid);
}

HWTEST_F(HdfP2pHostCTest, P2pCancelServiceDiscoveryTest_030, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pCancelServiceDiscovery(g_wpaObj, "p2p-dev-wlan0", "test");
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pRespServerDiscoveryTest_031, TestSize.Level1)
{
    struct HdiP2pServDiscReqInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pServDiscReqInfo), 0, sizeof(struct HdiP2pServDiscReqInfo));
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pRespServerDiscovery(g_wpaObj, "p2p-dev-wlan0", &info);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pConnectTest_032, TestSize.Level1)
{
    struct HdiP2pConnectInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pConnectInfo), 0, sizeof(struct HdiP2pConnectInfo));
    char *replyPin = (char *)calloc(REPLY_SIZE, sizeof(char));
    uint32_t replyPinLen = REPLY_SIZE;

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pConnect(g_wpaObj, "p2p-dev-wlan0", &info, replyPin, replyPinLen);
        ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    free(replyPin);
}

HWTEST_F(HdfP2pHostCTest, P2pHid2dConnectTest_033, TestSize.Level1)
{
    struct HdiHid2dConnectInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiHid2dConnectInfo), 0, sizeof(struct HdiHid2dConnectInfo));

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pHid2dConnect(g_wpaObj, "p2p-dev-wlan0", &info);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSetServDiscExternalTest_034, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSetServDiscExternal(g_wpaObj, "p2p-dev-wlan0", 0);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pRemoveGroupTest_035, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pRemoveGroup(g_wpaObj, "p2p-dev-wlan0", "test");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pCancelConnectTest_036, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pCancelConnect(g_wpaObj, "p2p-dev-wlan0");
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pGetGroupConfigTest_037, TestSize.Level1)
{
    int networkId = 1;
    char *value = (char *)calloc(REPLY_SIZE, sizeof(char));
    uint32_t valueLen = REPLY_SIZE;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pGetGroupConfig(g_wpaObj, "p2p-dev-wlan0", networkId, "ssid", value, valueLen);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    free(value);
}

HWTEST_F(HdfP2pHostCTest, P2pAddNetworkTest_038, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pAddNetwork(g_wpaObj, "p2p-dev-wlan0", &networkId);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pGetPeerTest_039, TestSize.Level1)
{
    struct HdiP2pDeviceInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pDeviceInfo), 0, sizeof(struct HdiP2pDeviceInfo));

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pGetPeer(g_wpaObj, "p2p-dev-wlan0", "00:00:00:00:00:00", &info);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pGetGroupCapabilityTest_040, TestSize.Level1)
{
    int cap = 0;
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pGetGroupCapability(g_wpaObj, "p2p-dev-wlan0", "00:00:00:00:00:00", &cap);
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pListNetworksTest_041, TestSize.Level1)
{
    struct HdiP2pNetworkList infoList;
    (void)memset_s(
        &infoList, sizeof(struct HdiP2pNetworkList), 0, sizeof(struct HdiP2pNetworkList));

    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pListNetworks(g_wpaObj, "p2p-dev-wlan0", &infoList);
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, P2pSaveConfigTest_042, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->P2pSaveConfig(g_wpaObj, "p2p-dev-wlan0");
        ASSERT_EQ(rc, HDF_SUCCESS);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

HWTEST_F(HdfP2pHostCTest, VendorProcessCmdTest_043, TestSize.Level1)
{
    int32_t rc = g_wpaObj->AddWpaIface(g_wpaObj, IFNAME, CONFNAME);
    ASSERT_EQ(rc, HDF_SUCCESS);
    if (rc == HDF_SUCCESS) {
        rc = g_wpaObj->VendorProcessCmd(g_wpaObj, IFNAME, "test");
        ASSERT_EQ(rc, HDF_FAILURE);
        rc = g_wpaObj->RemoveWpaIface(g_wpaObj, IFNAME);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
}

};
