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

#define IFNAME "p2p-dev-wlan0"
#define CONFNAME "/data/service/el1/public/wifi/wpa_supplicant/wpa_supplicant.conf"

#define HDF_LOG_TAG service_manager_test
using namespace testing::ext;

namespace HdiP2pDirectTest {
const char *g_wlanServiceNameP2p = "wpa_interface_service";

class HdfP2pHostDirectTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static struct IWpaInterface *g_wpaObj = nullptr;
struct IWpaCallback *g_wpaCallbackObj = nullptr;
void HdfP2pHostDirectTest::SetUpTestCase()
{
    g_wpaObj = IWpaInterfaceGetInstance(g_wlanServiceNameP2p, true);
    g_wpaCallbackObj = P2pCallbackServiceGet();
    ASSERT_TRUE(g_wpaObj != nullptr);
    ASSERT_TRUE(g_wpaCallbackObj != nullptr);
}

void HdfP2pHostDirectTest::TearDownTestCase()
{
    IWpaInterfaceReleaseInstance(g_wlanServiceNameP2p, g_wpaObj, true);
    P2pCallbackServiceRelease(g_wpaCallbackObj);
}

void HdfP2pHostDirectTest::SetUp()
{
}

void HdfP2pHostDirectTest::TearDown()
{
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetSsidPostfixNameTest_001, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetSsidPostfixName(g_wpaObj, nullptr, "test");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetSsidPostfixName(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetSsidPostfixName(g_wpaObj, IFNAME, "test");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetWpsDeviceTypeTest_002, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetWpsDeviceType(g_wpaObj, nullptr, "test");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWpsDeviceType(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWpsDeviceType(g_wpaObj, IFNAME, "test");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetWpsConfigMethodsTest_003, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetWpsConfigMethods(g_wpaObj, nullptr, "test");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWpsConfigMethods(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWpsConfigMethods(g_wpaObj, IFNAME, "test");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetGroupMaxIdleTest_004, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetGroupMaxIdle(g_wpaObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetGroupMaxIdle(g_wpaObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetWfdEnableTest_005, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetWfdEnable(g_wpaObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWfdEnable(g_wpaObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetPersistentReconnectTest_006, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetPersistentReconnect(g_wpaObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetPersistentReconnect(g_wpaObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetWpsSecondaryDeviceTypeTest_007, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetWpsSecondaryDeviceType(g_wpaObj, nullptr, "test");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWpsSecondaryDeviceType(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWpsSecondaryDeviceType(g_wpaObj, IFNAME, "test");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetupWpsPbcTest_008, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetupWpsPbc(g_wpaObj, nullptr, "00:00:00:00:00:00");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetupWpsPbc(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetupWpsPbc(g_wpaObj, IFNAME, "00:00:00:00:00:00");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetupWpsPinTest_009, TestSize.Level1)
{
    const char *pin = "00000000";
    char *resultBuf = (char *)calloc(REPLY_SIZE, sizeof(char));
    uint32_t resultBufLen = REPLY_SIZE;
    int32_t rc = g_wpaObj->P2pSetupWpsPin(g_wpaObj, nullptr, "00:00:00:00:00:00", pin, resultBuf, resultBufLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetupWpsPin(g_wpaObj, IFNAME, "00:00:00:00:00:00", pin, nullptr, resultBufLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetupWpsPin(g_wpaObj, IFNAME, "00:00:00:00:00:00", pin, resultBuf, resultBufLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    free(resultBuf);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetPowerSaveTest_010, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetPowerSave(g_wpaObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetPowerSave(g_wpaObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetDeviceNameTest_011, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetDeviceName(g_wpaObj, nullptr, "test");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetDeviceName(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetDeviceName(g_wpaObj, IFNAME, "test");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetWfdDeviceConfigTest_012, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetWfdDeviceConfig(g_wpaObj, nullptr, "test");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWfdDeviceConfig(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetWfdDeviceConfig(g_wpaObj, IFNAME, "test");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetRandomMacTest_013, TestSize.Level1)
{
    int networkId = 1;
    int32_t rc = g_wpaObj->P2pSetRandomMac(g_wpaObj, nullptr, networkId);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetRandomMac(g_wpaObj, IFNAME, networkId);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pStartFindTest_014, TestSize.Level1)
{
    const int time = 120;
    int32_t rc = g_wpaObj->P2pSetRandomMac(g_wpaObj, nullptr, time);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetRandomMac(g_wpaObj, IFNAME, time);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetExtListenTest_015, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetExtListen(g_wpaObj, nullptr, 0, 1, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetExtListen(g_wpaObj, IFNAME, 0, 1, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetListenChannelTest_016, TestSize.Level1)
{
    const int channel = 44;
    int32_t rc = g_wpaObj->P2pSetListenChannel(g_wpaObj, nullptr, channel, 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetListenChannel(g_wpaObj, IFNAME, channel, 0);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pProvisionDiscoveryTest_017, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pProvisionDiscovery(g_wpaObj, nullptr, "00:00:00:00:00:00", 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pProvisionDiscovery(g_wpaObj, IFNAME, nullptr, 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pProvisionDiscovery(g_wpaObj, IFNAME, "00:00:00:00:00:00", 0);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pAddGroupTest_018, TestSize.Level1)
{
    int networkId = 1;
    const int freq = 5220;
    int32_t rc = g_wpaObj->P2pAddGroup(g_wpaObj, nullptr, 0, networkId, freq);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pAddGroup(g_wpaObj, IFNAME, 0, networkId, freq);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pAddServiceTest_019, TestSize.Level1)
{
    struct HdiP2pServiceInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pServiceInfo), 0, sizeof(struct HdiP2pServiceInfo));
    int32_t rc = g_wpaObj->P2pAddService(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pAddService(g_wpaObj, nullptr, &info);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pAddService(g_wpaObj, IFNAME, &info);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pRemoveServiceTest_020, TestSize.Level1)
{
    struct HdiP2pServiceInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pServiceInfo), 0, sizeof(struct HdiP2pServiceInfo));

    int32_t rc = g_wpaObj->P2pRemoveService(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pRemoveService(g_wpaObj, nullptr, &info);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pRemoveService(g_wpaObj, IFNAME, &info);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pStopFindTest_021, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pStopFind(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pStopFind(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pFlushTest_022, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pFlush(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pFlush(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pFlushServiceTest_023, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pFlushService(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pFlushService(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pRemoveNetworkTest_024, TestSize.Level1)
{
    int networkId = 1;
    int32_t rc = g_wpaObj->P2pRemoveNetwork(g_wpaObj, nullptr, networkId);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pRemoveNetwork(g_wpaObj, IFNAME, networkId);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetGroupConfigTest_025, TestSize.Level1)
{
    int networkId = 1;
    int32_t rc = g_wpaObj->P2pSetGroupConfig(g_wpaObj, nullptr, networkId, "test_name", "test_value");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetGroupConfig(g_wpaObj, IFNAME, networkId, nullptr, "test_value");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetGroupConfig(g_wpaObj, IFNAME, networkId, "test_name", nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetGroupConfig(g_wpaObj, IFNAME, networkId, "test_name", "test_value");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pInviteTest_026, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pInvite(g_wpaObj, nullptr, "00:00:00:00:00:00", "11:11:11:11:11:11");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pInvite(g_wpaObj, IFNAME, nullptr, "11:11:11:11:11:11");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pInvite(g_wpaObj, IFNAME, "00:00:00:00:00:00", nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pInvite(g_wpaObj, IFNAME, "00:00:00:00:00:00", "11:11:11:11:11:11");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pReinvokeTest_027, TestSize.Level1)
{
    int networkId = 1;
    int32_t rc = g_wpaObj->P2pReinvoke(g_wpaObj, nullptr, networkId, "00:00:00:00:00:00");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pReinvoke(g_wpaObj, IFNAME, networkId, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pReinvoke(g_wpaObj, IFNAME, networkId, "00:00:00:00:00:00");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pGetDeviceAddressTest_028, TestSize.Level1)
{
    char *deviceAddress = (char *)calloc(WPA_CMD_BUF_LEN, sizeof(char));
    uint32_t deviceAddressLen = WPA_CMD_BUF_LEN;
    int32_t rc = g_wpaObj->P2pGetDeviceAddress(g_wpaObj, nullptr, deviceAddress, deviceAddressLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetDeviceAddress(g_wpaObj, IFNAME, nullptr, deviceAddressLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetDeviceAddress(g_wpaObj, IFNAME, deviceAddress, deviceAddressLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    free(deviceAddress);
}

HWTEST_F(HdfP2pHostDirectTest, P2pReqServiceDiscoveryTest_029, TestSize.Level1)
{
    char *replyDisc = (char *)calloc(REPLY_SIZE, sizeof(char));
    uint32_t replyDiscLen = REPLY_SIZE;
    struct HdiP2pReqService reqService;
    (void)memset_s(
        &reqService, sizeof(struct HdiP2pReqService), 0, sizeof(struct HdiP2pReqService));

    int32_t rc = g_wpaObj->P2pReqServiceDiscovery(g_wpaObj, nullptr, &reqService, replyDisc, replyDiscLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pReqServiceDiscovery(g_wpaObj, IFNAME, nullptr, replyDisc, replyDiscLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pReqServiceDiscovery(g_wpaObj, IFNAME, &reqService, nullptr, replyDiscLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pReqServiceDiscovery(g_wpaObj, IFNAME, &reqService, replyDisc, replyDiscLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    free(replyDisc);
}

HWTEST_F(HdfP2pHostDirectTest, P2pCancelServiceDiscoveryTest_030, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pCancelServiceDiscovery(g_wpaObj, nullptr, "test");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pCancelServiceDiscovery(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pCancelServiceDiscovery(g_wpaObj, IFNAME, "test");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pRespServerDiscoveryTest_031, TestSize.Level1)
{
    struct HdiP2pServDiscReqInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pServDiscReqInfo), 0, sizeof(struct HdiP2pServDiscReqInfo));
    int32_t rc = g_wpaObj->P2pRespServerDiscovery(g_wpaObj, nullptr, &info);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pRespServerDiscovery(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pRespServerDiscovery(g_wpaObj, IFNAME, &info);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pConnectTest_032, TestSize.Level1)
{
    struct HdiP2pConnectInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pConnectInfo), 0, sizeof(struct HdiP2pConnectInfo));
    char *replyPin = (char *)calloc(REPLY_SIZE, sizeof(char));
    uint32_t replyPinLen = REPLY_SIZE;

    int32_t rc = g_wpaObj->P2pConnect(g_wpaObj, nullptr, &info, replyPin, replyPinLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pConnect(g_wpaObj, IFNAME, nullptr, replyPin, replyPinLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pConnect(g_wpaObj, IFNAME, &info, nullptr, replyPinLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pConnect(g_wpaObj, IFNAME, &info, replyPin, replyPinLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    free(replyPin);
}

HWTEST_F(HdfP2pHostDirectTest, P2pHid2dConnectTest_033, TestSize.Level1)
{
    struct HdiHid2dConnectInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiHid2dConnectInfo), 0, sizeof(struct HdiHid2dConnectInfo));
    int32_t rc = g_wpaObj->P2pHid2dConnect(g_wpaObj, nullptr, &info);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pHid2dConnect(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pHid2dConnect(g_wpaObj, IFNAME, &info);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSetServDiscExternalTest_034, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSetServDiscExternal(g_wpaObj, nullptr, 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSetServDiscExternal(g_wpaObj, IFNAME, 0);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pRemoveGroupTest_035, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pRemoveGroup(g_wpaObj, nullptr, "test");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pRemoveGroup(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pRemoveGroup(g_wpaObj, IFNAME, "test");
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pCancelConnectTest_036, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pCancelConnect(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pCancelConnect(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pGetGroupConfigTest_037, TestSize.Level1)
{
    int networkId = 1;
    char *value = (char *)calloc(REPLY_SIZE, sizeof(char));
    uint32_t valueLen = REPLY_SIZE;

    int32_t rc = g_wpaObj->P2pGetGroupConfig(g_wpaObj, nullptr, networkId, "ssid", value, valueLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetGroupConfig(g_wpaObj, IFNAME, networkId, nullptr, value, valueLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetGroupConfig(g_wpaObj, IFNAME, networkId, "ssid", nullptr, valueLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetGroupConfig(g_wpaObj, IFNAME, networkId, "ssid", value, valueLen);
    ASSERT_EQ(rc, HDF_FAILURE);
    free(value);
}

HWTEST_F(HdfP2pHostDirectTest, P2pAddNetworkTest_038, TestSize.Level1)
{
    int networkId = 0;
    int32_t rc = g_wpaObj->P2pAddNetwork(g_wpaObj, nullptr, &networkId);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pAddNetwork(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pAddNetwork(g_wpaObj, IFNAME, &networkId);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pGetPeerTest_039, TestSize.Level1)
{
    struct HdiP2pDeviceInfo info;
    (void)memset_s(
        &info, sizeof(struct HdiP2pDeviceInfo), 0, sizeof(struct HdiP2pDeviceInfo));
    int32_t rc = g_wpaObj->P2pGetPeer(g_wpaObj, nullptr, "00:00:00:00:00:00", &info);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetPeer(g_wpaObj, IFNAME, nullptr, &info);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetPeer(g_wpaObj, IFNAME, "00:00:00:00:00:00", nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetPeer(g_wpaObj, IFNAME, "00:00:00:00:00:00", &info);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pGetGroupCapabilityTest_040, TestSize.Level1)
{
    int cap = 0;
    int32_t rc = g_wpaObj->P2pGetGroupCapability(g_wpaObj, nullptr, "00:00:00:00:00:00", &cap);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetGroupCapability(g_wpaObj, IFNAME, nullptr, &cap);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetGroupCapability(g_wpaObj, IFNAME, "00:00:00:00:00:00", nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pGetGroupCapability(g_wpaObj, IFNAME, "00:00:00:00:00:00", &cap);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pListNetworksTest_041, TestSize.Level1)
{
    struct HdiP2pNetworkList infoList;
    (void)memset_s(
        &infoList, sizeof(struct HdiP2pNetworkList), 0, sizeof(struct HdiP2pNetworkList));

    int32_t rc = g_wpaObj->P2pListNetworks(g_wpaObj, nullptr, &infoList);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pListNetworks(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pListNetworks(g_wpaObj, IFNAME, &infoList);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, P2pSaveConfigTest_042, TestSize.Level1)
{
    int32_t rc = g_wpaObj->P2pSaveConfig(g_wpaObj, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->P2pSaveConfig(g_wpaObj, IFNAME);
    ASSERT_EQ(rc, HDF_FAILURE);
}

HWTEST_F(HdfP2pHostDirectTest, VendorProcessCmdTest_043, TestSize.Level1)
{
    int32_t rc = g_wpaObj->VendorProcessCmd(g_wpaObj, nullptr, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wpaObj->VendorProcessCmd(g_wpaObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_FAILURE);
}
};

