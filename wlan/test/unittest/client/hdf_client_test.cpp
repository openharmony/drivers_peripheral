/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <osal_mem.h>
#include "wifi_driver_client.h"
 #ifdef OHOS_ARCH_LITE
#include "hostapd_client.h"
#include "wpa_client.h"
#endif
#include "securec.h"

using namespace testing::ext;

namespace ClientTest {
const uint32_t DEFAULT_COMBO_SIZE = 10;
const char *WLAN_IFNAME = "wlan0";
const uint32_t RESET_TIME = 3;
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

static int32_t Hid2dFunCb(const uint8_t *recvMsg, uint32_t recvMsgLen)
{
    (void)recvMsg;
    (void)recvMsgLen;
    return RET_CODE_SUCCESS;
}

static int32_t Hid2dFunCb2(uint32_t event, void *data, const char *ifName)
{
    (void)event;
    (void)data;
    (void)ifName;
    return RET_CODE_SUCCESS;
}

/**
 * @tc.name: WifiClientSetResetDriver001
 * @tc.desc: Wifi client reset driver function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiClientSetResetDriver001, TestSize.Level1)
{
    int32_t ret;
    uint8_t chipId = 0;

    ret = AcquireChipId(WLAN_IFNAME, &chipId);
    ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);

    ret = SetResetDriver(chipId, WLAN_IFNAME);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    sleep(RESET_TIME);
}

/**
 * @tc.name: WifiClientSetCountryCode001
 * @tc.desc: Wifi client set country code function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientSetCountryCode001, TestSize.Level1)
{
    int32_t ret;
    const char *code = "CN";
    const char *codeDigital = "99";
    const char *ifNameInvalid = "wlanTest";
    uint32_t len = 2;

    ret = WifiSetCountryCode(ifNameInvalid, code, len);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiSetCountryCode(WLAN_IFNAME, code, len);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    ret = WifiSetCountryCode(WLAN_IFNAME, codeDigital, len);
    bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientGetUsableNetworkInfo001
 * @tc.desc: Wifi client get usable networkInfo function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientGetUsableNetworkInfo001, TestSize.Level1)
{
    int32_t ret;
    struct NetworkInfoResult networkInfo;

    ret = GetUsableNetworkInfo(&networkInfo);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientIsSupportCombo001
 * @tc.desc: Wifi client is support combo function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientIsSupportCombo001, TestSize.Level1)
{
    int32_t ret;
    uint8_t isSupportCombo;

    ret = IsSupportCombo(&isSupportCombo);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetComboInfo001
 * @tc.desc: Wifi client get combo info function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientGetComboInfo001, TestSize.Level1)
{
    int32_t ret;
    uint64_t comboInfo[DEFAULT_COMBO_SIZE] = {};

    ret = GetComboInfo(comboInfo, DEFAULT_COMBO_SIZE);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetMacAddr001
 * @tc.desc: Wifi client set mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientSetMacAddr001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    unsigned char mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    unsigned char errorMac[ETH_ADDR_LEN] = {0x11, 0x34, 0x56, 0x78, 0xab, 0xcd};

    ret = SetMacAddr(WLAN_IFNAME, mac, ETH_ADDR_LEN);
    bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_DEVICE_BUSY);
    ASSERT_TRUE(flag);
    ret = SetMacAddr(WLAN_IFNAME, errorMac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = SetMacAddr(ifNameInvalid, mac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetDevMacAddr001
 * @tc.desc: Wifi client get mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientGetDevMacAddr001, TestSize.Level1)
{
    int32_t ret;
    unsigned char mac[ETH_ADDR_LEN] = {};
    int32_t type = WIFI_IFTYPE_STATION;
    const char *ifNameInvalid = "wlanTest";

    ret = GetDevMacAddr(WLAN_IFNAME, type, mac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_FAILURE, ret);
    ret = GetDevMacAddr(ifNameInvalid, type, mac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetDevMacAddr002
 * @tc.desc: Wifi client get mac addr function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetDevMacAddr002, TestSize.Level1)
{
    int32_t ret;
    unsigned char mac[ETH_ADDR_LEN] = {};
    int32_t type = WIFI_IFTYPE_AP;

    ret = GetDevMacAddr(WLAN_IFNAME, type, mac, ETH_ADDR_LEN);
    EXPECT_NE(RET_CODE_FAILURE, ret);
}

/**
 * @tc.name: WifiClientGetValidFreqByBand001
 * @tc.desc: Wifi client get valid freq function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientGetValidFreqByBand001, TestSize.Level1)
{
    int32_t ret;
    int32_t band = IEEE80211_BAND_2GHZ;
    int32_t bandNotSupport = IEEE80211_NUM_BANDS;
    struct FreqInfoResult result;
    uint32_t size = 14;
    uint32_t i;
    const char *ifNameInvalid = "wlanTest";

    result.freqs = (uint32_t *)OsalMemCalloc(35 * sizeof(uint32_t));
    if (result.freqs == NULL) {
        printf("%s: OsalMemCalloc failed", __FUNCTION__);
        return;
    }

    result.txPower = (uint32_t *)OsalMemCalloc(35 * sizeof(uint32_t));
    if (result.txPower == NULL) {
        printf("%s: OsalMemCalloc failed", __FUNCTION__);
        OsalMemFree(result.freqs);
        return;
    }

    ret = GetValidFreqByBand(WLAN_IFNAME, bandNotSupport, &result, size);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = GetValidFreqByBand(WLAN_IFNAME, band, nullptr, size);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = GetValidFreqByBand(ifNameInvalid, band, &result, size);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = GetValidFreqByBand(WLAN_IFNAME, band, &result, size);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    if (ret == RET_CODE_SUCCESS) {
        printf("%s: num = %u\n", __func__, result.nums);
        for (i = 0; i < result.nums; i++) {
            printf("%s: freq[%d] = %d\n", __func__, i, result.freqs[i]);
        }
    }

    OsalMemFree(result.txPower);
    OsalMemFree(result.freqs);
}

/**
 * @tc.name: WifiClientSetTxPower001
 * @tc.desc: Wifi client set tx power function test
 * @tc.type: FUNC
 * @tc.require: AR000FRMJC
 */
HWTEST_F(WifiClientTest, WifiClientSetTxPower001, TestSize.Level1)
{
    int32_t ret;
    int32_t power = 10;
    const char *ifNameInvalid = "wlanTest";

    ret = SetTxPower(ifNameInvalid, power);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = SetTxPower(WLAN_IFNAME, power);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetAssociatedStas001
 * @tc.desc: Wifi client get associated status function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetAssociatedStas001, TestSize.Level1)
{
    int32_t ret;
    struct AssocStaInfoResult result;

    ret = GetAssociatedStas(WLAN_IFNAME, &result);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientSetScanMacAddr001
 * @tc.desc: Wifi client set scan MAC address function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetScanMacAddr001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    unsigned char scanMac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};

    ret = SetScanMacAddr(ifNameInvalid, scanMac, ETH_ADDR_LEN);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = SetScanMacAddr(WLAN_IFNAME, scanMac, ETH_ADDR_LEN);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientAcquireChipId001
 * @tc.desc: Wifi client get chipId function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientAcquireChipId001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    uint8_t chipId = 0;

    ret = AcquireChipId(nullptr, &chipId);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = AcquireChipId(WLAN_IFNAME, nullptr);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = AcquireChipId(ifNameInvalid, &chipId);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = AcquireChipId(WLAN_IFNAME, &chipId);
    ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetIfNamesByChipId001
 * @tc.desc: Wifi client get ifName by chipId function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetIfNamesByChipId001, TestSize.Level1)
{
    int32_t ret;
    uint8_t chipId = 0;
    uint8_t chipIdInvalid = 100;
    char *ifNames = nullptr;
    uint32_t num = 0;

    ret = AcquireChipId(WLAN_IFNAME, &chipId);
    ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    ret = GetIfNamesByChipId(chipIdInvalid, &ifNames, &num);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = GetIfNamesByChipId(chipId, &ifNames, &num);
    EXPECT_NE(ifNames, nullptr);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    ret = GetIfNamesByChipId(chipId, &ifNames, nullptr);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = GetIfNamesByChipId(chipId, nullptr, &num);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    free(ifNames);
}

/**
 * @tc.name: WifiClientGetNetDeviceInfo001
 * @tc.desc: Wifi client get netDevice information function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetNetDeviceInfo001, TestSize.Level1)
{
    int32_t ret;
    struct NetDeviceInfoResult netDeviceInfoResult;

    ret = GetNetDeviceInfo(&netDeviceInfoResult);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiClientGetCurrentPowerMode001
 * @tc.desc: Wifi client get current power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientGetCurrentPowerMode001, TestSize.Level1)
{
    int32_t ret;
    uint8_t mode = 0;
    const char *ifNameInvalid = "wlanTest";

    ret = GetCurrentPowerMode(ifNameInvalid, &mode);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = GetCurrentPowerMode(WLAN_IFNAME, &mode);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetPowerMode001
 * @tc.desc: Wifi client set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetPowerMode001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";

    ret = SetPowerMode(ifNameInvalid, WIFI_POWER_MODE_SLEEPING);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
    ret = SetPowerMode(WLAN_IFNAME, WIFI_POWER_MODE_SLEEPING);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetPowerMode002
 * @tc.desc: Wifi client set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetPowerMode002, TestSize.Level1)
{
    int32_t ret;

    ret = SetPowerMode(WLAN_IFNAME, WIFI_POWER_MODE_GENERAL);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetPowerMode003
 * @tc.desc: Wifi client set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetPowerMode003, TestSize.Level1)
{
    int32_t ret;

    ret = SetPowerMode(WLAN_IFNAME, WIFI_POWER_MODE_THROUGH_WALL);
    bool flag = (ret == RET_CODE_SUCCESS || ret == RET_CODE_NOT_SUPPORT);
    ASSERT_TRUE(flag);
}

/**
 * @tc.name: WifiClientSetPowerMode004
 * @tc.desc: Wifi client set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiClientTest, WifiClientSetPowerMode004, TestSize.Level1)
{
    int32_t ret;

    ret = SetPowerMode(WLAN_IFNAME, WIFI_POWER_MODE_NUM);
    EXPECT_NE(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiRegisterHid2dCallback001
 * @tc.desc: Wifi register hid2d callback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiRegisterHid2dCallback001, TestSize.Level1)
{
    int32_t ret;

    ret = WifiRegisterHid2dCallback(nullptr, WLAN_IFNAME);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiRegisterHid2dCallback(Hid2dFunCb, nullptr);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiRegisterHid2dCallback(Hid2dFunCb, WLAN_IFNAME);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
    WifiUnregisterHid2dCallback(nullptr, WLAN_IFNAME);
    WifiUnregisterHid2dCallback(Hid2dFunCb, nullptr);
}

/**
 * @tc.name: WifiGetSignalPollInfo001
 * @tc.desc: Wifi get signal poll info function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiGetSignalPollInfo001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    struct SignalResult signalResult;
    (void)memset_s(&signalResult, sizeof(signalResult), 0, sizeof(signalResult));

    ret = WifiGetSignalPollInfo(nullptr, &signalResult);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiGetSignalPollInfo(ifNameInvalid, nullptr);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiGetSignalPollInfo(ifNameInvalid, &signalResult);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
}

static int32_t WifiEventCb(uint32_t event, void *respData, const char *ifName)
{
    (void)event;
    (void)respData;
    (void)ifName;
    return RET_CODE_SUCCESS;
}

/**
 * @tc.name: WifiRegisterEventCallback001
 * @tc.desc: Wifi register event callback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiRegisterEventCallback001, TestSize.Level1)
{
    int32_t ret;

    ret = WifiRegisterEventCallback(nullptr, WIFI_KERNEL_TO_HAL_CLIENT, WLAN_IFNAME);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiRegisterEventCallback(WifiEventCb, WIFI_KERNEL_TO_HAL_CLIENT, nullptr);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiUnregisterEventCallback(nullptr, WIFI_KERNEL_TO_HAL_CLIENT, WLAN_IFNAME);
    WifiUnregisterEventCallback(WifiEventCb, WIFI_KERNEL_TO_HAL_CLIENT, nullptr);
}

/**
 * @tc.name: WifiRegisterActionFrameReceiver001
 * @tc.desc: Wifi register action frame function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiRegisterActionFrameReceiver001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    uint8_t mastch = 0;
    uint32_t matchLen = RESET_TIME;

    ret = WifiRegisterActionFrameReceiver(nullptr, &mastch, matchLen);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiRegisterActionFrameReceiver(ifNameInvalid, 0, matchLen);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiRegisterActionFrameReceiver(ifNameInvalid, &mastch, 0);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiRegisterActionFrameReceiver(ifNameInvalid, &mastch, matchLen);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
}

/**
 * @tc.name: WifiSendActionFrame001
 * @tc.desc: Wifi send action frame function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiSendActionFrame001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    uint8_t frameData = 0;
    uint32_t freq = RESET_TIME;
    uint32_t frameDataLen = RESET_TIME;

    ret = WifiSendActionFrame(nullptr, freq, &frameData, frameDataLen);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiSendActionFrame(ifNameInvalid, 0, &frameData, frameDataLen);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiSendActionFrame(ifNameInvalid, freq, &frameData, frameDataLen);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiSendActionFrame(ifNameInvalid, freq, &frameData, 0);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = WifiSendActionFrame(ifNameInvalid, freq, &frameData, frameDataLen);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
}

/**
 * @tc.name: ClientGetApBandwidth001
 * @tc.desc: client get ap bandwidth function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, ClientGetApBandwidth001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    uint8_t bandwidth = 0;

    ret = ClientGetApBandwidth(nullptr, &bandwidth);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = ClientGetApBandwidth(ifNameInvalid, nullptr);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
    ret = ClientGetApBandwidth(ifNameInvalid, &bandwidth);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
}

/**
 * @tc.name: SetProjectionScreenParam001
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, SetProjectionScreenParam001, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    ProjectionScreenParam *param = nullptr;
    param->cmdId = CMD_ID_RX_REMAIN_ON_CHANNEL;
    param->buf[0] = 0;
    param->bufLen = 40;
    ret = SetProjectionScreenParam(ifNameInvalid, param);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
}

/**
 * @tc.name: SetProjectionScreenParam001
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, SetProjectionScreenParam002, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    ProjectionScreenParam *param = nullptr;
    param->cmdId = CMD_ID_RX_REMAIN_ON_CHANNEL;
    param->buf[0] = 0;
    param->bufLen = 1;
    ret = SetProjectionScreenParam(ifNameInvalid, param);
    EXPECT_EQ(RET_CODE_FAILURE, ret);
}
/**
 * @tc.name: WifiEapolPacketSend001
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiEapolPacketSend001, TestSize.Level1)
{
    int32_t ret;
    int32_t length = 0;
    const char *ifNameInvalid = "wlanTest";
    uint8_t srcAddr = 0;
    uint8_t dstAddr = 0;
    uint8_t buf = 0;
    ret = WifiEapolPacketSend(NULL, &srcAddr, &dstAddr, &buf, length);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiEapolPacketSend(ifNameInvalid, &srcAddr, &dstAddr, &buf, length);
}
/**
 * @tc.name: WifiEapolPacketReceive002
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiEapolPacketReceive002, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiRxEapol *rxEapol = NULL;
    ret = WifiEapolPacketReceive(NULL, rxEapol);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiEapolPacketReceive(ifNameInvalid, rxEapol);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
}
/**
 * @tc.name: WifiEapolEnable003
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiEapolEnable003, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    ret = WifiEapolEnable(NULL);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiEapolEnable(ifNameInvalid);
}
/**
 * @tc.name: WifiEapolDisable004
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiEapolDisable004, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    ret = WifiEapolDisable(NULL);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiEapolDisable(ifNameInvalid);
}
/**
 * @tc.name: WifiCmdSetAp005
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdSetAp005, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiApSetting *apsettings = NULL;
    ret = WifiCmdSetAp(NULL, apsettings);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiCmdSetAp(ifNameInvalid, apsettings);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
}
/**
 * @tc.name: WifiCmdChangeBeacon006
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdChangeBeacon006, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiApSetting *apsettings = NULL;
    ret = WifiCmdChangeBeacon(NULL, apsettings);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiCmdChangeBeacon(ifNameInvalid, apsettings);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
}
/**
 * @tc.name: WifiCmdSendMlme007
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdSendMlme007, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiMlmeData *mlme = NULL;
    ret = WifiCmdSendMlme(NULL, mlme);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiCmdSendMlme(ifNameInvalid, mlme);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
}
/**
 * @tc.name: WifiCmdDelKey008
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdDelKey008, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiKeyExt *keyExt = NULL;
    ret = WifiCmdDelKey(NULL, keyExt);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiCmdDelKey(ifNameInvalid, keyExt);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
}
/**
 * @tc.name: WifiCmdNewKey009
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdNewKey009, TestSize.Level1)
{
    const char *ifNameInvalid = "wlanTest";
    WifiKeyExt keyExt;
    WifiCmdNewKey(ifNameInvalid, &keyExt);
}
/**
 * @tc.name: WifiCmdSetKey0010
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdSetKey0010, TestSize.Level1)
{
    const char *ifNameInvalid = "wlanTest";
    WifiKeyExt keyExt;
    WifiCmdSetKey(ifNameInvalid, &keyExt);
}
/**
 * @tc.name: WifiCmdGetOwnMac0011
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdGetOwnMac0011, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    uint32_t len = 0;
    ret = WifiCmdGetOwnMac(NULL, NULL, len);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiCmdGetOwnMac(ifNameInvalid, NULL, len);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdGetOwnMac(ifNameInvalid, NULL, len);
}
/**
 * @tc.name: WifiCmdSetMode0012
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdSetMode0012, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiSetMode *setMode = NULL;
    ret = WifiCmdSetMode(NULL, setMode);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    ret = WifiCmdSetMode(ifNameInvalid, setMode);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
}
/**
 * @tc.name: WifiCmdGetHwFeature0013
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdGetHwFeature0013, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiHwFeatureData hwFeatureData;
    ret = WifiCmdGetHwFeature(NULL, &hwFeatureData);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdGetHwFeature(ifNameInvalid, &hwFeatureData);
}
/**
 * @tc.name: WifiCmdDisconnet0014
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdDisconnet0014, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    int32_t reasonCode = 0;
    ret = WifiCmdDisconnet(NULL, reasonCode);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdDisconnet(ifNameInvalid, reasonCode);
}
/**
 * @tc.name: WifiCmdAssoc0016
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdAssoc0016, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiAssociateParams assocParams;
    ret = WifiCmdAssoc(NULL, &assocParams);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdAssoc(ifNameInvalid, &assocParams);
}
/**
 * @tc.name: WifiCmdSetNetdev0017
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdSetNetdev0017, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiSetNewDev info;
    ret = WifiCmdSetNetdev(NULL, &info);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdSetNetdev(ifNameInvalid, &info);
}
/**
 * @tc.name: WifiCmdStaRemove0018
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdStaRemove0018, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    uint8_t *addr = NULL;
    uint32_t addrLen = 0;
    ret = WifiCmdStaRemove(NULL, addr, addrLen);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdStaRemove(ifNameInvalid, addr, addrLen);
}
/**
 * @tc.name: WifiCmdSendAction0019
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdSendAction0019, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiActionData actionData;
    ret = WifiCmdSendAction(NULL, &actionData);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdSendAction(ifNameInvalid, &actionData);
}
/**
 * @tc.name: WifiCmdSetClient0020
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdSetClient0020, TestSize.Level1)
{
    uint32_t clientNum = 0;
    WifiCmdSetClient(clientNum);
}
/**
 * @tc.name: WifiCmdProbeReqReport0021
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdProbeReqReport0021, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    int32_t *report = NULL;
    ret = WifiCmdProbeReqReport(NULL, report);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdProbeReqReport(ifNameInvalid, report);
}
/**
 * @tc.name: WifiCmdRemainOnChannel0022
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdRemainOnChannel0022, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiOnChannel onChannel;
    ret = WifiCmdRemainOnChannel(NULL, &onChannel);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdRemainOnChannel(ifNameInvalid, &onChannel);
}
/**
 * @tc.name: WifiCmdCancelRemainOnChannel0023
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdCancelRemainOnChannel0023, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    ret = WifiCmdCancelRemainOnChannel(NULL);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdCancelRemainOnChannel(ifNameInvalid);
}
/**
 * @tc.name: WifiCmdAddIf024
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdAddIf024, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiIfAdd ifAdd;
    ret = WifiCmdAddIf(NULL, &ifAdd);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdAddIf(ifNameInvalid, &ifAdd);
}
/**
 * @tc.name: WifiCmdRemoveIf025
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdRemoveIf025, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiIfRemove ifRemove;
    ret = WifiCmdRemoveIf(NULL, &ifRemove);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdRemoveIf(ifNameInvalid, &ifRemove);
}
/**
 * @tc.name: WifiCmdSetApWpsP2pIe026
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdSetApWpsP2pIe026, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiAppIe appIe;
    ret = WifiCmdSetApWpsP2pIe(NULL, &appIe);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdSetApWpsP2pIe(ifNameInvalid, &appIe);
}
/**
 * @tc.name: WifiCmdGetDrvFlags027
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiCmdGetDrvFlags027, TestSize.Level1)
{
    int32_t ret;
    const char *ifNameInvalid = "wlanTest";
    WifiGetDrvFlags params;
    ret = WifiCmdGetDrvFlags(NULL, &params);
    EXPECT_EQ(RET_CODE_INVALID_PARAM, ret);
    WifiCmdGetDrvFlags(ifNameInvalid, &params);
}
/**
 * @tc.name: WifiSetDpiMarkRule028
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiSetDpiMarkRule028, TestSize.Level1)
{
    int32_t srcAddr = 0;
    int32_t dstAddr = 0;
    int32_t buf = 0;
    WifiSetDpiMarkRule(srcAddr, dstAddr, buf);
}
/**
 * @tc.name: WpaEventReport
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef OHOS_ARCH_LITE
HWTEST_F(WifiClientTest, WpaEventReport, TestSize.Level1)
{
    int32_t dstAddr = 0;
    void *data = NULL;
    const char *ifNameInvalid = "wlanTest";
    WpaEventReport(ifNameInvalid, dstAddr, data);
}
/**
 * @tc.name: WpaEventReport
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WpaRegisterEventCallback, TestSize.Level1)
{
    int32_t dstAddr = 0;
    const char *ifNameInvalid = "wlanTest";
    WpaRegisterEventCallback(Hid2dFunCb2, dstAddr, ifNameInvalid);
}
/**
 * @tc.name: WpaUnregisterEventCallback
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WpaUnregisterEventCallback, TestSize.Level1)
{
    int32_t dstAddr = 0;
    const char *ifNameInvalid = "wlanTest";
    WpaUnregisterEventCallback(Hid2dFunCb2, dstAddr, ifNameInvalid);
}
/**
 * @tc.name: HostapdEventReport
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, HostapdEventReport, TestSize.Level1)
{
    int32_t dstAddr = 0;
    void *data = NULL;
    const char *ifNameInvalid = "wlanTest";
    HostapdEventReport(ifNameInvalid, dstAddr, data);
}
/**
 * @tc.name: HostapdRegisterEventCallback
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, HostapdRegisterEventCallback, TestSize.Level1)
{
    int32_t dstAddr = 0;
    const char *ifNameInvalid = "wlanTest";
    HostapdRegisterEventCallback(Hid2dFunCb2, dstAddr, ifNameInvalid);
}
/**
 * @tc.name: HostapdUnregisterEventCallback
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, HostapdUnregisterEventCallback, TestSize.Level1)
{
    int32_t dstAddr = 0;
    const char *ifNameInvalid = "wlanTest";
    HostapdUnregisterEventCallback(Hid2dFunCb2, dstAddr, ifNameInvalid);
}
/**
 * @tc.name: WifiSetPowerSaveMode029
 * @tc.desc: set rx remain On channel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiClientTest, WifiSetPowerSaveMode029, TestSize.Level1)
{
    int32_t frequency = 0;
    int32_t mode = 0;
    const char *ifName = "wlanTest";
    WifiSetPowerSaveMode(ifName, frequency, mode);
}
}
}
#endif
};