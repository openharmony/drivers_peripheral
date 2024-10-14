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
#include "hdf_base.h"
#include "hdf_sbuf.h"
#include "wifi_hal.h"
#include "wifi_hal_ap_feature.h"
#include "wifi_hal_base_feature.h"
#include "wifi_hal_sta_feature.h"
#include "securec.h"

struct ElementHeader {
    uint8_t id;
    uint8_t datalen;
};

using namespace testing::ext;

namespace HalTest {
struct IWiFi *g_wifi = nullptr;
const int32_t WLAN_TX_POWER = 160;
const uint32_t IFNAME_MIN_NUM = 0;
const uint32_t IFNAME_MAX_NUM = 32;
const uint32_t MAX_IF_NAME_LENGTH = 16;
const uint32_t TEST_PARAM_BUF_SIZE = 64;
const uint32_t SIZE = 4;
const int32_t TEST_CMD = 123;
const uint32_t RESET_TIME = 3;
const uint32_t SCAN_TIME = 3;
const uint32_t TEST_BUF_SIZE = 64;
const uint32_t WLAN_EID_SSID = 0;

class WifiHalTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void WifiHalTest::SetUpTestCase()
{
    int ret;

    ret = WifiConstruct(&g_wifi);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void WifiHalTest::TearDownTestCase()
{
    int ret;

    ret = WifiDestruct(&g_wifi);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void WifiHalTest::SetUp()
{
    int ret;

    ret = g_wifi->start(nullptr);
    ASSERT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->start(g_wifi);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void WifiHalTest::TearDown()
{
    int ret;

    ret = g_wifi->stop(nullptr);
    ASSERT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->stop(g_wifi);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

static void PrintSsid(const uint8_t *ie, uint32_t len)
{
    char ssid[MAX_SSID_LEN] = {0};
    uint8_t *pos = NULL;
    struct ElementHeader *hdr = (struct ElementHeader *)ie;

    if (ie == NULL || len < sizeof(struct ElementHeader)) {
        return;
    }
    while (ie + len >= ((uint8_t *)hdr + sizeof(*hdr) + hdr->datalen)) {
        pos = (uint8_t *)hdr + sizeof(*hdr);
        if (hdr->id == WLAN_EID_SSID) {
            if (hdr->datalen < MAX_SSID_LEN && memcpy_s(ssid, MAX_SSID_LEN, pos, hdr->datalen) == EOK) {
                printf("ssid: %s\n", ssid);
            }
            return;
        }
        hdr = (struct ElementHeader *)(pos + hdr->datalen);
    }
}

static void ParseScanResult(WifiScanResult *scanResult)
{
    printf("ParseScanResult: flags=%d, caps=%d, freq=%d, beaconInt=%d,\n", scanResult->flags, scanResult->caps,
        scanResult->freq, scanResult->beaconInt);
    printf("ParseScanResult: qual=%d, beaconIeLen=%d, level=%d, age=%d, ieLen=%d,\n", scanResult->qual,
        scanResult->beaconIeLen, scanResult->level, scanResult->age, scanResult->ieLen);
    PrintSsid(scanResult->ie, scanResult->ieLen);
}

static void ParseScanResults(WifiScanResults *scanResults)
{
    uint32_t i;
    printf("Receive %u scan results\n", scanResults->num);
    for (i = 0 ; i < scanResults->num; i++) {
        ParseScanResult(&scanResults->scanResult[i]);
    }
}

static int32_t Hid2dFunCb(const uint8_t *recvMsg, uint32_t recvMsgLen)
{
    (void)recvMsg;
    (void)recvMsgLen;
    return HDF_SUCCESS;
}

/**
 * @tc.name: WifiHalCreateAndDestroyFeature001
 * @tc.desc: Wifi hal create and destroy feature function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalCreateAndDestroyFeature001, TestSize.Level1)
{
    int ret;
    struct IWiFiAp *apFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = g_wifi->destroyFeature(nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalCreateAndDestroyFeature002
 * @tc.desc: Wifi hal create and destroy feature function test
 * @tc.type: FUNC
 * @tc.require: AR000F869E
 */
HWTEST_F(WifiHalTest, WifiHalCreateAndDestroyFeature002, TestSize.Level1)
{
    int ret;
    struct IWiFiSta *staFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = g_wifi->destroyFeature(nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalGetFeatureByIfName001
 * @tc.desc: Wifi hal get feature by ifname function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalGetFeatureByIfName001, TestSize.Level1)
{
    int ret;
    struct IWiFiAp *apFeature = nullptr;
    struct IWiFiAp *apFeatureGet = nullptr;
    const char *ifName0 = "wlanTest";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = g_wifi->getFeatureByIfName(nullptr, (struct IWiFiBaseFeature **)&apFeatureGet);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getFeatureByIfName(ifName0, (struct IWiFiBaseFeature **)&apFeatureGet);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getFeatureByIfName(apFeature->baseFeature.ifName, (struct IWiFiBaseFeature **)&apFeatureGet);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_NE(nullptr, apFeatureGet);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

static int32_t HalCallbackEvent(uint32_t event, void *respData, const char *ifName)
{
    (void)event;
    if (respData == nullptr) {
        return HDF_FAILURE;
    }
    printf("HalCallbackEvent ifName = %s, event = %d\n", ifName, event);
    switch (event) {
        case WIFI_EVENT_SCAN_DONE:
            printf("HalCallbackEvent WIFI_EVENT_SCAN_DONE Process\n");
            break;
        case WIFI_EVENT_SCAN_RESULT:
            ParseScanResult((WifiScanResult *)respData);
            break;
        case WIFI_EVENT_SCAN_RESULTS:
            ParseScanResults((WifiScanResults *)respData);
            break;
        default:
            printf("HalCallbackEvent: Invalid event\n");
    }
    return HDF_SUCCESS;
}

/**
 * @tc.name: WifiHalRegisterEventCallback001
 * @tc.desc: Wifi hal register callback function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalRegisterEventCallback001, TestSize.Level1)
{
    int ret;

    ret = g_wifi->registerEventCallback(HalCallbackEvent, "wlan0");
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.name: WifiHalUnRegisterEventCallback001
 * @tc.desc: Wifi hal unregister callback function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalUnRegisterEventCallback001, TestSize.Level1)
{
    int ret;

    ret = g_wifi->unregisterEventCallback(HalCallbackEvent, "wlan0");
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.name: WifiHalGetNetworkIfaceName001
 * @tc.desc: Wifi hal get network iface name function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalGetNetworkIfaceName001, TestSize.Level1)
{
    int ret;
    struct IWiFiAp *apFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        const char *ifnameTest = apFeature->baseFeature.getNetworkIfaceName(nullptr);
        EXPECT_EQ(nullptr, ifnameTest);
        const char *ifName = apFeature->baseFeature.getNetworkIfaceName((const struct IWiFiBaseFeature *)apFeature);
        EXPECT_NE(nullptr, ifName);
        if (strncmp(ifName, "wlan", 4) == 0 || strncmp(ifName, "nan", 3) == 0 || strncmp(ifName, "p2p", 3) == 0) {
            ret = 0;
        } else {
            ret = -1;
        }
        EXPECT_EQ(0, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalGetGetFeatureType001
 * @tc.desc: Wifi hal get feature type function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalGetGetFeatureType001, TestSize.Level1)
{
    int ret;
    struct IWiFiAp *apFeature = nullptr;
    int32_t type;
    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        type = apFeature->baseFeature.getFeatureType(nullptr);
        EXPECT_EQ(HDF_FAILURE, type);
        type = apFeature->baseFeature.getFeatureType((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(PROTOCOL_80211_IFTYPE_AP, type);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalSetMacAddress001
 * @tc.desc: Wifi hal set Mac address function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalSetMacAddress001, TestSize.Level1)
{
    int ret;
    struct IWiFiAp *apFeature = nullptr;
    unsigned char errorMac[ETH_ADDR_LEN] = {0x11, 0x34, 0x56, 0x78, 0xab, 0xcd};
    unsigned char mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = apFeature->baseFeature.setMacAddress(nullptr, mac, ETH_ADDR_LEN);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.setMacAddress((struct IWiFiBaseFeature *)apFeature, nullptr, ETH_ADDR_LEN);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.setMacAddress((struct IWiFiBaseFeature *)apFeature, mac, 0);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.setMacAddress((struct IWiFiBaseFeature *)apFeature, errorMac, ETH_ADDR_LEN);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->baseFeature.setMacAddress((struct IWiFiBaseFeature *)apFeature, mac, ETH_ADDR_LEN);
        printf("%s: ret = %d\n", __func__, ret);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_DEVICE_BUSY);
        ASSERT_TRUE(flag);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalSetMacAddress002
 * @tc.desc: Wifi hal set Mac address function test
 * @tc.type: FUNC
 * @tc.require: AR000F869E
 */
HWTEST_F(WifiHalTest, WifiHalSetMacAddress002, TestSize.Level1)
{
    int ret;
    struct IWiFiSta *staFeature = nullptr;
    unsigned char mac[ETH_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    unsigned char errorMac[ETH_ADDR_LEN] = {0x11, 0x34, 0x56, 0x78, 0xab, 0xcd};

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->baseFeature.setMacAddress(nullptr, mac, ETH_ADDR_LEN);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.setMacAddress((struct IWiFiBaseFeature *)staFeature, nullptr, ETH_ADDR_LEN);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.setMacAddress((struct IWiFiBaseFeature *)staFeature, mac, 0);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.setMacAddress((struct IWiFiBaseFeature *)staFeature, errorMac, ETH_ADDR_LEN);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.setMacAddress((struct IWiFiBaseFeature *)staFeature, mac, ETH_ADDR_LEN);
        printf("%s: ret = %d\n", __func__, ret);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_ERR_DEVICE_BUSY);
        ASSERT_TRUE(flag);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalSetTxPower001
 * @tc.desc: Wifi hal set transmit power function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalSetTxPower001, TestSize.Level1)
{
    int ret;
    struct IWiFiAp *apFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = apFeature->baseFeature.setTxPower(nullptr, WLAN_TX_POWER);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->baseFeature.setTxPower((struct IWiFiBaseFeature *)apFeature, 0);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->baseFeature.setTxPower((struct IWiFiBaseFeature *)apFeature, WLAN_TX_POWER);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: ResetDriver001
 * @tc.desc: wifi hal reset driver function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, ResetDriver001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    uint8_t chipId = 0;
    uint8_t chipIdInvalid = 20;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->baseFeature.getChipId((struct IWiFiBaseFeature *)staFeature, &chipId);
        ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->resetDriver(chipIdInvalid, "wlan0");
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = g_wifi->resetDriver(chipId, nullptr);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = g_wifi->resetDriver(chipId, staFeature->baseFeature.ifName);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(RESET_TIME);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: ResetDriver002
 * @tc.desc: wifi hal reset driver function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, ResetDriver002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    uint8_t chipId = 0;
    uint8_t chipIdInvalid = 20;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = apFeature->baseFeature.getChipId((struct IWiFiBaseFeature *)apFeature, &chipId);
        ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->resetDriver(chipIdInvalid, "wlan0");
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = g_wifi->resetDriver(chipId, nullptr);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = g_wifi->resetDriver(chipId, apFeature->baseFeature.ifName);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(RESET_TIME);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalSetCountryCode001
 * @tc.desc: Wifi hal set country code function test
 * @tc.type: FUNC
 * @tc.require: AR000F869K
 */
HWTEST_F(WifiHalTest, WifiHalSetCountryCode001, TestSize.Level1)
{
    int ret;
    struct IWiFiAp *apFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = apFeature->setCountryCode(apFeature, nullptr, 0);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->setCountryCode(nullptr, "CN", 2);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->setCountryCode(apFeature, "CN", 3);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->setCountryCode(apFeature, "99", 2);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_TIMEOUT || ret == HDF_FAILURE);
        ASSERT_TRUE(flag);
        ret = apFeature->setCountryCode(apFeature, "CN", 2);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalGetIfNamesByChipId001
 * @tc.desc: Obtain all ifNames and the number of the current chip
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, WifiHalGetIfNamesByChipId001, TestSize.Level1)
{
    int ret;
    struct IWiFiSta *staFeature = nullptr;
    char *ifNames = nullptr;
    unsigned int num = 0;
    unsigned char chipId = 0;
    uint8_t i;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->baseFeature.getChipId((struct IWiFiBaseFeature *)staFeature, &chipId);
        ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.getIfNamesByChipId(chipId, nullptr, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.getIfNamesByChipId(100, &ifNames, &num);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.getIfNamesByChipId(chipId, &ifNames, &num);
        EXPECT_NE(nullptr, ifNames);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ASSERT_TRUE(num <= IFNAME_MAX_NUM && num >= IFNAME_MIN_NUM);
        for (i = 0; i < num; i++) {
            EXPECT_EQ(0, strncmp("wlan", ifNames + i * MAX_IF_NAME_LENGTH, SIZE));
        }
        free(ifNames);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

HWTEST_F(WifiHalTest, GetNetDevInfo001, TestSize.Level1)
{
    int ret;
    struct IWiFiAp *apFeature = nullptr;
    struct NetDeviceInfoResult netDeviceInfoResult;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = g_wifi->getNetDevInfo(nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getNetDevInfo(&netDeviceInfoResult);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

HWTEST_F(WifiHalTest, GetNetDevInfo002, TestSize.Level1)
{
    int ret;
    struct IWiFiSta *staFeature = nullptr;
    struct NetDeviceInfoResult netDeviceInfoResult;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = g_wifi->getNetDevInfo(nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getNetDevInfo(&netDeviceInfoResult);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: GetPowerModeTest_001
 * @tc.desc: Wifi hdi get power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, GetPowerMode001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    const char *ifName = "eth0";
    uint8_t mode;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        printf("GetPowerMode001: ifname is %s\n", apFeature->baseFeature.ifName);
        ret = g_wifi->getPowerMode(nullptr, &mode);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getPowerMode(ifName, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getPowerMode(ifName, &mode);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getPowerMode(apFeature->baseFeature.ifName, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getPowerMode(apFeature->baseFeature.ifName, &mode);
        printf("%s: ret = %d\n", __func__, ret);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: GetPowerModeTest_002
 * @tc.desc: Wifi hdi get power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, GetPowerMode002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "eth0";
    uint8_t mode;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        printf("GetPowerMode002: ifname is %s\n", staFeature->baseFeature.ifName);
        ret = g_wifi->getPowerMode(nullptr, &mode);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getPowerMode(ifName, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getPowerMode(ifName, &mode);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getPowerMode(staFeature->baseFeature.ifName, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getPowerMode(staFeature->baseFeature.ifName, &mode);
        printf("%s: ret = %d\n", __func__, ret);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetPowerMode001
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, SetPowerMode001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    const char *ifName = "eth0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        printf("SetPowerMode001: ifname is %s\n", apFeature->baseFeature.ifName);
        ret = g_wifi->setPowerMode(nullptr, WIFI_POWER_MODE_NUM);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(ifName, WIFI_POWER_MODE_NUM);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(apFeature->baseFeature.ifName, WIFI_POWER_MODE_NUM);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetPowerMode002
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, SetPowerMode002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    const char *ifName = "eth0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        printf("SetPowerMode002: ifname is %s\n", apFeature->baseFeature.ifName);
        ret = g_wifi->setPowerMode(nullptr, WIFI_POWER_MODE_SLEEPING);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(ifName, WIFI_POWER_MODE_SLEEPING);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(apFeature->baseFeature.ifName, WIFI_POWER_MODE_SLEEPING);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetPowerMode003
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, SetPowerMode003, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    const char *ifName = "eth0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        printf("SetPowerMode003: ifname is %s\n", apFeature->baseFeature.ifName);
        ret = g_wifi->setPowerMode(nullptr, WIFI_POWER_MODE_GENERAL);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(ifName, WIFI_POWER_MODE_GENERAL);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(apFeature->baseFeature.ifName, WIFI_POWER_MODE_GENERAL);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetPowerMode004
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, SetPowerMode004, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    const char *ifName = "eth0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        printf("SetPowerMode004: ifname is %s\n", apFeature->baseFeature.ifName);
        ret = g_wifi->setPowerMode(nullptr, WIFI_POWER_MODE_THROUGH_WALL);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(ifName, WIFI_POWER_MODE_THROUGH_WALL);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(apFeature->baseFeature.ifName, WIFI_POWER_MODE_THROUGH_WALL);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetPowerMode005
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, SetPowerMode005, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "eth0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        printf("SetPowerMode005: ifname is %s\n", staFeature->baseFeature.ifName);
        ret = g_wifi->setPowerMode(nullptr, WIFI_POWER_MODE_NUM);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(ifName, WIFI_POWER_MODE_NUM);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(staFeature->baseFeature.ifName, WIFI_POWER_MODE_NUM);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetPowerMode006
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, SetPowerMode006, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "eth0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        printf("SetPowerMode005: ifname is %s\n", staFeature->baseFeature.ifName);
        ret = g_wifi->setPowerMode(nullptr, WIFI_POWER_MODE_SLEEPING);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(ifName, WIFI_POWER_MODE_SLEEPING);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(staFeature->baseFeature.ifName, WIFI_POWER_MODE_SLEEPING);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetPowerMode007
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, SetPowerMode007, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "eth0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        printf("SetPowerMode005: ifname is %s\n", staFeature->baseFeature.ifName);
        ret = g_wifi->setPowerMode(nullptr, WIFI_POWER_MODE_GENERAL);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(ifName, WIFI_POWER_MODE_GENERAL);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(staFeature->baseFeature.ifName, WIFI_POWER_MODE_GENERAL);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetPowerMode008
 * @tc.desc: Wifi hdi set power mode function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, SetPowerMode008, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "eth0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        printf("SetPowerMode005: ifname is %s\n", staFeature->baseFeature.ifName);
        ret = g_wifi->setPowerMode(nullptr, WIFI_POWER_MODE_THROUGH_WALL);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(ifName, WIFI_POWER_MODE_THROUGH_WALL);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->setPowerMode(staFeature->baseFeature.ifName, WIFI_POWER_MODE_THROUGH_WALL);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalStartScan001
 * @tc.desc: Wifi hdi Start Scan function test
 * @tc.type: FUNC
 * @tc.require: AR000H60O7
 */
HWTEST_F(WifiHalTest, WifiHalStartScan001, TestSize.Level1)
{
    int ret;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "wlan0";
    const char *ifNameInvalid = "wlanTest";
    WifiScan scan = {0};

    ret = g_wifi->registerEventCallback(HalCallbackEvent, ifName);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(staFeature, nullptr);
        ret = staFeature->startScan(nullptr, &scan);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->startScan(ifName, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->startScan(ifNameInvalid, &scan);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->startScan(ifName, &scan);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(SCAN_TIME);
    }
}

/**
 * @tc.name: WifiHalCreateFeature003
 * @tc.desc: Wifi hal create feature function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, WifiHalCreateFeature003, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, nullptr);
    EXPECT_EQ(ret, HDF_FAILURE);
    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, nullptr);
    EXPECT_EQ(ret, HDF_FAILURE);

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_NUM, (struct IWiFiBaseFeature **)&staFeature);
    EXPECT_NE(HDF_SUCCESS, ret);
    ret = g_wifi->createFeature(-1, (struct IWiFiBaseFeature **)&staFeature);
    EXPECT_NE(HDF_SUCCESS, ret);
}

/**
 * @tc.name: WifiHalGetFeatureByIfName002
 * @tc.desc: Wifi hal get feature by ifname function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, WifiHalGetFeatureByIfName002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    struct IWiFiSta *staFeatureGet = nullptr;
    const char *ifName0 = "wlanTest";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = g_wifi->getFeatureByIfName(nullptr, (struct IWiFiBaseFeature **)&staFeature);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getFeatureByIfName(ifName0, (struct IWiFiBaseFeature **)&staFeature);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->getFeatureByIfName(staFeature->baseFeature.ifName, (struct IWiFiBaseFeature **)&staFeatureGet);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_NE(nullptr, staFeatureGet);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalRegisterEventCallback002
 * @tc.desc: Wifi hal register event callback test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, WifiHalRegisterEventCallback002, TestSize.Level1)
{
    int32_t ret;

    ret = g_wifi->registerEventCallback(nullptr, "wlan0");
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->registerEventCallback(HalCallbackEvent, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

/**
 * @tc.name: WifiHalUnRegisterEventCallback002
 * @tc.desc: Wifi hal unregister event callback test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, WifiHalUnRegisterEventCallback002, TestSize.Level1)
{
    int32_t ret;

    ret = g_wifi->unregisterEventCallback(nullptr, "wlan0");
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->unregisterEventCallback(HalCallbackEvent, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

/**
 * @tc.name: GetSupportFeature001
 * @tc.desc: Wifi hal get supported feature test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, GetSupportFeature001, TestSize.Level1)
{
    int32_t ret;
    uint8_t supType[PROTOCOL_80211_IFTYPE_NUM + 1] = {0};

    ret = g_wifi->getSupportFeature(nullptr, PROTOCOL_80211_IFTYPE_NUM + 1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->getSupportFeature(supType, PROTOCOL_80211_IFTYPE_NUM);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = g_wifi->getSupportFeature(supType, PROTOCOL_80211_IFTYPE_NUM + 1);
    EXPECT_EQ(RET_CODE_SUCCESS, ret);
}

/**
 * @tc.name: WifiHalGetNetworkIfaceName002
 * @tc.desc: Wifi hal get network iface name function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, WifiHalGetNetworkIfaceName002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        const char *ifnameTest = staFeature->baseFeature.getNetworkIfaceName(nullptr);
        EXPECT_EQ(nullptr, ifnameTest);
        const char *ifName = staFeature->baseFeature.getNetworkIfaceName((const struct IWiFiBaseFeature *)staFeature);
        EXPECT_NE(nullptr, ifName);
        if (strncmp(ifName, "wlan", 4) == 0 || strncmp(ifName, "nan", 3) == 0 || strncmp(ifName, "p2p", 3) == 0) {
            ret = 0;
        } else {
            ret = -1;
        }
        EXPECT_EQ(0, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalGetGetFeatureType002
 * @tc.desc: Wifi hal get feature type function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, WifiHalGetGetFeatureType002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    int32_t type;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        type = staFeature->baseFeature.getFeatureType(nullptr);
        EXPECT_EQ(HDF_FAILURE, type);
        type = staFeature->baseFeature.getFeatureType((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(PROTOCOL_80211_IFTYPE_STATION, type);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: GetDeviceMacAddress001
 * @tc.desc: Wifi hal get device's MAC address test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, GetDeviceMacAddress001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        unsigned char readMac[ETH_ADDR_LEN] = {0};
        ret = apFeature->baseFeature.getDeviceMacAddress(nullptr, readMac, ETH_ADDR_LEN);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.getDeviceMacAddress((struct IWiFiBaseFeature *)apFeature, nullptr, 0);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.getDeviceMacAddress((struct IWiFiBaseFeature *)apFeature, readMac, 0);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.getDeviceMacAddress((struct IWiFiBaseFeature *)apFeature, readMac, ETH_ADDR_LEN);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: GetDeviceMacAddress002
 * @tc.desc: Wifi hal get device's MAC address test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, GetDeviceMacAddress002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        unsigned char readMac[ETH_ADDR_LEN] = {0};
        ret = staFeature->baseFeature.getDeviceMacAddress(nullptr, readMac, ETH_ADDR_LEN);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.getDeviceMacAddress((struct IWiFiBaseFeature *)staFeature, nullptr, 0);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.getDeviceMacAddress((struct IWiFiBaseFeature *)staFeature, readMac, 0);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.getDeviceMacAddress((struct IWiFiBaseFeature *)staFeature, readMac, ETH_ADDR_LEN);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: GetValidFreqsWithBand001
 * @tc.desc: Wifi hal get valid frequency with specific band test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, GetValidFreqsWithBand001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    int32_t band = IEEE80211_BAND_2GHZ;
    int32_t bandNotSupport = IEEE80211_NUM_BANDS;
    int32_t freqs[MAX_CHANNEL_NUM] = {0};
    uint32_t size = MAX_CHANNEL_NUM;
    uint32_t num = 0;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->baseFeature.getValidFreqsWithBand(nullptr, band, freqs, size, &num);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)staFeature,
                                                            band, nullptr, size, &num);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)staFeature,
                                                            band, freqs, 10, &num);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)staFeature,
                                                            band, freqs, size, nullptr);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = staFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)staFeature,
                                                            bandNotSupport, freqs, size, &num);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)staFeature,
                                                            band, freqs, size, &num);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: GetValidFreqsWithBand002
 * @tc.desc: Wifi hal get valid frequency with specific band test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, GetValidFreqsWithBand002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    int32_t band = IEEE80211_BAND_2GHZ;
    int32_t bandNotSupport = IEEE80211_NUM_BANDS;
    int32_t freqs[MAX_CHANNEL_NUM] = {0};
    uint32_t size = MAX_CHANNEL_NUM;
    uint32_t num = 0;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = apFeature->baseFeature.getValidFreqsWithBand(nullptr, band, freqs, size, &num);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)apFeature,
                                                           band, nullptr, size, &num);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)apFeature, band, freqs, 10, &num);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)apFeature,
                                                           band, freqs, size, nullptr);
        EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
        ret = apFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)apFeature,
                                                           bandNotSupport, freqs, size, &num);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->baseFeature.getValidFreqsWithBand((struct IWiFiBaseFeature *)apFeature,
                                                           band, freqs, size, &num);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalSetTxPower002
 * @tc.desc: Wifi hal set transmit power function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, WifiHalSetTxPower002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->baseFeature.setTxPower(nullptr, WLAN_TX_POWER);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.setTxPower((struct IWiFiBaseFeature *)staFeature, -1);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.setTxPower((struct IWiFiBaseFeature *)staFeature, WLAN_TX_POWER);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiHalGetIfNamesByChipId002
 * @tc.desc: Obtain all ifNames and the number of the current chip
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, WifiHalGetIfNamesByChipId002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    char *ifNames = nullptr;
    unsigned int num = 0;
    unsigned char chipId = 0;
    uint8_t i;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = apFeature->baseFeature.getChipId((struct IWiFiBaseFeature *)apFeature, &chipId);
        ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = apFeature->baseFeature.getIfNamesByChipId(chipId, nullptr, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->baseFeature.getIfNamesByChipId(100, &ifNames, &num);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->baseFeature.getIfNamesByChipId(chipId, &ifNames, &num);
        EXPECT_NE(nullptr, ifNames);
        EXPECT_EQ(HDF_SUCCESS, ret);
        bool flag = (num <= IFNAME_MAX_NUM && num >= IFNAME_MIN_NUM);
        ASSERT_TRUE(flag);
        for (i = 0; i < num; i++) {
            EXPECT_EQ(0, strncmp("wlan", ifNames + i * MAX_IF_NAME_LENGTH, SIZE));
        }
        free(ifNames);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: HalGetChipId001
 * @tc.desc: wifi hal get chip ID function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, HalGetChipId001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    unsigned char chipId = 0;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->baseFeature.getChipId(nullptr, &chipId);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.getChipId((struct IWiFiBaseFeature *)staFeature, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->baseFeature.getChipId((struct IWiFiBaseFeature *)staFeature, &chipId);
        ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: HalGetChipId002
 * @tc.desc: wifi hal get chip ID function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, HalGetChipId002, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    unsigned char chipId = 0;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = apFeature->baseFeature.getChipId(nullptr, &chipId);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->baseFeature.getChipId((struct IWiFiBaseFeature *)apFeature, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->baseFeature.getChipId((struct IWiFiBaseFeature *)apFeature, &chipId);
        ASSERT_TRUE(chipId < MAX_WLAN_DEVICE);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: GetAssociatedStas001
 * @tc.desc: wifi hal get association state function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, GetAssociatedStas001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiAp *apFeature = nullptr;
    struct StaInfo staInfo[MAX_ASSOC_STA_NUM];
    (void)memset_s(staInfo, sizeof(StaInfo) * MAX_ASSOC_STA_NUM, 0, sizeof(StaInfo) * MAX_ASSOC_STA_NUM);
    uint32_t num = 0;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, apFeature);
        ret = apFeature->getAssociatedStas(nullptr, staInfo, MAX_ASSOC_STA_NUM, &num);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->getAssociatedStas(apFeature, nullptr, MAX_ASSOC_STA_NUM, &num);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->getAssociatedStas(apFeature, staInfo, 0, &num);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->getAssociatedStas(apFeature, staInfo, MAX_ASSOC_STA_NUM, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = apFeature->getAssociatedStas(apFeature, staInfo, MAX_ASSOC_STA_NUM, &num);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetScanningMacAddress001
 * @tc.desc: wifi hal set scanning MAC address function test
 * @tc.type: FUNC
 * @tc.require: AR000H603L
 */
HWTEST_F(WifiHalTest, SetScanningMacAddress001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    unsigned char scanMac[WIFI_MAC_ADDR_LENGTH] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->setScanningMacAddress(nullptr, scanMac, WIFI_MAC_ADDR_LENGTH);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->setScanningMacAddress(staFeature, nullptr, WIFI_MAC_ADDR_LENGTH);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->setScanningMacAddress(staFeature, scanMac, 0);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->setScanningMacAddress(staFeature, scanMac, WIFI_MAC_ADDR_LENGTH);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: SetProjectionScreenParam001
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require: AR000HDUEE
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam001, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->cmdId = TEST_CMD;
    param->bufLen = 1;
    param->buf[0] = 0;
    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(nullptr, nullptr);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->setProjectionScreenParam(apFeature->baseFeature.ifName, nullptr);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->setProjectionScreenParam(nullptr, param);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->setProjectionScreenParam(apFeature->baseFeature.ifName, param);
        EXPECT_NE(ret, HDF_SUCCESS);

        param->cmdId = CMD_CLOSE_GO_CAC;
        ret = g_wifi->setProjectionScreenParam(apFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam002
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam002, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->bufLen = 1;
    param->buf[0] = 0;
    param->cmdId = CMD_SET_GO_CSA_CHANNEL;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(apFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam003
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam003, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->bufLen = 1;
    param->buf[0] = 0;
    param->cmdId = CMD_SET_GO_RADAR_DETECT;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(apFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam004
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam004, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->bufLen = 1;
    param->buf[0] = 0;
    param->cmdId = CMD_ID_MCC_STA_P2P_QUOTA_TIME;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(apFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam005
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam005, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->bufLen = 1;
    param->buf[0] = 0;
    param->cmdId = CMD_ID_CTRL_ROAM_CHANNEL;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(apFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam006
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam006, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->cmdId = TEST_CMD;
    param->bufLen = 1;
    param->buf[0] = 0;
    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(nullptr, nullptr);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->setProjectionScreenParam(staFeature->baseFeature.ifName, nullptr);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->setProjectionScreenParam(nullptr, param);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->setProjectionScreenParam(staFeature->baseFeature.ifName, param);
        EXPECT_NE(ret, HDF_SUCCESS);

        param->cmdId = CMD_CLOSE_GO_CAC;
        ret = g_wifi->setProjectionScreenParam(staFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam007
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam007, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->bufLen = 1;
    param->buf[0] = 0;
    param->cmdId = CMD_SET_GO_CSA_CHANNEL;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(staFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam008
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam008, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->bufLen = 1;
    param->buf[0] = 0;
    param->cmdId = CMD_SET_GO_RADAR_DETECT;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(staFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam009
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam009, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->bufLen = 1;
    param->buf[0] = 0;
    param->cmdId = CMD_ID_MCC_STA_P2P_QUOTA_TIME;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(staFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SetProjectionScreenParam010
 * @tc.desc: wifi hal config projection screen function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SetProjectionScreenParam010, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    ProjectionScreenParam *param;

    param = (ProjectionScreenParam *)OsalMemCalloc(sizeof(ProjectionScreenParam) + TEST_PARAM_BUF_SIZE);
    EXPECT_NE(nullptr, param);
    param->bufLen = 1;
    param->buf[0] = 0;
    param->cmdId = CMD_ID_CTRL_ROAM_CHANNEL;

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->setProjectionScreenParam(staFeature->baseFeature.ifName, param);
        printf("SetProjectionScreenParam_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
    OsalMemFree(param);
}

/**
 * @tc.name: SendCmdIoctl001
 * @tc.desc: wifi hal send ioctl command function test
 * @tc.type: FUNC
 * @tc.require: AR000HDUEE
 */
HWTEST_F(WifiHalTest, SendCmdIoctl001, TestSize.Level1)
{
    int32_t cmdId = 0;
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    int8_t data[TEST_BUF_SIZE] = {0};
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->sendCmdIoctl(nullptr, cmdId, nullptr, TEST_BUF_SIZE);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, nullptr, TEST_BUF_SIZE);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->sendCmdIoctl(nullptr, cmdId, data, TEST_BUF_SIZE);
        EXPECT_NE(ret, HDF_SUCCESS);
        cmdId = CMD_HID2D_MODULE_INIT;
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, data, TEST_BUF_SIZE);
        printf("sendCmdIoctl_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SendCmdIoctl002
 * @tc.desc: wifi hal send ioctl command function test
 * @tc.type: FUNC
 * @tc.require: AR000HDUEE
 */
HWTEST_F(WifiHalTest, SendCmdIoctl002, TestSize.Level1)
{
    int32_t cmdId = 0;
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    int8_t data[TEST_BUF_SIZE] = {0};
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        cmdId = CMD_SET_BATTERY_LEVEL;
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, data, TEST_BUF_SIZE);
        printf("sendCmdIoctl_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SendCmdIoctl003
 * @tc.desc: wifi hal send ioctl command function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SendCmdIoctl003, TestSize.Level1)
{
    int32_t cmdId = 0;
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    int8_t data[TEST_BUF_SIZE] = {0};
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        cmdId = CMD_SET_SUPP_COEX_CHAN_LIST;
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, data, TEST_BUF_SIZE);
        printf("sendCmdIoctl_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SendCmdIoctl004
 * @tc.desc: wifi hal send ioctl command function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SendCmdIoctl004, TestSize.Level1)
{
    int32_t cmdId = 0;
    int32_t ret;
    bool flag;
    struct IWiFiAp *apFeature = nullptr;
    int8_t data[TEST_BUF_SIZE] = {0};
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        cmdId = CMD_SET_CHAN_ADJUST;
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, data, TEST_BUF_SIZE);
        printf("sendCmdIoctl_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SendCmdIoctl005
 * @tc.desc: wifi hal send ioctl command function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SendCmdIoctl005, TestSize.Level1)
{
    int32_t cmdId = 0;
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    int8_t data[TEST_BUF_SIZE] = {0};
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->sendCmdIoctl(nullptr, cmdId, nullptr, TEST_BUF_SIZE);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, nullptr, TEST_BUF_SIZE);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->sendCmdIoctl(nullptr, cmdId, data, TEST_BUF_SIZE);
        EXPECT_NE(ret, HDF_SUCCESS);

        cmdId = CMD_HID2D_MODULE_INIT;
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, data, TEST_BUF_SIZE);
        printf("sendCmdIoctl_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);

        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SendCmdIoctl006
 * @tc.desc: wifi hal send ioctl command function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SendCmdIoctl006, TestSize.Level1)
{
    int32_t cmdId = 0;
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    int8_t data[TEST_BUF_SIZE] = {0};
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        cmdId = CMD_SET_BATTERY_LEVEL;
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, data, TEST_BUF_SIZE);
        printf("sendCmdIoctl_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SendCmdIoctl007
 * @tc.desc: wifi hal send ioctl command function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SendCmdIoctl007, TestSize.Level1)
{
    int32_t cmdId = 0;
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    int8_t data[TEST_BUF_SIZE] = {0};
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        cmdId = CMD_SET_SUPP_COEX_CHAN_LIST;
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, data, TEST_BUF_SIZE);
        printf("sendCmdIoctl_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: SendCmdIoctl008
 * @tc.desc: wifi hal send ioctl command function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, SendCmdIoctl008, TestSize.Level1)
{
    int32_t cmdId = 0;
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    int8_t data[TEST_BUF_SIZE] = {0};
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        cmdId = CMD_SET_CHAN_ADJUST;
        ret = g_wifi->sendCmdIoctl(ifName, cmdId, data, TEST_BUF_SIZE);
        printf("sendCmdIoctl_%d: ret = %d\n", __LINE__, ret);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_DEV_ERR_NETDOWN);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetStationInfo001
 * @tc.desc: Wifi hdi get station information function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, GetStationInfo001, TestSize.Level1)
{
    int32_t ret;
    StationInfo info;
    bool flag;
    uint8_t mac[ETH_ADDR_LEN] = {0};
    struct IWiFiAp *apFeature = nullptr;
    const char *ifName = "wlan0";
    const char *ifNameInvalid = "wlanTest";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&apFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->getStationInfo(nullptr, nullptr, nullptr, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifName, nullptr, nullptr, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(nullptr, &info, nullptr, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(nullptr, nullptr, mac, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifName, &info, nullptr, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(nullptr, &info, mac, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifName, nullptr, mac, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifNameInvalid, &info, mac, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifName, &info, mac, ETH_ADDR_LEN);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)apFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetStationInfo002
 * @tc.desc: Wifi hdi get station information function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, GetStationInfo002, TestSize.Level1)
{
    int32_t ret;
    StationInfo info;
    bool flag;
    uint8_t mac[ETH_ADDR_LEN] = {0};
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_AP, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        ret = g_wifi->getStationInfo(nullptr, nullptr, nullptr, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifName, nullptr, nullptr, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(nullptr, &info, nullptr, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(nullptr, nullptr, mac, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifName, &info, nullptr, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(nullptr, &info, mac, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifName, nullptr, mac, ETH_ADDR_LEN);
        EXPECT_NE(ret, HDF_SUCCESS);
        ret = g_wifi->getStationInfo(ifName, &info, mac, ETH_ADDR_LEN);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(ret, HDF_SUCCESS);
    }
}

/**
 * @tc.name: GetSignalPollInfo001
 * @tc.desc: wifi hal get signal information function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, GetSignalPollInfo001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    const char *interfaceName = "wlan0";
    struct SignalResult signalResult;
    (void)memset_s(&signalResult, sizeof(signalResult), 0, sizeof(signalResult));

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->getSignalPollInfo(interfaceName, &signalResult);
        printf("getSignalPollInfo ret = %d.\n", ret);
        bool flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiStartChannelMeas001
 * @tc.desc: Wifi start channel meas and get meas result test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, StartChannelMeasTest001, TestSize.Level1)
{
    int32_t ret;
    const char *ifName = "wlan0";
    struct MeasParam measChannelParam;
    struct MeasResult measChannelResult = {0};
    measChannelParam.channelId = 1;
    measChannelParam.measTime = 15;

    ret = g_wifi->startChannelMeas(nullptr, &measChannelParam);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->startChannelMeas(ifName, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->startChannelMeas(ifName, &measChannelParam);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    ret = g_wifi->getChannelMeasResult(nullptr, &measChannelResult);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->getChannelMeasResult(ifName, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->getChannelMeasResult(ifName, &measChannelResult);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}

/**
 * @tc.name: HalRegisterHid2dCallback001
 * @tc.desc: Hal register hid2d callback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, HalRegisterHid2dCallback001, TestSize.Level1)
{
    int32_t ret;
    const char *ifName = "wlan0";

    ret = g_wifi->registerHid2dCallback(nullptr, ifName);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->registerHid2dCallback(Hid2dFunCb, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->registerHid2dCallback(Hid2dFunCb, ifName);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.name: HalUnregisterHid2dCallback001
 * @tc.desc: Hal unregister hid2d callback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, HalUnregisterHid2dCallback001, TestSize.Level1)
{
    int32_t ret;
    const char *ifName = "wlan0";

    ret = g_wifi->unregisterHid2dCallback(nullptr, ifName);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->unregisterHid2dCallback(Hid2dFunCb, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = g_wifi->unregisterHid2dCallback(Hid2dFunCb, ifName);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
 * @tc.name: WifiHalStartPnoScan001
 * @tc.desc: Wifi hal Start Scan function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, WifiHalStartPnoScan001, TestSize.Level1)
{
    int32_t ret;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "wlan0";
    WifiPnoSettings pnoSettings;
    (void)memset_s(&pnoSettings, sizeof(pnoSettings), 0, sizeof(pnoSettings));

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(staFeature, nullptr);
        ret = staFeature->startPnoScan(nullptr, &pnoSettings);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->startPnoScan(ifName, nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}
/**
 * @tc.name: WifiHalStartPnoScan002
 * @tc.desc: Wifi hal Start Scan function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, WifiHalStartPnoScan002, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "wlan0";
    string ssid1 = "xa-hw";
    string ssid2 = "xa-hw-03";
    WifiPnoSettings pnoSettings;
    (void)memset_s(&pnoSettings, sizeof(pnoSettings), 0, sizeof(pnoSettings));
    pnoSettings.min2gRssi = -120;
    pnoSettings.min5gRssi = -130;
    pnoSettings.scanIntervalMs = 60000;
    pnoSettings.scanIterations = 3;

    pnoSettings.pnoNetworksLen = 2;
    pnoSettings.pnoNetworks = (WifiPnoNetwork *)OsalMemCalloc(sizeof(WifiPnoNetwork) * 2);
    pnoSettings.pnoNetworks[0].isHidden = 1;
    memcpy_s(pnoSettings.pnoNetworks[0].ssid.ssid, MAX_SSID_LEN, ssid1.c_str(), ssid1.length());
    pnoSettings.pnoNetworks[0].ssid.ssidLen = ssid1.length();
    pnoSettings.pnoNetworks[1].isHidden = 0;
    memcpy_s(pnoSettings.pnoNetworks[1].ssid.ssid, MAX_SSID_LEN, ssid2.c_str(), ssid2.length());
    pnoSettings.pnoNetworks[1].ssid.ssidLen = ssid2.length();

    ret = g_wifi->registerEventCallback(HalCallbackEvent, ifName);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(staFeature, nullptr);
        ret = staFeature->startPnoScan(ifName, &pnoSettings);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        printf("ret = %d.\n", ret);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    ret = g_wifi->unregisterEventCallback(HalCallbackEvent, ifName);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMemFree(pnoSettings.pnoNetworks);
}

/**
 * @tc.name: WifiHalStopPnoScan001
 * @tc.desc: Wifi hal stop pno scan
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, WifiHalStopPnoScan001, TestSize.Level1)
{
    int32_t ret;
    bool flag;
    struct IWiFiSta *staFeature = nullptr;
    const char *ifName = "wlan0";

    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_STATION, (struct IWiFiBaseFeature **)&staFeature);
    if (ret == HDF_SUCCESS) {
        EXPECT_NE(nullptr, staFeature);
        ret = staFeature->stopPnoScan(nullptr);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = staFeature->stopPnoScan(ifName);
        flag = (ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ASSERT_TRUE(flag);
        ret = g_wifi->destroyFeature((struct IWiFiBaseFeature *)staFeature);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

/**
 * @tc.name: WifiSendActionFrame001
 * @tc.desc: Wifi send action frame factiom test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, WifiSendActionFrame001, TestSize.Level1)
{
    int32_t freq = WLAN_TX_POWER;
    uint8_t frameData[IFNAME_MAX_NUM - 1] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    uint32_t frameDataLen = IFNAME_MAX_NUM;
    const char *ifName = "wlan0";

    int32_t rc = g_wifi->sendActionFrame(nullptr, freq, frameData, frameDataLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wifi->sendActionFrame(ifName, 0, frameData, frameDataLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wifi->sendActionFrame(ifName, freq, nullptr, frameDataLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wifi->sendActionFrame(ifName, freq, frameData, 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    g_wifi->sendActionFrame(ifName, freq, frameData, frameDataLen);
}

/**
 * @tc.name: RegisterActionFrameReceiver001
 * @tc.desc: Wifi send action frame factiom test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiHalTest, RegisterActionFrameReceiver001, TestSize.Level1)
{
    uint8_t match[IFNAME_MAX_NUM - 1] = {0x12, 0x34, 0x56, 0x78, 0xab, 0xcd};
    uint32_t matchLen = IFNAME_MAX_NUM;
    const char *ifName = "wlan0";

    int32_t rc = g_wifi->registerActionFrameReceiver(nullptr, match, matchLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wifi->registerActionFrameReceiver(ifName, nullptr, matchLen);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_wifi->registerActionFrameReceiver(ifName, match, 0);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    g_wifi->registerActionFrameReceiver(ifName, match, matchLen);
}

/**
 * @tc.name: WifiHalGetGetFeatureType001
 * @tc.desc: Wifi hal get feature type function test
 * @tc.type: FUNC
 * @tc.require: AR000F869G
 */
HWTEST_F(WifiHalTest, InitFeatureByType001, TestSize.Level1)
{
    int ret;
    struct IWiFiP2p *p2pFeature = nullptr;
    ret = g_wifi->createFeature(PROTOCOL_80211_IFTYPE_P2P_DEVICE, nullptr);
    EXPECT_EQ(ret, HDF_FAILURE);
    g_wifi->createFeature(PROTOCOL_80211_IFTYPE_P2P_DEVICE, (struct IWiFiBaseFeature **)&p2pFeature);
}
}; // namespace HalTest
