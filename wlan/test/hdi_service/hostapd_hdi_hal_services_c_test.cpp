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
#include "v1_0/ihostapd_interface.h"
#include "hostapd_callback_impl.h"
#include "securec.h"

#define IFNAME "wlan0"

#define HDF_LOG_TAG service_manager_test
using namespace testing::ext;

namespace HdiApTest {
const char *g_hdiServiceNameHostapd = "hostapd_interface_service";

class HdfHostapdHostCTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static struct IHostapdInterface *g_hostapdObj = nullptr;
struct IHostapdCallback *g_hostapdCallbackObj = nullptr;
void HdfHostapdHostCTest::SetUpTestCase()
{
    g_hostapdObj = IHostapdInterfaceGetInstance(g_hdiServiceNameHostapd, false);
    g_hostapdCallbackObj = HostapdCallbackServiceGet();
    ASSERT_TRUE(g_hostapdObj != nullptr);
    ASSERT_TRUE(g_hostapdCallbackObj != nullptr);
    int32_t rc = g_hostapdObj->StartApWithCmd(g_hostapdObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
    printf("hostapd_interface_service start successful.");
}

void HdfHostapdHostCTest::TearDownTestCase()
{
    int32_t rc = g_hostapdObj->StopAp(g_hostapdObj);
    ASSERT_EQ(rc, HDF_SUCCESS);
    IHostapdInterfaceReleaseInstance(g_hdiServiceNameHostapd, g_hostapdObj, false);
    HostapdCallbackServiceRelease(g_hostapdCallbackObj);
    printf("hostapd_interface_service stop successful.");
}

void HdfHostapdHostCTest::SetUp()
{
}

void HdfHostapdHostCTest::TearDown()
{
}

/**
 * @tc.name: EnableApTest_001
 * @tc.desc: Wifi hdi Add Hostapd Iface function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, EnableApTest_001, TestSize.Level1)
{
    printf("Ready enter to DisableAp.");
    int32_t rc = g_hostapdObj->DisableAp(g_hostapdObj, IFNAME, 1);
    if (rc == HDF_SUCCESS) {
        printf("Ready enter to EnableAp.");
        rc = g_hostapdObj->EnableAp(g_hostapdObj, IFNAME, 1);
        ASSERT_EQ(rc, HDF_SUCCESS);
    }
    printf("ifName EnableAP succ.");
}

/**
 * @tc.name: SetApPasswdTest_002
 * @tc.desc: Wifi hdi set ap passwd function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetApPasswdTest_002, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApPasswd(g_hostapdObj, IFNAME, "123456789", 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
    printf("ready to enter DisableAp in HdfHostapdHostCTest.");
    printf("DisableAp done in HdfHostapdHostCTest.");
}

/**
 * @tc.name: SetApNameTest_003
 * @tc.desc: Wifi hdi set ap name function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetApNameTest_003, TestSize.Level1)
{
    printf("ready to enter EnableAp in HdfHostapdHostCTest.");
    printf("ready to enter SetApName in HdfHostapdHostCTest.");
    int32_t rc = g_hostapdObj->SetApName(g_hostapdObj, IFNAME, "SFG001", 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
    printf("ready to enter DisableAp in HdfHostapdHostCTest.");
}

/**
 * @tc.name: SetApWpaValueTest_004
 * @tc.desc: Wifi hdi set ap WpaValue function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetApWpaValueTest_004, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApWpaValue(g_hostapdObj, IFNAME, 2, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

 /**
 * @tc.name: SetApBandTest_005
 * @tc.desc: Wifi hdi set ap band function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetApBandTest_005, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApBand(g_hostapdObj, IFNAME, 1, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

 /**
 * @tc.name: SetAp80211nTest_006
 * @tc.desc: Wifi hdi set ap 80211n function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetAp80211nTest_006, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetAp80211n(g_hostapdObj, IFNAME, 1, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

 /**
 * @tc.name: SetApWmmTest_007
 * @tc.desc: Wifi hdi set ap Wmm function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetApWmmTest_007, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApWmm(g_hostapdObj, IFNAME, 1, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetApChannelTest_008
 * @tc.desc: Wifi hdi set ap channel function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetApChannelTest_008, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApChannel(g_hostapdObj, IFNAME, 6, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetApMaxConnTest_009
 * @tc.desc: Wifi hdi set ap MaxConn function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetApMaxConnTest_009, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApMaxConn(g_hostapdObj, IFNAME, 3, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: SetMacFilterTest_010
 * @tc.desc: Wifi hdi set mac filter function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, SetMacFilterTest_010, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetMacFilter(g_hostapdObj, IFNAME, "34:3a:20:32:fb:31", 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: DelMacFilterTest_011
 * @tc.desc: Wifi hdi del mac filter function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, DelMacFilterTest_011, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->DelMacFilter(g_hostapdObj, IFNAME, "34:3a:20:32:fb:31", 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: GetStaInfosTest_012
 * @tc.desc: Wifi hdi get sta infos function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, GetStaInfosTest_012, TestSize.Level1)
{
    char *buf = (char *)calloc(4096 * 10, sizeof(char));
    uint32_t bufLen = 4096 * 10;
    int32_t size = 1024;
    int32_t rc = g_hostapdObj->GetStaInfos(g_hostapdObj, IFNAME, buf, bufLen, size, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
    free(buf);
}

/**
 * @tc.name: DisassociateStaTest_013
 * @tc.desc: Wifi hdi disassociate sta function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, DisassociateStaTest_013, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->DisassociateSta(g_hostapdObj, IFNAME, "34:3a:20:32:fb:31", 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: HostApdShellCmdTest_015
 * @tc.desc: Wifi hdi HostApdShellCmd function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, HostApdShellCmdTest_015, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->HostApdShellCmd(g_hostapdObj, IFNAME, "");
    ASSERT_EQ(rc, HDF_SUCCESS);
}

/**
 * @tc.name: ReloadApConfigInfo_016
 * @tc.desc: Wifi hdi ReloadApConfigInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostCTest, ReloadApConfigInfo_016, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->ReloadApConfigInfo(g_hostapdObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_SUCCESS);
}

};
