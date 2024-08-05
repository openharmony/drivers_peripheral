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
#include <securec.h>

#define IFNAME "wlan0"

#define HDF_LOG_TAG service_manager_test
using namespace testing::ext;

namespace HdiHostapdDirectTest {
const char *g_hdiServiceNameHostapd = "hostapd_interface_service";

class HdfHostapdHostDirectTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static struct IHostapdInterface *g_hostapdObj = nullptr;
struct IHostapdCallback *g_hostapdCallbackObj = nullptr;
void HdfHostapdHostDirectTest::SetUpTestCase()
{
    g_hostapdObj = IHostapdInterfaceGetInstance(g_hdiServiceNameHostapd, true);
    g_hostapdCallbackObj = HostapdCallbackServiceGet();
    ASSERT_TRUE(g_hostapdObj != nullptr);
    ASSERT_TRUE(g_hostapdCallbackObj != nullptr);
    printf("hostapd_interface_service start successful.");
}

void HdfHostapdHostDirectTest::TearDownTestCase()
{
    IHostapdInterfaceReleaseInstance(g_hdiServiceNameHostapd, g_hostapdObj, true);
    HostapdCallbackServiceRelease(g_hostapdCallbackObj);
    printf("hostapd_interface_service stop successful.");
}

void HdfHostapdHostDirectTest::SetUp()
{
}

void HdfHostapdHostDirectTest::TearDown()
{
}

/**
 * @tc.name: EnableApTest_001
 * @tc.desc: Hostapd enable ap feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, EnableApTest_001, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->EnableAp(g_hostapdObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->EnableAp(g_hostapdObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: DisableApTest_002
 * @tc.desc: Hostapd disable ap feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, DisableApTest_002, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->DisableAp(g_hostapdObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->DisableAp(g_hostapdObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: SetApPasswdTest_003
 * @tc.desc: Hostapd hdi set ap passwd feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetApPasswdTest_003, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApPasswd(g_hostapdObj, IFNAME, "123123123", 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->SetApPasswd(g_hostapdObj, nullptr, "123123123", 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_hostapdObj->SetApPasswd(g_hostapdObj, IFNAME, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: SetApNameTest_004
 * @tc.desc: Hostapd hdi set ap name feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetApNameTest_004, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApName(g_hostapdObj, IFNAME, "SFG001", 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->SetApName(g_hostapdObj, nullptr, "SFG001", 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_hostapdObj->SetApName(g_hostapdObj, IFNAME, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: SetApWpaValueTest_005
 * @tc.desc: Hostapd hdi set ap WpaValue feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetApWpaValueTest_005, TestSize.Level1)
{
}

/**
 * @tc.name: SetApBandTest_006
 * @tc.desc: Hostapd hdi set ap band feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetApBandTest_006, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApBand(g_hostapdObj, IFNAME, 6, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->SetApBand(g_hostapdObj, nullptr, 1, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: SetAp80211nTest_007
 * @tc.desc: Hostapd hdi set ap 80211n feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetAp80211nTest_007, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetAp80211n(g_hostapdObj, IFNAME, 1, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->SetAp80211n(g_hostapdObj, nullptr, 1, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: SetApWmmTest_008
 * @tc.desc: Hostapd hdi set ap Wmm feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetApWmmTest_008, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApWmm(g_hostapdObj, IFNAME, 1, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->SetApWmm(g_hostapdObj, nullptr, 1, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: SetApChannelTest_009
 * @tc.desc: Hostapd hdi set ap channel feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetApChannelTest_009, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApChannel(g_hostapdObj, IFNAME, 6, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->SetApChannel(g_hostapdObj, nullptr, 6, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: SetApMaxConnTest_010
 * @tc.desc: Hostapd hdi set ap MaxConn feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetApMaxConnTest_010, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetApMaxConn(g_hostapdObj, IFNAME, 3, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->SetApMaxConn(g_hostapdObj, nullptr, 3, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: SetMacFilterTest_011
 * @tc.desc: Hostapd hdi set mac filter feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, SetMacFilterTest_011, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->SetMacFilter(g_hostapdObj, IFNAME, "34:3a:20:32:fb:31", 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->SetMacFilter(g_hostapdObj, nullptr, "34:3a:20:32:fb:31", 2);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_hostapdObj->SetMacFilter(g_hostapdObj, IFNAME, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: DelMacFilterTest_012
 * @tc.desc: Hostapd hdi del mac filter feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, DelMacFilterTest_012, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->DelMacFilter(g_hostapdObj, IFNAME, "34:3a:20:32:fb:31", 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->DelMacFilter(g_hostapdObj, nullptr, "34:3a:20:32:fb:31", 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_hostapdObj->DelMacFilter(g_hostapdObj, IFNAME, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: GetStaInfosTest_013
 * @tc.desc: Hostapd hdi get sta infos feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, GetStaInfosTest_013, TestSize.Level1)
{
    char *buf = (char *)calloc(4096 * 10, sizeof(char));
    const uint32_t bufLen = 4096*10;
    const int32_t size = 1024;
    int32_t rc = g_hostapdObj->GetStaInfos(g_hostapdObj, IFNAME, buf, bufLen, size, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->GetStaInfos(g_hostapdObj, nullptr, buf, bufLen, size, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_hostapdObj->GetStaInfos(g_hostapdObj, IFNAME, nullptr, bufLen, size, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: DisassociateStaTest_014
 * @tc.desc: Hostapd hdi disassociate sta feature function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, DisassociateStaTest_014, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->DisassociateSta(g_hostapdObj, IFNAME, "34:3a:20:32:fb:31", 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->DisassociateSta(g_hostapdObj, nullptr, "34:3a:20:32:fb:31", 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_hostapdObj->DisassociateSta(g_hostapdObj, IFNAME, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: HostApdShellCmdTest_015
 * @tc.desc: Wifi hdi HostApdShellCmd function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, HostApdShellCmdTest_015, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->HostApdShellCmd(g_hostapdObj, IFNAME, "");
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->HostApdShellCmd(g_hostapdObj, nullptr, "");
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
    rc = g_hostapdObj->HostApdShellCmd(g_hostapdObj, IFNAME, nullptr);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: StartApTest_016
 * @tc.desc: Wifi hdi StartAp function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, StartApTest_016, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->StartAp(g_hostapdObj);
    ASSERT_EQ(rc, HDF_FAILURE);
}

/**
 * @tc.name: StartApWithCmdTest_017
 * @tc.desc: Wifi hdi StartApWithCmd function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, StartApWithCmdTest_017, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->StartApWithCmd(g_hostapdObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->StartApWithCmd(g_hostapdObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}

/**
 * @tc.name: StopApTest_018
 * @tc.desc: Wifi hdi StopAp function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, StopApTest_018, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->StopAp(g_hostapdObj);
    ASSERT_EQ(rc, HDF_FAILURE);
}

/**
 * @tc.name: ReloadApConfigInfoTest_019
 * @tc.desc: Wifi hdi ReloadApConfigInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HdfHostapdHostDirectTest, ReloadApConfigInfoTest_019, TestSize.Level1)
{
    int32_t rc = g_hostapdObj->ReloadApConfigInfo(g_hostapdObj, IFNAME, 1);
    ASSERT_EQ(rc, HDF_FAILURE);
    rc = g_hostapdObj->ReloadApConfigInfo(g_hostapdObj, nullptr, 1);
    ASSERT_EQ(rc, HDF_ERR_INVALID_PARAM);
}
};
