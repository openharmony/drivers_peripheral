/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <hdf_log.h>
#include "../../../chip/hdi_service/iface_tool.h"
#include "../../../chip/hdi_service/wifi_chip.h"
#include "wifi_hal_fn.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiChipTest {
    
const std::string TEST_AP_IFNAME = "wlan1";
const std::string TEST_STA_IFNAME = "wlan0";
const std::string TEST_P2P_IFNAME = "p2p0";

class WifiChipTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        int32_t chipId = 0;
        bool isPrimary = true;
        ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn;
        InitWifiHalFuncTable(&fn);
        wifiVendorHalTest = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
        wifiChip = new WifiChip(chipId, isPrimary, wifiVendorHalTest,
            std::make_shared<IfaceUtil>(ifaceTool), HandlerMock);
    }
    void TearDown() {}

    static void HandlerMock(const std::string& ifName)
    {
        HDF_LOGI("HandlerMock enter");
    }

public:
    std::shared_ptr<WifiVendorHal> wifiVendorHalTest;
    std::shared_ptr<IfaceTool> ifaceTool;
    sptr<WifiChip> wifiChip;
};

/**
 * @tc.name: GetCurrentModeTest
 * @tc.desc: GetCurrentMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiChipTest, GetCurrentModeTest, TestSize.Level1)
{
    HDF_LOGI("GetCurrentModeTest started");
    uint32_t modeId = -1;
    if (wifiChip == nullptr) {
        HDF_LOGE("wifiChip is null");
        return;
    }
    EXPECT_TRUE(wifiChip->GetCurrentMode(modeId) == HDF_ERR_INVALID_PARAM);
    modeId = 0;
    wifiChip->GetCurrentMode(modeId);
    wifiChip->RegisterChipEventCallback(nullptr);
}

/**
 * @tc.name: SetChipModeTest
 * @tc.desc: SetChipMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiChipTest, SetChipModeTest, TestSize.Level1)
{
    HDF_LOGI("SetChipModeTest started");
    uint32_t modeId = UINT32_MAX;
    if (wifiChip == nullptr) {
        HDF_LOGE("wifiChip is null");
        return;
    }
    EXPECT_TRUE(wifiChip->SetChipMode(modeId) == HDF_FAILURE);
}

/**
 * @tc.name: CreateApServiceTest
 * @tc.desc: CreateApService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiChipTest, CreateApServiceTest, TestSize.Level1)
{
    HDF_LOGI("CreateApServiceTest started");
    if (wifiChip == nullptr) {
        HDF_LOGE("wifiChip is null");
        return;
    }
    std::vector<std::string> instances;
    std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
    WifiHalFn fn;
    std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
    sptr<IChipIface> apIface = new (std::nothrow) WifiApIface(TEST_AP_IFNAME, instances, vendorHal,
        std::make_shared<IfaceUtil>(ifaceTool));
    wifiChip->CreateApService(apIface);
    std::vector<std::string> ifnames;
    wifiChip->GetApServiceIfNames(ifnames);
    std::string ifname1;
    wifiChip->GetApService(ifname1, apIface);
    wifiChip->RemoveApService(ifname1);
    EXPECT_TRUE(wifiChip->GetApServiceIfNames(ifnames) == HDF_FAILURE);
    EXPECT_TRUE(wifiChip->GetApService(ifname1, apIface) == HDF_FAILURE);
}

/**
 * @tc.name: CreateP2pIfaceTest
 * @tc.desc: CreateP2pIface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiChipTest, CreateP2pIfaceTest, TestSize.Level1)
{
    HDF_LOGI("CreateP2pIfaceTest started");
    if (wifiChip == nullptr) {
        HDF_LOGE("wifiChip is null");
        return;
    }
    std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
    WifiHalFn fn;
    std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
    sptr<IChipIface> p2pIface = new (std::nothrow) WifiP2pIface(TEST_P2P_IFNAME, vendorHal,
        std::make_shared<IfaceUtil>(ifaceTool));
    wifiChip->CreateP2pService(p2pIface);
    std::vector<std::string> ifnames;
    wifiChip->GetP2pServiceIfNames(ifnames);
    std::string ifname1;
    wifiChip->GetP2pService(ifname1, p2pIface);
    wifiChip->RemoveP2pService(ifname1);
    EXPECT_TRUE(wifiChip->GetP2pServiceIfNames(ifnames) == HDF_FAILURE);
    EXPECT_TRUE(wifiChip->GetP2pService(ifname1, p2pIface) == HDF_FAILURE);
}

/**
 * @tc.name: CreateStaIfaceTest
 * @tc.desc: CreateStaIface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiChipTest, CreateStaIfaceTest, TestSize.Level1)
{
    HDF_LOGI("CreateStaIfaceTest started");
    if (wifiChip == nullptr) {
        HDF_LOGE("wifiChip is null");
        return;
    }
    std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
    WifiHalFn fn;
    std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
    sptr<IChipIface> staIface = new (std::nothrow) WifiStaIface(TEST_STA_IFNAME, vendorHal,
        std::make_shared<IfaceUtil>(ifaceTool));
    wifiChip->CreateStaService(staIface);

    std::vector<std::string> ifnames;
    wifiChip->GetStaServiceIfNames(ifnames);
    std::string ifname1;
    wifiChip->GetStaService(ifname1, staIface);
    wifiChip->RemoveStaService(ifname1);
    EXPECT_TRUE(wifiChip->GetStaServiceIfNames(ifnames) == HDF_FAILURE);
    EXPECT_TRUE(wifiChip->GetStaService(ifname1, staIface) == HDF_FAILURE);
}
}

