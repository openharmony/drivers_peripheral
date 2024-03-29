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
#include "../../../chip/hdi_service/interface_tool.h"
#include "../../../chip/hdi_service/wifi_chip.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiChipTest {
class WifiChipTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        int32_t chipId = 0;
        bool isPrimary = true;
        std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn;
        const std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(
            ifaceTool, fn, isPrimary);
        const std::weak_ptr<WifiChipModes> chipModes = std::make_shared<WifiChipModes>();
        wifiChip = new WifiChip(chipId, isPrimary, vendorHal, chipModes, handlerMock);
    }
    void TearDown() {}

    static void handlerMock(const std::string& ifName)
    {
        HDF_LOGI("handlerMock enter");
    }

public:
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
    HDF_LOGI("GetCurrentModeTest start");
    uint32_t modeId = -1;
    if (wifiChip == nullptr) {
        return;
    }
    EXPECT_TRUE(wifiChip->GetCurrentMode(modeId) == HDF_ERR_INVALID_PARAM);
    modeId = 0;
    wifiChip->GetCurrentMode(modeId);
}

/**
 * @tc.name: SetChipModeTest
 * @tc.desc: SetChipMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiChipTest, SetChipModeTest, TestSize.Level1)
{
    HDF_LOGI("SetChipModeTest start");
    uint32_t modeId = -1;
    if (wifiChip == nullptr) {
        return;
    }
    EXPECT_TRUE(wifiChip->SetChipMode(modeId) == HDF_FAILURE);
    wifiChip->SetChipMode(0);
}

/**
 * @tc.name: CreateApServiceTest
 * @tc.desc: CreateApService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiChipTest, CreateApServiceTest, TestSize.Level1)
{
    HDF_LOGI("CreateApServiceTest start");
    if (wifiChip == nullptr) {
        return;
    }
    std::string ifname = "ap";
    std::vector<std::string> instances;
    std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
    WifiHalFn fn;
    std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
    sptr<IChipIface> apIface = new (std::nothrow) WifiApIface(ifname, instances, vendorHal);
    wifiChip->CreateApService(apIface);
    std::vector<std::string> ifnames;
    EXPECT_TRUE(wifiChip->GetApServiceIfNames(ifnames) == HDF_SUCCESS);
    std::string ifname1;
    EXPECT_TRUE(wifiChip->GetApService(ifname1, apIface) == HDF_SUCCESS);
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
    HDF_LOGI("CreateP2pIfaceTest start");
    if (wifiChip == nullptr) {
        return;
    }
    std::string ifname = "P2P";
    std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
    WifiHalFn fn;
    std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
    sptr<IChipIface> p2pIface = new (std::nothrow) WifiP2pIface(ifname, vendorHal);
    wifiChip->CreateP2pService(p2pIface);

    std::vector<std::string> ifnames;
    EXPECT_TRUE(wifiChip->GetP2pServiceIfNames(ifnames) == HDF_SUCCESS);
    std::string ifname1;
    EXPECT_TRUE(wifiChip->GetP2pService(ifname1, p2pIface) == HDF_SUCCESS);
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
    HDF_LOGI("CreateStaIfaceTest start");
    if (wifiChip == nullptr) {
        return;
    }
    std::string ifname = "wlan0";
    std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
    WifiHalFn fn;
    std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
    sptr<IChipIface> staIface = new (std::nothrow) WifiStaIface(ifname, vendorHal);
    wifiChip->CreateStaService(staIface);

    std::vector<std::string> ifnames;
    EXPECT_TRUE(wifiChip->GetStaServiceIfNames(ifnames) == HDF_SUCCESS);
    std::string ifname1;
    EXPECT_TRUE(wifiChip->GetStaService(ifname1, staIface) == HDF_SUCCESS);
    wifiChip->RemoveStaService(ifname1);
    EXPECT_TRUE(wifiChip->GetStaServiceIfNames(ifnames) == HDF_FAILURE);
    EXPECT_TRUE(wifiChip->GetStaService(ifname1, staIface) == HDF_FAILURE);
}
}

