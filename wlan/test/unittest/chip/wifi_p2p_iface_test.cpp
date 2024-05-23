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
#include "../../../chip/hdi_service/wifi_p2p_iface.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiP2pIfaceTest {
const std::string P2P_IFNAME = "P2P0";
const std::string TEST_MAC = "000000";

class WifiP2pIfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        std::weak_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn;
        std::weak_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
        p2pIface = new (std::nothrow) WifiP2pIface(P2P_IFNAME, vendorHal,
            std::make_shared<IfaceUtil>(ifaceTool));
        if (p2pIface == nullptr) {
            HDF_LOGE("iface is null");
            return;
        }
    }
    void TearDown()
    {
        delete p2pIface;
        if (p2pIface != nullptr) {
            p2pIface = nullptr;
        }
    }

public:
    sptr<WifiP2pIface> p2pIface;
};

/**
 * @tc.name: WifiP2pIfaceTest
 * @tc.desc: WifiP2pIface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiP2pIfaceTest, WifiP2pIfaceTest, TestSize.Level1)
{
    HDF_LOGI("WifiP2pIfaceTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    p2pIface->Invalidate();
    EXPECT_FALSE(p2pIface->IsValid());
    EXPECT_TRUE(p2pIface->GetName() == P2P_IFNAME);
    IfaceType type = IfaceType::STA;
    EXPECT_TRUE(p2pIface->GetIfaceType(type) == HDF_SUCCESS);
    EXPECT_TRUE(type == IfaceType::P2P);
    std::string name;
    EXPECT_TRUE(p2pIface->GetIfaceName(name) == HDF_SUCCESS);
    EXPECT_TRUE(name == P2P_IFNAME);
    std::vector<uint32_t> frequencies;
    EXPECT_TRUE(p2pIface->GetSupportFreqs(1, frequencies) == HDF_SUCCESS);
}

HWTEST_F(WifiP2pIfaceTest, SetMacAddressTest, TestSize.Level1)
{
    HDF_LOGI("SetMacAddressTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(p2pIface->SetMacAddress(TEST_MAC) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, SetCountryCodeTest, TestSize.Level1)
{
    HDF_LOGI("SetCountryCodeTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(p2pIface->SetCountryCode("CN") == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, GetPowerModeTest, TestSize.Level1)
{
    HDF_LOGI("GetPowerModeTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    int32_t mode;
    EXPECT_TRUE(p2pIface->GetPowerMode(mode) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, SetPowerModeTest, TestSize.Level1)
{
    HDF_LOGI("SetPowerModeTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(p2pIface->SetPowerMode(0) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, GetIfaceCapTest, TestSize.Level1)
{
    HDF_LOGI("GetIfaceCapTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    uint32_t cap;
    EXPECT_TRUE(p2pIface->GetIfaceCap(cap) == HDF_SUCCESS);
}

HWTEST_F(WifiP2pIfaceTest, StartScanTest, TestSize.Level1)
{
    HDF_LOGI("StartScanTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    ScanParams scanParam;
    scanParam.bssid = TEST_MAC;
    EXPECT_TRUE(p2pIface->StartScan(scanParam) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, GetScanInfosTest, TestSize.Level1)
{
    HDF_LOGI("GetScanInfosTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    std::vector<ScanResultsInfo> scanResult;
    EXPECT_TRUE(p2pIface->GetScanInfos(scanResult) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, StartPnoScanTest, TestSize.Level1)
{
    HDF_LOGI("StartPnoScanTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    PnoScanParams pnoParam;
    pnoParam.min2gRssi = 1;
    EXPECT_TRUE(p2pIface->StartPnoScan(pnoParam) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, StopPnoScanTest, TestSize.Level1)
{
    HDF_LOGI("StopPnoScanTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(p2pIface->StopPnoScan() == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, GetSignalPollInfoTest, TestSize.Level1)
{
    HDF_LOGI("GetSignalPollInfoTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    SignalPollResult info;
    EXPECT_TRUE(p2pIface->GetSignalPollInfo(info) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, SetDpiMarkRuleTest, TestSize.Level1)
{
    HDF_LOGI("SetDpiMarkRuleTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(p2pIface->SetDpiMarkRule(0, 0, 0) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiP2pIfaceTest, EnablePowerModeTest, TestSize.Level1)
{
    HDF_LOGI("EnablePowerModeTest started");
    if (p2pIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(p2pIface->EnablePowerMode(0) == HDF_ERR_NOT_SUPPORT);
}
}