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
#include "../../../chip/hdi_service/wifi_ap_iface.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiApIfaceTest {
const std::string AP_IFNAME = "wlan1";
const std::string TEST_MAC = "000000";
class WifiApIfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        std::vector<std::string> instances;
        std::shared_ptr<IfaceTool> ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn;
        std::shared_ptr<WifiVendorHal> vendorHal = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
        apIface = new (std::nothrow) WifiApIface(AP_IFNAME, instances, vendorHal,
            std::make_shared<IfaceUtil>(ifaceTool));
        if (apIface == nullptr) {
            HDF_LOGE("iface is null");
            return;
        }
    }
    void TearDown()
    {
        delete apIface;
        if (apIface != nullptr) {
            apIface = nullptr;
        }
    }

public:
    sptr<WifiApIface> apIface;
};

/**
 * @tc.name: wifiApIfaceTest
 * @tc.desc: wifiApIface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiApIfaceTest, wifiApIfaceTest001, TestSize.Level1)
{
    HDF_LOGI("wifiApIfaceTest001 started");
    if (apIface == nullptr) {
        return;
    }
    apIface->Invalidate();
    EXPECT_FALSE(apIface->IsValid());
    EXPECT_TRUE(apIface->GetName() == AP_IFNAME);
    apIface->RemoveInstance(AP_IFNAME);
    IfaceType type;
    EXPECT_TRUE(apIface->GetIfaceType(type) == HDF_SUCCESS);
    EXPECT_TRUE(type == IfaceType::AP);
    std::string name;
    EXPECT_TRUE(apIface->GetIfaceName(name) == HDF_SUCCESS);
    EXPECT_TRUE(name == AP_IFNAME);
}

/**
 * @tc.name: GetIfaceCapTest
 * @tc.desc: GetIfaceCap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiApIfaceTest, GetIfaceCapTest, TestSize.Level1)
{
    HDF_LOGI("GetIfaceCapTest started");
    if (apIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    uint32_t cap;
    EXPECT_TRUE(apIface->GetIfaceCap(cap) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiApIfaceTest, StartScanTest, TestSize.Level1)
{
    HDF_LOGI("StartScanTest started");
    if (apIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    ScanParams scanParam;
    scanParam.bssid = TEST_MAC;
    EXPECT_TRUE(apIface->StartScan(scanParam) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiApIfaceTest, GetScanInfosTest, TestSize.Level1)
{
    HDF_LOGI("GetScanInfosTest started");
    if (apIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    std::vector<ScanResultsInfo> scanResult;
    EXPECT_TRUE(apIface->GetScanInfos(scanResult) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiApIfaceTest, StartPnoScanTest, TestSize.Level1)
{
    HDF_LOGI("StartPnoScanTest started");
    if (apIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    PnoScanParams pnoParam;
    pnoParam.min2gRssi = 1;
    EXPECT_TRUE(apIface->StartPnoScan(pnoParam) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiApIfaceTest, StopPnoScanTest, TestSize.Level1)
{
    HDF_LOGI("StopPnoScanTest started");
    if (apIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(apIface->StopPnoScan() == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiApIfaceTest, GetSignalPollInfoTest, TestSize.Level1)
{
    HDF_LOGI("GetSignalPollInfoTest started");
    if (apIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    SignalPollResult info;
    EXPECT_TRUE(apIface->GetSignalPollInfo(info) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiApIfaceTest, SetDpiMarkRuleTest, TestSize.Level1)
{
    HDF_LOGI("SetDpiMarkRuleTest started");
    if (apIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(apIface->SetDpiMarkRule(0, 0, 0) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiApIfaceTest, EnablePowerModeTest, TestSize.Level1)
{
    HDF_LOGI("EnablePowerModeTest started");
    if (apIface == nullptr) {
        HDF_LOGE("iface is null");
        return;
    }
    EXPECT_TRUE(apIface->EnablePowerMode(0) == HDF_ERR_NOT_SUPPORT);
}
}